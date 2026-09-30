package sshd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"golang.org/x/crypto/ssh"
	"net/http"
	"tailscale.com/tsnet"
)

func TestLiveTailnetLobbyIdentityAndCapability(t *testing.T) {
	for _, name := range []string{"SILO_E2E_TS_TAILNET", "SILO_E2E_TS_CLIENT_SECRET", "SILO_E2E_TS_PEER_CLIENT_SECRET"} {
		if os.Getenv(name) == "" {
			t.Skip("LIVE TAILNET NOT QUALIFIED: missing " + name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := config.Defaults()
	c.Home = t.TempDir()
	c.Tailnet.Hostname = "silo-test"
	c.Tailnet.Tag = "tag:silo-test"
	c.Tailnet.ControlURL = os.Getenv("SILO_E2E_TS_CONTROL_URL")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	node, e := tailnet.Start(ctx, c, config.Secrets{ClientSecret: os.Getenv("SILO_E2E_TS_CLIENT_SECRET")}, log)
	if e != nil {
		t.Fatal(e)
	}
	defer node.Close()
	if e = node.WaitReady(ctx); e != nil {
		t.Fatal(e)
	}
	status, e := node.Client.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if status.CurrentTailnet == nil || !strings.EqualFold(strings.TrimSuffix(status.CurrentTailnet.MagicDNSSuffix, "."), strings.TrimSuffix(os.Getenv("SILO_E2E_TS_TAILNET"), ".")) {
		t.Fatal("wrong qualification tailnet")
	}
	listener, e := node.Server.ListenSSH(":22")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	audit, e := state.OpenAudit(c.Home, 4096, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	svc := &service.Service{Audit: audit, Capability: c.Tailnet.Capability}
	server := &Server{Service: svc, Resolver: node, Global: 16, PerPeer: 4}
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		listener.Close()
		closing, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if e := server.Wait(closing); e != nil {
			t.Error(e)
		}
		select {
		case <-served:
		case <-closing.Done():
			t.Error("live SSH accept loop did not join")
		}
	}()
	for _, tag := range []string{"tag:silo-test-vm", "tag:silo-test-peer"} {
		key, e := tailnet.Mint(ctx, &http.Client{Timeout: 30 * time.Second}, "https://api.tailscale.com", os.Getenv("SILO_E2E_TS_PEER_CLIENT_SECRET"), tag)
		if e != nil {
			t.Fatal(e)
		}
		peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "silo-peer-" + strings.TrimPrefix(tag, "tag:"), AuthKey: key, AdvertiseTags: []string{tag}, ControlURL: c.Tailnet.ControlURL, UserLogf: t.Logf}
		defer peer.Close()
		if _, e = peer.Up(ctx); e != nil {
			t.Fatal(e)
		}
		conn, e := peer.Dial(ctx, "tcp", status.Self.TailscaleIPs[0].String()+":22")
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		defer conn.Close()
		// Disposable-node first contact, never a production pin bypass.
		cc, channels, requests, e := ssh.NewClientConn(conn, "silo-test", &ssh.ClientConfig{User: "untrusted-username", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		client := ssh.NewClient(cc, channels, requests)
		session, e := client.NewSession()
		if e != nil {
			t.Fatal(e)
		}
		output, e := session.Output("whoami --json")
		if e != nil {
			t.Fatal(e)
		}
		session.Close()
		client.Close()
		var response struct {
			OK   bool
			Data service.WhoAmI
		}
		if e = json.Unmarshal(output, &response); e != nil || !response.OK || len(response.Data.Peer.Principals) != 1 || string(response.Data.Peer.Principals[0]) != tag {
			t.Fatalf("%s %v", output, e)
		}
		permitted := len(response.Data.Peer.Permissions.Actions) > 0
		if permitted != (tag == "tag:silo-test-vm") {
			t.Fatalf("unexpected capability on %s", tag)
		}
	}
}
