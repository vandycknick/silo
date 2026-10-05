//go:build e2e

package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/crypto/ssh"
	"tailscale.com/tsnet"
)

func TestLiveTailnetKVMOwnedOperations(t *testing.T) {
	for _, name := range []string{"SILO_E2E_TS_TAILNET", "SILO_E2E_TS_CLIENT_SECRET", "SILO_E2E_TS_PEER_CLIENT_SECRET"} {
		if os.Getenv(name) == "" {
			t.Skip("LIVE PHASE 11 NOT QUALIFIED: missing " + name)
		}
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("LIVE PHASE 11 NOT QUALIFIED: missing SILO_E2E_KVM=1")
	}
	rootfs := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Second)
	defer cancel()
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	c.Tailnet.Hostname = "silo-s11-" + suffix
	c.Tailnet.Tag = "tag:silo-test"
	c.Tailnet.ControlURL = os.Getenv("SILO_E2E_TS_CONTROL_URL")
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: "1GiB", Disk: "1GiB"}
	node, e := tailnet.Start(ctx, c, config.Secrets{ClientSecret: os.Getenv("SILO_E2E_TS_CLIENT_SECRET")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	key, e := tailnet.Mint(ctx, &http.Client{Timeout: 30 * time.Second}, "https://api.tailscale.com", os.Getenv("SILO_E2E_TS_PEER_CLIENT_SECRET"), "tag:silo-test-vm")
	if e != nil {
		t.Fatal(e)
	}
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: "silo-s11-peer-" + suffix, AuthKey: key, AdvertiseTags: []string{"tag:silo-test-vm"}, ControlURL: c.Tailnet.ControlURL, UserLogf: t.Logf}
	defer peer.Close()
	if _, e = peer.Up(ctx); e != nil {
		t.Fatal(e)
	}
	// Registered control-plane clients are initialized before temporary native
	// registry trust. No credentials or host-image escape enters the create API.
	registry := testfixture.OCIRegistry(t, rootfs)
	c.VM.DefaultImage = registry.Reference
	c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	r, e := runtime.Open(ctx, c, "live-s11")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	jobctx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	svc := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(jobctx, 16), Config: c, Capability: c.Tailnet.Capability, VisibleNames: node.VisibleNames}
	listener, e := node.Server.ListenSSH(":22")
	if e != nil {
		t.Fatal(e)
	}
	server := &Server{Service: svc, Resolver: node, Global: 16, PerPeer: 4}
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		_ = listener.Close()
		server.CloseSessions()
		closing, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_ = server.Wait(closing)
		_ = svc.Jobs.Wait(closing)
		select {
		case <-served:
		case <-closing.Done():
			t.Error("live service did not drain")
		}
		entries, _ := r.SDK.Inventory(closing)
		for _, entry := range entries {
			m, e := r.SDK.Machine(closing, entry.ID)
			if e == nil {
				_, _ = m.StopWith(closing, silo.StopOptions{Force: true, Timeout: time.Second})
				_ = m.Remove(closing)
				_ = m.Close()
			}
		}
	}()
	if status.Self == nil || len(status.Self.TailscaleIPs) == 0 {
		t.Fatal("service has no tailnet address")
	}
	connection, e := peer.Dial(ctx, "tcp", status.Self.TailscaleIPs[0].String()+":22")
	if e != nil {
		t.Fatal(e)
	}
	_ = connection.SetDeadline(time.Now().Add(180 * time.Second))
	defer connection.Close()
	// Disposable first contact inside the explicitly gated qualification tailnet.
	cc, ch, requests, e := ssh.NewClientConn(connection, c.Tailnet.Hostname, &ssh.ClientConfig{User: "forged-lobby-username", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	client := ssh.NewClient(cc, ch, requests)
	defer client.Close()
	run := func(command string) ([]byte, error) {
		session, e := client.NewSession()
		if e != nil {
			return nil, e
		}
		defer session.Close()
		return session.Output(command)
	}
	output, e := run("whoami --json")
	if e != nil {
		t.Fatal(e)
	}
	var who struct {
		OK   bool
		Data service.WhoAmI
	}
	if e = json.Unmarshal(output, &who); e != nil || !who.OK || len(who.Data.Peer.Principals) != 1 || who.Data.Peer.Principals[0] != "tag:silo-test-vm" {
		t.Fatal(string(output), e)
	}
	name := "s11-" + suffix
	for _, command := range []string{"create --name " + name + " --json", "ls --json", "show " + name + " --json", "exec " + name + " -- /bin/id -u"} {
		output, e = run(command)
		if e != nil {
			t.Fatalf("%s: %v %s", command, e, output)
		}
	}
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	if e = session.RequestPty("s11-live", 37, 119, ssh.TerminalModes{}); e != nil {
		t.Fatal(e)
	}
	session.Stdin = strings.NewReader("stty size\nexit 3\n")
	var terminal, terminalError bytes.Buffer
	session.Stdout = &terminal
	session.Stderr = &terminalError
	e = session.Run("shell " + name)
	_ = session.Close()
	if exit, ok := e.(*ssh.ExitError); !ok || exit.ExitStatus() != 3 || !strings.Contains(terminal.String(), "37 119") {
		t.Fatal("live PTY status/initial size", e, terminal.String())
	}
	if _, e = run("rm " + name + " --yes"); e == nil {
		t.Fatal("running removal accepted")
	} else if exit, ok := e.(*ssh.ExitError); !ok || exit.ExitStatus() != 5 {
		t.Fatal(e)
	}
	for _, command := range []string{"logs " + name + " --stream serial", "stop " + name + " --json", "set " + name + " memory=768MiB --json", "start " + name + " --json", "restart " + name + " --json", "ops --json", "rm " + name + " --force --yes --json"} {
		if output, e = run(command); e != nil {
			t.Fatalf("%s: %v %s", command, e, output)
		}
	}
}
