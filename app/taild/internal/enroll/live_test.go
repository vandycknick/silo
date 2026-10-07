//go:build e2e

package enroll

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/crypto/ssh"
	"tailscale.com/tsnet"
)

// This gate uses real control, tsnet-produced state, native KVM and a real tag
// peer's SSH connection. Domain service inputs elsewhere do not qualify WhoIs.
func TestLiveNetdTagEnrollmentKVMStateReuseAndSSH(t *testing.T) {
	for _, key := range []string{"SILO_E2E_TS_TAILNET", "SILO_E2E_TS_CLIENT_SECRET", "SILO_E2E_TS_PEER_CLIENT_SECRET", "SILO_E2E_TS_API_TOKEN"} {
		if os.Getenv(key) == "" {
			t.Skip(key + " required; live enrollment UNVERIFIED")
		}
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	root := testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	registry := testfixture.OCIRegistry(t, testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true))
	cfg := testfixture.Config()
	cfg.Home = t.TempDir()
	cfg.Components = testfixture.Components(root)
	cfg.Tailnet.Tag = "tag:silo-test"
	cfg.Tailnet.Hostname = fmt.Sprintf("s13-lobby-%x", time.Now().UnixNano())
	cfg.Tailnet.ControlURL = os.Getenv("SILO_E2E_TS_CONTROL_URL")
	secrets := config.Secrets{ClientSecret: os.Getenv("SILO_E2E_TS_CLIENT_SECRET"), APIToken: os.Getenv("SILO_E2E_TS_API_TOKEN")}
	lobby, err := tailnet.Start(ctx, cfg, secrets, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal("live lobby startup failed")
	}
	defer lobby.Close()
	if err = lobby.WaitReady(ctx); err != nil {
		t.Fatal("live lobby readiness failed")
	}
	observed, err := lobby.Status(ctx)
	if err != nil {
		t.Fatal("live lobby status unavailable")
	}
	if identity.CanonicalDNS(observed.CurrentTailnet.MagicDNSSuffix) != identity.CanonicalDNS(os.Getenv("SILO_E2E_TS_TAILNET")) {
		t.Fatal("qualification tailnet mismatch")
	}
	pin := state.NodePin{Tailnet: observed.CurrentTailnet.Name, Suffix: observed.CurrentTailnet.MagicDNSSuffix, ControlURL: cfg.Tailnet.ControlURL}
	devices := NewDevices(secrets.APIToken)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = lobby.Close()
		if devices.Delete(cleanup, string(observed.Self.ID)) != nil {
			t.Error("live lobby device retained")
		}
	}()
	fixture := daemon.Open(t, cfg, "live-enrollment", 1)
	sdk := fixture.SDK
	name := fmt.Sprintf("s13-vm-%x", time.Now().UnixNano())
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{Tunnels: []silo.TailscaleTunnel{{Name: "vm", Hostname: &name, Tags: []string{"tag:silo-test-vm"}, ControlURL: &pin.ControlURL}}})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := sdk.CreateMachine(ctx, silo.OCIImage(registry.Reference), silo.WithName(name), silo.WithVsock(true), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithRootDiskSize(silo.Gibibytes(1)), silo.WithGuestUser("silo", 1000, 1000, "/home/silo"), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	var stable string
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 45*time.Second)
		defer done()
		_, _ = machine.StopWith(cleanup, silo.StopOptions{Force: true, Timeout: time.Second})
		_ = machine.Remove(cleanup)
		if stable != "" {
			if devices.Delete(cleanup, stable) != nil {
				t.Error("live VM device retained")
			}
		}
	}()
	if err = machine.SetSecret(ctx, "tailscale.vm.client_secret", []byte(secrets.ClientSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.WaitReady(ctx, 45*time.Second); err != nil {
		t.Fatal(err)
	}
	data, err := fixture.Control.Inspect(ctx, machine.ID())
	if err != nil || data.RunID == nil {
		t.Fatal("started VM run unavailable", err)
	}
	firstRun := *data.RunID
	waitNode := func(run string) string {
		t.Helper()
		for {
			snapshot, inspectErr := fixture.Control.Inspect(ctx, data.ID)
			if inspectErr == nil && snapshot.NetworkObservation != nil {
				live := snapshot.NetworkObservation.Live
				if live != nil && live.State == w.NodeState_NODE_STATE_READY {
					if snapshot.RunID == nil || *snapshot.RunID != run || live.MachineId != data.ID || live.RunId != run || live.GetNodeId() == "" {
						t.Fatal("ready node observation does not match VM run")
					}
					return live.GetNodeId()
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("netd enrollment did not complete", inspectErr)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	stable = waitNode(firstRun)
	key, err := tailnet.Mint(ctx, &http.Client{Timeout: 30 * time.Second}, "https://api.tailscale.com", os.Getenv("SILO_E2E_TS_PEER_CLIENT_SECRET"), "tag:silo-test-vm")
	if err != nil {
		t.Fatal("live peer mint failed")
	}
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: fmt.Sprintf("s13-peer-%x", time.Now().UnixNano()), AuthKey: key, AdvertiseTags: []string{"tag:silo-test-vm"}, ControlURL: pin.ControlURL, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
	defer peer.Close()
	peerStatus, err := peer.Up(ctx)
	if err != nil {
		t.Fatal("live peer not running")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = peer.Close()
		if devices.Delete(cleanup, string(peerStatus.Self.ID)) != nil {
			t.Error("live peer device retained")
		}
	}()
	conn, err := peer.Dial(ctx, "tcp", net.JoinHostPort(name+"."+pin.Suffix, "22"))
	if err != nil {
		t.Fatal("VM SSH dial failed")
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	sshConn, chans, requests, err := ssh.NewClientConn(conn, name, &ssh.ClientConfig{User: "silo", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 15 * time.Second})
	if err != nil {
		conn.Close()
		t.Fatal("VM SSH handshake failed")
	}
	client := ssh.NewClient(sshConn, chans, requests)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("printf s13-live")
	session.Close()
	client.Close()
	if err != nil || strings.TrimSpace(string(output)) != "s13-live" {
		t.Fatal("live guest SSH execution failed")
	}
	if _, err = machine.StopWith(ctx, silo.StopOptions{Force: true, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.WaitReady(ctx, 45*time.Second); err != nil {
		t.Fatal(err)
	}
	restarted, err := fixture.Control.Inspect(ctx, data.ID)
	if err != nil || restarted.RunID == nil {
		t.Fatal("restarted VM run unavailable", err)
	}
	if *restarted.RunID == firstRun {
		t.Fatal("restart reused VM run")
	}
	if waitNode(*restarted.RunID) != stable {
		t.Fatal("restart changed stable node")
	}
}
