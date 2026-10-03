//go:build e2e

package enroll

import (
	"context"
	"fmt"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	"golang.org/x/crypto/ssh"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"tailscale.com/tsnet"
	"testing"
	"time"
)

// This gate uses real control, tsnet-produced state, native KVM and a real tag
// peer's SSH connection. Domain service inputs elsewhere do not qualify WhoIs.
func TestLiveTagEnrollmentKVMStateReuseReauthAndSSH(t *testing.T) {
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
	cfg := config.Defaults()
	cfg.Home = t.TempDir()
	cfg.RuntimeRoot = root
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
	cfg.Enrollment.Timeout = "1m"
	manager := &Manager{Config: cfg, Secrets: secrets, Pin: pin, Registry: NewRegistry(), Devices: NewDevices(secrets.APIToken), Visible: lobby.Status}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = lobby.Close()
		if manager.Devices.Delete(cleanup, string(observed.Self.ID)) != nil {
			t.Error("live lobby device retained")
		}
	}()
	sdk, err := silo.Open(ctx, silo.WithHome(cfg.Home), silo.WithRuntimeRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	defer sdk.Close()
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
			if manager.Devices.Delete(cleanup, stable) != nil {
				t.Error("live VM device retained")
			}
		}
	}()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Enroll(ctx, machine, data, "tag:silo-test-vm", false, func(line string) { t.Log(line) }, nil); err != nil {
		t.Fatal("live enrollment failed")
	}
	enrolled, s := state.ReadNode(data.Network.Tailscale.StateDir, name, "tag:silo-test-vm", &pin)
	if s != state.Enrolled {
		t.Fatal("actual tsnet state unreadable")
	}
	stable = enrolled.NodeID
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.WaitReady(ctx, 45*time.Second); err != nil {
		t.Fatal(err)
	}
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
		if manager.Devices.Delete(cleanup, string(peerStatus.Self.ID)) != nil {
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
	if err = manager.Enroll(ctx, machine, data, "tag:silo-test-vm", true, func(line string) { t.Log(line) }, nil); err != nil {
		t.Fatal("explicit live reauth failed")
	}
	renewed, s := state.ReadNode(data.Network.Tailscale.StateDir, name, "tag:silo-test-vm", &pin)
	if s != state.Enrolled || renewed.NodeID != stable || renewed.NodeKey == enrolled.NodeKey {
		t.Fatal("closed reauth state failed stable-ID or changed-public-key verification")
	}
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.WaitReady(ctx, 45*time.Second); err != nil {
		t.Fatal(err)
	}
	reused, s := state.ReadNode(data.Network.Tailscale.StateDir, name, "tag:silo-test-vm", &pin)
	if s != state.Enrolled || reused.NodeID != stable {
		t.Fatal("restart changed stable node")
	}
}
