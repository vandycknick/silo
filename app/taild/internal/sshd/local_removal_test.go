package sshd

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

func TestRemovalOpenSSHLocalTailscaleAndStoppedShow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	s, caller, _ := nativeService(t, ctx, "local-removal", "user:7")
	caller.Peer.Login = "owner@example.test"
	// Keep the fresh identity resolver consistent with this explicit test input.
	peer := caller.Peer
	caller.Resolve = func(ctx context.Context) (identity.Peer, error) { return peer, ctx.Err() }
	s.VMNodesEnabled = true
	s.Config.Enrollment.Mode = "interactive"
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}, Registry: enroll.NewRegistry()}
	removalDispatch(t, ctx, s, caller, "create --name local-vm --tailscale --no-start", 0)
	m, err := s.Runtime.SDK.Machine(ctx, "local-vm")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	d, err := m.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d.Network.Tailscale.StateDir, "tailscaled.state"), []byte("unreadable"), 0600); err != nil {
		t.Fatal(err)
	}
	address := terminalSSHServer(t, s, caller)
	_, diagnostic, code := sshPipeCommand(t, address, "show local-vm", nil, false)
	text := string(diagnostic)
	for _, want := range []string{"Owner: owner@example.test\n", "Guest user: root\n", "Node: local-vm.tail.test\n", "Node state: stopped\n", "Key expiry: Unavailable\n"} {
		if code != 0 || !strings.Contains(text, want) {
			t.Fatal(code, text, want)
		}
	}
	for _, bad := range []string{"Labels:", "map[", "Last operation:", "state unreadable"} {
		if strings.Contains(text, bad) {
			t.Fatal(text)
		}
	}
	_, diagnostic, code = sshPipeCommand(t, address, "rm local-vm --yes", nil, false)
	if code != 0 || !regexp.MustCompile(`^   ✓ Removed +local-vm \([0-9.]+s\)\n$`).Match(diagnostic) {
		t.Fatal("unexpected removal output", code, string(diagnostic))
	}
	if _, err = os.Stat(d.MachineDir); !os.IsNotExist(err) {
		t.Fatal("machine files remain", err)
	}
}
