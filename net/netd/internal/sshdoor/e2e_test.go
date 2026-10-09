package sshdoor

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This uses an actual already-running native KVM fixture, its machine CA,
// immutable libvm pin and the actual VMM mux. It never enrolls a tailnet node.
func TestNativeKVMRelayCore(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SKIPPED: SILO_E2E_KVM=1 required")
	}
	machine, mux := os.Getenv("SILO_TEST_SSH_MACHINE_DIR"), os.Getenv("SILO_TEST_SSH_MUX")
	if machine == "" || mux == "" {
		t.Skip("SKIPPED: running fixture SILO_TEST_SSH_MACHINE_DIR and SILO_TEST_SSH_MUX required")
	}
	data, err := os.ReadFile(filepath.Join(machine, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var records map[string]struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	ca := []byte(records["silo.ssh_ca.private_key"].Value)
	if len(ca) == 0 {
		t.Fatal("actual machine CA absent")
	}
	ctx, cancel := context.WithCancel(context.Background())
	d, err := New(ctx, filepath.Join(machine, "ssh"), mux, ca, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	f := &fixture{door: d, user: "root", ctx: ctx, cancel: cancel}
	f.front(t)
	t.Cleanup(func() { cancel(); f.wg.Wait(); d.Close() })
	c := f.client(t)
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Setenv("SILO_PEER", "spoof"); err == nil {
		t.Fatal("overwrite accepted")
	}
	out, err := s.CombinedOutput("printf 'S9_NATIVE:%s\\n' \"$SILO_PEER\"; cat /etc/ssh/silo_ca.pub")
	s.Close()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !bytes.Contains(out, []byte("S9_NATIVE:offline@example.com")) || !bytes.Contains(out, []byte(records["silo.ssh_ca.public_key"].Value)) {
		t.Fatalf("%s", out)
	}
	s, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("xterm", 37, 119, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	out, err = s.CombinedOutput("/bin/stty size; printf 'S9_PTY\\n'")
	s.Close()
	if err != nil || !bytes.Contains(out, []byte("37 119")) {
		t.Fatalf("native PTY: %v %s", err, out)
	}
	s, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var shell bytes.Buffer
	s.Stdout = &shell
	s.Stdin = strings.NewReader("printf 'S9_SHELL:%s\\n' \"$SILO_PEER\"\nexit 0\n")
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if !bytes.Contains(shell.Bytes(), []byte("S9_SHELL:offline@example.com")) {
		t.Fatalf("native shell: %s", shell.Bytes())
	}
	t.Log("PASS actual native KVM shell/exec/PTY relay with machine CA, pin and mux; native SFTP/port-forwarding unsupported and not claimed")
}

func TestAuthenticationDenialBannerAndShutdown(t *testing.T) {
	_, ca := testKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event, 20)
	d, err := New(ctx, filepath.Join(t.TempDir(), "ssh"), "unused", ca, func(e Event) { events <- e })
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx, l, nil) }()
	key, _ := testKey(t)
	for _, auth := range [][]ssh.AuthMethod{nil, {ssh.Password("ignored")}, {ssh.PublicKeys(key)}} {
		var banner string
		c, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{User: "requested-user", Auth: auth, HostKeyCallback: ssh.FixedHostKey(d.host.PublicKey()), Timeout: time.Second, BannerCallback: func(message string) error { banner += message; return nil }})
		if err == nil {
			c.Close()
			t.Fatal("missing WhoIs identity allowed")
		}
		if !bytes.Contains([]byte(banner), []byte("not the owner of this VM")) {
			t.Fatalf("actionable denial absent: %q (%v)", banner, err)
		}
		select {
		case e := <-events:
			if e.User != "requested-user" || e.Decision != "deny" || e.RequestID == "" || e.Reason != "not_owner" {
				t.Fatalf("%+v", e)
			}
		case <-time.After(time.Second):
			t.Fatal("denial not audited")
		}
	}
	// Handshakes blocked before an SSH banner must be actively closed, joined
	// and release handshake/connection reservations on owner cancellation.
	for range 16 {
		stalled, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer stalled.Close()
	}
	deadline := time.Now().Add(time.Second)
	for len(d.handshakes) != 16 {
		if time.Now().After(deadline) {
			t.Fatal("handshakes not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	seventeenth, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer seventeenth.Close()
	select {
	case e := <-events:
		if e.Reason != "handshake_limit" || e.Decision != "deny" {
			t.Fatalf("%+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("17th handshake not rejected")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not join cancelled setup")
	}
	if len(d.handshakes) != 0 || len(d.connections) != 0 {
		t.Fatal("setup reservations leaked")
	}
}
