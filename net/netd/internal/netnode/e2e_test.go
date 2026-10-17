package netnode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/tsnet"
)

// This gate uses a real CLI, local disk, KVM, embedded peer and control plane.
// The local ext4 fixture must contain the real static /bin/s8-guest HTTP probe.
func TestRealTailnetKVMGuestMagicDNSAndClosedPort(t *testing.T) {
	secret, suffix := os.Getenv("SILO_E2E_TS_CLIENT_SECRET"), os.Getenv("SILO_E2E_TS_TAILNET")
	if os.Getenv("SILO_E2E_KVM") != "1" || secret == "" || suffix == "" {
		t.Skip("requires SILO_E2E_KVM=1, SILO_E2E_TS_CLIENT_SECRET and SILO_E2E_TS_TAILNET")
	}
	cli, disk := os.Getenv("SILO_TEST_CLI_BIN"), os.Getenv("SILO_E2E_TS_VM_ROOT_DISK")
	if cli == "" || disk == "" {
		t.Skip("requires SILO_TEST_CLI_BIN and SILO_E2E_TS_VM_ROOT_DISK (local ext4 containing /bin/s8-guest), plus installed runtime")
	}
	if info, err := os.Stat(disk); err != nil || !info.Mode().IsRegular() {
		t.Fatal("invalid local root disk")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	name := fmt.Sprintf("silo-s8-%x", time.Now().UnixNano())
	peer := &tsnet.Server{Dir: t.TempDir(), Hostname: name + "-peer", AuthKey: mintEnrollmentKey(t, ctx, secret), AdvertiseTags: []string{"tag:silo-test-vm"}, ControlURL: os.Getenv("SILO_E2E_TS_CONTROL_URL"), UserLogf: t.Logf}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	status, err := peer.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Self == nil || !strings.HasSuffix(strings.TrimSuffix(status.Self.DNSName, "."), suffix) {
		t.Fatal("unexpected test tailnet")
	}
	listener, err := peer.Listen("tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "S8_REAL_TAILNET_PEER") })}
	go server.Serve(listener)
	defer server.Close()
	home := t.TempDir()
	stored := map[string]struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}{"vm.tailscale.auth_key": {Type: "plain", Value: mintEnrollmentKey(t, ctx, secret)}}
	body, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(home, "secrets.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(home, "policy.json")
	control := os.Getenv("SILO_E2E_TS_CONTROL_URL")
	policyBody := fmt.Sprintf(`{"version":1,"settings":{"default_action":"allow"},"tailscale":[{"name":"vm","hostname":%q,"tags":["tag:silo-test-vm"],"control_url":%q}],"endpoints":[{"name":"tail","kind":"ip","family":"ip","transport":"packet-filter","tls":"none","destination_cidrs":["100.64.0.0/10","fd7a:115c:a1e0::/48"],"protocol":"tcp"}],"rules":[{"name":"tail","endpoints":["tail"],"tunnel":"vm","verdict":"allow"}]}`, name, control)
	if err = os.WriteFile(policyPath, []byte(policyBody), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "SILO_HOME="+home)
	runCLI := func(args ...string) []byte {
		command := exec.CommandContext(ctx, cli, args...)
		command.Env = env
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %s: %v\n%s", args[0], err, output)
		}
		return output
	}
	runCLI("create", "disk:"+disk, "--name", name, "--cpus", "1", "--memory", "1gb", "--network", "private", "--vsock")
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, args := range [][]string{{"stop", name, "--force", "--timeout", "5s"}, {"rm", name}} {
			command := exec.CommandContext(cleanup, cli, args...)
			command.Env = env
			if output, err := command.CombinedOutput(); err != nil {
				t.Errorf("cleanup %s: %v %s", args[0], err, output)
			}
		}
	}()
	runCLI("network", "set", name, "private", "--policy", policyPath)
	runCLI("start", name)
	var view struct {
		ID    string `json:"id"`
		Ready bool   `json:"ready"`
	}
	if err = json.Unmarshal(runCLI("show", name, "--format", "json"), &view); err != nil || !view.Ready {
		t.Fatalf("guest status %v %v", view, err)
	}
	lc, err := peer.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	var vmIP netip.Addr
	for ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		raw, _, err := lc.QueryDNS(bounded, name+"."+suffix, "A")
		cancel()
		answer := new(dns.Msg)
		if err == nil && answer.Unpack(raw) == nil {
			for _, rr := range answer.Answer {
				if a, ok := rr.(*dns.A); ok {
					vmIP, _ = netip.AddrFromSlice(a.A)
				}
			}
		}
		if vmIP.IsValid() {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !vmIP.IsValid() {
		t.Fatal("real VM node did not enroll")
	}
	output := runCLI("exec", name, "--", "/bin/s8-guest", "request", "http://"+strings.TrimSuffix(status.Self.DNSName, ".")+":8080/")
	if !strings.Contains(string(output), "S8_REAL_TAILNET_PEER") {
		t.Fatalf("guest MagicDNS tunnel response %s", output)
	}
	dial, err := strictDialer(peer)
	if err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := dial(bounded, netip.AddrPortFrom(vmIP.Unmap(), 8080))
	cancel()
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
		if err == nil {
			t.Fatal("closed guest port delivered bytes")
		}
	}
	auditPath := filepath.Join(home, "logs", "machines", view.ID, "network", "audit.jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for {
		body, err := os.ReadFile(auditPath)
		if err == nil && strings.Contains(string(body), `"reason":"guest_connection_failed"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed guest port missing actual inbound audit")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
