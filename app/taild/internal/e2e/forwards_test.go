//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"tailscale.com/tsnet"
)

// This test publishes disposable certificate-transparency names. It requires a
// certificate-enabled test tailnet, trusted system roots, real KVM/native assets,
// and an independently denied peer. It never modifies grants or DNS settings.
// The denied secret/tag must enroll a distinct identity with no grant to VM 443;
// additive broad grants invalidate that fixture and make this test fail.
// SILO_TAILD_TEST_ROOTFS must boot systemd as PID 1 and include systemctl.
// Once-only shell userdata installs/enables the persistent probe unit; it does
// not depend on userdata being rerun on subsequent starts.
func TestLiveTailnetPolicyForwards(t *testing.T) {
	for _, key := range []string{"SILO_E2E_TS_TAILNET", "SILO_E2E_TS_CLIENT_SECRET", "SILO_E2E_TS_PEER_CLIENT_SECRET", "SILO_E2E_TS_API_TOKEN", "SILO_E2E_TS_DENIED_CLIENT_SECRET", "SILO_E2E_TS_DENIED_TAG", "SILO_TAILD_FORWARD_PROBE"} {
		if os.Getenv(key) == "" {
			if os.Getenv("SILO_TAILD_REQUIRE_FIXTURES") == "1" {
				t.Fatal(key + " required; live forward proof UNVERIFIED")
			}
			t.Skip(key + " required; live forward proof UNVERIFIED")
		}
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required; live forward proof UNVERIFIED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	// Capture normal trust before OCIRegistry installs its isolated registry CA.
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	probe, err := os.ReadFile(testfixture.Path(t, "SILO_TAILD_FORWARD_PROBE", false))
	if err != nil {
		t.Fatal(err)
	}
	rootfs := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	hasSystemctl := false
	for _, candidate := range []string{"usr/bin/systemctl", "bin/systemctl"} {
		if _, err := os.Lstat(filepath.Join(rootfs, candidate)); err == nil {
			hasSystemctl = true
		}
	}
	if !hasSystemctl {
		t.Fatal("live forwards require SILO_TAILD_TEST_ROOTFS with systemctl and systemd as PID 1; once-only userdata installs a persistent systemd service")
	}
	registry := testfixture.OCIRegistry(t, rootfs, testfixture.GuestFile{Path: "usr/local/bin/silo-forward-probe", Mode: 0755, Data: probe})
	cfg := daemon.Config(t, registry)
	cfg.VM.Defaults.Memory = 1 << 30
	cfg.Tailnet.Tag = "tag:silo-test"
	cfg.Tailnet.Hostname = fmt.Sprintf("forward-lobby-%x", time.Now().UnixNano())
	cfg.Tailnet.ControlURL = os.Getenv("SILO_E2E_TS_CONTROL_URL")
	secrets := config.Secrets{ClientSecret: os.Getenv("SILO_E2E_TS_CLIENT_SECRET"), APIToken: os.Getenv("SILO_E2E_TS_API_TOKEN")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lobby, err := tailnet.Start(ctx, cfg, secrets, logger)
	if err != nil {
		t.Fatal("live lobby startup failed")
	}
	defer lobby.Close()
	if err = lobby.WaitReady(ctx); err != nil {
		t.Fatal("live lobby readiness failed")
	}
	status, err := lobby.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if identity.CanonicalDNS(status.CurrentTailnet.MagicDNSSuffix) != identity.CanonicalDNS(os.Getenv("SILO_E2E_TS_TAILNET")) {
		t.Fatal("qualification tailnet mismatch")
	}
	pin := state.NodePin{Tailnet: status.CurrentTailnet.Name, Suffix: status.CurrentTailnet.MagicDNSSuffix, ControlURL: cfg.Tailnet.ControlURL}
	devices := testfixture.NewDevices(secrets.APIToken)
	cleanupDevice := func(id string, closeNode func() error) {
		t.Helper()
		_ = closeNode()
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if err := devices.Delete(cleanup, id); err != nil {
			t.Error("live test device retained")
		}
	}
	defer cleanupDevice(string(status.Self.ID), lobby.Close)
	startPeer := func(secret, tag, prefix string) *tsnet.Server {
		t.Helper()
		key, err := tailnet.Mint(ctx, &http.Client{Timeout: 30 * time.Second}, "https://api.tailscale.com", secret, tag)
		if err != nil {
			t.Fatal("live peer mint failed")
		}
		peer := &tsnet.Server{Dir: t.TempDir(), Hostname: fmt.Sprintf("%s-%x", prefix, time.Now().UnixNano()), AuthKey: key, AdvertiseTags: []string{tag}, ControlURL: pin.ControlURL, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
		t.Cleanup(func() { _ = peer.Close() })
		observed, err := peer.Up(ctx)
		if err != nil {
			t.Fatal("live peer not running")
		}
		t.Cleanup(func() { cleanupDevice(string(observed.Self.ID), peer.Close) })
		if observed.Self == nil || observed.CurrentTailnet == nil || identity.CanonicalDNS(observed.CurrentTailnet.MagicDNSSuffix) != identity.CanonicalDNS(pin.Suffix) || observed.Self.Tags == nil || !slices.Contains(observed.Self.Tags.AsSlice(), tag) {
			t.Fatal("live peer identity does not match qualification tag/tailnet")
		}
		return peer
	}
	peer := startPeer(os.Getenv("SILO_E2E_TS_PEER_CLIENT_SECRET"), "tag:silo-test-vm", "forward-peer")
	deniedTag := os.Getenv("SILO_E2E_TS_DENIED_TAG")
	if deniedTag == "tag:silo-test-vm" || deniedTag == cfg.Tailnet.Tag {
		t.Fatal("denied peer requires an independent tag")
	}
	denied := startPeer(os.Getenv("SILO_E2E_TS_DENIED_CLIENT_SECRET"), deniedTag, "forward-denied")
	// Keep an actual peer -> lobby socket alive for WhoIs, including subsequent
	// job revalidation. Never manufacture principals or capability permissions.
	listener, err := lobby.Server.Listen("tcp", ":22")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	incoming := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			incoming <- conn
		}
		close(incoming)
	}()
	authConn, err := peer.Dial(ctx, "tcp", net.JoinHostPort(identity.CanonicalDNS(status.Self.DNSName), "22"))
	if err != nil {
		t.Fatal("authorized peer requires existing lobby port 22 grant")
	}
	defer authConn.Close()
	var accepted net.Conn
	select {
	case accepted = <-incoming:
	case <-ctx.Done():
		t.Fatal("lobby authentication connection timed out")
	}
	if accepted == nil {
		t.Fatal("lobby listener failed")
	}
	defer accepted.Close()
	resolve := func(ctx context.Context) (identity.Peer, error) {
		return lobby.WhoIs(ctx, accepted.RemoteAddr().String())
	}
	verified, err := resolve(ctx)
	if err != nil {
		t.Fatal("real lobby WhoIs/capability lookup failed")
	}
	caller := service.Caller{Peer: verified, Resolve: resolve}
	fixture := daemon.Open(t, cfg, "live-forwards", 4)
	s := &service.Service{Runtime: fixture.Runtime, Audit: fixture.Audit, Jobs: fixture.Jobs, Config: cfg, Capability: cfg.Tailnet.Capability, VMNodesEnabled: true, Enrollment: &enroll.Manager{Config: cfg, Secrets: secrets, Pin: pin, Registry: enroll.NewRegistry(), Metrics: fixture.Runtime.Metrics}}
	run := func(line, input string) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := sshd.DispatchSession(ctx, s, caller, line, service.IO{Stdin: strings.NewReader(input), Stdout: &out, Stderr: &diagnostic}); code != 0 {
			t.Fatalf("%s exit %d\n%s\n%s", line, code, &out, &diagnostic)
		}
		return out.String() + diagnostic.String()
	}
	policy := `forward "tailscale" "web" {
 listen = ":443"
 target = "self"
 target_port = 8080
 protocol = "https"
 tls { provider = "tailscale" }
}
forward "tailscale" "raw" {
 listen = ":18080"
 target = "self"
 target_port = 8080
 protocol = "tcp"
}
`
	run("policy validate --json", policy)
	run("policy create web-forward --json", policy)
	run("policy show web-forward --json", "")
	template := fmt.Sprintf(`version: '1'
image: %s
resources: {cpus: 1, memory: 1GiB}
disk_size: 1GiB
vsock: true
network: {kind: private, policy_ref: web-forward}
userdata: |
  #!/bin/sh
  set -eu
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    echo 'Live forwards require SILO_TAILD_TEST_ROOTFS booting systemd as PID 1 with systemctl' >&2
    exit 1
  fi
  mkdir -p /etc/systemd/system
  cat >/etc/systemd/system/silo-forward-probe.service <<'UNIT'
  [Unit]
  Description=Silo live forward guest probe
  After=network.target
  [Service]
  ExecStart=/usr/local/bin/silo-forward-probe
  Restart=on-failure
  [Install]
  WantedBy=multi-user.target
  UNIT
  systemctl daemon-reload
  systemctl enable --now silo-forward-probe.service
`, registry.Reference)
	run("template create web-forward --json", template)
	name := fmt.Sprintf("forward-vm-%x", time.Now().UnixNano())
	var nodeID string
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 45*time.Second)
		defer done()
		var diagnostic bytes.Buffer
		code := sshd.DispatchSession(cleanup, s, caller, "rm "+name+" --force --yes --json", service.IO{Stdout: io.Discard, Stderr: &diagnostic})
		if code != 0 {
			t.Errorf("live VM cleanup exit %d: %s", code, &diagnostic)
		}
		if nodeID != "" && devices.Delete(cleanup, nodeID) != nil {
			t.Error("live VM device retained")
		}
	}()
	run("create --name "+name+" --template web-forward --tailscale --tag tag:silo-test-vm --json", "")
	var vmAddress string
	waitNode := func() (string, string) {
		t.Helper()
		for {
			d, err := fixture.Control.Inspect(ctx, name)
			if err == nil && d.RunID != nil && d.NetworkObservation != nil && d.NetworkObservation.Live != nil {
				live := d.NetworkObservation.Live
				if live.State == w.NodeState_NODE_STATE_READY && live.MachineId == d.ID && live.RunId == *d.RunID && live.GetNodeId() != "" && live.GetDnsName() != "" {
					if len(live.GetAddresses()) == 0 || net.ParseIP(live.GetAddresses()[0]) == nil {
						t.Fatal("VM node missing verified tailnet address")
					}
					vmAddress = live.GetAddresses()[0]
					return live.GetNodeId(), identity.CanonicalDNS(live.GetDnsName())
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("VM node not ready", err)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	nodeID, dns := waitNode()
	if shown := run("show "+name+" --json", ""); !strings.Contains(shown, dns) {
		t.Fatal("show missing verified VM DNS", shown)
	}
	transport := &http.Transport{Proxy: nil, DialContext: peer.Dial, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 35 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	var heldPeer string
	request := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+dns+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if path == "/hold-stream" {
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				heldPeer = info.Conn.LocalAddr().String()
			}}))
		}
		req.Header.Set("Forwarded", "host=spoof.invalid;proto=http")
		req.Header.Set("X-Forwarded-Host", "spoof.invalid")
		req.Header.Set("X-Forwarded-Proto", "http")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("normally verified VM HTTPS failed", err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatal("unexpected VM HTTP status", resp.StatusCode)
		}
		return resp
	}
	prove := func() {
		t.Helper()
		conn, err := peer.Dial(ctx, "tcp", net.JoinHostPort(dns, "18080"))
		if err != nil {
			t.Fatal(err)
		}
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dns)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "SILO_FORWARD_GUEST" {
			t.Fatalf("raw TCP guest proof: %q %v", body, err)
		}
		resp = request("/")
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "SILO_FORWARD_GUEST" {
			t.Fatalf("HTTPS guest proof: %q %v", body, err)
		}
	}
	prove()
	resp := request("/headers")
	var headers map[string]string
	err = json.NewDecoder(resp.Body).Decode(&headers)
	resp.Body.Close()
	if err != nil || headers["host"] != dns || headers["x_forwarded_host"] != dns || headers["x_forwarded_proto"] != "https" {
		t.Fatalf("public authority/spoof stripping: %v %v", headers, err)
	}
	var firstAt time.Time
	resp = request("/stream")
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		resp.Body.Close()
		t.Fatal("stream first chunk missing", first, err)
	}
	firstAt = time.Now()
	second, err := reader.ReadString('\n')
	resp.Body.Close()
	if err != nil || second != "second\n" || time.Since(firstAt) < 500*time.Millisecond {
		t.Fatal("stream buffered until backend completion", second, err)
	}
	wrong, err := peer.Dial(ctx, "tcp", net.JoinHostPort(dns, "443"))
	if err != nil {
		t.Fatal(err)
	}
	badTLS := tls.Client(wrong, &tls.Config{RootCAs: roots, ServerName: "wrong.invalid", MinVersion: tls.VersionTLS12})
	handshake, done := context.WithTimeout(ctx, 10*time.Second)
	err = badTLS.HandshakeContext(handshake)
	done()
	badTLS.Close()
	if err == nil {
		t.Fatal("wrong SNI accepted")
	}
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		t.Fatal("server supplied a certificate for rejected SNI instead of refusing the handshake")
	}
	negative, done := context.WithTimeout(ctx, 5*time.Second)
	// Dial the verified IP, not DNS: a hidden denied-peer DNS record must not
	// masquerade as a packet-filter denial.
	blocked, err := denied.Dial(negative, "tcp", net.JoinHostPort(vmAddress, "443"))
	done()
	if err == nil {
		blocked.Close()
		t.Fatal("independently denied peer reached VM 443; check additive grants")
	}
	// Hold both an unfinished TLS handshake and an active streamed response at
	// stop. Stop's successful return must join netd's owners, not orphan sockets.
	stalled, err := peer.Dial(ctx, "tcp", net.JoinHostPort(dns, "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	resp = request("/hold-stream")
	reader = bufio.NewReader(resp.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "first\n" {
		resp.Body.Close()
		t.Fatal("active stream missing", err)
	}
	started, err := fixture.Control.Inspect(ctx, name)
	if err != nil || started.RunID == nil {
		t.Fatal("running generation unavailable before stop", err)
	}
	stoppedRun := *started.RunID
	run("stop "+name+" --timeout 45s --json", "")
	exit, err := fixture.Control.Machines.WaitForRun(ctx, &w.WaitForRunRequest{Machine: &w.MachineRunRef{Id: started.ID, RunId: stoppedRun}, Timeout: durationpb.New(5 * time.Second)})
	if err != nil || exit.GetRunId() != stoppedRun || exit.GetOutcome() != w.ExitOutcome_EXIT_OUTCOME_CLEAN {
		t.Fatalf("stop must observe exact clean MachineExit, never supervisor force: exit=%v err=%v", exit, err)
	}
	_ = stalled.SetReadDeadline(time.Now().Add(5 * time.Second))
	var one [1]byte
	if _, err := stalled.Read(one[:]); err == nil {
		t.Fatal("stalled TLS connection survived stop")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("stop did not close stalled TLS connection")
	}
	_, streamErr := io.ReadAll(reader)
	resp.Body.Close()
	if streamErr == nil {
		t.Fatal("stop did not interrupt active stream")
	}
	// Persisted terminal connection audits must precede the netd generation stop
	// boundary. Socket disappearance alone could also mean supervisor SIGKILL.
	requireForwardStopAudit(t, ctx, filepath.Join(cfg.Home, "logs", "machines", started.ID, "network", "audit.jsonl"), stoppedRun, stalled.LocalAddr().String(), heldPeer)
	transport.CloseIdleConnections()
	run("start "+name+" --json", "")
	restartedID, restartedDNS := waitNode()
	if restartedID != nodeID || restartedDNS != dns {
		t.Fatal("stop/start changed node identity")
	}
	prove()
	t.Logf("real guest TCP and trusted HTTPS https://%s/; spoof stripping, streaming, denied peer, wrong SNI and stop/start identity qualified", dns)
}

func requireForwardStopAudit(t *testing.T, ctx context.Context, path, runID string, peers ...string) {
	t.Helper()
	ports := make(map[uint16]bool, len(peers))
	for _, peer := range peers {
		_, port, err := net.SplitHostPort(peer)
		if err != nil {
			t.Fatal("forward peer address unavailable", err)
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		ports[uint16(number)] = false
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			seen := make(map[uint16]bool, len(ports))
			stopSeen := false
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				var event struct {
					RunID      string `json:"run_id"`
					Family     string `json:"family"`
					Phase      string `json:"phase"`
					Protocol   string `json:"protocol"`
					SourcePort uint16 `json:"source_port"`
					Forward    *struct {
						Name       string `json:"name"`
						TargetPort uint16 `json:"target_port"`
					} `json:"forward"`
				}
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					t.Fatal("invalid persisted network audit", err)
				}
				if event.RunID != runID {
					continue
				}
				if event.Family == "forward" && event.Phase == "end" && event.Protocol == "https" && event.Forward != nil && event.Forward.Name == "web" && event.Forward.TargetPort == 8080 {
					if _, tracked := ports[event.SourcePort]; tracked {
						seen[event.SourcePort] = true
					}
				}
				if event.Family == "netd_generation" && event.Phase == "stop" {
					stopSeen = true
					for port := range ports {
						if !seen[port] {
							t.Fatalf("netd stopped without terminal forward audit for peer port %d", port)
						}
					}
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if stopSeen {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("forward audit join interrupted", ctx.Err())
		case <-deadline.C:
			t.Fatal("missing persisted netd stop boundary; clean VM exit alone does not prove forward ownership")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
