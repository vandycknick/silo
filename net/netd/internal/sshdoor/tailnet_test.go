package sshdoor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/vandycknick/silo/net/netd/internal/bootenv"
	"github.com/vandycknick/silo/net/netd/internal/netnode"
	"golang.org/x/crypto/ssh"
	"tailscale.com/tsnet"
)

// Qualification invokes the actual running netd front door, not the offline
// authorized listener. Its target must be a disposable owner-tagged KVM VM.
func TestRealTailnetSSHFrontDoor(t *testing.T) {
	for _, name := range []string{"SILO_E2E_KVM", "SILO_E2E_TS_TAILNET", "SILO_E2E_TS_PEER_CLIENT_SECRET", "SILO_E2E_TS_SSH_TARGET", "SILO_TEST_SSH_MACHINE_DIR"} {
		if os.Getenv(name) == "" {
			t.Skipf("SKIPPED: %s required for real tailnet/KVM SSH qualification", name)
		}
	}
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SKIPPED: SILO_E2E_KVM=1 required")
	}
	target, err := netip.ParseAddr(os.Getenv("SILO_E2E_TS_SSH_TARGET"))
	if err != nil || !target.IsValid() {
		t.Fatal("SILO_E2E_TS_SSH_TARGET must be the VM's tailnet IP")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	data, err := os.ReadFile(filepath.Join(os.Getenv("SILO_TEST_SSH_MACHINE_DIR"), "ssh/tailnet_host_ed25519_key"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := parseCA(data)
	if err != nil {
		t.Fatal(err)
	}
	login := os.Getenv("SILO_TEST_SSH_USER")
	if login == "" {
		login = "silo"
	}
	for _, tag := range []string{"tag:silo-test-vm", "tag:silo-test-peer"} {
		t.Run(tag, func(t *testing.T) {
			key := mintPeerKey(t, ctx, os.Getenv("SILO_E2E_TS_PEER_CLIENT_SECRET"), tag)
			s := &tsnet.Server{Dir: t.TempDir(), Hostname: "s9-ssh-" + strings.TrimPrefix(tag, "tag:"), AuthKey: key, AdvertiseTags: []string{tag}, Ephemeral: true, ControlURL: os.Getenv("SILO_E2E_TS_CONTROL_URL")}
			defer s.Close()
			upCtx, stop := context.WithTimeout(ctx, 45*time.Second)
			defer stop()
			status, err := s.Up(upCtx)
			if err != nil {
				t.Fatal("qualification peer enrollment failed")
			}
			if status.CurrentTailnet == nil || strings.TrimSuffix(status.CurrentTailnet.MagicDNSSuffix, ".") != strings.TrimSuffix(os.Getenv("SILO_E2E_TS_TAILNET"), ".") {
				t.Fatal("wrong qualification tailnet")
			}
			raw, err := s.Dial(upCtx, "tcp", netip.AddrPortFrom(target, 22).String())
			if err != nil {
				t.Fatal("peer cannot reach TCP22; negative fixture must allow packets to test SSH-door denial")
			}
			defer raw.Close()
			deadline, _ := ctx.Deadline()
			raw.SetDeadline(deadline)
			var banner string
			conn, ch, req, err := ssh.NewClientConn(raw, "vm", &ssh.ClientConfig{User: login, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), BannerCallback: func(message string) error { banner += message; return nil }})
			if tag == "tag:silo-test-peer" {
				if err == nil {
					conn.Close()
					t.Fatal("non-intersecting tag admitted")
				}
				if !strings.Contains(banner, "not the owner of this VM") {
					t.Fatalf("no actionable SSH denial: %q", banner)
				}
				return
			}
			if err != nil {
				t.Fatalf("owner SSH: %v", err)
			}
			client := ssh.NewClient(conn, ch, req)
			defer client.Close()
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			out, err := session.CombinedOutput("id; printf 'S9_WHOIS:%s\\n' \"$SILO_PEER\"")
			session.Close()
			if err != nil || !bytes.Contains(out, []byte("S9_WHOIS:node:")) {
				t.Fatalf("owner exec: %v: %s", err, out)
			}
			// 200MB both directions exercises the encrypted relay and SSH EOF.
			// This is cat throughput, not an scp or native SFTP-support claim.
			session, err = client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			payload := make([]byte, 200_000_000)
			for i := range payload {
				payload[i] = byte(i * 13)
			}
			want := sha256.Sum256(payload)
			hash := sha256.New()
			session.Stdin = bytes.NewReader(payload)
			session.Stdout = hash
			start := time.Now()
			if err := session.Run("cat"); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want[:], hash.Sum(nil)) {
				t.Fatal("200MB tailnet transfer hash mismatch")
			}
			t.Logf("real-tailnet 200MB roundtrip duration=%s (not local throughput)", time.Since(start))
			t.Run("scp-200mb", func(t *testing.T) { liveSCP(t, ctx, s, target, login, host.PublicKey(), payload) })
		})
	}
}

func liveSCP(t *testing.T, ctx context.Context, peer *tsnet.Server, target netip.Addr, user string, hostKey ssh.PublicKey, payload []byte) {
	t.Helper()
	if os.Getenv("SILO_TEST_SSH_BACKEND") == "native" {
		t.Skip("SKIPPED: native guest has no SFTP; modern scp requires an OpenSSH guest")
	}
	scp, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("SKIPPED: scp binary absent")
	}
	// A test-only raw TCP proxy lets the real OpenSSH scp binary use this
	// actual enrolled peer's transport. Identity still comes from netd WhoIs.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(proxyCtx, func() { l.Close() })
	var tasks sync.WaitGroup
	tasks.Add(1)
	go func() {
		defer tasks.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			tasks.Add(1)
			go func() {
				defer tasks.Done()
				defer c.Close()
				raw, err := peer.Dial(proxyCtx, "tcp", netip.AddrPortFrom(target, 22).String())
				if err != nil {
					return
				}
				defer raw.Close()
				netnode.Relay(proxyCtx, c, raw)
			}()
		}
	}()
	defer func() { cancel(); stop(); l.Close(); tasks.Wait() }()
	dir := t.TempDir()
	known := filepath.Join(dir, "known_hosts")
	config := filepath.Join(dir, "config")
	host, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(known, append([]byte("["+host+"]:"+port+" "), ssh.MarshalAuthorizedKey(hostKey)...), 0600); err != nil {
		t.Fatal(err)
	}
	text := "Host live\n HostName " + host + "\n Port " + port + "\n User " + user + "\n UserKnownHostsFile " + known + "\n StrictHostKeyChecking yes\n BatchMode yes\n ConnectTimeout 10\n"
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	source, back := filepath.Join(dir, "source"), filepath.Join(dir, "back")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	remote := "/tmp/s9-tailnet-" + filepath.Base(dir) + ".bin"
	for _, args := range [][]string{{"-F", config, source, "live:" + remote}, {"-F", config, "live:" + remote, back}} {
		commandCtx, done := context.WithTimeout(ctx, 60*time.Second)
		start := time.Now()
		out, err := exec.CommandContext(commandCtx, scp, args...).CombinedOutput()
		done()
		if err != nil {
			t.Fatalf("real-tailnet scp: %v: %s", err, out)
		}
		t.Logf("real-tailnet scp bytes=%d duration=%s", len(payload), time.Since(start))
	}
	got, err := os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("200MB real-tailnet scp hash mismatch")
	}
}

func mintPeerKey(t *testing.T, parent context.Context, secret, tag string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"some-client-id"}, "client_secret": {secret}}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(r)
	if err != nil {
		t.Fatal("qualification OAuth failed")
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || token.AccessToken == "" {
		t.Fatal("qualification OAuth rejected")
	}
	body := map[string]interface{}{"capabilities": map[string]interface{}{"devices": map[string]interface{}{"create": map[string]interface{}{"reusable": false, "ephemeral": true, "tags": []string{tag}}}}}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/tailnet/-/keys", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token.AccessToken)
	r.Header.Set("Content-Type", "application/json")
	response, err = client.Do(r)
	if err != nil {
		t.Fatal("qualification enrollment request failed")
	}
	var key struct {
		Key string `json:"key"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&key)
	response.Body.Close()
	if err != nil || response.StatusCode/100 != 2 || !strings.HasPrefix(key.Key, "tskey-auth-") {
		t.Fatal("qualification enrollment rejected")
	}
	return key.Key
}
