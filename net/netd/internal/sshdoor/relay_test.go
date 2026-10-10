package sshdoor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fixture struct {
	door               *Door
	address, user, dir string
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
}

type slowBuffer struct{ bytes.Buffer }

func (b *slowBuffer) Write(p []byte) (int, error) {
	time.Sleep(100 * time.Microsecond)
	return b.Buffer.Write(p)
}

// The local TCP listener is deliberately test-only. It admits an explicit
// already-authorized identity and calls the production connect/Relay core.
func (f *fixture) front(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.address = l.Addr().String()
	context.AfterFunc(f.ctx, func() { l.Close() })
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				stop := context.AfterFunc(f.ctx, func() { c.Close() })
				defer stop()
				id := Identity{Login: "offline@example.com", Node: "offline-node", UserID: "7"}
				config := &ssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) { return permissions(id), nil }}
				config.AddHostKey(f.door.host)
				c.SetDeadline(time.Now().Add(10 * time.Second))
				down, dc, dr, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				defer down.Close()
				setup, cancel := context.WithTimeout(f.ctx, 10*time.Second)
				up, uc, ur, raw, err := f.door.connect(setup, down.User(), id, "offline-request")
				cancel()
				if err != nil {
					t.Errorf("guest connect: %v", err)
					return
				}
				defer raw.Close()
				defer up.Close()
				c.SetDeadline(time.Time{})
				raw.SetDeadline(time.Time{})
				Relay(f.ctx, down, up, dc, uc, dr, ur, id, f.door.limits)
			}()
		}
	}()
}

func localFixture(t *testing.T, extra ...string) *fixture {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal("qualification requires sshd in PATH: ", err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca, caBytes := testKey(t)
	host, hostBytes := testKey(t)
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.pub", ssh.MarshalAuthorizedKey(ca.PublicKey()))
	write("host", hostBytes)
	config := fmt.Sprintf("HostKey %s\nTrustedUserCAKeys %s\nAuthenticationMethods publickey\nPubkeyAuthentication yes\nPubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com\nCASignatureAlgorithms ssh-ed25519\nAuthorizedKeysFile none\nAuthorizedPrincipalsFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\nGSSAPIAuthentication no\nUsePAM no\nPermitRootLogin yes\nAcceptEnv SILO_*\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n", filepath.Join(dir, "host"), filepath.Join(dir, "ca.pub"))
	write("config", []byte(config+"MaxSessions 64\n"+strings.Join(extra, "\n")+"\n"))
	ctx, cancel := context.WithCancel(context.Background())
	d, err := New(ctx, filepath.Join(dir, "ssh"), filepath.Join(dir, "mux"), caBytes, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh/known_host"), ssh.MarshalAuthorizedKey(host.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{door: d, user: u.Username, dir: dir, ctx: ctx, cancel: cancel}
	l, err := net.Listen("unix", d.mux)
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { l.Close() })
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				r := bufio.NewReader(c)
				line, err := r.ReadString('\n')
				if err != nil || line != "CONNECT 22\n" {
					return
				}
				// Real TCP accepted socket descriptors are inherited by sshd -i.
				tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Error(err)
					return
				}
				client, err := net.Dial("tcp", tcp.Addr().String())
				if err != nil {
					tcp.Close()
					t.Error(err)
					return
				}
				defer client.Close()
				server, err := tcp.AcceptTCP()
				tcp.Close()
				if err != nil {
					t.Error(err)
					return
				}
				file, err := server.File()
				server.Close()
				if err != nil {
					t.Error(err)
					return
				}
				cmd := exec.CommandContext(ctx, sshd, "-i", "-e", "-f", filepath.Join(dir, "config"))
				cmd.Stdin = file
				cmd.Stdout = file
				var log bytes.Buffer
				cmd.Stderr = &log
				if err := cmd.Start(); err != nil {
					file.Close()
					t.Error(err)
					return
				}
				file.Close()
				defer func() { cmd.Process.Kill(); cmd.Wait(); t.Logf("sshd: %s", log.String()) }()
				banner := bufio.NewReader(client)
				b, err := banner.ReadString('\n')
				if err != nil {
					t.Error(err)
					return
				}
				// ACK and actual sshd banner share a write, exercising read-ahead.
				if _, err := io.WriteString(c, "OK 12345\n"+b); err != nil {
					return
				}
				var pumps sync.WaitGroup
				pumps.Add(2)
				go func() { defer pumps.Done(); io.Copy(client, r); client.(*net.TCPConn).CloseWrite() }()
				go func() { defer pumps.Done(); io.Copy(c, banner); c.(*net.UnixConn).CloseWrite() }()
				pumps.Wait()
			}()
		}
	}()
	f.front(t)
	t.Cleanup(func() { cancel(); f.wg.Wait(); d.Close() })
	return f
}

func (f *fixture) client(t *testing.T) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", f.address, &ssh.ClientConfig{User: f.user, HostKeyCallback: ssh.FixedHostKey(f.door.host.PublicKey()), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRealOpenSSHUpdateHostKeysStopsAtDoor(t *testing.T) {
	client, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal("qualification requires OpenSSH ssh in PATH: ", err)
	}
	f := localFixture(t)
	host, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	known := []byte(fmt.Sprintf("[%s]:%s %s", host, port, ssh.MarshalAuthorizedKey(f.door.host.PublicKey())))
	knownPath := filepath.Join(f.dir, "front_known_hosts")
	if err := os.WriteFile(knownPath, known, 0600); err != nil {
		t.Fatal(err)
	}
	guestKey, err := os.ReadFile(filepath.Join(f.dir, "ssh/known_host"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(guestKey, ssh.MarshalAuthorizedKey(f.door.host.PublicKey())) {
		t.Fatal("fixture must have different front and guest host keys")
	}
	for range 2 {
		ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
		cmd := exec.CommandContext(ctx, client, "-F", "/dev/null", "-vv",
			"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
			"-o", "UpdateHostKeys=yes", "-o", "UserKnownHostsFile="+knownPath,
			"-o", "GlobalKnownHostsFile=/dev/null", "-p", port, "-l", f.user, host,
			"printf HOSTKEY_BOUNDARY_OK")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		cancel()
		if err != nil || stdout.String() != "HOSTKEY_BOUNDARY_OK" {
			t.Fatalf("OpenSSH command: %v; stdout=%q stderr=%s", err, stdout.String(), stderr.String())
		}
		log := strings.ToLower(stderr.String())
		if strings.Contains(log, "bad signature") || strings.Contains(log, "invalid signature") || strings.Contains(log, "server gave bad signature") {
			t.Fatalf("session-bound proof crossed the door: %s", stderr.String())
		}
		got, err := os.ReadFile(knownPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, known) {
			t.Fatalf("front known_hosts changed (guest keys must not be enrolled): %s", got)
		}
	}
	c := f.client(t)
	key, _, _, _, err := ssh.ParseAuthorizedKey(guestKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hostkeys-prove-00@openssh.com", "hostkeys-prove"} {
		ok, payload, err := c.SendRequest(name, true, ssh.Marshal(struct{ Key string }{string(key.Marshal())}))
		if err != nil || ok || len(payload) != 0 {
			t.Fatalf("%s must fail locally without proof: ok=%v payload=%x err=%v", name, ok, payload, err)
		}
	}
}

// Actual TCP SSH transports expose raw global streams on both sides, allowing
// assertions about messages that must never arrive and exact reply payloads.
func TestRelayGlobalHostKeyBoundaryBothDirections(t *testing.T) {
	type endpoint struct {
		conn     ssh.Conn
		channels <-chan ssh.NewChannel
		requests <-chan *ssh.Request
	}
	pair := func() (endpoint, endpoint) {
		t.Helper()
		key, _ := testKey(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		serverResult := make(chan endpoint, 1)
		serverError := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				serverError <- err
				return
			}
			raw.SetDeadline(time.Now().Add(10 * time.Second))
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(key)
			conn, channels, requests, err := ssh.NewServerConn(raw, config)
			if err != nil {
				raw.Close()
				serverError <- err
				return
			}
			serverResult <- endpoint{conn, channels, requests}
		}()
		raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		conn, channels, requests, err := ssh.NewClientConn(raw, listener.Addr().String(),
			&ssh.ClientConfig{User: "fixture", HostKeyCallback: ssh.FixedHostKey(key.PublicKey())})
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		select {
		case server := <-serverResult:
			t.Cleanup(func() { server.conn.Close() })
			return endpoint{conn, channels, requests}, server
		case err := <-serverError:
			t.Fatal(err)
		case <-time.After(10 * time.Second):
			t.Fatal("SSH server handshake timed out")
		}
		return endpoint{}, endpoint{}
	}
	downClient, downServer := pair()
	upClient, upServer := pair()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Relay(ctx, downServer.conn, upClient.conn, downServer.channels, upClient.channels,
			downServer.requests, upClient.requests, Identity{}, NewLimits())
	}()
	t.Cleanup(func() { cancel(); <-done })
	for _, direction := range []struct {
		name     string
		from, to endpoint
	}{{"downstream", downClient, upServer}, {"upstream", upServer, downClient}} {
		t.Run(direction.name, func(t *testing.T) {
			for _, name := range []string{"hostkeys-00@openssh.com", "hostkeys-prove-00@openssh.com", "hostkeys", "hostkeys-prove"} {
				ok, payload, err := direction.from.conn.SendRequest(name, true, []byte("must-not-cross"))
				if err != nil || ok || len(payload) != 0 {
					t.Fatalf("%s: ok=%v payload=%x err=%v", name, ok, payload, err)
				}
				if _, _, err := direction.from.conn.SendRequest(name, false, []byte("ignored-advertisement")); err != nil {
					t.Fatal(err)
				}
			}
			// Ordered generic requests are also barriers: any leaked host-key
			// message would be the next request read at the opposite endpoint.
			for _, reply := range []struct{ want, ok bool }{{false, false}, {true, true}, {true, false}} {
				var replyPayload []byte
				if reply.ok {
					replyPayload = []byte{255, 0, 2}
				}
				result := make(chan error, 1)
				go func() {
					ok, payload, err := direction.from.conn.SendRequest("fixture-global@example.com", reply.want, []byte{0, 1, 255})
					if err == nil && reply.want && (ok != reply.ok || !bytes.Equal(payload, replyPayload)) {
						err = fmt.Errorf("reply lost: ok=%v payload=%x", ok, payload)
					}
					result <- err
				}()
				select {
				case r := <-direction.to.requests:
					if r == nil || r.Type != "fixture-global@example.com" || r.WantReply != reply.want || !bytes.Equal(r.Payload, []byte{0, 1, 255}) {
						t.Fatalf("unexpected relayed request: %+v", r)
					}
					if reply.want {
						if err := r.Reply(reply.ok, replyPayload); err != nil {
							t.Fatal(err)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("generic request did not relay")
				}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRealOpenSSHExecBinaryAndPTY(t *testing.T) {
	f := localFixture(t)
	c := f.client(t)
	t.Run("exit3-stderr-identity", func(t *testing.T) {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Setenv("SILO_PEER", "spoof"); err == nil {
			t.Fatal("peer overwrite accepted")
		}
		for _, name := range []string{"SILO_PEER=poison", "SILO_PEER\x00ignored"} {
			if err := s.Setenv(name, "spoof"); err == nil {
				t.Fatalf("ambiguous environment identity name accepted: %q", name)
			}
		}
		if _, err := s.SendRequest("env", false, ssh.Marshal(struct{ Name, Value string }{"SILO_PEER", "no-reply-spoof"})); err != nil {
			t.Fatal(err)
		}
		if err := s.Setenv("SILO_OTHER", "ok"); err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		s.Stdout = &out
		s.Stderr = &stderr
		err = s.Run("printf '%s:%s' \"$SILO_PEER\" \"$SILO_OTHER\"; printf 'stderr-proof' >&2; exit 3")
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.ExitStatus() != 3 {
			t.Fatalf("exit: %v", err)
		}
		if out.String() != "offline@example.com:ok" || stderr.String() != "stderr-proof" {
			t.Fatalf("%q %q", out.String(), stderr.String())
		}
	})
	t.Run("binary-and-stderr-backpressure", func(t *testing.T) {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		data := make([]byte, 8<<20)
		for i := range data {
			data[i] = byte(i * 31)
		}
		s.Stdin = bytes.NewReader(data)
		var out, stderr slowBuffer
		s.Stdout = &out
		s.Stderr = &stderr
		if err := s.Run("cat; head -c 2097152 /dev/zero >&2"); err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(data) != sha256.Sum256(out.Bytes()) || stderr.Len() != 2097152 {
			t.Fatalf("binary/stderr truncated: %d/%d", out.Len(), stderr.Len())
		}
	})
	t.Run("exit-signal", func(t *testing.T) {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skip("SKIPPED: bash required to issue deterministic exit-signal")
		}
		err = s.Run("exec " + bash + " -c 'kill -TERM $$'")
		var exit *ssh.ExitError
		if !errors.As(err, &exit) || exit.Signal() != "TERM" {
			t.Fatalf("exit-signal lost: %v", err)
		}
	})
	t.Run("shell-pty-resize", func(t *testing.T) {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			t.Fatal(err)
		}
		stdin, err := s.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		s.Stdout = &out
		s.Stderr = &stderr
		if err := s.Shell(); err != nil {
			t.Fatal(err)
		}
		if err := s.WindowChange(37, 119); err != nil {
			t.Fatal(err)
		}
		io.WriteString(stdin, "stty size; printf 'PTY-%s\\n' \"$SILO_PEER\"; exit\n")
		stdin.Close()
		if err := s.Wait(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "37 119") || !strings.Contains(out.String(), "PTY-offline@example.com") {
			t.Fatalf("%q", out.String())
		}
	})
}

func TestRealOpenSSHKeepaliveAndLateEnvOverwrite(t *testing.T) {
	f := localFixture(t, "ClientAliveInterval 1", "ClientAliveCountMax 5")
	raw, err := net.DialTimeout("tcp", f.address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, ch, requests, err := ssh.NewClientConn(raw, f.address, &ssh.ClientConfig{User: f.user, HostKeyCallback: ssh.FixedHostKey(f.door.host.PublicKey())})
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	var globals atomic.Int32
	forwarded := make(chan *ssh.Request)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(forwarded)
		for r := range requests {
			if r.Type == "keepalive@openssh.com" {
				globals.Add(1)
			}
			forwarded <- r
		}
	}()
	c := ssh.NewClient(conn, ch, forwarded)
	defer func() { c.Close(); <-done }()
	// With no session channel, sshd uses a global keepalive. With a session
	// open it chooses a channel request instead, so observe the global first.
	deadline := time.Now().Add(5 * time.Second)
	for globals.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("upstream global keepalive not forwarded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start("sleep 32; printf '%s' \"$SILO_PEER\""); err != nil {
		t.Fatal(err)
	}
	if err := s.Setenv("SILO_PEER", "late-spoof"); err == nil {
		t.Fatal("post-exec overwrite accepted")
	}
	if err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	// The one-second server keepalive traverses the upstream global request
	// stream; the relay also sends its own 30-second keepalive on both legs.
	if globals.Load() < 2 {
		t.Fatalf("upstream global requests were consumed: %d", globals.Load())
	}
}

func TestRealOpenSSHForwardingAndAgent(t *testing.T) {
	f := localFixture(t)
	c := f.client(t)
	setup, stop := context.WithTimeout(f.ctx, 5*time.Second)
	directConn, directChannels, directRequests, directRaw, err := f.door.connect(setup, f.user, Identity{Login: "offline"}, "rejection-baseline")
	stop()
	if err != nil {
		t.Fatal(err)
	}
	directRaw.SetDeadline(time.Time{})
	direct := ssh.NewClient(directConn, directChannels, directRequests)
	defer direct.Close()
	_, _, baseline := direct.OpenChannel("unsupported-silo-channel", []byte("identical-extra"))
	var expected *ssh.OpenChannelError
	if !errors.As(baseline, &expected) {
		t.Fatalf("missing direct backend rejection: %v", baseline)
	}
	if channel, _, err := c.OpenChannel("unsupported-silo-channel", []byte("identical-extra")); err == nil {
		channel.Close()
		t.Fatal("unsupported channel admitted")
	} else {
		var rejected *ssh.OpenChannelError
		if !errors.As(err, &rejected) || rejected.Reason != expected.Reason || rejected.Message != expected.Message {
			t.Fatalf("backend rejection details lost: %v", err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	conn, err := c.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "local-forward")
	b := make([]byte, 13)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "local-forward" {
		t.Fatalf("%s %v", b, err)
	}
	conn.Close()
	remote, err := c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Addr().(*net.TCPAddr).Port == 0 {
		t.Fatal("dynamic port reply lost")
	}
	accepted := make(chan error, 1)
	go func() {
		c, err := remote.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		b := make([]byte, 14)
		_, err = io.ReadFull(c, b)
		if err == nil && string(b) != "remote-forward" {
			err = fmt.Errorf("%q", b)
		}
		accepted <- err
	}()
	raw, err := net.DialTimeout("tcp", remote.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(raw, "remote-forward")
	raw.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
	remote.Close()
	keyring := agent.NewKeyring()
	_, keyBytes := testKey(t)
	key, err := ssh.ParseRawPrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "offline-agent-proof"}); err != nil {
		t.Fatal(err)
	}
	if err := agent.ForwardToAgent(c, keyring); err != nil {
		t.Fatal(err)
	}
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := agent.RequestAgentForwarding(s); err != nil {
		t.Fatal(err)
	}
	sshAdd, err := exec.LookPath("ssh-add")
	if err != nil {
		t.Skip("SKIPPED agent command: ssh-add absent")
	}
	out, err := s.CombinedOutput(sshAdd + " -L")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !bytes.Contains(out, []byte("offline-agent-proof")) {
		t.Fatalf("agent channel lost: %s", out)
	}
}

func TestRealOpenSSHSessionLimitAndCancellation(t *testing.T) {
	f := localFixture(t)
	a, b := f.client(t), f.client(t)
	var sessions []*ssh.Session
	for i := range 32 {
		c := a
		if i%2 != 0 {
			c = b
		}
		s, err := c.NewSession()
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		sessions = append(sessions, s)
	}
	if s, err := b.NewSession(); err == nil {
		s.Close()
		t.Fatal("33rd active session admitted across connections")
	} else {
		var open *ssh.OpenChannelError
		if !errors.As(err, &open) || open.Reason != ssh.ResourceShortage {
			t.Fatalf("rejection details lost: %v", err)
		}
	}
	for _, s := range sessions {
		s.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := a.NewSession()
		if err == nil {
			s.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session slots never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s, err := b.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("sleep 60"); err != nil {
		t.Fatal(err)
	}
	f.cancel()
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled session succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation failed to close and join")
	}
}

func TestRealOpenSSHForwardReservationLimit(t *testing.T) {
	f := localFixture(t)
	a, b := f.client(t), f.client(t)
	var listeners []net.Listener
	for i := range 256 {
		c := a
		if i%2 != 0 {
			c = b
		}
		l, err := c.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("forward %d: %v", i, err)
		}
		listeners = append(listeners, l)
	}
	if l, err := b.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("257th forwarding listener admitted")
	}
	if err := listeners[0].Close(); err != nil {
		t.Fatal(err)
	}
	l, err := b.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cancel did not release dynamic port reservation: %v", err)
	}
	l.Close()
	for _, l := range listeners[1:] {
		l.Close()
	}
	if len(f.door.limits.forwarding) != 0 {
		t.Fatal("forwarding reservations leaked")
	}
}
