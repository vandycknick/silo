package gateway

import (
	_ "github.com/vandycknick/silo/app/tsgate/internal/bootenv"

	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/enroll"
	"github.com/vandycknick/silo/app/tsgate/internal/testnet"
	"github.com/vandycknick/silo/app/tsgate/internal/wire"
	"tailscale.com/tsnet"
)

const testCapability = "silo.test/cap/lobby"
const testValue = `{"role":"operator"}`

type owner struct {
	conn   *net.UnixConn
	reader *wire.Reader
	writer *wire.Writer
	done   chan error
}

func startGateway(t *testing.T, b wire.Bootstrap) *owner {
	t.Helper()
	a, c, err := wire.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	o := &owner{conn: a, reader: &wire.Reader{Conn: a}, writer: &wire.Writer{Conn: a}, done: make(chan error, 1)}
	t.Cleanup(func() { a.Close(); o.reader.Close() })
	a.SetDeadline(time.Now().Add(40 * time.Second))
	go func() { o.done <- Run(context.Background(), c) }()
	if err = o.writer.Send(b, nil); err != nil {
		t.Fatal(err)
	}
	return o
}
func (o *owner) running(t *testing.T) wire.State {
	t.Helper()
	sawState := false
	for {
		m, fd, e := o.reader.Receive()
		if fd != nil {
			fd.Close()
		}
		if e != nil {
			t.Fatal(e)
		}
		s, ok := m.(*wire.State)
		if !ok {
			t.Fatalf("expected state before any connection: %T", m)
		}
		if !sawState && s.Phase != "starting" {
			t.Fatalf("first state: %+v", s)
		}
		sawState = true
		if s.Phase == "failed" {
			t.Fatal(s.Error)
		}
		if s.Phase == "running" {
			return *s
		}
	}
}
func (o *owner) connection(t *testing.T) (*wire.Conn, *net.UnixConn) {
	t.Helper()
	for {
		m, fd, e := o.reader.Receive()
		if e != nil {
			t.Fatal(e)
		}
		if c, ok := m.(*wire.Conn); ok {
			if fd == nil {
				t.Fatal("missing fd")
			}
			stream, e := net.FileConn(fd)
			fd.Close()
			if e != nil {
				t.Fatal(e)
			}
			u, ok := stream.(*net.UnixConn)
			if !ok {
				t.Fatalf("not Unix stream: %T", stream)
			}
			u.SetDeadline(time.Now().Add(10 * time.Second))
			t.Cleanup(func() { u.Close() })
			return c, u
		}
		if fd != nil {
			fd.Close()
			t.Fatal("unexpected fd")
		}
	}
}
func (o *owner) reply(t *testing.T, id uint64) *wire.Reply {
	t.Helper()
	for {
		m, fd, e := o.reader.Receive()
		if fd != nil {
			fd.Close()
			t.Fatal("unexpected fd")
		}
		if e != nil {
			t.Fatal(e)
		}
		if r, ok := m.(*wire.Reply); ok {
			if r.ID != id {
				t.Fatal(r.ID, id)
			}
			return r
		}
	}
}
func (o *owner) stop(t *testing.T) {
	t.Helper()
	o.conn.Close()
	select {
	case err := <-o.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway survived owner loss")
	}
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func bootstrap(dir, url string) wire.Bootstrap {
	return wire.Bootstrap{Type: "bootstrap", Version: 1, Hostname: "lobby", Tag: "tag:lobby", StateDir: dir, ControlURL: url, Capability: testCapability}
}
func startPeer(t *testing.T, url string) *tsnet.Server {
	t.Helper()
	p := &tsnet.Server{Dir: t.TempDir(), Hostname: "peer", ControlURL: url, AdvertiseTags: []string{"tag:peer"}, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
	t.Cleanup(func() { p.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return p
}
func dial(t *testing.T, p *tsnet.Server) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, e := p.Dial(ctx, "tcp", "lobby.tail-scale.ts.net:22")
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func TestGatewayRealTailnet(t *testing.T) {
	url := testnet.Start(t, testCapability, testValue)
	peer := startPeer(t, url)
	o := startGateway(t, bootstrap(privateDir(t), url))
	state := o.running(t)
	if state.Tailnet == "" || state.Suffix == "" {
		t.Fatal(state)
	}
	peerConn := dial(t, peer)
	meta, stream := o.connection(t)
	if meta.Listener != "ssh" {
		t.Fatal(meta)
	}
	if _, err := io.WriteString(peerConn, "from peer"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("from peer"))
	if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != "from peer" {
		t.Fatal(string(buf), err)
	}
	if _, err := io.WriteString(stream, "from owner"); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("from owner"))
	if _, err := io.ReadFull(peerConn, buf); err != nil || string(buf) != "from owner" {
		t.Fatal(string(buf), err)
	}
	if err := o.writer.Send(wire.WhoIsRequest{Type: "whois", ID: 7, Remote: meta.Remote}, nil); err != nil {
		t.Fatal(err)
	}
	if err := o.writer.Send(wire.WhoIsRequest{Type: "whois", ID: 9, Remote: "192.0.2.1:12345"}, nil); err != nil {
		t.Fatal(err)
	}
	// Both requests are sent before reading either response. Replies may arrive
	// in either order, and a failed lookup must not hold up the known peer.
	var reply *wire.Reply
	received := make(map[uint64]bool)
	if err := o.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for len(received) < 2 {
		m, fd, err := o.reader.Receive()
		if fd != nil {
			fd.Close()
			t.Fatal("unexpected descriptor")
		}
		if err != nil {
			t.Fatal(err)
		}
		r, ok := m.(*wire.Reply)
		if !ok {
			if _, state := m.(*wire.State); state {
				continue
			}
			t.Fatalf("unexpected message: %T", m)
		}
		if received[r.ID] {
			t.Fatalf("duplicate reply: %d", r.ID)
		}
		received[r.ID] = true
		switch r.ID {
		case 7:
			reply = r
		case 9:
			if r.Error == nil || *r.Error != "WhoIs unavailable" || r.WhoIs != nil {
				t.Fatalf("unknown peer response: %+v", r)
			}
		default:
			t.Fatalf("unexpected reply ID: %d", r.ID)
		}
	}
	if err := o.conn.SetReadDeadline(time.Now().Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if reply.Error != nil || reply.WhoIs == nil {
		t.Fatalf("%+v", reply)
	}
	who := reply.WhoIs
	if len(who.Tags) != 1 || who.Tags[0] != "tag:peer" || who.NodeID == "" || !strings.HasPrefix(who.NodeName, "peer.") || len(who.Capability) != 1 {
		t.Fatalf("%+v", who)
	}
	var capValue map[string]string
	if err := json.Unmarshal(who.Capability[0], &capValue); err != nil || capValue["role"] != "operator" {
		t.Fatal(string(who.Capability[0]), err)
	}
	if err := o.writer.Send(wire.StatusRequest{Type: "status", ID: 8}, nil); err != nil {
		t.Fatal(err)
	}
	if r := o.reply(t, 8); r.Status == nil || r.Status.Phase != "running" {
		t.Fatalf("%+v", r)
	}
	cw, ok := peerConn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("missing CloseWrite: %T", peerConn)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(stream)
	if err != nil || len(tail) != 0 {
		t.Fatal(string(tail), err)
	}
	if _, err = io.WriteString(stream, "reply after EOF"); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	replyBytes, err := io.ReadAll(peerConn)
	if err != nil || string(replyBytes) != "reply after EOF" {
		t.Fatal(string(replyBytes), err)
	}
	_ = dial(t, peer)
	_, live := o.connection(t)
	defer live.Close()
	o.stop(t)
}
func TestRestartDoesNotMint(t *testing.T) {
	url := testnet.Start(t, testCapability, testValue)
	dir := privateDir(t)
	first := startGateway(t, bootstrap(dir, url))
	first.running(t)
	first.stop(t)
	if _, state := enroll.ReadNode(dir, "lobby", "tag:lobby", nil); state != enroll.Enrolled {
		t.Fatalf("stored node: %s", state)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("enrolled restart called credential API")
		http.Error(w, "must not mint", 500)
	}))
	defer api.Close()
	b := bootstrap(dir, url)
	b.ClientSecret = "tskey-client-never-use"
	b.APIBaseURL = api.URL
	second := startGateway(t, b)
	second.running(t)
	if err := second.writer.Send(wire.Shutdown{Type: "shutdown"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-second.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}
func TestBootstrapValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*wire.Bootstrap)
	}{{"version", func(b *wire.Bootstrap) { b.Version = 2 }}, {"empty hostname", func(b *wire.Bootstrap) { b.Hostname = "" }}, {"uppercase", func(b *wire.Bootstrap) { b.Hostname = "Lobby" }}, {"long", func(b *wire.Bootstrap) { b.Hostname = strings.Repeat("a", 64) }}, {"invalid character", func(b *wire.Bootstrap) { b.Hostname = "lobby.test" }}, {"tag", func(b *wire.Bootstrap) { b.Tag = "lobby" }}, {"empty tag", func(b *wire.Bootstrap) { b.Tag = "tag:" }}, {"relative path", func(b *wire.Bootstrap) { b.StateDir = "relative" }}} {
		t.Run(tc.name, func(t *testing.T) {
			b := bootstrap(privateDir(t), "")
			tc.change(&b)
			if err := validate(b); err == nil {
				t.Fatal("invalid bootstrap accepted")
			}
		})
	}
	root := t.TempDir()
	dir := filepath.Join(root, "new")
	if err := validate(bootstrap(dir, "")); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0755)
	if err := validate(bootstrap(dir, "")); err == nil {
		t.Fatal("insecure permissions accepted")
	}
	os.Chmod(dir, 0700)
	link := filepath.Join(root, "link")
	os.Symlink(dir, link)
	if err := validate(bootstrap(link, "")); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestOwnerLossDuringEnrollment(t *testing.T) {
	started := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer api.Close()
	b := bootstrap(privateDir(t), "")
	b.ClientSecret = "tskey-client-test"
	b.APIBaseURL = api.URL
	o := startGateway(t, b)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("mint did not start")
	}
	if err := o.writer.Send(wire.StatusRequest{Type: "status", ID: 99}, nil); err != nil {
		t.Fatal(err)
	}
	o.stop(t)
}
