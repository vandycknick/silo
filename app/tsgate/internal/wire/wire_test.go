package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, b, e := SocketPair()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func TestRoundTrip(t *testing.T) {
	a, b := pair(t)
	r := &Reader{Conn: b}
	defer r.Close()
	w := &Writer{Conn: a}
	messages := []Message{Bootstrap{Type: "bootstrap", Version: 1, Hostname: "lobby", Tag: "tag:lobby", StateDir: "/tmp/state", Capability: "example/cap"}, WhoIsRequest{Type: "whois", ID: ^uint64(0), Remote: "100.64.0.1:123"}, Shutdown{Type: "shutdown"}, State{Type: "state", Phase: "running", Tags: []string{}}, Reply{Type: "reply", ID: 2, WhoIs: &WhoIs{Tags: []string{}, Capability: []json.RawMessage{json.RawMessage(`{"x":1}`)}}}}
	for _, m := range messages {
		if e := w.Send(m, nil); e != nil {
			t.Fatal(e)
		}
		got, fd, e := r.Receive()
		if e != nil || fd != nil {
			t.Fatal(got, fd, e)
		}
		want, _ := Encode(m)
		actual, _ := Encode(got)
		if !bytes.Equal(want, actual) {
			t.Fatalf("%s != %s", want, actual)
		}
	}
	x, y := pair(t)
	f, e := x.File()
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = w.Send(Conn{Type: "conn", Listener: "ssh", Remote: "100.64.0.1:123"}, f); e != nil {
		t.Fatal(e)
	}
	m, fd, e := r.Receive()
	if e != nil || fd == nil {
		t.Fatal(m, fd, e)
	}
	defer fd.Close()
	received, e := net.FileConn(fd)
	if e != nil {
		t.Fatal(e)
	}
	defer received.Close()
	if _, e = y.Write([]byte("fd")); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 2)
	if _, e = io.ReadFull(received, buf); e != nil || string(buf) != "fd" {
		t.Fatal(string(buf), e)
	}
}
func TestDecodeRejects(t *testing.T) {
	cases := []string{"", `null`, `[]`, `1`, `"x"`, `{}`, `{"type":1}`, `{"type":null}`, `{"type":"unknown"}`, `{"type":"status","id":1}`, `{"type":"whois","id":-1}`, `{"type":"whois","id":1.5}`, `{"type":"whois","id":18446744073709551616}`, `{"type":"whois","id":null}`, `{"type":"conn","listener":"other"}`, `{"type":"reply","id":1}`, `{"type":"reply","id":1,"whois":{},"error":"bad"}`, `{"type":"reply","id":1,"status":{}}`, `{"type":"state","phase":"other"}`, `{"type":"state","phase":"running","tags":1}`, `{"type":"shutdown"} {}`}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			if _, e := Decode([]byte(s)); e == nil {
				t.Fatalf("accepted %s", s)
			}
		})
	}
	if _, e := Decode([]byte{'{', '"', 't', 'y', 'p', 'e', '"', ':', '"', 255, '"', '}'}); e == nil {
		t.Fatal("accepted invalid utf8")
	}
}
func TestLimitsAndTruncation(t *testing.T) {
	base := `{"type":"shutdown","extra":"` + strings.Repeat("x", MaxFrame-len(`{"type":"shutdown","extra":""}`)) + `"}`
	if len(base) != MaxFrame {
		t.Fatal(len(base))
	}
	if _, e := Decode([]byte(base)); e != nil {
		t.Fatal(e)
	}
	if _, e := Decode([]byte(base + " ")); e == nil {
		t.Fatal("oversize accepted")
	}
	for _, n := range []uint32{0, MaxFrame + 1} {
		t.Run(string(rune(n)), func(t *testing.T) {
			a, b := pair(t)
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, n)
			a.Write(header)
			a.Close()
			r := &Reader{Conn: b}
			if _, _, e := r.Receive(); e == nil {
				t.Fatal("invalid length accepted")
			}
		})
	}
	for _, data := range [][]byte{{0}, {0, 0, 0}, {0, 0, 0, 10, '{'}} {
		a, b := pair(t)
		a.Write(data)
		a.Close()
		r := &Reader{Conn: b}
		if _, _, e := r.Receive(); !errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatal(e)
		}
	}
}
func TestDescriptorRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		msg   Message
		count int
	}{{"missing", Conn{Type: "conn", Listener: "ssh"}, 0}, {"nonconn", Shutdown{Type: "shutdown"}, 1}, {"two", Conn{Type: "conn", Listener: "http"}, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := pair(t)
			b.SetReadDeadline(time.Now().Add(time.Second))
			x, y := pair(t)
			xf, _ := x.File()
			yf, _ := y.File()
			defer xf.Close()
			defer yf.Close()
			fds := []int{int(xf.Fd()), int(yf.Fd())}
			frame, e := Encode(tc.msg)
			if e != nil {
				t.Fatal(e)
			}
			var rights []byte
			if tc.count > 0 {
				rights = unix.UnixRights(fds[:tc.count]...)
			}
			if _, _, e = a.WriteMsgUnix(frame, rights, nil); e != nil {
				t.Fatal(e)
			}
			r := &Reader{Conn: b}
			if _, fd, e := r.Receive(); e == nil {
				if fd != nil {
					fd.Close()
				}
				t.Fatal("fd mismatch accepted")
			}
			if len(r.fds) != 0 {
				t.Fatal("queued descriptors leaked")
			}
		})
	}
	a, b := pair(t)
	w := &Writer{Conn: a}
	f, e := os.Open(os.DevNull)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = w.Send(Shutdown{Type: "shutdown"}, f); e == nil {
		t.Fatal("writer accepted stray fd")
	}
	if e = w.Send(Conn{Type: "conn", Listener: "ssh"}, nil); e == nil {
		t.Fatal("writer accepted missing fd")
	}
	b.Close()
}
func TestCoalescedFramesAndFragmentation(t *testing.T) {
	a, b := pair(t)
	state, _ := Encode(State{Type: "state", Phase: "running", Tags: []string{}})
	conn, _ := Encode(Conn{Type: "conn", Listener: "ssh"})
	x, _ := pair(t)
	f, _ := x.File()
	defer f.Close()
	rights := unix.UnixRights(int(f.Fd()))
	go func() {
		a.Write(state[:2])
		a.WriteMsgUnix(append(state[2:], conn...), rights, nil)
	}()
	r := &Reader{Conn: b}
	defer r.Close()
	if m, fd, e := r.Receive(); e != nil || fd != nil {
		t.Fatal(m, fd, e)
	}
	if m, fd, e := r.Receive(); e != nil || fd == nil {
		t.Fatal(m, fd, e)
	} else {
		fd.Close()
	}
}

func TestUnknownFieldsRemainLenient(t *testing.T) {
	for _, body := range []string{
		`{"type":"shutdown","future":null,"id":null}`,
		`{"type":"whois","id":1,"remote":"100.64.0.1:123","future":{"any":[1,true,null]}}`,
	} {
		if _, err := Decode([]byte(body)); err != nil {
			t.Fatal(body, err)
		}
	}
}
