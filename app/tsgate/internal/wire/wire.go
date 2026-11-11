// Package wire implements the private, versioned silod control seam.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const MaxFrame = 65536

type Message interface{ message() }
type Bootstrap struct {
	Type         string `json:"type"`
	Version      int    `json:"version"`
	Hostname     string `json:"hostname"`
	Tag          string `json:"tag"`
	ControlURL   string `json:"control_url"`
	StateDir     string `json:"state_dir"`
	Capability   string `json:"capability"`
	ClientSecret string `json:"client_secret,omitempty"`
	APIBaseURL   string `json:"api_base_url,omitempty"`
}

func (Bootstrap) message() {}

type WhoIsRequest struct {
	Type   string `json:"type"`
	ID     uint64 `json:"id"`
	Remote string `json:"remote"`
}

func (WhoIsRequest) message() {}

type StatusRequest struct {
	Type string `json:"type"`
	ID   uint64 `json:"id"`
}

func (StatusRequest) message() {}

type Shutdown struct {
	Type string `json:"type"`
}

func (Shutdown) message() {}

type Status struct {
	Phase   string   `json:"phase"`
	DNSName string   `json:"dns_name"`
	Tailnet string   `json:"tailnet"`
	Suffix  string   `json:"suffix"`
	Tags    []string `json:"tags"`
}
type State struct {
	Type        string   `json:"type"`
	Phase       string   `json:"phase"`
	ApprovalURL string   `json:"approval_url,omitempty"`
	DNSName     string   `json:"dns_name,omitempty"`
	Tailnet     string   `json:"tailnet,omitempty"`
	Suffix      string   `json:"suffix,omitempty"`
	Tags        []string `json:"tags"`
	Error       string   `json:"error,omitempty"`
}

func (State) message()         {}
func (s State) Status() Status { return Status{s.Phase, s.DNSName, s.Tailnet, s.Suffix, s.Tags} }

type Conn struct {
	Type     string `json:"type"`
	Listener string `json:"listener"`
	Remote   string `json:"remote"`
}

func (Conn) message() {}

type WhoIs struct {
	NodeID      string            `json:"node_id"`
	NodeName    string            `json:"node_name"`
	Tags        []string          `json:"tags"`
	UserID      int64             `json:"user_id"`
	LoginName   string            `json:"login_name"`
	DisplayName string            `json:"display_name"`
	Capability  []json.RawMessage `json:"capability"`
}
type Reply struct {
	Type   string  `json:"type"`
	ID     uint64  `json:"id"`
	WhoIs  *WhoIs  `json:"whois,omitempty"`
	Status *Status `json:"status,omitempty"`
	Error  *string `json:"error,omitempty"`
}

func (Reply) message() {}

func Decode(body []byte) (Message, error) {
	if len(body) == 0 || len(body) > MaxFrame || !utf8.Valid(body) {
		return nil, errors.New("invalid frame length or UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return nil, errors.New("frame must be a JSON object")
	}
	var typ string
	if err := json.Unmarshal(fields["type"], &typ); err != nil {
		return nil, errors.New("missing or invalid message type")
	}
	var m Message
	var known []string
	switch typ {
	case "bootstrap":
		m = &Bootstrap{}
		known = []string{"version", "hostname", "tag", "control_url", "state_dir", "capability", "client_secret", "api_base_url"}
	case "whois":
		m = &WhoIsRequest{}
		known = []string{"id", "remote"}
	case "status":
		m = &StatusRequest{}
		known = []string{"id"}
	case "shutdown":
		m = &Shutdown{}
	case "state":
		m = &State{}
		known = []string{"phase", "approval_url", "dns_name", "tailnet", "suffix", "tags", "error"}
	case "conn":
		m = &Conn{}
		known = []string{"listener", "remote"}
	case "reply":
		m = &Reply{}
		known = []string{"id", "whois", "status", "error"}
	default:
		return nil, fmt.Errorf("unknown message type %q", typ)
	}
	// Unknown fields remain lenient, including null. Known fields cannot use
	// null in place of their declared wire type.
	for _, key := range known {
		if string(fields[key]) == "null" {
			return nil, fmt.Errorf("null field %q", key)
		}
	}
	if err := json.Unmarshal(body, m); err != nil {
		return nil, errors.New("invalid message fields")
	}
	switch v := m.(type) {
	case *Conn:
		if v.Listener != "ssh" && v.Listener != "http" {
			return nil, errors.New("invalid conn listener")
		}
	case *State:
		switch v.Phase {
		case "starting", "needs_login", "needs_tag", "running", "failed":
		default:
			return nil, errors.New("invalid state phase")
		}
	case *Reply:
		n := 0
		if v.WhoIs != nil {
			n++
		}
		if v.Status != nil {
			n++
		}
		if v.Error != nil {
			n++
		}
		if n != 1 {
			return nil, errors.New("reply must have exactly one result")
		}
	}
	return m, nil
}
func Encode(m Message) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if _, err = Decode(body); err != nil {
		return nil, err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

// Writer serializes ordinary frames and the single sendmsg required for conn.
type Writer struct {
	Conn *net.UnixConn
	mu   sync.Mutex
}

func (w *Writer) Send(m Message, fd *os.File) error {
	frame, err := Encode(m)
	if err != nil {
		return err
	}
	_, isConn := m.(Conn)
	if _, ok := m.(*Conn); ok {
		isConn = true
	}
	if isConn != (fd != nil) {
		return errors.New("fd-count mismatch")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if fd != nil {
		n, _, err := w.Conn.WriteMsgUnix(frame, unix.UnixRights(int(fd.Fd())), nil)
		if err != nil {
			return err
		}
		if n != len(frame) {
			return io.ErrShortWrite
		}
		return nil
	}
	for len(frame) > 0 {
		n, err := w.Conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// Reader owns received descriptors until a successful conn transfers ownership.
// Close must be called after the reader goroutine stops.
type Reader struct {
	Conn *net.UnixConn
	buf  []byte
	fds  []*os.File
	data []byte
	oob  []byte
}

func (r *Reader) Close() {
	for _, f := range r.fds {
		_ = f.Close()
	}
	r.fds = nil
}
func (r *Reader) Receive() (m Message, fd *os.File, err error) {
	defer func() {
		if err != nil {
			r.Close()
		}
	}()
	for {
		if len(r.buf) >= 4 {
			n := int(binary.BigEndian.Uint32(r.buf))
			if n == 0 || n > MaxFrame {
				return nil, nil, errors.New("invalid frame length")
			}
			if len(r.buf) >= 4+n {
				m, err = Decode(r.buf[4 : 4+n])
				if err != nil {
					return nil, nil, err
				}
				r.buf = r.buf[4+n:]
				if _, ok := m.(*Conn); ok {
					if len(r.fds) == 0 {
						return nil, nil, errors.New("fd-count mismatch")
					}
					fd = r.fds[0]
					r.fds = r.fds[1:]
				} else if len(r.fds) > 0 && len(r.buf) == 0 {
					return nil, nil, errors.New("fd-count mismatch")
				}
				return m, fd, nil
			}
		}
		if r.data == nil {
			r.data = make([]byte, MaxFrame+4)
			r.oob = make([]byte, unix.CmsgSpace(4*16))
		}
		n, on, flags, _, e := r.Conn.ReadMsgUnix(r.data, r.oob)
		if on > 0 {
			cms, pe := unix.ParseSocketControlMessage(r.oob[:on])
			if pe != nil {
				return nil, nil, pe
			}
			invalid := false
			for _, cm := range cms {
				fds, pe := unix.ParseUnixRights(&cm)
				if pe != nil {
					invalid = true
					continue
				}
				if len(fds) != 1 {
					invalid = true
				}
				for _, f := range fds {
					unix.CloseOnExec(f)
					r.fds = append(r.fds, os.NewFile(uintptr(f), "tsgate-received"))
				}
			}
			if invalid {
				return nil, nil, errors.New("fd-count mismatch")
			}
		}
		if flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
			return nil, nil, errors.New("truncated control message")
		}
		if n > 0 {
			r.buf = append(r.buf, r.data[:n]...)
		}
		if e != nil {
			if errors.Is(e, io.EOF) && (len(r.buf) > 0 || len(r.fds) > 0) {
				return nil, nil, io.ErrUnexpectedEOF
			}
			return nil, nil, e
		}
		if n == 0 {
			if len(r.buf) > 0 || len(r.fds) > 0 {
				return nil, nil, io.ErrUnexpectedEOF
			}
			return nil, nil, io.EOF
		}
	}
}

func SocketPair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	files := [2]*os.File{os.NewFile(uintptr(fds[0]), "tsgate-socketpair"), os.NewFile(uintptr(fds[1]), "tsgate-socketpair")}
	defer files[0].Close()
	defer files[1].Close()
	a, err := net.FileConn(files[0])
	if err != nil {
		return nil, nil, err
	}
	b, err := net.FileConn(files[1])
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a.(*net.UnixConn), b.(*net.UnixConn), nil
}
