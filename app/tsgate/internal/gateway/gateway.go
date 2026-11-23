// Package gateway owns the lobby tsnet node and forwards streams to silod.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/tsgate/internal/enroll"
	"github.com/vandycknick/silo/app/tsgate/internal/wire"
	"golang.org/x/sys/unix"
	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

const (
	maxConnections      = 256
	maxConnectionsPerIP = 32
)

// connectionCounts is protected by session.mu and shared by both listeners.
type connectionCounts struct {
	total int
	perIP map[netip.Addr]int
}

func (c *connectionCounts) acquire(ip netip.Addr) bool {
	ip = ip.Unmap()
	if c.total >= maxConnections || c.perIP[ip] >= maxConnectionsPerIP {
		return false
	}
	if c.perIP == nil {
		c.perIP = make(map[netip.Addr]int)
	}
	c.total++
	c.perIP[ip]++
	return true
}

func (c *connectionCounts) release(ip netip.Addr) {
	ip = ip.Unmap()
	c.total--
	c.perIP[ip]--
	if c.perIP[ip] == 0 {
		delete(c.perIP, ip)
	}
}

type session struct {
	writer      *wire.Writer
	server      *tsnet.Server
	mu          sync.Mutex
	stopping    bool
	listeners   []net.Listener
	streams     map[net.Conn]struct{}
	connections connectionCounts
	copies      sync.WaitGroup
}

// Run takes ownership of control. Owner loss always interrupts startup and live
// streams; explicit shutdown first allows existing streams four seconds to drain.
func Run(ctx context.Context, control *net.UnixConn) error {
	defer control.Close()
	reader := &wire.Reader{Conn: control}
	first, fd, err := reader.Receive()
	if fd != nil {
		fd.Close()
	}
	if err != nil {
		reader.Close()
		return err
	}
	boot, ok := first.(*wire.Bootstrap)
	if !ok {
		reader.Close()
		return errors.New("first frame must be bootstrap")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s := &session{writer: &wire.Writer{Conn: control}, server: &tsnet.Server{}, streams: make(map[net.Conn]struct{})}
	commands := make(chan wire.Message)
	incoming := make(chan wire.Message)
	readDone := make(chan error, 1)
	go func() {
		defer reader.Close()
		for {
			m, fd, err := reader.Receive()
			if fd != nil {
				fd.Close()
				err = errors.New("unexpected descriptor from owner")
			}
			if err != nil {
				readDone <- err
				return
			}
			switch m.(type) {
			case *wire.WhoIsRequest, *wire.Shutdown:
			default:
				readDone <- errors.New("unexpected control message")
				return
			}
			select {
			case incoming <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	served := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		served <- s.serve(ctx, *boot, commands)
	}()
	var result error
	drain := false
	var pending []wire.Message
loop:
	for {
		var output chan wire.Message
		var next wire.Message
		if len(pending) > 0 {
			output, next = commands, pending[0]
		}
		select {
		case m := <-incoming:
			if _, ok := m.(*wire.Shutdown); ok {
				drain = true
				break loop
			}
			pending = append(pending, m)
		case output <- next:
			pending[0] = nil
			pending = pending[1:]
		case err := <-readDone:
			if !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET) {
				result = err
			}
			break loop
		case result = <-served:
			break loop
		case <-ctx.Done():
			result = ctx.Err()
			break loop
		}
	}
	s.stopListeners()
	if drain {
		done := make(chan struct{})
		go func() { s.copies.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
		}
	}
	cancel()
	control.Close()
	s.mu.Lock()
	for conn := range s.streams {
		conn.Close()
	}
	s.mu.Unlock()
	timeout := 4 * time.Second
	if drain {
		timeout = time.Second
	}
	select {
	case <-finished:
	case <-time.After(timeout):
	}
	return result
}

func validate(b wire.Bootstrap) error {
	if b.Version != 1 {
		return errors.New("unsupported bootstrap version")
	}
	if !regexp.MustCompile(`^[a-z0-9-]{1,63}$`).MatchString(b.Hostname) {
		return errors.New("invalid hostname")
	}
	if !strings.HasPrefix(b.Tag, "tag:") || len(b.Tag) == 4 {
		return errors.New("invalid node tag")
	}
	if !filepath.IsAbs(b.StateDir) {
		return errors.New("state_dir must be absolute")
	}
	if err := os.MkdirAll(b.StateDir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(b.StateDir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || int(st.Uid) != os.Geteuid() {
		return errors.New("state directory must be owned by this uid with mode 0700")
	}
	return nil
}

func (s *session) serve(ctx context.Context, b wire.Bootstrap, commands <-chan wire.Message) (err error) {
	secretPattern := regexp.MustCompile(`tskey-[A-Za-z0-9_-]+`)
	redact := func(text string) string {
		if b.ClientSecret != "" {
			text = strings.ReplaceAll(text, b.ClientSecret, "[redacted]")
		}
		return secretPattern.ReplaceAllString(text, "[redacted]")
	}
	defer func() {
		if err != nil {
			err = errors.New(redact(err.Error()))
		}
		if err != nil && ctx.Err() == nil {
			_ = s.writer.Send(wire.State{Type: "state", Phase: "failed", Tags: []string{}, Error: redact(err.Error())}, nil)
		}
	}()
	if err = validate(b); err != nil {
		return err
	}
	if err = s.writer.Send(wire.State{Type: "state", Phase: "starting", Tags: []string{}}, nil); err != nil {
		return err
	}
	authKey := ""
	if _, state := enroll.ReadNode(b.StateDir, b.Hostname, b.Tag, nil); state != enroll.Enrolled && b.ClientSecret != "" {
		base := b.APIBaseURL
		if base == "" {
			base = "https://api.tailscale.com"
		}
		authKey, err = enroll.Mint(ctx, enroll.NewHTTPClient(30*time.Second), base, b.ClientSecret, b.Tag)
		if err != nil {
			return err
		}
	}
	logf := func(format string, args ...any) {
		text := fmt.Sprintf(format, args...)
		if authKey != "" {
			text = strings.ReplaceAll(text, authKey, "[redacted]")
		}
		log.Print("tsgate: " + redact(text))
	}
	// The serving goroutine alone owns Start and Close: tsnet forbids overlap.
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return ctx.Err()
	}
	s.server.Dir = b.StateDir
	s.server.Hostname = b.Hostname
	s.server.AuthKey = authKey
	s.server.AdvertiseTags = []string{b.Tag}
	s.server.ControlURL = b.ControlURL
	s.server.UserLogf = logf
	s.server.Logf = func(format string, args ...any) {
		if strings.HasPrefix(format, "[v1]") || strings.HasPrefix(format, "[v2]") {
			return
		}
		logf(format, args...)
	}
	s.mu.Unlock()
	// tsnet's logtail transport must never upload internal logs.
	envknob.SetNoLogsNoSupport()
	err = s.server.Start()
	defer s.server.Close()
	if err != nil {
		return err
	}
	client, err := s.server.LocalClient()
	if err != nil {
		return err
	}
	state := wire.State{Type: "state", Phase: "starting", Tags: []string{}}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	active := false
	whoisSlots := make(chan struct{}, 32)
	requestErrors := make(chan error, 1)
	for {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		status, e := client.StatusWithoutPeers(attempt)
		cancel()
		next := wire.State{Type: "state", Phase: "starting", Tags: []string{}}
		if e == nil {
			next = nodeState(status, b)
		}
		if next.Phase == "running" && !active {
			ssh, e := s.server.Listen("tcp", ":22")
			if e != nil {
				return e
			}
			https, e := s.server.ListenTLS("tcp", ":443")
			if e != nil {
				ssh.Close()
				return e
			}
			s.mu.Lock()
			if s.stopping {
				s.mu.Unlock()
				ssh.Close()
				https.Close()
				return ctx.Err()
			}
			s.listeners = []net.Listener{ssh, https}
			s.mu.Unlock()
			if err = s.writer.Send(next, nil); err != nil {
				return err
			}
			state = next
			active = true
			go s.accept(ctx, ssh, "ssh")
			go s.accept(ctx, https, "http")
		} else {
			if next.Phase != "running" && active {
				s.closeListeners()
				active = false
			}
			if !reflect.DeepEqual(state, next) {
				if err = s.writer.Send(next, nil); err != nil {
					return err
				}
				state = next
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-requestErrors:
			return err
		case m := <-commands:
			switch v := m.(type) {
			case *wire.WhoIsRequest:
				running := state.Phase == "running"
				reply := wire.Reply{Type: "reply", ID: v.ID}
				if !running {
					msg := "tailnet not ready"
					reply.Error = &msg
				} else {
					select {
					case whoisSlots <- struct{}{}:
						go func() {
							defer func() { <-whoisSlots }()
							who, e := whoIs(ctx, client, v.Remote, b.Capability)
							result := wire.Reply{Type: "reply", ID: v.ID, WhoIs: who}
							if e != nil {
								msg := "WhoIs unavailable"
								result.Error = &msg
							}
							if e := s.writer.Send(result, nil); e != nil {
								select {
								case requestErrors <- e:
								default:
								}
							}
						}()
						continue
					default:
						msg := "WhoIs busy"
						reply.Error = &msg
					}
				}
				if err = s.writer.Send(reply, nil); err != nil {
					return err
				}
			}
		case <-ticker.C:
		}
	}
}

func nodeState(st *ipnstate.Status, b wire.Bootstrap) wire.State {
	state := wire.State{Type: "state", Phase: "starting", Tags: []string{}}
	if st.AuthURL != "" {
		state.Phase = "needs_login"
		state.ApprovalURL = st.AuthURL
	}
	if st.BackendState != "Running" || st.Self == nil || st.CurrentTailnet == nil {
		return state
	}
	state.DNSName = st.Self.DNSName
	state.Tailnet = st.CurrentTailnet.Name
	state.Suffix = strings.TrimSuffix(strings.ToLower(st.CurrentTailnet.MagicDNSSuffix), ".")
	if st.Self.Tags != nil {
		state.Tags = append(state.Tags, st.Self.Tags.AsSlice()...)
	}
	state.Phase = "needs_tag"
	state.ApprovalURL = ""
	if !slices.Contains(state.Tags, b.Tag) {
		state.Error = "node not tagged with requested tag"
		return state
	}
	if err := enroll.PinNodeControl(b.StateDir, enroll.NodePin{Tailnet: state.Tailnet, Suffix: state.Suffix, ControlURL: b.ControlURL}); err != nil {
		state.Error = err.Error()
		return state
	}
	state.Phase = "running"
	return state
}
func whoIs(ctx context.Context, client *local.Client, remote, capability string) (*wire.WhoIs, error) {
	if _, err := netip.ParseAddrPort(remote); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	who, err := client.WhoIs(ctx, remote)
	if err != nil {
		return nil, err
	}
	if who.Node == nil || who.UserProfile == nil {
		return nil, errors.New("incomplete WhoIs response")
	}
	result := &wire.WhoIs{NodeID: string(who.Node.StableID), NodeName: who.Node.Name, Tags: append([]string{}, who.Node.Tags...), UserID: int64(who.UserProfile.ID), LoginName: who.UserProfile.LoginName, DisplayName: who.UserProfile.DisplayName, Capability: []json.RawMessage{}}
	for _, value := range who.CapMap[tailcfg.PeerCapability(capability)] {
		result.Capability = append(result.Capability, json.RawMessage(value))
	}
	return result, nil
}
func (s *session) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
}
func (s *session) stopListeners() {
	s.mu.Lock()
	s.stopping = true
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
	s.mu.Unlock()
}
func (s *session) accept(ctx context.Context, l net.Listener, name string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		remote, err := netip.ParseAddrPort(conn.RemoteAddr().String())
		if err != nil {
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.stopping {
			s.mu.Unlock()
			conn.Close()
			return
		}
		if !s.connections.acquire(remote.Addr()) {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		a, b, err := wire.SocketPair()
		if err != nil {
			s.connections.release(remote.Addr())
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.streams[conn] = struct{}{}
		s.streams[a] = struct{}{}
		s.copies.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.copies.Done()
			defer func() {
				conn.Close()
				a.Close()
				s.mu.Lock()
				delete(s.streams, conn)
				delete(s.streams, a)
				s.connections.release(remote.Addr())
				s.mu.Unlock()
			}()
			fd, err := b.File()
			b.Close()
			if err != nil {
				return
			}
			err = s.writer.Send(wire.Conn{Type: "conn", Listener: name, Remote: conn.RemoteAddr().String()}, fd)
			fd.Close()
			if err != nil {
				return
			}
			proxy(conn, a)
		}()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
func proxy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			a.Close()
			b.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}
