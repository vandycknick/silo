package sshd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/httpd"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	_ "tailscale.com/feature/ssh"
	"tailscale.com/ssh/tailssh"
)

type Server struct {
	Service  *service.Service
	Resolver httpd.Resolver
	Global   int
	PerPeer  int
	mu       sync.Mutex
	peers    map[string]int
	active   map[*tailssh.Session]bool
	wg       sync.WaitGroup
	closing  bool
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close(); s.CloseSessions() })
	defer stop()
	for {
		c, e := ln.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		sess, ok := c.(*tailssh.Session)
		if !ok {
			c.Close()
			return errors.New("listener did not return SSH session")
		}
		s.mu.Lock()
		if s.active == nil {
			s.active = make(map[*tailssh.Session]bool)
			s.peers = make(map[string]int)
		}
		if s.closing || len(s.active) >= s.Global {
			s.mu.Unlock()
			_ = sess.Exit(6)
			continue
		}
		s.active[sess] = true
		s.Service.Runtime.Metrics.Session(1)
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer sess.Close()
			defer func() { s.mu.Lock(); delete(s.active, sess); s.mu.Unlock(); s.Service.Runtime.Metrics.Session(-1) }()
			s.session(ctx, sess)
		}()
	}
}
func (s *Server) CloseSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closing = true
	for session := range s.active {
		_ = session.Close()
	}
}
func (s *Server) Wait(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) session(parent context.Context, sess *tailssh.Session) {
	ctx, cancel := context.WithCancel(sess.Context())
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	closeOnCancel := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer closeOnCancel()
	initial, windows, pty := sess.Pty()
	closeChannel := func() { _ = sess.Close() }
	var diagnostic io.Writer = sessionOutput{ctx, sess.Stderr(), closeChannel}
	if pty {
		diagnostic = &humanWriter{out: diagnostic}
	}
	converted := make(chan service.Window, 1)
	convertedSignals := make(chan uint32, 1)
	terminal := service.Terminal{Present: pty, Term: initial.Term, Windows: converted, Signals: convertedSignals}
	if initial.Window.Height > 0 && initial.Window.Height <= 65535 && initial.Window.Width > 0 && initial.Window.Width <= 65535 {
		terminal.Window = service.Window{Rows: uint16(initial.Window.Height), Columns: uint16(initial.Window.Width)}
	}
	streams := terminalStreams(ctx, sess, service.IO{Stdout: sessionOutput{ctx, sess, closeChannel}, Stderr: sessionOutput{ctx, sess.Stderr(), closeChannel}, Human: diagnostic, Terminal: terminal})
	// Pty creates an upstream converter. Drain through close even when WhoIs
	// denies the session, and fan resize out to the editor and guest controls.
	if pty {
		go func() {
			defer close(converted)
			for w := range windows {
				terminalResize(streams, converted, w.Width, w.Height)
			}
		}()
	}
	peer, e := s.Resolver.WhoIs(ctx, sess.RemoteAddr().String())
	if e != nil {
		_, _ = fmt.Fprintln(diagnostic, "Error: identity unavailable or node not tagged")
		_ = sess.Exit(4)
		return
	}
	nodeID := peer.NodeID
	s.mu.Lock()
	if s.peers[peer.NodeID] >= s.PerPeer {
		s.mu.Unlock()
		_ = sess.Exit(6)
		return
	}
	s.peers[peer.NodeID]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.peers[nodeID]--
		if s.peers[nodeID] == 0 {
			delete(s.peers, nodeID)
		}
		s.mu.Unlock()
	}()
	if sess.Subsystem() != "" {
		_, _ = fmt.Fprintln(diagnostic, "Error: subsystems are not supported")
		_ = sess.Exit(2)
		return
	}
	signals := make(chan tailssh.Signal, 16)
	sess.Signals(signals)
	defer sess.Signals(nil)
	go func() {
		defer close(convertedSignals)
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-signals:
				numbers := map[tailssh.Signal]uint32{"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "ABRT": 6, "FPE": 8, "KILL": 9, "USR1": 10, "SEGV": 11, "USR2": 12, "PIPE": 13, "ALRM": 14, "TERM": 15}
				if n, ok := numbers[sig]; ok {
					select {
					case convertedSignals <- n:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	remote := sess.RemoteAddr().String()
	caller := service.Caller{Peer: peer, Resolve: func(jobctx context.Context) (identity.Peer, error) { return s.Resolver.WhoIs(jobctx, remote) }}
	line := sess.RawCommand()
	if strings.TrimSpace(line) != "" {
		_ = sess.Exit(DispatchSession(ctx, s.Service, caller, line, streams))
		return
	}
	if !pty {
		_, _ = io.WriteString(diagnostic, Help)
		_ = sess.Exit(2)
		return
	}
	rechecks := time.NewTicker(30 * time.Second)
	defer rechecks.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-rechecks.C:
				updated, err := s.Resolver.WhoIs(ctx, sess.RemoteAddr().String())
				if err != nil || updated.NodeID != nodeID {
					cancel()
					return
				}
			}
		}
	}()
	_ = sess.Exit(Lobby(ctx, s.Service, caller, streams))
}
