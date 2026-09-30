package sshd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/httpd"
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
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer sess.Close()
			defer func() { s.mu.Lock(); delete(s.active, sess); s.mu.Unlock() }()
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
	peer, e := s.Resolver.WhoIs(ctx, sess.RemoteAddr().String())
	if e != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), "Error: identity unavailable or node not tagged")
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
		_, _ = fmt.Fprintln(sess.Stderr(), "Error: subsystems are not supported")
		_ = sess.Exit(2)
		return
	}
	_, windows, pty := sess.Pty()
	// Pinned Pty creates a converter goroutine; always drain it through close.
	if pty {
		go func() {
			for range windows {
			}
		}()
	}
	line := sess.RawCommand()
	if strings.TrimSpace(line) != "" {
		_ = sess.Exit(Dispatch(s.Service, peer, line, sess, sess.Stderr()))
		return
	}
	if !pty {
		_, _ = io.WriteString(sess.Stderr(), Help)
		_ = sess.Exit(2)
		return
	}
	_ = Dispatch(s.Service, peer, "whoami", sess, sess.Stderr())
	_, _ = io.WriteString(sess.Stderr(), Help)
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
	scanner := bufio.NewScanner(sess)
	scanner.Buffer(make([]byte, 1024), 16384)
	for {
		_, _ = io.WriteString(sess.Stderr(), "silo> ")
		if !scanner.Scan() {
			if scanner.Err() != nil {
				_ = sess.Exit(2)
			} else {
				_ = sess.Exit(0)
			}
			return
		}
		line = scanner.Text()
		if strings.TrimSpace(line) == "exit" {
			_ = sess.Exit(0)
			return
		}
		peer, e = s.Resolver.WhoIs(ctx, sess.RemoteAddr().String())
		if e != nil || peer.NodeID != nodeID {
			_ = sess.Exit(4)
			return
		}
		_ = Dispatch(s.Service, peer, line, sess, sess.Stderr())
	}
}
