package sshdoor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Limits struct{ sessions, forwarding chan struct{} }

func NewLimits() *Limits { return &Limits{make(chan struct{}, 32), make(chan struct{}, 256)} }
func take(slots chan struct{}) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// Relay owns the raw streams returned by NewServerConn/NewClientConn. NewClient
// must not wrap the upstream: it would consume global requests and channel opens.
func Relay(ctx context.Context, down, up ssh.Conn, downChannels, upChannels <-chan ssh.NewChannel, downRequests, upRequests <-chan *ssh.Request, id Identity, limits *Limits) {
	if limits == nil {
		limits = NewLimits()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeBoth := func() { down.Close(); up.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	var tasks sync.WaitGroup
	spawn := func(f func()) { tasks.Add(1); go func() { defer tasks.Done(); f() }() }
	spawn(func() { down.Wait(); cancel() })
	spawn(func() { up.Wait(); cancel() })
	global := func(in <-chan *ssh.Request, out ssh.Conn, clientOrigin bool) {
		reservations := make(map[string]struct{})
		var unconfirmed uint64
		defer func() {
			for range reservations {
				<-limits.forwarding
			}
		}()
		for r := range in {
			var forward struct {
				Address string
				Port    uint32
			}
			reserved := false
			var streamlocal struct{ Path string }
			allocate := clientOrigin && (r.Type == "tcpip-forward" || r.Type == "streamlocal-forward@openssh.com")
			if allocate {
				valid := true
				if r.Type == "tcpip-forward" {
					valid = ssh.Unmarshal(r.Payload, &forward) == nil && forward.Port <= 65535
				} else {
					valid = ssh.Unmarshal(r.Payload, &streamlocal) == nil && streamlocal.Path != ""
				}
				if !valid || !take(limits.forwarding) {
					if r.WantReply {
						r.Reply(false, nil)
					}
					continue
				}
				reserved = true
			}
			ok, payload, err := out.SendRequest(r.Type, r.WantReply, r.Payload)
			if reserved {
				if err == nil && (ok || !r.WantReply) {
					if r.Type == "tcpip-forward" && forward.Port == 0 && r.WantReply {
						var dynamic struct{ Port uint32 }
						if ssh.Unmarshal(payload, &dynamic) != nil || dynamic.Port == 0 || dynamic.Port > 65535 {
							<-limits.forwarding
							cancel()
							return
						}
						forward.Port = dynamic.Port
					}
					key := fmt.Sprintf("tcp:%s:%d", forward.Address, forward.Port)
					if r.Type == "streamlocal-forward@openssh.com" {
						key = "unix:" + streamlocal.Path
					}
					if !r.WantReply {
						unconfirmed++
						key = fmt.Sprintf("unconfirmed:%d:%s", unconfirmed, key)
					}
					if _, exists := reservations[key]; exists {
						<-limits.forwarding
					} else {
						reservations[key] = struct{}{}
					}
				} else {
					<-limits.forwarding
				}
			}
			if clientOrigin && r.Type == "cancel-tcpip-forward" && ok && err == nil && ssh.Unmarshal(r.Payload, &forward) == nil {
				key := fmt.Sprintf("tcp:%s:%d", forward.Address, forward.Port)
				if _, exists := reservations[key]; exists {
					delete(reservations, key)
					<-limits.forwarding
				}
			}
			if clientOrigin && r.Type == "cancel-streamlocal-forward@openssh.com" && ok && err == nil && ssh.Unmarshal(r.Payload, &streamlocal) == nil {
				key := "unix:" + streamlocal.Path
				if _, exists := reservations[key]; exists {
					delete(reservations, key)
					<-limits.forwarding
				}
			}
			if err != nil {
				cancel()
				return
			}
			if r.WantReply {
				if err := r.Reply(ok, payload); err != nil {
					cancel()
					return
				}
			}
		}
	}
	spawn(func() { global(downRequests, up, true) })
	spawn(func() { global(upRequests, down, false) })
	keepalive := func(c ssh.Conn) {
		timer := time.NewTicker(30 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				// Only one outstanding keepalive per leg; cancellation closes the
				// connection and joins a stalled SendRequest.
				timeout := time.AfterFunc(10*time.Second, cancel)
				_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
				timeout.Stop()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}
	spawn(func() { keepalive(down) })
	spawn(func() { keepalive(up) })
	opens := func(in <-chan ssh.NewChannel, out ssh.Conn, clientOrigin bool) {
		for ch := range in {
			slots := limits.forwarding
			if ch.ChannelType() == "session" {
				slots = limits.sessions
			}
			if !take(slots) {
				ch.Reject(ssh.ResourceShortage, "SSH channel limit reached")
				continue
			}
			// Admit before spawning so pending opens also have a finite bound.
			spawn(func() { defer func() { <-slots }(); relayChannel(ch, out, clientOrigin, id) })
		}
	}
	spawn(func() { opens(downChannels, up, true) })
	spawn(func() { opens(upChannels, down, false) })
	<-ctx.Done()
	closeBoth()
	tasks.Wait()
}

func relayChannel(in ssh.NewChannel, out ssh.Conn, clientOrigin bool, id Identity) {
	b, br, err := out.OpenChannel(in.ChannelType(), in.ExtraData())
	if err != nil {
		var rejected *ssh.OpenChannelError
		if errors.As(err, &rejected) {
			in.Reject(rejected.Reason, rejected.Message)
		} else {
			in.Reject(ssh.ConnectionFailed, err.Error())
		}
		return
	}
	a, ar, err := in.Accept()
	if err != nil {
		b.Close()
		return
	}
	defer a.Close()
	defer b.Close()
	var directions sync.WaitGroup
	direction := func(dst, src ssh.Channel, requests <-chan *ssh.Request, inject bool) {
		defer directions.Done()
		var work sync.WaitGroup
		work.Add(1)
		go func() {
			defer work.Done()
			injected := false
			for r := range requests {
				if inject && r.Type == "env" {
					var env struct{ Name, Value string }
					if ssh.Unmarshal(r.Payload, &env) != nil || !validEnvironmentName(env.Name) || env.Name == "SILO_PEER" {
						if r.WantReply {
							r.Reply(false, nil)
						}
						continue
					}
				}
				if inject && !injected && (r.Type == "shell" || r.Type == "exec" || r.Type == "subsystem") {
					ok, err := dst.SendRequest("env", true, ssh.Marshal(struct{ Name, Value string }{"SILO_PEER", id.Login}))
					if err != nil || !ok {
						if r.WantReply {
							r.Reply(false, nil)
						}
						a.Close()
						b.Close()
						return
					}
					injected = true
				}
				ok, err := dst.SendRequest(r.Type, r.WantReply, r.Payload)
				if err != nil {
					a.Close()
					b.Close()
					return
				}
				if r.WantReply {
					if err := r.Reply(ok, nil); err != nil {
						a.Close()
						b.Close()
						return
					}
				}
			}
		}()
		var pumps sync.WaitGroup
		pumps.Add(2)
		copyOne := func(w io.Writer, r io.Reader) {
			defer pumps.Done()
			if _, err := io.Copy(w, r); err != nil {
				a.Close()
				b.Close()
			}
		}
		go copyOne(dst, src)
		go copyOne(dst.Stderr(), src.Stderr())
		pumps.Wait()
		// Extended data shares channel EOF. Never let the data pump truncate
		// stderr by closing the write half before the second pump finishes.
		dst.CloseWrite()
		work.Wait() // drain exit-status/exit-signal before sending channel close
		a.Close()
		b.Close()
	}
	directions.Add(2)
	go direction(b, a, ar, clientOrigin && in.ChannelType() == "session")
	go direction(a, b, br, false)
	directions.Wait()
}

// '=' and NUL can change how a guest represents an environment assignment.
// Reject ambiguous names at the authoritative identity boundary.
func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range []byte(name) {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
