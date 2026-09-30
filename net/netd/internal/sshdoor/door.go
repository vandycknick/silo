package sshdoor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"tailscale.com/client/local"
)

type Event struct {
	Peer, Login, Node, UserID, User, Decision, Reason, RequestID string
	Duration                                                     time.Duration
}
type Door struct {
	dir                     *os.File
	ca, host                ssh.Signer
	mux                     string
	limits                  *Limits
	handshakes, connections chan struct{}
	audit                   func(Event)
}

func New(ctx context.Context, dir, mux string, ca []byte, audit func(Event)) (*Door, error) {
	signer, err := parseCA(ca)
	if err != nil {
		return nil, err
	}
	d, err := openSSHDir(dir)
	if err != nil {
		return nil, err
	}
	host, err := hostKey(ctx, d)
	if err != nil {
		d.Close()
		return nil, err
	}
	return &Door{dir: d, ca: signer, host: host, mux: mux, limits: NewLimits(), handshakes: make(chan struct{}, 16), connections: make(chan struct{}, 128), audit: audit}, nil
}
func (d *Door) Close() error { return d.dir.Close() }

func (d *Door) Serve(ctx context.Context, listener net.Listener, client *local.Client) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var tasks sync.WaitGroup
	defer func() { cancel(); tasks.Wait() }()
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !take(d.connections) {
			d.denied(c, "connection_limit")
			continue
		}
		if !take(d.handshakes) {
			<-d.connections
			d.denied(c, "handshake_limit")
			continue
		}
		tasks.Add(1)
		go func() { defer tasks.Done(); defer func() { <-d.connections }(); d.handle(ctx, c, client) }()
	}
}
func (d *Door) denied(c net.Conn, reason string) {
	defer c.Close()
	if d.audit != nil {
		d.audit(Event{Peer: c.RemoteAddr().String(), Decision: "deny", Reason: reason, RequestID: uuid.NewString()})
	}
}
func (d *Door) handle(ctx context.Context, c net.Conn, client *local.Client) {
	start := time.Now()
	event := Event{Peer: c.RemoteAddr().String(), Decision: "deny", Reason: "setup_failed", RequestID: uuid.NewString()}
	defer func() {
		event.Duration = time.Since(start)
		if d.audit != nil {
			d.audit(event)
		}
	}()
	defer c.Close()
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	stop := context.AfterFunc(setup, func() { c.Close() })
	released := false
	release := func() {
		if !released {
			<-d.handshakes
			released = true
		}
	}
	defer release()
	defer cancel()
	defer stop()
	deadline, _ := setup.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		event.Reason = "setup_deadline_failed"
		return
	}
	auth := func(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
		event.User = meta.User()
		id, err := boundedWhoIs(setup, client, c.RemoteAddr().String())
		event.Login = id.Login
		event.Node = id.Node
		event.UserID = id.UserID
		if err != nil {
			event.Reason = "not_owner"
			return nil, &ssh.BannerError{Err: err, Message: "not the owner of this VM; connect from its owning user or owner tag\r\n"}
		}
		return permissions(id), nil
	}
	config := &ssh.ServerConfig{NoClientAuth: true, NoClientAuthCallback: auth,
		PasswordCallback:            func(m ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) { return auth(m) },
		PublicKeyCallback:           func(m ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) { return auth(m) },
		KeyboardInteractiveCallback: func(m ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) { return auth(m) }}
	config.AddHostKey(d.host)
	down, dc, dr, err := ssh.NewServerConn(c, config)
	if err != nil {
		return
	}
	defer down.Close()
	id := Identity{Login: down.Permissions.Extensions["silo.login"], Node: down.Permissions.Extensions["silo.node"], UserID: down.Permissions.Extensions["silo.user_id"]}
	up, uc, ur, raw, err := d.connect(setup, down.User(), id, event.RequestID)
	if err != nil {
		event.Reason = err.Error()
		return
	}
	defer raw.Close()
	defer up.Close()
	if !stop() || setup.Err() != nil {
		return
	}
	if err := errors.Join(c.SetDeadline(time.Time{}), raw.SetDeadline(time.Time{})); err != nil {
		event.Reason = "clear_setup_deadline_failed"
		return
	}
	cancel()
	release()
	event.Decision = "allow"
	event.Reason = "connected"
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-relayCtx.Done():
				return
			case <-ticker.C:
				observed, err := boundedWhoIs(relayCtx, client, c.RemoteAddr().String())
				if err != nil || observed != id {
					event.Reason = "owner_revoked"
					relayCancel()
					return
				}
			}
		}
	}()
	Relay(relayCtx, down, up, dc, uc, dr, ur, id, d.limits)
	relayCancel()
	<-done
}

func (d *Door) connect(ctx context.Context, user string, id Identity, request string) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, net.Conn, error) {
	pin, err := guestPin(ctx, d.dir)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signer, err := issue(d.ca, user, id, request, time.Now())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	raw, err := DialMux(ctx, d.mux)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn, ch, req, err := ssh.NewClientConn(raw, "guest", &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(pin)})
	if err != nil {
		raw.Close()
		return nil, nil, nil, nil, fmt.Errorf("guest SSH handshake: %w", err)
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		raw.Close()
		return nil, nil, nil, nil, err
	}
	return conn, ch, req, raw, nil
}
