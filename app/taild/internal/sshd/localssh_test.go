package sshd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"golang.org/x/crypto/ssh"
)

// Real SSH framing below the authentication boundary. The explicit domain
// principal is test-owned; this is not a WhoIs or tailnet qualification test.
func TestLocalSSHDispatchJSONAndExit(t *testing.T) {
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal(e)
	}
	audit, e := state.OpenAudit(t.TempDir(), 4096, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	svc := &service.Service{Audit: audit, Capability: "cap"}
	peer := identity.Peer{Principals: []identity.Principal{"tag:ci"}, NodeID: "domain-node", ObservedAt: time.Now()}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		raw, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, channels, requests, e := ssh.NewServerConn(raw, serverConfig)
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(requests)
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			ch, requests, e := newChannel.Accept()
			if e != nil {
				done <- e
				return
			}
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if e = ssh.Unmarshal(req.Payload, &payload); e != nil {
					done <- e
					return
				}
				_ = req.Reply(true, nil)
				code := dispatch(svc, peer, payload.Command, ch, ch.Stderr())
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
				_ = ch.Close()
				break
			}
		}
		done <- nil
	}()
	client, e := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "forged-user:999", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errOut
	if e = session.Run("whoami --json"); e != nil {
		t.Fatal(e)
	}
	var result struct {
		OK   bool
		Data service.WhoAmI
	}
	if e = json.Unmarshal(out.Bytes(), &result); e != nil || !result.OK || result.Data.Peer.Principals[0] != "tag:ci" {
		t.Fatalf("%s %v", out.Bytes(), e)
	}
	session.Close()
	session, e = client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	var exit *ssh.ExitError
	if e = session.Run("create dev"); e == nil {
		t.Fatal("create without capability accepted")
	} else if !errors.As(e, &exit) || exit.ExitStatus() != 4 {
		t.Fatal(e)
	}
	session.Close()
	client.Close()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local SSH did not join")
	}
}
