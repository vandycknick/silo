package sshdoor

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestOwner(t *testing.T) {
	tags := views.SliceOf([]string{"tag:owner"})
	for _, tt := range []struct {
		name           string
		selfID, peerID tailcfg.UserID
		selfTags       *views.Slice[string]
		peerTags       []string
		allowed        bool
	}{
		{"human", 7, 7, nil, nil, true}, {"other", 7, 8, nil, nil, false}, {"zero", 0, 0, nil, nil, false},
		{"tagged-peer-human", 7, 7, nil, []string{"tag:owner"}, false},
		{"owner-tag", 7, 8, &tags, []string{"tag:owner"}, true},
		{"creator-not-owner", 7, 7, &tags, nil, false}, {"different-tag", 7, 7, &tags, []string{"tag:other"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peer := &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: "node-id", User: tt.peerID, Tags: tt.peerTags}, UserProfile: &tailcfg.UserProfile{ID: tt.peerID, LoginName: "owner@example.com"}}
			status := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{UserID: tt.selfID, Tags: tt.selfTags}}
			id, err := Owner(peer, status)
			if (err == nil) != tt.allowed {
				t.Fatalf("%+v %v", id, err)
			}
			if tt.allowed && tt.selfTags != nil && id.Login != "node:node-id" {
				t.Fatalf("tag identity borrowed creator: %+v", id)
			}
			status.BackendState = "Stopped"
			if _, err := Owner(peer, status); err == nil {
				t.Fatal("stopped allowed")
			}
		})
	}
	if _, err := Owner(nil, nil); err == nil {
		t.Fatal("nil allowed")
	}
}

func testKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(b)
	s, err := parseCA(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestCertificatesAndPersistentKeys(t *testing.T) {
	ca, bytes := testKey(t)
	now := time.Now()
	signer, err := issue(ca, "guest", Identity{Login: "node:stable"}, "req", now)
	if err != nil {
		t.Fatal(err)
	}
	c := signer.PublicKey().(*ssh.Certificate)
	if c.CertType != ssh.UserCert || c.KeyId != "silo:tailnet:node:stable:req" || len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "guest" || c.ValidAfter != uint64(now.Unix()-60) || c.ValidBefore != uint64(now.Unix()+300) || len(c.Extensions) != 3 {
		t.Fatalf("%+v", c)
	}
	for _, extension := range []string{"permit-pty", "permit-agent-forwarding", "permit-port-forwarding"} {
		if value, ok := c.Extensions[extension]; !ok || value != "" {
			t.Fatalf("missing certificate extension: %s", extension)
		}
	}
	if len(c.CriticalOptions) != 0 {
		t.Fatal("unexpected certificate critical options")
	}
	checker := ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(ca.PublicKey().Marshal()) }}
	if err := checker.CheckCert("guest", c); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckCert("other", c); err == nil {
		t.Fatal("wrong principal")
	}
	dir := filepath.Join(t.TempDir(), "ssh")
	d, err := New(context.Background(), dir, "unused", bytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := guestPin(context.Background(), d.dir); err == nil {
		t.Fatal("TOFU")
	}
	first := d.host.PublicKey().Marshal()
	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			other, err := New(context.Background(), dir, "unused", bytes, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer other.Close()
			if string(first) != string(other.host.PublicKey().Marshal()) {
				t.Error("host identity changed")
			}
		}()
	}
	writers.Wait()
	pin := filepath.Join(dir, "known_host")
	if err := os.WriteFile(pin, ssh.MarshalAuthorizedKey(ca.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := guestPin(context.Background(), d.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pin, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := guestPin(context.Background(), d.dir); err == nil {
		t.Fatal("permissive pin accepted")
	}
	if err := os.Remove(pin); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "tailnet_host_ed25519_key"), pin); err != nil {
		t.Fatal(err)
	}
	if _, err := guestPin(context.Background(), d.dir); err == nil {
		t.Fatal("symlink pin accepted")
	}
}

func TestCARejectsEncryptedWrongTypeAndTrailingMaterial(t *testing.T) {
	_, data := testKey(t)
	if _, err := parseCA(append(append([]byte{}, data...), data...)); err == nil {
		t.Fatal("multiple CA keys accepted")
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("test-only"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCA(pem.EncodeToMemory(block)); err == nil {
		t.Fatal("encrypted CA accepted")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err = ssh.MarshalPrivateKey(other, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCA(pem.EncodeToMemory(block)); err == nil {
		t.Fatal("non-Ed25519 CA accepted")
	}
}
