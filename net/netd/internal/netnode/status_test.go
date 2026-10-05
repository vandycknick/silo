package netnode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestManagedNodeStatusAndTrafficGate(t *testing.T) {
	e := &ExpectedIdentity{Owner: "user:7", Tailnet: "owner.test", Suffix: "tail.test"}
	n := newTestNode(t, Options{Identity: e})
	n.options.Declaration.Hostname = "dev"
	s := &ipnstate.Status{BackendState: "Running", CurrentTailnet: &ipnstate.TailnetStatus{Name: "owner.test", MagicDNSSuffix: "tail.test"}, Self: &ipnstate.PeerStatus{ID: "node-7", UserID: 7, DNSName: "dev.tail.test."}}
	n.observe(s)
	if !n.running || n.snapshot(s).State != "ready" {
		t.Fatal("valid identity rejected")
	}
	for _, change := range []func(){
		func() { s.Self.UserID = 8 },
		func() { s.Self.DNSName = "dev-1.tail.test." },
		func() { s.CurrentTailnet.Name = "other.test" },
		func() { s.CurrentTailnet.MagicDNSSuffix = "other.test" },
		func() { tags := views.SliceOf([]string{"tag:other"}); s.Self.Tags = &tags },
	} {
		original, _ := json.Marshal(s)
		change()
		n.observe(s)
		if n.running || n.snapshot(s).State != "failed" || n.snapshot(s).DNSName != "" {
			t.Fatal("mismatched node admitted", s)
		}
		if err := json.Unmarshal(original, &s); err != nil {
			t.Fatal(err)
		}
	}
	e.Owner = "tag:owner"
	tags := views.SliceOf([]string{"tag:owner"})
	s.Self.Tags = &tags
	if e.verify(s, "dev") != nil {
		t.Fatal("owning tag rejected")
	}
	s.Self.Tags = nil
	if e.verify(s, "dev") == nil {
		t.Fatal("tag owner accepted as a user")
	}
	e.Owner = "user:7"
	before := time.Now().Add(-time.Minute)
	s.Self.KeyExpiry = &before
	n.observe(s)
	if n.running || n.snapshot(s).ErrorCode != "key_expired" {
		t.Fatal("expired node admitted")
	}
	s.Self.KeyExpiry = nil
	s.BackendState, s.AuthURL = "NeedsLogin", "https://login.tailscale.com/a/test"
	v := n.snapshot(s)
	if v.State != "approval_required" || v.ApprovalURL != s.AuthURL || v.NodeID != "" {
		t.Fatal(v)
	}
	for _, link := range []string{"http://login.test", "https://user:secret@login.test", "https://login.test/\n", "https://login.test/\x1b"} {
		s.AuthURL = link
		if n.snapshot(s).ApprovalURL != "" {
			t.Fatal("invalid URL published", link)
		}
	}
}

func TestStatusRetainsVerifiedMetadataWithoutClaimingConnectivity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	o := Options{Dir: dir, VMID: "vm", RunID: "run", Identity: &ExpectedIdentity{Owner: "user:7", Tailnet: "fixture", Suffix: "tail.test"}, Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "dev"}}
	n := newTestNode(t, o)
	s := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "node", UserID: 7, DNSName: "dev.tail.test."}, CurrentTailnet: &ipnstate.TailnetStatus{Name: "fixture", MagicDNSSuffix: "tail.test"}}
	n.observe(s)
	read := func() Snapshot {
		t.Helper()
		b, err := os.ReadFile(dir + ".status.json")
		if err != nil {
			t.Fatal(err)
		}
		var v Snapshot
		if err = json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := read()
	if v.LastKnown == nil || v.LastKnown.KeyExpiry != nil || !v.KeyExpiryKnown {
		t.Fatal("nonexpiring self not recognized", v)
	}
	observed := v.LastKnown.ObservedAt
	n.observe(nil)
	v = n.snapshot(nil)
	v.State = "stopped"
	n.publish(v)
	v = read()
	if v.State != "stopped" || v.DNSName != "" || v.KeyExpiryKnown || v.ApprovalURL != "" || v.LastKnown == nil || !v.LastKnown.ObservedAt.Equal(observed) || v.LastKnown.DNSName != "dev.tail.test" {
		t.Fatal(v)
	}
	o.RunID = "next"
	next := newTestNode(t, o)
	next.restoreObservation()
	next.observe(nil)
	v = read()
	if v.RunID != "next" || v.State != "connecting" || v.LastKnown == nil || !v.LastKnown.ObservedAt.Equal(observed) || next.running {
		t.Fatal("history became current identity", v)
	}
	expiry := time.Now().Add(time.Hour)
	s.Self.KeyExpiry = &expiry
	next.observe(s)
	v = read()
	if v.KeyExpiry == nil || v.LastKnown.KeyExpiry == nil || !v.LastKnown.KeyExpiry.Equal(expiry) {
		t.Fatal(v)
	}
	s.Self.UserID = 8
	next.observe(s)
	v = read()
	if v.LastKnown != nil || v.State != "failed" || next.running {
		t.Fatal("mismatched identity hidden by history", v)
	}
}

func TestSnapshotAtomicReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	v := Snapshot{Version: 1, VMID: "vm", RunID: "run", State: "connecting"}
	if err := writeSnapshot(dir, v); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			if err := writeSnapshot(dir, v); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 200 {
		b, err := os.ReadFile(dir + ".status.json")
		var read Snapshot
		if err != nil || json.Unmarshal(b, &read) != nil || read.RunID != "run" {
			t.Error("partial snapshot", string(b), err)
			break
		}
	}
	wg.Wait()
	info, err := os.Stat(dir + ".status.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files leaked", entries, err)
	}
}

func TestFirstObservationOfExpiredKeyKeepsDateWithoutGrantingAccess(t *testing.T) {
	n := newTestNode(t, Options{Identity: &ExpectedIdentity{Owner: "user:7", Tailnet: "fixture", Suffix: "tail.test"}, Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "dev"}})
	expiry := time.Now().Add(-time.Hour).UTC()
	s := &ipnstate.Status{BackendState: "NeedsLogin", Self: &ipnstate.PeerStatus{ID: "node", UserID: 7, DNSName: "dev.tail.test.", KeyExpiry: &expiry}, CurrentTailnet: &ipnstate.TailnetStatus{Name: "fixture", MagicDNSSuffix: "tail.test"}, AuthURL: "https://login.tailscale.com/a/example"}
	n.observe(s)
	v := n.snapshot(s)
	if n.running || v.State != "approval_required" || !v.KeyExpiryKnown || v.KeyExpiry == nil || !v.KeyExpiry.Equal(expiry) || n.lastKnown == nil || !n.lastKnown.KeyExpiry.Equal(expiry) {
		t.Fatal("expired identity lost date or established connectivity", v)
	}
	s.Self.UserID = 8
	n.observe(s)
	if n.lastKnown != nil || n.snapshot(s).ErrorCode != "identity_mismatch" {
		t.Fatal("foreign expired identity reused history")
	}
	s.Self.UserID, s.Self.Expired, s.Self.KeyExpiry = 7, true, nil
	v = n.snapshot(s)
	if v.KeyExpiryKnown {
		t.Fatal("missing expired timestamp interpreted as never", v)
	}
}

func TestManagedIdentityMetadata(t *testing.T) {
	for _, raw := range []any{1, "{}", `{"owner":"user:0","tailnet":"a","suffix":"b"}`, `{"owner":"tag:","tailnet":"a","suffix":"b"}`} {
		if _, err := ParseIdentity(map[string]any{IdentityMetadata: raw}); err == nil {
			t.Fatal(raw)
		}
	}
	if v, err := ParseIdentity(nil); err != nil || v != nil {
		t.Fatal(v, err)
	}
	v, err := ParseIdentity(map[string]any{IdentityMetadata: `{"owner":"user:7","tailnet":"a","suffix":"b"}`})
	if err != nil || v.Owner != "user:7" {
		t.Fatal(v, err)
	}
}
