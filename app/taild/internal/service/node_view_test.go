package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestStoppedNodeUsesConfigurationAndHistoricalExpiry(t *testing.T) {
	s := &Service{Enrollment: &enroll.Manager{Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}}}
	dir := filepath.Join(t.TempDir(), "tailscale")
	d := &silo.MachineData{ID: "vm", Name: "dev", Labels: map[string]string{runtime.OwnerLabel: "user:7", runtime.LoginLabel: "owner@example.test", runtime.TagsLabel: `["tag:dev"]`}, Network: silo.MachineNetwork{Tailscale: &silo.MachineTailscale{StateDir: dir, Hostname: "dev"}}, Status: silo.MachineStatus{Kind: silo.MachineStatusStopped}}
	old := time.Now().Add(-24 * time.Hour).UTC()
	o := state.NodeObservation{Owner: "user:7", Tailnet: "fixture", NodeID: "node", DNSName: "dev.tail.test", Tags: []string{"tag:dev"}, ObservedAt: old}
	snapshot := state.NetdStatus{Version: 1, VMID: "vm", RunID: "old", ObservedAt: old.Add(time.Minute), State: "stopped", LastKnown: &o}
	write := func() {
		t.Helper()
		b, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dir+".status.json", b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	v := s.nodeView(d)
	if v.Node != "dev.tail.test" || v.NodeState != state.NodeState("stopped") || v.KeyExpiry != "never" || !v.KeyExpiryLastKnown || v.OwnerLogin != "owner@example.test" || v.DefaultUser != "root" || v.ApprovalURL != "" {
		t.Fatal(v)
	}
	if v.KeyExpiryObservedAt == nil || !v.KeyExpiryObservedAt.Equal(old) {
		t.Fatal("history was made fresh", v)
	}
	expiry := old.Add(72 * time.Hour)
	o.KeyExpiry = &expiry
	write()
	v = s.nodeView(d)
	if v.KeyExpiry != expiry.Format(time.RFC3339) {
		t.Fatal(v)
	}
	for _, change := range []func(){func() { snapshot.VMID = "other" }, func() { o.Owner = "user:8" }, func() { o.DNSName = "other.tail.test" }, func() { o.Tailnet = "other" }, func() { o.Tags = []string{"tag:admin"} }, func() { o.ObservedAt = time.Now().Add(time.Hour) }} {
		before, _ := json.Marshal(snapshot)
		change()
		write()
		v = s.nodeView(d)
		if v.Node != "dev.tail.test" || v.NodeState != state.NodeState("stopped") || v.KeyExpiry != "unknown" {
			t.Fatal("bad history affected display", v)
		}
		if err := json.Unmarshal(before, &snapshot); err != nil {
			t.Fatal(err)
		}
		o = *snapshot.LastKnown
		snapshot.LastKnown = &o
	}
	current := "current"
	d.RunID = &current
	d.Status.Kind = silo.MachineStatusRunning
	write()
	v = s.nodeView(d)
	if v.Node != "" || v.NodeState == state.Enrolled {
		t.Fatal("historical run established readiness", v)
	}
	snapshot.RunID = current
	snapshot.ObservedAt = time.Now().UTC()
	snapshot.State = "ready"
	snapshot.NodeID = "node"
	snapshot.DNSName = "dev.tail.test"
	snapshot.Tags = []string{"tag:dev"}
	snapshot.KeyExpiryKnown = true
	write()
	v = s.nodeView(d)
	if v.KeyExpiry != "never" || v.KeyExpiryLastKnown || v.NodeState != state.Enrolled {
		t.Fatal("current nonexpiry not displayed", v)
	}
	snapshot.KeyExpiry = &expiry
	write()
	v = s.nodeView(d)
	if v.KeyExpiry != expiry.Format(time.RFC3339) || v.KeyExpiryLastKnown {
		t.Fatal(v)
	}
	snapshot.DNSName = "wrong.tail.test"
	write()
	v = s.nodeView(d)
	if v.NodeState != state.Unreadable || v.KeyExpiry != "unknown" {
		t.Fatal("history concealed identity mismatch", v)
	}
	expired := time.Now().Add(-time.Hour).UTC()
	snapshot.State, snapshot.ErrorCode, snapshot.DNSName = "approval_required", "key_expired", "dev.tail.test"
	snapshot.KeyExpiry, snapshot.LastKnown = &expired, nil
	write()
	v = s.nodeView(d)
	if v.NodeState != state.Pending || v.Node != "" || v.KeyExpiry != expired.Format(time.RFC3339) || v.KeyExpiryLastKnown {
		t.Fatal("expired first observation lost date or implied connectivity", v)
	}
	d.Network.Tailscale = nil
	v = s.nodeView(d)
	if v.Node != "" || v.NodeState != state.NoNode {
		t.Fatal(v)
	}
}

func TestShowOwnerLoginUsesVerifiedOwner(t *testing.T) {
	s := actualService(t)
	c := domainCaller(t, s, "user:7")
	c.Peer.Login = "current@example.test"
	disk := filepath.Join(s.Config.Home, "input.raw")
	if err := os.WriteFile(disk, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []identity.Principal{"user:7", "tag:owner"} {
		m, err := s.Runtime.SDK.CreateMachine(t.Context(), silo.DiskImage(disk), silo.WithName("dev"), silo.WithGuestUser("nickvd", 1000, 1000, "/home/nickvd"), silo.WithLabels(map[string]string{runtime.OwnerLabel: string(owner), runtime.LoginLabel: "recorded@example.test", runtime.NameLabel: "dev", runtime.InstanceLabel: s.Runtime.Instance, runtime.ModeLabel: "none"}))
		if err != nil {
			t.Fatal(err)
		}
		peer := c.Peer
		peer.Principals = []identity.Principal{owner}
		v, err := s.Show(t.Context(), peer, "dev")
		if err != nil {
			t.Fatal(err)
		}
		if v.DefaultUser != "nickvd" || v.Owner != owner {
			t.Fatal(v)
		}
		if owner.IsTag() {
			if v.OwnerLogin != "" {
				t.Fatal("tag borrowed human login", v)
			}
		} else {
			if v.OwnerLogin != "current@example.test" {
				t.Fatal(v)
			}
			peer.Login = ""
			v, err = s.Show(t.Context(), peer, "dev")
			if err != nil || v.OwnerLogin != "recorded@example.test" {
				t.Fatal(v, err)
			}
		}
		if err = m.Remove(t.Context()); err != nil {
			t.Fatal(err)
		}
		m.Close()
	}
}
