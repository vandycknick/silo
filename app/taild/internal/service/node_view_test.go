package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStoppedNodeUsesConfigurationAndHistoricalExpiry(t *testing.T) {
	s := &Service{Enrollment: &enroll.Manager{Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}}}
	d := &control.Snapshot{MachineData: &silo.MachineData{ID: "vm", Name: "dev", Labels: map[string]string{runtime.OwnerLabel: "user:7", runtime.LoginLabel: "owner@example.test", runtime.TagsLabel: `["tag:dev"]`}, Network: silo.MachineNetwork{Tailscale: &silo.MachineTailscale{Hostname: "dev"}}, Status: silo.MachineStatus{Kind: silo.MachineStatusStopped}}, NetworkObservation: &w.NetworkObservation{}}
	old := time.Now().Add(-24 * time.Hour).UTC()
	o := &w.NodeObservation{MachineId: "vm", Owner: "user:7", Tailnet: "fixture", NodeId: "node", DnsName: "dev.tail.test", Tags: []string{"tag:dev"}, ObservedAt: timestamppb.New(old)}
	d.NetworkObservation.Historical = o
	v := s.nodeView(d)
	if v.Node != "dev.tail.test" || v.NodeState != state.NodeState("stopped") || v.KeyExpiry != "never" || !v.KeyExpiryLastKnown || v.OwnerLogin != "owner@example.test" || v.DefaultUser != "root" || v.ApprovalURL != "" {
		t.Fatal(v)
	}
	if v.KeyExpiryObservedAt == nil || !v.KeyExpiryObservedAt.Equal(old) {
		t.Fatal("history was made fresh", v)
	}
	expiry := old.Add(72 * time.Hour)
	o.KeyExpiry = timestamppb.New(expiry)
	v = s.nodeView(d)
	if v.KeyExpiry != expiry.Format(time.RFC3339) {
		t.Fatal(v)
	}
	for _, change := range []func(*w.NodeObservation){
		func(o *w.NodeObservation) { o.MachineId = "other" },
		func(o *w.NodeObservation) { o.Owner = "user:8" },
		func(o *w.NodeObservation) { o.DnsName = "other.tail.test" },
		func(o *w.NodeObservation) { o.Tailnet = "other" },
		func(o *w.NodeObservation) { o.Tags = []string{"tag:admin"} },
	} {
		bad := proto.Clone(o).(*w.NodeObservation)
		change(bad)
		d.NetworkObservation.Historical = bad
		v = s.nodeView(d)
		if v.Node != "dev.tail.test" || v.KeyExpiry != "unknown" {
			t.Fatal("bad history affected display", v)
		}
	}
	d.NetworkObservation.Historical = o
	current := "current"
	d.RunID = &current
	d.Status.Kind = silo.MachineStatusRunning
	v = s.nodeView(d)
	if v.Node != "" || v.NodeState == state.Enrolled {
		t.Fatal("historical run established readiness", v)
	}
	node, dns := "node", "dev.tail.test"
	status := &w.NodeStatus{MachineId: "vm", RunId: current, UpdatedAt: timestamppb.Now(), State: w.NodeState_NODE_STATE_READY, NodeId: &node, DnsName: &dns, Tags: []string{"tag:dev"}, KeyExpiryKnown: true}
	d.NetworkObservation.Live = status
	v = s.nodeView(d)
	if v.KeyExpiry != "never" || v.KeyExpiryLastKnown || v.NodeState != state.Enrolled {
		t.Fatal("current nonexpiry not displayed", v)
	}
	status.KeyExpiry = timestamppb.New(expiry)
	v = s.nodeView(d)
	if v.KeyExpiry != expiry.Format(time.RFC3339) || v.KeyExpiryLastKnown {
		t.Fatal(v)
	}
	wrong := "wrong.tail.test"
	status.DnsName = &wrong
	v = s.nodeView(d)
	if v.NodeState != state.Unreadable || v.KeyExpiry != "unknown" {
		t.Fatal("history concealed identity mismatch", v)
	}
	status.DnsName = &dns
	status.RunId = "old"
	v = s.nodeView(d)
	if v.NodeState == state.Enrolled {
		t.Fatal("wrong run established readiness", v)
	}
	status.RunId = current
	expired, code := time.Now().Add(-time.Hour).UTC(), "key_expired"
	status.State, status.ErrorCode = w.NodeState_NODE_STATE_APPROVAL_REQUIRED, &code
	status.KeyExpiry = timestamppb.New(expired)
	d.NetworkObservation.Historical = nil
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
	s, sdk := actualNativeService(t)
	c := domainCaller(s, "user:7")
	c.Peer.Login = "current@example.test"
	disk := filepath.Join(s.Config.Home, "input.raw")
	if err := os.WriteFile(disk, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []identity.Principal{"user:7", "tag:owner"} {
		m, err := sdk.CreateMachine(t.Context(), silo.DiskImage(disk), silo.WithName("dev"), silo.WithGuestUser("nickvd", 1000, 1000, "/home/nickvd"), silo.WithLabels(map[string]string{runtime.OwnerLabel: string(owner), runtime.LoginLabel: "recorded@example.test", runtime.NameLabel: "dev", runtime.InstanceLabel: s.Runtime.Instance, runtime.ModeLabel: "none"}))
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

func TestManagerNodeObservationRejectsUnsafeAndInvalidHistory(t *testing.T) {
	s, sdk := actualNativeService(t)
	s.Enrollment = &enroll.Manager{Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}}
	disk := filepath.Join(s.Config.Home, "observation.raw")
	if err := os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "observed" }`)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sdk.CreateMachine(t.Context(), silo.DiskImage(disk), silo.WithName("observed"), silo.WithLabels(map[string]string{runtime.OwnerLabel: "user:7", runtime.NameLabel: "observed", runtime.InstanceLabel: s.Runtime.Instance, runtime.ModeLabel: "interactive"}), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	d, err := s.Runtime.Control.Inspect(t.Context(), m.ID())
	if err != nil {
		t.Fatal(err)
	}
	path := d.Network.Tailscale.StateDir + ".status.json"
	now := time.Now().UTC()
	history := map[string]any{"owner": "user:7", "tailnet": "fixture", "node_id": "node", "dns_name": "observed.tail.test", "observed_at": now.Add(-time.Hour)}
	status := map[string]any{"version": 1, "vm_id": d.ID, "run_id": "previous", "observed_at": now, "state": "stopped", "last_known": history}
	write := func(mode os.FileMode) {
		t.Helper()
		b, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	check := func(expected bool) {
		t.Helper()
		d, err := s.Runtime.Control.Inspect(t.Context(), m.ID())
		if err != nil {
			t.Fatal(err)
		}
		if d.NetworkObservation.GetLive() != nil {
			t.Fatal("stopped history established live readiness")
		}
		v := s.nodeView(d)
		if (v.KeyExpiry == "never" && v.KeyExpiryLastKnown) != expected {
			t.Fatal(v, d.NetworkObservation)
		}
	}
	write(0600)
	check(true)
	status["vm_id"] = "another-machine"
	write(0600)
	check(false)
	status["vm_id"] = d.ID
	write(0644)
	check(false)
	write(0600)
	history["observed_at"] = now.Add(time.Hour)
	write(0600)
	check(false)
	if err = os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false)
}
