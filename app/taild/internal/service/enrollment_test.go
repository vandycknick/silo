package service

import (
	"context"
	"encoding/json"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	"os"
	"path/filepath"
	"slices"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
	"testing"
)

func TestNativeRemoveSnapshotsStableNodeBeforeDeletingState(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	c := domainCaller(t, s, "user:123")
	disk := filepath.Join(s.Config.Home, "input.raw")
	if err := os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "snapshot" }`)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{runtime.OwnerLabel: "user:123", runtime.InstanceLabel: s.Runtime.Instance, runtime.NameLabel: "snapshot", runtime.ModeLabel: "interactive"}
	machine, err := s.Runtime.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("snapshot"), silo.WithLabels(labels), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Public serializers exercise state interoperability at the file-format level,
	// not a fabricated control-plane enrollment or tsnet-produced-state claim.
	profile := ipn.LoginProfile{ID: "profile", Key: "profile-key", NodeID: "stable-snapshot", UserProfile: tailcfg.UserProfile{ID: 123, LoginName: "user@example.com"}}
	prefs := ipn.Prefs{Hostname: "snapshot", Persist: &persist.Persist{NodeID: profile.NodeID, UserProfile: profile.UserProfile, PrivateNodeKey: key.NewNode()}}
	st, err := store.NewFileStore(t.Logf, filepath.Join(data.Network.Tailscale.StateDir, "tailscaled.state"))
	if err != nil {
		t.Fatal(err)
	}
	known, err := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profile.ID: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		k ipn.StateKey
		b []byte
	}{{ipn.CurrentProfileStateKey, []byte(profile.Key)}, {ipn.KnownProfilesStateKey, known}, {profile.Key, prefs.ToBytes()}} {
		if err = st.WriteState(entry.k, entry.b); err != nil {
			t.Fatal(err)
		}
	}
	for _, missing := range []identity.Action{identity.Start, identity.Stop} {
		restricted := c
		restricted.Peer.Permissions.Actions = slices.DeleteFunc(slices.Clone(c.Peer.Permissions.Actions), func(a identity.Action) bool { return a == missing })
		if _, err = s.Reauth(ctx, restricted, "snapshot"); err == nil || Categorize(err).Exit != 4 {
			t.Fatal("reauth accepted missing composite capability", missing, err)
		}
	}
	op, err := s.Remove(ctx, c, "snapshot", RemoveRequest{Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	result := waitOperation(t, s, c, op)
	if result.Error != nil || !slices.Contains(result.Progress, "device_retained: stable-snapshot") {
		t.Fatal("lost pre-remove stable identity", result)
	}
	if _, err = os.Stat(data.Network.Tailscale.StateDir); !os.IsNotExist(err) {
		t.Fatal("native state was not removed", err)
	}
}

func TestRemoveRetainsUnknownNodeTransaction(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	c := domainCaller(t, s, "user:123")
	disk := filepath.Join(s.Config.Home, "retained.raw")
	if e := os.WriteFile(disk, []byte("stopped fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	policy, e := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "retained" }`)
	if e != nil {
		t.Fatal(e)
	}
	labels := map[string]string{runtime.OwnerLabel: "user:123", runtime.InstanceLabel: s.Runtime.Instance, runtime.NameLabel: "retained", runtime.ModeLabel: "interactive"}
	machine, e := s.Runtime.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("retained"), silo.WithLabels(labels), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if e != nil {
		t.Fatal(e)
	}
	defer machine.Close()
	data, e := machine.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	dir := data.Network.Tailscale.StateDir
	lease, e := machine.LeaseNodeState(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = state.BeginNodeTransaction(dir); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(dir+".pending", 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir+".pending", "tailscaled.state"), []byte("unknown private state"), 0600); e != nil {
		t.Fatal(e)
	}
	lease.Close()
	op, e := s.Remove(ctx, c, "retained", RemoveRequest{Confirmed: true})
	if e != nil {
		t.Fatal(e)
	}
	result := waitOperation(t, s, c, op)
	if result.Error == nil || result.Error.Exit != 5 {
		t.Fatal("unknown transaction removed", result)
	}
	for _, path := range []string{dir, dir + ".pending", dir + ".transaction"} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal("retained state erased", e)
		}
	}
	kept, e := s.Runtime.SDK.Machine(ctx, "retained")
	if e != nil {
		t.Fatal("retained VM erased", e)
	}
	kept.Close()
}
