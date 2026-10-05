package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/runtime"
	silo "github.com/vandycknick/silo/sdk/go"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func TestNativeRemoveDiscardsNodeStateLocally(t *testing.T) {
	for _, kind := range []string{"enrolled", "pending", "malformed", "transaction"} {
		t.Run(kind, func(t *testing.T) {
			s := actualService(t)
			ctx := context.Background()
			c := domainCaller(t, s, "user:123")
			disk := filepath.Join(s.Config.Home, "input.raw")
			if err := os.WriteFile(disk, []byte("stopped fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			policy, err := silo.ParseNetworkPolicyHCL(`tailscale "vm" { hostname = "local-removal" }`)
			if err != nil {
				t.Fatal(err)
			}
			labels := map[string]string{runtime.OwnerLabel: "user:123", runtime.InstanceLabel: s.Runtime.Instance, runtime.NameLabel: "local-removal", runtime.ModeLabel: "interactive"}
			m, err := s.Runtime.SDK.CreateMachine(ctx, silo.DiskImage(disk), silo.WithName("local-removal"), silo.WithLabels(labels), silo.WithVsock(true), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			d, err := m.Inspect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.SetSecret(ctx, "tailscale.vm.auth_key", []byte("test-bootstrap")); err != nil {
				t.Fatal(err)
			}
			dir := d.Network.Tailscale.StateDir
			if err = os.WriteFile(dir+".status.json", []byte("broken status"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "enrolled" {
				profile := ipn.LoginProfile{ID: "profile", Key: "profile-key", NodeID: "stable-node", UserProfile: tailcfg.UserProfile{ID: 123, LoginName: "owner@example.test"}}
				prefs := ipn.Prefs{Hostname: d.Name, Persist: &persist.Persist{NodeID: profile.NodeID, UserProfile: profile.UserProfile, PrivateNodeKey: key.NewNode()}}
				st, err := store.NewFileStore(t.Logf, filepath.Join(dir, "tailscaled.state"))
				if err != nil {
					t.Fatal(err)
				}
				known, err := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profile.ID: profile})
				if err != nil {
					t.Fatal(err)
				}
				for k, b := range map[ipn.StateKey][]byte{ipn.CurrentProfileStateKey: []byte(profile.Key), ipn.KnownProfilesStateKey: known, profile.Key: prefs.ToBytes()} {
					if err = st.WriteState(k, b); err != nil {
						t.Fatal(err)
					}
				}
			} else if kind != "pending" {
				if err = os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("unknown private state"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "transaction" {
				for _, suffix := range []string{".transaction", ".unreadable"} {
					if err = os.WriteFile(dir+suffix, []byte("abandoned"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				for _, suffix := range []string{".pending", ".backup"} {
					if err = os.Mkdir(dir+suffix, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			lease, err := m.LeaseNodeState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			op, err := s.Remove(ctx, c, d.Name, RemoveRequest{Confirmed: true})
			if err != nil {
				t.Fatal(err)
			}
			blocked := waitOperation(t, s, c, op)
			if blocked.Error == nil {
				t.Fatal("active lease did not block removal")
			}
			lease.Close()
			op, err = s.Remove(ctx, c, d.Name, RemoveRequest{Confirmed: true})
			succeeded(t, s, c, op, err)
			result := waitOperation(t, s, c, op)
			for _, line := range result.Progress {
				if strings.Contains(line, "device_") || strings.Contains(line, "tailscale") {
					t.Fatal("unexpected cloud cleanup", line)
				}
			}
			for _, path := range []string{d.MachineDir, dir, dir + ".status.json", filepath.Join(d.MachineDir, "secrets.json")} {
				if _, err = os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("local state remains", path, err)
				}
			}
		})
	}
}
