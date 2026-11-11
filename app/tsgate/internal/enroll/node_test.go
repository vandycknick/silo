package enroll

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func writeNode(t *testing.T, dir string, change func(*ipn.LoginProfile, *ipn.Prefs)) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	st, err := store.NewFileStore(t.Logf, filepath.Join(dir, "tailscaled.state"))
	if err != nil {
		t.Fatal(err)
	}
	profile := ipn.LoginProfile{ID: "abc", Key: "profile-abc", NodeID: "node-1", UserProfile: tailcfg.UserProfile{ID: 123, LoginName: "tagged-devices"}, ControlURL: ipn.DefaultControlURL, NetworkProfile: ipn.NetworkProfile{DomainName: "tailnet", MagicDNSName: "tail.test"}}
	prefs := ipn.Prefs{Hostname: "lobby", ControlURL: ipn.DefaultControlURL, AdvertiseTags: []string{"tag:lobby"}, Persist: &persist.Persist{NodeID: profile.NodeID, UserProfile: profile.UserProfile, PrivateNodeKey: key.NewNode()}}
	if change != nil {
		change(&profile, &prefs)
	}
	b, err := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profile.ID: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		k ipn.StateKey
		b []byte
	}{{ipn.CurrentProfileStateKey, []byte(profile.Key)}, {ipn.KnownProfilesStateKey, b}, {profile.Key, prefs.ToBytes()}} {
		if err = st.WriteState(v.k, v.b); err != nil {
			t.Fatal(err)
		}
	}
}
func TestReadNode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ipn.LoginProfile, *ipn.Prefs)
		want   NodeState
	}{
		{"enrolled", nil, Enrolled},
		{"hostname", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.Hostname = "other" }, Unreadable},
		{"tag", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.AdvertiseTags = []string{"tag:other"} }, Unreadable},
		{"node id", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.Persist.NodeID = "other" }, Unreadable},
		{"user id", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.Persist.UserProfile.ID = 999 }, Unreadable},
		{"key absent", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.Persist.PrivateNodeKey = key.NodePrivate{} }, Unreadable},
		{"no node", func(p *ipn.LoginProfile, v *ipn.Prefs) {
			v.Persist.NodeID = ""
			p.NodeID = ""
			v.Persist.PrivateNodeKey = key.NodePrivate{}
		}, Pending},
		{"persist absent", func(_ *ipn.LoginProfile, p *ipn.Prefs) { p.Persist = nil }, Unreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeNode(t, dir, tc.change)
			node, state := ReadNode(dir, "lobby", "tag:lobby", nil)
			if state != tc.want {
				t.Fatal(node, state, tc.want)
			}
			if state == Enrolled && node.NodeID != "node-1" {
				t.Fatal(node)
			}
		})
	}
	dir := t.TempDir()
	if _, s := ReadNode(dir, "lobby", "tag:lobby", nil); s != Pending {
		t.Fatal(s)
	}
	if err := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, s := ReadNode(dir, "lobby", "tag:lobby", nil); s != Unreadable {
		t.Fatal(s)
	}
	os.Remove(filepath.Join(dir, "tailscaled.state"))
	os.Symlink("/dev/null", filepath.Join(dir, "tailscaled.state"))
	if _, s := ReadNode(dir, "lobby", "tag:lobby", nil); s != Unreadable {
		t.Fatal(s)
	}
}
func TestReadNodePin(t *testing.T) {
	dir := t.TempDir()
	writeNode(t, dir, nil)
	pin := NodePin{Tailnet: "tailnet", Suffix: "TAIL.TEST.", ControlURL: ipn.DefaultControlURL}
	if _, state := ReadNode(dir, "lobby", "tag:lobby", &pin); state != Enrolled {
		t.Fatal(state)
	}
	for _, bad := range []NodePin{{Tailnet: "other", Suffix: "tail.test"}, {Tailnet: "tailnet", Suffix: "other.test"}, {Tailnet: "tailnet", Suffix: "tail.test", ControlURL: "https://foreign.test"}} {
		if _, state := ReadNode(dir, "lobby", "tag:lobby", &bad); state != Unreadable {
			t.Fatal(bad, state)
		}
	}
}
func TestControlPin(t *testing.T) {
	dir := t.TempDir()
	pin := NodePin{Tailnet: "tailnet", Suffix: "TAIL.TEST."}
	if err := PinNodeControl(dir, pin); err != nil {
		t.Fatal(err)
	}
	pin.Suffix = "tail.test"
	pin.ControlURL = ipn.DefaultControlURL
	if err := PinNodeControl(dir, pin); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []NodePin{{Tailnet: "other", Suffix: "tail.test"}, {Tailnet: "tailnet", Suffix: "other.test"}, {Tailnet: "tailnet", Suffix: "tail.test", ControlURL: "https://foreign.test"}, {}} {
		if err := PinNodeControl(dir, bad); err == nil {
			t.Fatal("pin changed", bad)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "control-pin.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "control-pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]string
	if err = json.Unmarshal(b, &raw); err != nil || raw["tailnet"] != "tailnet" || raw["suffix"] != "tail.test" || raw["control_url"] != ipn.DefaultControlURL {
		t.Fatal(string(b), err)
	}
}
func TestControlPinConcurrentFirstWriter(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := PinNodeControl(dir, NodePin{Tailnet: "tailnet", Suffix: "tail.test"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestControlURLNormalization(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ipn.DefaultControlURL},
		{"https://login.tailscale.com", ipn.DefaultControlURL},
		{"https://login.tailscale.com/", "https://login.tailscale.com"},
		{"https://control.test/", "https://control.test"},
		{"https://control.test", "https://control.test"},
	} {
		if got := controlURL(tc.input); got != tc.want {
			t.Fatal(tc.input, got, tc.want)
		}
	}
}
