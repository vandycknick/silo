package state

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func TestAuditRotationConcurrentRealFiles(t *testing.T) {
	home := t.TempDir()
	a, e := OpenAudit(home, 1024, 100)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := range 20 {
				if e := a.Append(Decision{NodeID: fmt.Sprintf("%d-%d", worker, i), Principals: []identity.Principal{"user:1"}, Action: "vm.read", Allowed: true}); e != nil {
					t.Error(e)
				}
			}
		}(worker)
	}
	wg.Wait()
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	files, e := filepath.Glob(filepath.Join(home, "logs", "taild", "audit.jsonl*"))
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, path := range files {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("%v %v", info, e)
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var d Decision
			if e := json.Unmarshal(scanner.Bytes(), &d); e != nil {
				t.Fatal(e)
			}
			if seen[d.NodeID] {
				t.Fatal("duplicate event")
			}
			seen[d.NodeID] = true
		}
		if e = scanner.Err(); e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	if len(seen) != 160 {
		t.Fatalf("lost events: %d", len(seen))
	}
}
func TestPrivateAtomicFiles(t *testing.T) {
	home := t.TempDir()
	if e := PrivateDir(filepath.Join(home, "taild")); e != nil {
		t.Fatal(e)
	}
	id, e := Instance(home)
	if e != nil {
		t.Fatal(e)
	}
	second, e := Instance(home)
	if e != nil || id != second {
		t.Fatal("unstable instance")
	}
	if e = PinTailnet(home, "first"); e != nil {
		t.Fatal(e)
	}
	if e = PinTailnet(home, "other"); e == nil {
		t.Fatal("tailnet change accepted")
	}
}

func TestExclusiveHomeLock(t *testing.T) {
	home := t.TempDir()
	first, e := LockHome(home)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := LockHome(home); e == nil {
		second.Close()
		t.Fatal("duplicate daemon admitted")
	}
	if e = first.Close(); e != nil {
		t.Fatal(e)
	}
	second, e := LockHome(home)
	if e != nil {
		t.Fatal(e)
	}
	second.Close()
}

func writeNode(t *testing.T, dir, hostname string) {
	t.Helper()
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	st, e := store.NewFileStore(t.Logf, filepath.Join(dir, "tailscaled.state"))
	if e != nil {
		t.Fatal(e)
	}
	profile := ipn.LoginProfile{ID: "abc", Key: "profile-abc", NodeID: "node-1", UserProfile: tailcfg.UserProfile{ID: 123, LoginName: "test@example.com"}}
	b, e := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profile.ID: profile})
	if e != nil {
		t.Fatal(e)
	}
	prefs := ipn.Prefs{Hostname: hostname, Persist: &persist.Persist{NodeID: profile.NodeID, UserProfile: profile.UserProfile, PrivateNodeKey: key.NewNode()}}
	for _, v := range []struct {
		k ipn.StateKey
		b []byte
	}{{ipn.CurrentProfileStateKey, []byte(profile.Key)}, {ipn.KnownProfilesStateKey, b}, {profile.Key, prefs.ToBytes()}} {
		if e = st.WriteState(v.k, v.b); e != nil {
			t.Fatal(e)
		}
	}
}
func TestProfileState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	if _, s := ReadNode(dir, "dev", "user:123", nil); s != Pending {
		t.Fatal(s)
	}
	writeNode(t, dir, "dev")
	if _, s := ReadNode(dir, "dev", "user:123", nil); s != Enrolled {
		t.Fatal(s)
	}
	if _, s := ReadNode(dir, "dev", "user:999", nil); s != Unreadable {
		t.Fatal("foreign profile accepted")
	}
	if _, s := ReadNode(dir, "other", "user:123", nil); s != Unreadable {
		t.Fatal("renamed profile accepted")
	}
	if e := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, s := ReadNode(dir, "dev", "user:123", nil); s != Unreadable {
		t.Fatal(s)
	}
}

func TestPublicProfilePinControlTailnetAndStableID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	writeNode(t, dir, "dev")
	st, e := store.NewFileStore(t.Logf, filepath.Join(dir, "tailscaled.state"))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := st.ReadState(ipn.KnownProfilesStateKey)
	if e != nil {
		t.Fatal(e)
	}
	var known map[ipn.ProfileID]ipn.LoginProfile
	if e = json.Unmarshal(raw, &known); e != nil {
		t.Fatal(e)
	}
	p := known["abc"]
	p.NetworkProfile = ipn.NetworkProfile{DomainName: "tailnet", MagicDNSName: "tail.test"}
	p.ControlURL = ipn.DefaultControlURL
	known["abc"] = p
	raw, e = json.Marshal(known)
	if e != nil {
		t.Fatal(e)
	}
	if e = st.WriteState(ipn.KnownProfilesStateKey, raw); e != nil {
		t.Fatal(e)
	}
	pin := NodePin{Tailnet: "tailnet", Suffix: "TAIL.TEST.", ControlURL: ipn.DefaultControlURL}
	node, s := ReadNode(dir, "dev", "user:123", &pin)
	if s != Enrolled || node.NodeID != "node-1" {
		t.Fatal(node, s)
	}
	for _, bad := range []NodePin{{Tailnet: "other", Suffix: "tail.test"}, {Tailnet: "tailnet", Suffix: "other.test"}, {Tailnet: "tailnet", Suffix: "tail.test", ControlURL: "https://foreign.test"}} {
		if _, s = ReadNode(dir, "dev", "user:123", &bad); s != Unreadable {
			t.Fatal("foreign pin accepted", bad, s)
		}
	}
}

func TestHomeControlPinCannotChangeControlOrSuffix(t *testing.T) {
	home := t.TempDir()
	if e := PrivateDir(filepath.Join(home, "taild")); e != nil {
		t.Fatal(e)
	}
	pin := NodePin{Tailnet: "tailnet", Suffix: "TAIL.TEST."}
	if e := PinNodeControl(home, pin); e != nil {
		t.Fatal(e)
	}
	pin.Suffix = "tail.test"
	pin.ControlURL = ipn.DefaultControlURL
	if e := PinNodeControl(home, pin); e != nil {
		t.Fatal(e)
	}
	pin.ControlURL = "https://foreign.test"
	if e := PinNodeControl(home, pin); e == nil {
		t.Fatal("foreign control accepted")
	}
	pin.ControlURL = ipn.DefaultControlURL
	pin.Suffix = "foreign.test"
	if e := PinNodeControl(home, pin); e == nil {
		t.Fatal("foreign DNS suffix accepted")
	}
}
