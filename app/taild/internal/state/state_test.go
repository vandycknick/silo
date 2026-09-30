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
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
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
	path, e := PrincipalDir(home, "user:123")
	if e != nil {
		t.Fatal(e)
	}
	if filepath.Dir(path) != filepath.Join(home, "taild", "principals") {
		t.Fatal(path)
	}
	if _, e = PrincipalDir(home, "tag:../../escape"); e == nil {
		t.Fatal("path traversal")
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
func TestProfileStateAndStoppedRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	if _, s := ReadNode(dir, "dev", "user:123"); s != Pending {
		t.Fatal(s)
	}
	writeNode(t, dir, "dev")
	if _, s := ReadNode(dir, "dev", "user:123"); s != Enrolled {
		t.Fatal(s)
	}
	if _, s := ReadNode(dir, "dev", "user:999"); s != Unreadable {
		t.Fatal("foreign profile accepted")
	}
	if _, s := ReadNode(dir, "other", "user:123"); s != Unreadable {
		t.Fatal("renamed profile accepted")
	}
	if e := os.Rename(dir, dir+".backup"); e != nil {
		t.Fatal(e)
	}
	if s := RecoverNode(dir, "dev", "user:123", false); s != Unreadable {
		t.Fatal("running recovery accepted")
	}
	if s := RecoverNode(dir, "dev", "user:123", true); s != Enrolled {
		t.Fatal(s)
	}
	if e := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, s := ReadNode(dir, "dev", "user:123"); s != Unreadable {
		t.Fatal(s)
	}
}

func TestRecoveryAtPromotionCrashBoundaries(t *testing.T) {
	for _, step := range []string{"before-backup", "after-backup", "after-promotion", "corrupt-canonical"} {
		t.Run(step, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "tailscale")
			writeNode(t, dir, "dev")
			switch step {
			case "before-backup":
				writeNode(t, dir+".pending", "dev")
			case "after-backup":
				if e := os.Rename(dir, dir+".backup"); e != nil {
					t.Fatal(e)
				}
				writeNode(t, dir+".pending", "dev")
			case "after-promotion":
				writeNode(t, dir+".backup", "dev")
			case "corrupt-canonical":
				writeNode(t, dir+".backup", "dev")
				if e := os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("broken"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if s := RecoverNode(dir, "dev", "user:123", true); s != Enrolled {
				t.Fatal(s)
			}
			if _, s := ReadNode(dir, "dev", "user:123"); s != Enrolled {
				t.Fatal(s)
			}
			if _, e := os.Stat(dir + ".backup"); !os.IsNotExist(e) {
				t.Fatal("validated backup was not finalized")
			}
		})
	}
}
