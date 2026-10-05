package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNetdStatusRejectsStaleRunsAndInvalidSnapshots(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	now := time.Now().UTC()
	valid := NetdStatus{Version: 1, VMID: "vm", RunID: "run", ObservedAt: now, State: "approval_required", ApprovalURL: "https://login.tailscale.com/a/example"}
	write := func(v NetdStatus) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dir+".status.json", b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(valid)
	if got, err := ReadNetdStatus(dir, "vm", "run", now); err != nil || got.ApprovalURL != valid.ApprovalURL {
		t.Fatal(got, err)
	}
	for _, change := range []func(*NetdStatus){
		func(v *NetdStatus) { v.Version = 2 }, func(v *NetdStatus) { v.VMID = "other" }, func(v *NetdStatus) { v.RunID = "old" },
		func(v *NetdStatus) { v.ObservedAt = now.Add(-61 * time.Second) }, func(v *NetdStatus) { v.ObservedAt = now.Add(time.Minute) },
		func(v *NetdStatus) { v.State = "bogus" }, func(v *NetdStatus) { v.ApprovalURL = "http://login.test" },
		func(v *NetdStatus) { v.State = "ready" },
	} {
		v := valid
		change(&v)
		write(v)
		if _, err := ReadNetdStatus(dir, "vm", "run", now); err == nil {
			t.Fatal("invalid snapshot accepted", v)
		}
	}
	write(valid)
	if _, err := ReadNetdStatus(dir, "vm", "", now); err == nil {
		t.Fatal("missing active run accepted")
	}
	if err := os.Chmod(dir+".status.json", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNetdStatus(dir, "vm", "run", now); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Remove(dir + ".status.json"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other", dir+".status.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNetdStatus(dir, "vm", "run", now); err == nil {
		t.Fatal("symlink accepted")
	}
}
