package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestNodeStateAdmission(t *testing.T) {
	b := bootstrap(privateDir(t), "")
	if got := nodeState(&ipnstate.Status{}, b); got.Phase != "starting" {
		t.Fatal(got)
	}
	if got := nodeState(&ipnstate.Status{AuthURL: "https://control.test/approve"}, b); got.Phase != "needs_login" || got.ApprovalURL != "https://control.test/approve" {
		t.Fatal(got)
	}
	st := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{DNSName: "lobby.tail.test."}, CurrentTailnet: &ipnstate.TailnetStatus{Name: "tailnet", MagicDNSSuffix: "TAIL.TEST."}}
	if got := nodeState(st, b); got.Phase != "needs_tag" || got.Error == "" {
		t.Fatal(got)
	}
	if _, err := os.Stat(filepath.Join(b.StateDir, "control-pin.json")); !os.IsNotExist(err) {
		t.Fatal("untagged node pinned control", err)
	}
	tags := views.SliceOf([]string{"tag:lobby"})
	st.Self.Tags = &tags
	if got := nodeState(st, b); got.Phase != "running" || got.Suffix != "tail.test" {
		t.Fatal(got)
	}
	st.CurrentTailnet.Name = "other"
	if got := nodeState(st, b); got.Phase != "needs_tag" || got.Error == "" {
		t.Fatal("foreign tailnet admitted", got)
	}
	st.CurrentTailnet.Name = "tailnet"
	st.CurrentTailnet.MagicDNSSuffix = "foreign.test"
	if got := nodeState(st, b); got.Phase != "needs_tag" || got.Error == "" {
		t.Fatal("foreign suffix admitted", got)
	}
	st.CurrentTailnet.MagicDNSSuffix = "tail.test"
	b.ControlURL = "https://foreign.test"
	if got := nodeState(st, b); got.Phase != "needs_tag" || got.Error == "" {
		t.Fatal("foreign control admitted", got)
	}
}
