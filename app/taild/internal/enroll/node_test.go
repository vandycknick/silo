package enroll

import (
	"github.com/vandycknick/silo/app/taild/internal/state"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
	"testing"
)

func TestActualStatusOwnershipAndExactDNSDomain(t *testing.T) {
	pin := state.NodePin{Tailnet: "tailnet", Suffix: "tail.test"}
	fresh := func() *ipnstate.Status {
		return &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "stable-id", NodeID: 123, UserID: 7, DNSName: "DEV.TAIL.TEST."}, CurrentTailnet: &ipnstate.TailnetStatus{Name: "tailnet", MagicDNSSuffix: "tail.test"}}
	}
	if err := Verify(fresh(), "dev", "user:7", pin); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ipnstate.Status){func(s *ipnstate.Status) { s.Self.UserID = 0 }, func(s *ipnstate.Status) { s.Self.UserID = 8 }, func(s *ipnstate.Status) { s.Self.DNSName = "dev-1.tail.test." }, func(s *ipnstate.Status) { s.CurrentTailnet.Name = "other" }, func(s *ipnstate.Status) { v := views.SliceOf([]string{"tag:ci"}); s.Self.Tags = &v }} {
		status := fresh()
		change(status)
		if Verify(status, "dev", "user:7", pin) == nil {
			t.Fatal("foreign/suffixed status accepted")
		}
	}
	status := fresh()
	tags := views.SliceOf([]string{"tag:ci"})
	status.Self.Tags = &tags
	if Verify(status, "dev", "tag:ci", pin) != nil || Verify(status, "dev", "tag:other", pin) == nil {
		t.Fatal("owner tag verification")
	}
	status.Self.Tags = nil
	if Verify(status, "dev", "tag:ci", pin) == nil {
		t.Fatal("creator user used as tag fallback")
	}
}

func TestVisibleExactDNSCollisionExcludesOnlyOwnStableID(t *testing.T) {
	status := &ipnstate.Status{Self: &ipnstate.PeerStatus{ID: "own-stable", NodeID: 123, DNSName: "DEV.TAIL.TEST."}}
	pin := state.NodePin{Suffix: "tail.test"}
	if NameTaken(status, "dev", "own-stable", pin) {
		t.Fatal("own node collided")
	}
	if !NameTaken(status, "dev", "123", pin) {
		t.Fatal("numeric peer ID excluded stable node")
	}
	if NameTaken(status, "other", "", pin) {
		t.Fatal("unrelated name collided")
	}
	if !NameTaken(status, "dev", "foreign", pin) {
		t.Fatal("global visible name collision ignored")
	}
}
