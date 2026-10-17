package sshdoor

import (
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"testing"
)

func TestHumanOwnsTaggedVMWithoutGrantingOtherTagMembers(t *testing.T) {
	tags := views.SliceOf([]string{"tag:dev"})
	s := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "vm", Tags: &tags}}
	p := &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: "peer", User: 7}, UserProfile: &tailcfg.UserProfile{ID: 7, LoginName: "owner@example.test"}}
	if _, err := ManagementOwner(p, s, "user:7"); err != nil {
		t.Fatal(err)
	}
	p.Node.User = 8
	p.UserProfile.ID = 8
	if _, err := ManagementOwner(p, s, "user:7"); err == nil {
		t.Fatal("other user accepted")
	}
	p.Node.Tags = []string{"tag:dev"}
	p.Node.User = 7
	p.UserProfile.ID = 7
	if _, err := ManagementOwner(p, s, "user:7"); err == nil {
		t.Fatal("tagged creator accepted as human")
	}
	if _, err := ManagementOwner(p, s, "tag:dev"); err != nil {
		t.Fatal(err)
	}
}
