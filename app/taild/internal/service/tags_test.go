package service

import (
	"encoding/json"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
)

func TestHumanRequestedTagsKeepManagementOwnership(t *testing.T) {
	// Install fixture TLS trust before the real daemon inherits its environment.
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.VMNodesEnabled = true
	s.Config.Enrollment.Mode = "interactive"
	s.Enrollment = &enroll.Manager{Config: s.Config, Registry: enroll.NewRegistry(), Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}}
	c := domainCaller(s, "user:7")
	tagged := domainCaller(s, "tag:creator")
	if _, err := s.ValidateCreate(t.Context(), tagged.Peer, CreateRequest{Image: registry.Reference, Tailscale: true, Tags: []string{"tag:delegated"}}); err != nil {
		t.Fatal("taild tried to replace Tailscale tagOwners", err)
	}
	if _, err := s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, Name: "invalid", Tags: []string{"tag:dev"}}); err == nil {
		t.Fatal("tag without tailscale accepted")
	}
	op, err := s.Create(t.Context(), c, CreateRequest{Image: registry.Reference, Name: "tagged", Tailscale: true, Tags: []string{"tag:Dev", "tag:testing", "tag:dev"}, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	d, err := s.Runtime.Control.Inspect(t.Context(), "tagged")
	if err != nil {
		t.Fatal(err)
	}
	if d.Labels[runtime.OwnerLabel] != "user:7" || d.Labels[runtime.TagsLabel] != `["tag:dev","tag:testing"]` {
		t.Fatal(d.Labels)
	}
	var policy struct {
		Metadata  map[string]json.RawMessage `json:"metadata"`
		Tailscale []struct {
			Tags []string `json:"tags"`
		} `json:"tailscale"`
	}
	if err = json.Unmarshal([]byte(d.PolicyJSON), &policy); err != nil {
		t.Fatal(err)
	}
	var nodeAuthority string
	if err = json.Unmarshal(policy.Metadata["io.silo.taild.node"], &nodeAuthority); err != nil {
		t.Fatal(err)
	}
	if len(policy.Tailscale) != 1 || len(policy.Tailscale[0].Tags) != 2 {
		t.Fatal(policy)
	}
	var expected struct {
		Owner     string   `json:"owner"`
		Bootstrap string   `json:"bootstrap"`
		Tags      []string `json:"tags"`
	}
	if err = json.Unmarshal([]byte(nodeAuthority), &expected); err != nil || expected.Owner != "user:7" || expected.Bootstrap != "interactive" || len(expected.Tags) != 2 {
		t.Fatal(expected, err)
	}
	if _, err = s.Show(t.Context(), domainCaller(s, "tag:dev").Peer, "tagged"); err == nil {
		t.Fatal("tag membership conferred management ownership")
	}
	if err = s.Runtime.Control.Remove(t.Context(), d.ID); err != nil {
		t.Fatal(err)
	}
}
