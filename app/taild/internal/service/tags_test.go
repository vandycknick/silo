package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestHumanRequestedTagsKeepManagementOwnership(t *testing.T) {
	s := actualService(t)
	registry := testfixture.OCIRegistry(t, "")
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	s.VMNodesEnabled = true
	s.Config.Enrollment.Mode = "interactive"
	s.Enrollment = &enroll.Manager{Config: s.Config, Registry: enroll.NewRegistry(), Pin: state.NodePin{Tailnet: "fixture", Suffix: "tail.test"}}
	c := domainCaller(t, s, "user:7")
	tagged := domainCaller(t, s, "tag:creator")
	if _, err := s.ValidateCreate(tagged.Peer, CreateRequest{Tailscale: true, Tags: []string{"tag:delegated"}}); err != nil {
		t.Fatal("taild tried to replace Tailscale tagOwners", err)
	}
	if _, err := s.Create(t.Context(), c, CreateRequest{Name: "invalid", Tags: []string{"tag:dev"}}); err == nil {
		t.Fatal("tag without tailscale accepted")
	}
	op, err := s.Create(t.Context(), c, CreateRequest{Name: "tagged", Tailscale: true, Tags: []string{"tag:Dev", "tag:testing", "tag:dev"}, NoStart: true})
	succeeded(t, s, c, op, err)
	m, err := s.Runtime.SDK.Machine(t.Context(), "tagged")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	d, err := m.Inspect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if d.Labels[runtime.OwnerLabel] != "user:7" || d.Labels[runtime.TagsLabel] != `["tag:dev","tag:testing"]` {
		t.Fatal(d.Labels)
	}
	var policy struct {
		Metadata  map[string]string `json:"metadata"`
		Tailscale []struct {
			Tags []string `json:"tags"`
		} `json:"tailscale"`
	}
	if err = json.Unmarshal([]byte(d.Network.Policy.JSON()), &policy); err != nil {
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
	if err = json.Unmarshal([]byte(policy.Metadata["io.silo.taild.node"]), &expected); err != nil || expected.Owner != "user:7" || expected.Bootstrap != "interactive" || len(expected.Tags) != 2 {
		t.Fatal(expected, err)
	}
	if _, err = s.Show(t.Context(), domainCaller(t, s, "tag:dev").Peer, "tagged"); err == nil {
		t.Fatal("tag membership conferred management ownership")
	}
	if err = m.Remove(t.Context()); err != nil {
		t.Fatal(err)
	}
}
