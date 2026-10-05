package service

import (
	"context"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestGuestUserValidationBeforeImagePull(t *testing.T) {
	s := actualService(t)
	c := domainCaller(s, "user:1")
	registry := testfixture.OCIRegistry(t, "")
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	for _, u := range []silo.GuestUser{{Name: "root", UID: 1000, GID: 1000, Home: "/home/root"}, {Name: "nickvd", UID: 1000, GID: 1000, Home: "../host"}} {
		if _, err := s.Create(context.Background(), c, CreateRequest{Name: "invalid-user", GuestUser: &u}); err == nil || Categorize(err).Exit != 2 {
			t.Fatal(err)
		}
	}
	if len(s.Jobs.List(c.Peer)) != 0 {
		t.Fatal("invalid account admitted a job")
	}
	if registry.Requests.Load() != 0 {
		t.Fatal("invalid account pulled a VM image")
	}
	entries, err := s.Runtime.SDK.Inventory(context.Background())
	if err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
}
