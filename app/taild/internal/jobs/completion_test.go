package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func TestCompletionIsAnImmutableJobSnapshot(t *testing.T) {
	r := New(t.Context(), 1)
	peer := identity.Peer{Principals: []identity.Principal{"user:7"}}
	result := &Completion{VMID: "id", Name: "original", ApprovalURL: "https://login.tailscale.com/a/example"}
	op, err := r.SubmitResult("create", "original", "user:7", func(context.Context, func(string)) (*Completion, error) { return result, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = r.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	result.Name = "mutated-source"
	first, _, err := r.Observe(peer, op.ID)
	if err != nil || first.Completion == nil || first.Completion.Name != "original" {
		t.Fatal(first, err)
	}
	first.Completion.Name = "mutated-observation"
	second, _, err := r.Observe(peer, op.ID)
	if err != nil || second.Completion.Name != "original" {
		t.Fatal(second, err)
	}
}
