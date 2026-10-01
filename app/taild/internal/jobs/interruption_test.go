package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func TestHostShutdownInterruptionRestoresOnlyFutureAdmission(t *testing.T) {
	r := New(context.Background(), 2)
	started := make(chan struct{})
	op, err := r.Submit("create", "dev", "user:1", func(ctx context.Context, progress func(string)) error { close(started); <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	<-started
	r.InterruptIf(func() bool { return true })
	select {
	case <-r.Drained():
	case <-time.After(time.Second):
		t.Fatal("cancelled job did not drain")
	}
	p := identity.Peer{Principals: []identity.Principal{"user:1"}}
	got, _, err := r.Observe(p, op.ID)
	if err != nil || got.Error == nil || got.Error.Exit != 9 {
		t.Fatal(got, err)
	}
	r.Resume()
	_, err = r.Submit("start", "dev", "user:1", func(ctx context.Context, progress func(string)) error { return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if got := r.List(p); len(got) != 2 || got[1].State != "succeeded" {
		t.Fatal(got)
	}
}
