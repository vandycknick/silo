package jobs

import (
	"context"
	"encoding/base32"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
)

func TestRestartRegistryIsEmptyAndShutdownJoins(t *testing.T) {
	r := &Registry{}
	if e := r.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !r.closing {
		t.Fatal("registry did not seal")
	}
}

func peer(owner identity.Principal) identity.Peer {
	return identity.Peer{Principals: []identity.Principal{owner}}
}
func finished(t *testing.T, r *Registry, p identity.Peer, id string) Operation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		op, ch, e := r.Observe(p, id)
		if e != nil {
			t.Fatal(e)
		}
		if op.Finished != nil {
			return op
		}
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal("operation did not finish")
		}
	}
}
func TestCanonicalCryptoULID(t *testing.T) {
	now := time.UnixMilli(1770000000123)
	seen := map[string]bool{}
	alphabet := "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// An independent bigint decoder checks all 130 bits and the 48-bit timestamp.
	for range 1000 {
		id, e := newID(now)
		if e != nil {
			t.Fatal(e)
		}
		if len(id) != 29 || !strings.HasPrefix(id, "op_") || id[3] > '7' || seen[id] {
			t.Fatal(id)
		}
		seen[id] = true
		value := new(big.Int)
		for _, c := range id[3:] {
			n := strings.IndexRune(alphabet, c)
			if n < 0 {
				t.Fatal(id)
			}
			value.Lsh(value, 5)
			value.Or(value, big.NewInt(int64(n)))
		}
		timestamp := new(big.Int).Rsh(value, 80)
		if timestamp.Int64() != now.UnixMilli() {
			t.Fatal(timestamp)
		}
		if len(value.Bytes()) > 16 {
			t.Fatal("ULID overflow")
		}
	}
	if _, e := newID(time.UnixMilli(-1)); e == nil {
		t.Fatal("negative timestamp accepted")
	}
	// Confirm a known canonical zero vector against the standard base32 alphabet.
	if base32.NewEncoding(alphabet).EncodeToString(make([]byte, 5)) != "00000000" {
		t.Fatal("alphabet mismatch")
	}
}
func TestDetachedSerializationAdmissionVisibilityAndExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := New(ctx, 2)
	p := peer("user:1")
	other := peer("user:2")
	entered := make(chan struct{})
	release := make(chan struct{})
	second := make(chan struct{})
	a, e := r.Submit("start", "vm", "user:1", func(ctx context.Context, progress func(string)) error {
		close(entered)
		<-release
		for range 150 {
			progress("real milestone")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	<-entered
	b, e := r.Submit("stop", "vm", "user:1", func(ctx context.Context, progress func(string)) error { close(second); return nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Submit("overflow", "other", "user:1", func(context.Context, func(string)) error { return nil }); e == nil {
		t.Fatal("admission unbounded")
	}
	select {
	case <-second:
		t.Fatal("VM mutations overlapped")
	default:
	}
	if _, _, e = r.Observe(other, a.ID); e == nil || len(r.List(other)) != 0 {
		t.Fatal("foreign operations visible")
	}
	// Observing and then discarding the notification channel is not cancellation.
	if _, _, e = r.Observe(p, a.ID); e != nil {
		t.Fatal(e)
	}
	close(release)
	op := finished(t, r, p, a.ID)
	if op.State != "succeeded" || len(op.Progress) != 128 {
		t.Fatal(op)
	}
	if finished(t, r, p, b.ID).State != "succeeded" {
		t.Fatal("queued operation failed")
	}
	r.mu.Lock()
	expired := time.Now().Add(-25 * time.Hour)
	r.entries[a.ID].op.Finished = &expired
	r.mu.Unlock()
	if _, _, e = r.Observe(p, a.ID); e == nil {
		t.Fatal("expired operation retained")
	}
	if e = r.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Submit("late", "vm", "user:1", func(context.Context, func(string)) error { return nil }); e == nil {
		t.Fatal("shutdown accepted work")
	}
}
func TestDaemonCancellationReleasesQueuedLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := New(ctx, 2)
	entered := make(chan struct{})
	a, e := r.Submit("start", "vm", "user:1", func(ctx context.Context, f func(string)) error { close(entered); <-ctx.Done(); return ctx.Err() })
	if e != nil {
		t.Fatal(e)
	}
	<-entered
	b, e := r.Submit("stop", "vm", "user:1", func(ctx context.Context, f func(string)) error { return ctx.Err() })
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	for _, op := range []Operation{a, b} {
		if finished(t, r, peer("user:1"), op.ID).State != "failed" {
			t.Fatal("daemon cancellation ignored")
		}
	}
	if e = r.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != 0 || len(r.locks) != 0 {
		t.Fatal("lock/admission leak")
	}
}
