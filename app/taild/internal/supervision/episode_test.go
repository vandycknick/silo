package supervision

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/units"
)

// These tests drive the ordered-message domain and real pipe FDs. They do not
// emulate a D-Bus server, SDK stop behavior, or claim a live login1 qualification.
func episodeFixture(t *testing.T, budget time.Duration) (*Inhibitor, *state.ShutdownGate, chan<- loginEvent, <-chan loginEvent, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	c := config.Defaults()
	c.Shutdown.StopBudget = units.Duration{Duration: budget}
	receipts := make(chan loginEvent, 8)
	i := &Inhibitor{owner: ":1.42", maxDelay: time.Second, receipts: receipts, snapshotSequence: 10}
	t.Cleanup(i.Close)
	gate := &state.ShutdownGate{}
	events := i.admitEvents(ctx, c, false, gate, func() {})
	return i, gate, receipts, events, ctx
}

func deliverEpisode(t *testing.T, ctx context.Context, receipts chan<- loginEvent, events <-chan loginEvent, sequence uint64, preparing bool) {
	t.Helper()
	receipts <- loginEvent{signal: orderedSignal(dbus.Sequence(sequence), preparing), received: time.Now()}
	select {
	case <-events:
	case <-ctx.Done():
		t.Fatal("ordered domain event not consumed")
	}
}

func pipeEOF(t *testing.T, reader *os.File, within time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { var b [1]byte; _, err := reader.Read(b[:]); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	case <-time.After(within):
		t.Fatal("inhibitor FD outlived current episode deadline")
	}
}

func TestReturnedFDUsesCurrentEpisodeDuringBlockedAcquisition(t *testing.T) {
	for _, mode := range []string{"before-deadline", "after-deadline", "cancelled-request"} {
		t.Run(mode, func(t *testing.T) {
			for range 12 {
				i, gate, receipts, events, ctx := episodeFixture(t, 40*time.Millisecond)
				deliverEpisode(t, ctx, receipts, events, 11, true)
				deliverEpisode(t, ctx, receipts, events, 12, false)
				if !i.needsFD() {
					t.Fatal("cancelled A did not request independent FD reacquisition")
				}
				reader, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
				acquisition, cancel := context.WithCancel(ctx)
				blocked, finish := make(chan struct{}), make(chan struct{})
				installed := make(chan error, 1)
				go func() { close(blocked); <-finish; installed <- i.installFD(acquisition, writer) }()
				<-blocked
				// Receipt advances to B while A's false-path acquisition is blocked.
				deliverEpisode(t, ctx, receipts, events, 13, true)
				b := i.snapshot()
				if b.phase != episodePreparing || b.revision != 3 || !gate.Pending() {
					t.Fatal("wrong active B episode", b)
				}
				if mode == "after-deadline" {
					<-b.ctx.Done()
				}
				if mode == "cancelled-request" {
					cancel()
				}
				close(finish)
				err = <-installed
				if mode == "cancelled-request" {
					if !errors.Is(err, context.Canceled) {
						t.Fatal("stale acquisition context accepted", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if mode == "before-deadline" && time.Now().Before(b.deadline) {
					i.mu.Lock()
					held := i.fd != nil
					i.mu.Unlock()
					if !held {
						t.Fatal("FD discarded before active B deadline")
					}
				}
				pipeEOF(t, reader, 200*time.Millisecond)
				if !gate.Pending() {
					t.Fatal("FD timeout reopened admission")
				}
				cancel()
				i.Close()
			}
		})
	}
}

func TestLatestCancelledEpisodeRecoversAfterOlderWorkerRetires(t *testing.T) {
	for range 100 {
		i, gate, receipts, events, ctx := episodeFixture(t, time.Second)
		home := t.TempDir()
		deliverEpisode(t, ctx, receipts, events, 11, true)
		a := i.snapshot()
		if err := gate.Mark(home); err != nil {
			t.Fatal(err)
		}
		drainA := make(chan struct{})
		coordinator := episodeCoordinator{work: drainA, sweptRevision: a.revision}
		deliverEpisode(t, ctx, receipts, events, 12, false)
		cancelledA := i.snapshot()
		// B's complete true/false pair is received before A finishes draining.
		deliverEpisode(t, ctx, receipts, events, 13, true)
		deliverEpisode(t, ctx, receipts, events, 14, false)
		b := i.snapshot()
		if b.phase != episodeCancelled || b.revision != 3 {
			t.Fatal("lost cancelled B", b)
		}
		if coordinator.canRecover(b) || coordinator.canSweep(b) {
			t.Fatal("older native work was not retained")
		}
		close(drainA)
		if !coordinator.canRecover(b) || coordinator.canSweep(b) || coordinator.work != nil {
			t.Fatal("A did not retire into current B recovery")
		}
		if cleared, err := i.recoverEpisode(home, cancelledA, gate); err != nil || cleared {
			t.Fatal("stale A recovery accepted", cleared, err)
		}
		if cleared, err := i.recoverEpisode(home, b, gate); err != nil || !cleared || gate.Pending() {
			t.Fatal("cancelled unswept B remained permanently sealed", cleared, err)
		}
		// Even a verified B cancellation cannot reopen a later active C.
		deliverEpisode(t, ctx, receipts, events, 15, true)
		if cleared, err := i.recoverEpisode(home, b, gate); err != nil || cleared || !gate.Pending() {
			t.Fatal("false reopened newer true", cleared, err)
		}
		deliverEpisode(t, ctx, receipts, events, 16, false)
		if cleared, err := i.recoverEpisode(home, i.snapshot(), gate); err != nil || !cleared {
			t.Fatal(cleared, err)
		}
		i.Close()
	}
}
