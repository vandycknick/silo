package supervision

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vandycknick/silo/app/taild/internal/state"
)

type episodePhase uint8

const (
	episodeIdle episodePhase = iota
	episodeAcquiring
	episodePreparing
	episodeCancelled
	episodeRecovered
)

// There is one current episode, owned by Inhibitor.mu. Native work may belong
// to an older revision, but cannot change the current phase or FD deadline.
type shutdownEpisode struct {
	phase    episodePhase
	sequence dbus.Sequence
	revision uint64
	deadline time.Time
	ctx      context.Context
	cancel   context.CancelFunc
}

func (i *Inhibitor) snapshot() shutdownEpisode {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.current
}

func (i *Inhibitor) needsFD() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || i.fd != nil {
		return false
	}
	e := i.current
	return e.phase == episodeCancelled || e.phase == episodePreparing && time.Now().Before(e.deadline) && i.completedRevision != e.revision
}

func (i *Inhibitor) closeFDLocked() {
	if i.fd != nil {
		_ = i.fd.Close()
		i.fd = nil
	}
}

func (i *Inhibitor) applyDeadlineLocked() {
	if i.timer != nil {
		i.timer.Stop()
		i.timer = nil
	}
	e := i.current
	if e.phase != episodePreparing && e.phase != episodeAcquiring {
		return
	}
	if !time.Now().Before(e.deadline) || e.phase == episodePreparing && i.completedRevision == e.revision {
		i.closeFDLocked()
		return
	}
	i.timer = time.AfterFunc(time.Until(e.deadline), func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		// A previous timer must not touch a later episode's FD. Conversely,
		// this episode's timer closes whichever FD is currently installed.
		if i.current.phase == e.phase && i.current.revision == e.revision && i.current.deadline.Equal(e.deadline) {
			i.closeFDLocked()
		}
	})
}

// installFD is the completion boundary for an acquisition. D-Bus I/O never
// holds the owner mutex; every returned FD uses the state current at completion,
// not the state (or FD pointer) from when that request started.
func (i *Inhibitor) installFD(ctx context.Context, fd *os.File) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if ctx.Err() != nil || i.closed {
		_ = fd.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("inhibitor closed")
	}
	if i.fd != nil {
		_ = fd.Close()
		return nil
	}
	i.fd = fd
	i.applyDeadlineLocked()
	return nil
}

func (i *Inhibitor) transition(ctx context.Context, event loginEvent, preparing bool, budget time.Duration, gate *state.ShutdownGate) shutdownEpisode {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return i.current
	}
	if i.current.cancel != nil {
		i.current.cancel()
	}
	if preparing {
		deadline := event.received.Add(budget)
		operation, cancel := context.WithDeadline(ctx, deadline)
		i.current = shutdownEpisode{phase: episodePreparing, sequence: event.signalSequence(), revision: gate.Seal(), deadline: deadline, ctx: operation, cancel: cancel}
	} else {
		i.current.phase = episodeCancelled
		i.current.sequence = event.signalSequence()
		i.closeFDLocked()
	}
	i.applyDeadlineLocked()
	return i.current
}

func (e loginEvent) signalSequence() dbus.Sequence {
	if e.signal == nil {
		return dbus.NoSequence
	}
	return e.signal.Sequence
}

func (i *Inhibitor) completeStops(revision uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.completedRevision = revision
	if i.current.phase == episodePreparing && i.current.revision == revision {
		i.closeFDLocked()
	}
}

// Disk recovery cannot hold the FD mutex. The latch's compare-and-swap rejects
// an intervening true transition; the second state check rejects newer episodes.
func (i *Inhibitor) recoverEpisode(home string, expected shutdownEpisode, gate *state.ShutdownGate) (bool, error) {
	i.mu.Lock()
	stable := i.current.phase == episodeCancelled && i.current.revision == expected.revision && i.current.sequence == expected.sequence
	i.mu.Unlock()
	if !stable {
		return false, nil
	}
	cleared, err := gate.Recover(home, expected.revision)
	if err != nil || !cleared {
		return cleared, err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.current.phase != episodeCancelled || i.current.revision != expected.revision || i.current.sequence != expected.sequence {
		return false, nil
	}
	i.current.phase = episodeRecovered
	return true, nil
}

// One worker owns stop/drain work. Retiring it never selects its old revision
// for recovery: the next action is derived from the latest authoritative state.
type episodeCoordinator struct {
	work          <-chan struct{}
	sweptRevision uint64
}

func (c *episodeCoordinator) retire() {
	if c.work == nil {
		return
	}
	select {
	case <-c.work:
		c.work = nil
	default:
	}
}

func (c *episodeCoordinator) canSweep(e shutdownEpisode) bool {
	c.retire()
	return c.work == nil && e.phase == episodePreparing && e.revision != c.sweptRevision
}

func (c *episodeCoordinator) canRecover(e shutdownEpisode) bool {
	c.retire()
	return c.work == nil && e.phase == episodeCancelled
}
