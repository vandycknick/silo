package state

import (
	"sync"
	"sync/atomic"
)

// ShutdownGate is the process-local authority when durable storage fails. Odd
// revisions are sealed. Each new shutdown advances the revision so old recovery
// cannot reopen admission after a newer authenticated transition.
type ShutdownGate struct {
	revision atomic.Uint64
	diskMu   sync.Mutex
}

func (g *ShutdownGate) Pending() bool    { return g != nil && g.revision.Load()&1 != 0 }
func (g *ShutdownGate) Revision() uint64 { return g.revision.Load() }
func (g *ShutdownGate) Seal() uint64 {
	for {
		old := g.revision.Load()
		next := old + 1
		if old&1 != 0 {
			next++
		}
		if g.revision.CompareAndSwap(old, next) {
			return next
		}
	}
}
func (g *ShutdownGate) Mark(home string) error {
	g.diskMu.Lock()
	defer g.diskMu.Unlock()
	if !g.Pending() {
		return nil
	}
	return MarkShutdown(home)
}

// Recover is called only after verified non-shutdown observation and actual
// native/job/helper drain. Disk operations serialize, but Seal never waits for
// them. A racing new Seal prevents the final compare-and-swap from reopening.
func (g *ShutdownGate) Recover(home string, revision uint64) (bool, error) {
	g.diskMu.Lock()
	defer g.diskMu.Unlock()
	if g.revision.Load() != revision {
		return false, nil
	}
	if err := ClearShutdown(home); err != nil {
		return false, err
	}
	next := revision + 1
	if revision&1 == 0 {
		next++
	}
	return g.revision.CompareAndSwap(revision, next), nil
}
