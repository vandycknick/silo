package netnode

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

const observationInterval = 15 * time.Second

// Notifications are invalidations, not deltas applied to a cached netmap. A
// bounded mailbox merges bursts while preserving changes during a status read.
type observationChanges struct {
	mu               sync.Mutex
	wake             chan struct{}
	revision         uint64
	connected        bool
	full, invalidate bool
}

type observationChange struct {
	revision                    uint64
	connected, full, invalidate bool
}

func newObservationChanges() *observationChanges {
	return &observationChanges{wake: make(chan struct{}, 1)}
}

func (c *observationChanges) signal(connected, full, invalidate bool) {
	c.mu.Lock()
	c.revision++
	c.connected = connected
	c.full = c.full || full
	c.invalidate = c.invalidate || invalidate
	select {
	case c.wake <- struct{}{}:
	default:
	}
	c.mu.Unlock()
}

func (c *observationChanges) take() observationChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.wake:
	default:
	}
	v := observationChange{c.revision, c.connected, c.full, c.invalidate}
	c.full, c.invalidate = false, false
	return v
}

func (c *observationChanges) current(revision uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected && c.revision == revision
}

func notificationChange(v ipn.Notify) (relevant, full, invalidate bool) {
	full = v.InitialStatus != nil || v.NetMap != nil || len(v.PeersChanged) != 0 || len(v.PeersRemoved) != 0 || len(v.PeerChangedPatch) != 0
	invalidate = v.ErrMessage != nil || (v.State != nil && *v.State != ipn.Running)
	relevant = full || invalidate || v.SelfChange != nil || v.State != nil || v.BrowseToURL != nil || v.LoginFinished != nil
	return
}

func (n *Node) watch(ctx context.Context, client *local.Client, changes *observationChanges) {
	for ctx.Err() == nil {
		// Runtime NetMap notifications are legacy and absent on Linux. Explicit
		// peer changes include removals and promoted per-field patches.
		watcher, err := client.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyInitialStatus|ipn.NotifyPeerChanges|ipn.NotifyNoNetMap)
		if err == nil {
			first := true
			for {
				v, err := watcher.Next()
				if err != nil {
					break
				}
				relevant, full, invalidate := notificationChange(v)
				if first || relevant {
					changes.signal(true, first || full, invalidate)
				}
				first = false
			}
			_ = watcher.Close()
		}
		changes.signal(false, true, true)
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type statusObservation struct {
	status *ipnstate.Status
	at     time.Time
}

func offerObservation(actions chan statusObservation, observation statusObservation) {
	select {
	case actions <- observation:
		return
	default:
	}
	select {
	case <-actions:
	default:
	}
	actions <- observation // Sole producer; the consumer can only free capacity.
}

// Enrollment and management API calls can take seconds. They must not block
// local observation, disconnect invalidation or the snapshot freshness lease.
func (n *Node) runActions(ctx context.Context, client *local.Client, actions <-chan statusObservation) {
	n.authenticate(ctx, client, nil)
	for {
		select {
		case <-ctx.Done():
			return
		case observation := <-actions:
			if time.Since(observation.at) >= observationInterval {
				continue
			}
			n.authenticate(ctx, client, observation.status)
			if time.Since(observation.at) < observationInterval {
				n.maintain(ctx, observation.status)
			}
		}
	}
}

func (n *Node) runObservations(ctx context.Context, client *local.Client, changes *observationChanges, actions chan statusObservation) {
	ticker := time.NewTicker(observationInterval)
	defer ticker.Stop()
	var peers *ipnstate.Status
	up := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-changes.wake:
		}
		change := changes.take()
		if change.invalidate || !change.connected {
			peers = nil
			n.observe(nil)
			offerObservation(actions, statusObservation{at: time.Now()})
		}
		if !change.connected {
			continue
		}
		full := change.full || peers == nil
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		var status *ipnstate.Status
		var err error
		if full {
			status, err = client.Status(bounded)
		} else {
			status, err = client.StatusWithoutPeers(bounded)
			// Never attach a previous identity's peer view to a new self state.
			if err == nil && !sameStatusIdentity(peers, status) {
				full = true
				status, err = client.Status(bounded)
			}
		}
		if err == nil && status != nil && status.BackendState == "Running" && !up {
			// Up also clears persisted Serve configuration once. Preserve that
			// startup behavior, consume its result, and never repeat it at idle.
			status, err = n.server.Up(bounded)
			full = true
			if err == nil {
				var dial func(context.Context, netip.AddrPort) (net.Conn, error)
				dial, err = strictDialer(n.server)
				if err == nil {
					n.mu.Lock()
					n.dial = dial
					n.mu.Unlock()
					up = true
				}
			}
		}
		cancel()
		if !changes.current(change.revision) {
			// The pending invalidation will trigger another read. Do not extend
			// freshness or publish a response superseded during this query.
			peers = nil
			continue
		}
		if err != nil || status == nil {
			peers = nil
			n.observe(nil)
			offerObservation(actions, statusObservation{at: time.Now()})
			continue
		}
		if full {
			peers = status
		} else {
			status.Peer = peers.Peer
		}
		observation := statusObservation{status, time.Now()}
		n.observeStatus(status, full)
		offerObservation(actions, observation)
	}
}

func sameStatusIdentity(a, b *ipnstate.Status) bool {
	if a == nil || b == nil || a.BackendState != b.BackendState {
		return false
	}
	if (a.Self == nil) != (b.Self == nil) || (a.CurrentTailnet == nil) != (b.CurrentTailnet == nil) {
		return false
	}
	if a.Self != nil && (a.Self.ID != b.Self.ID || a.Self.DNSName != b.Self.DNSName || !slices.Equal(a.Self.TailscaleIPs, b.Self.TailscaleIPs)) {
		return false
	}
	return a.CurrentTailnet == nil || (a.CurrentTailnet.Name == b.CurrentTailnet.Name && a.CurrentTailnet.MagicDNSSuffix == b.CurrentTailnet.MagicDNSSuffix)
}

func (n *Node) observe(s *ipnstate.Status) { n.observeStatus(s, true) }

func (n *Node) observeStatus(s *ipnstate.Status, peersChanged bool) {
	n.observationMu.Lock()
	defer n.observationMu.Unlock()
	n.mu.Lock()
	running := s != nil && s.BackendState == "Running" && n.options.Identity.verify(s, n.options.Declaration.Hostname) == nil
	suffix := ""
	if s != nil && s.CurrentTailnet != nil {
		suffix = canonical(s.CurrentTailnet.MagicDNSSuffix)
	}
	fingerprint := n.fingerprint
	if peersChanged || running != n.running || suffix != n.suffix {
		parts := []string{fmt.Sprint(running), suffix}
		if s != nil {
			if s.Self != nil {
				parts = append(parts, fmt.Sprint(s.Self.ID, s.Self.TailscaleIPs))
			}
			for _, p := range s.Peer {
				if p != nil && p.DNSName != "" {
					parts = append(parts, fmt.Sprint(canonical(p.DNSName), p.TailscaleIPs, p.Online))
				}
			}
		}
		sort.Strings(parts)
		fingerprint = strings.Join(parts, "|")
	}
	if fingerprint != n.fingerprint {
		short, full := make(map[string]string), make(map[string]struct{})
		if s != nil {
			for _, p := range s.Peer {
				if p == nil {
					continue
				}
				name := canonical(p.DNSName)
				if name == "" {
					continue
				}
				label, _, _ := strings.Cut(name, ".")
				if len(full) < 4096 {
					full[name] = struct{}{}
				}
				if _, ok := short[label]; ok {
					short[label] = ""
				} else if len(short) < 4096 {
					short[label] = name
				}
			}
		}
		n.pruneAddresses(time.Now())
		for ip, until := range n.provenance {
			if until.After(n.quarantined[ip]) {
				n.quarantined[ip] = until
			}
		}
		clear(n.provenance)
		n.fingerprint, n.short, n.fullNames = fingerprint, short, full
		for name := range short {
			if _, known := n.knownShort[name]; !known {
				if len(n.knownShort) < 4096 {
					n.knownShort[name] = struct{}{}
				} else {
					n.classificationFull = true
				}
			}
		}
		if len(short) == 4096 || len(full) == 4096 {
			n.classificationFull = true
		}
	}
	if suffix != "" {
		if _, known := n.knownSuffixes[suffix]; !known {
			if len(n.knownSuffixes) < 32 {
				n.knownSuffixes[suffix] = struct{}{}
			} else {
				n.classificationFull = true
			}
		}
	}
	n.suffix, n.running = suffix, running
	n.observeCertificateIdentityLocked(s)
	snapshot := n.snapshot(s)
	n.mu.Unlock()
	n.publishObservation(snapshot)
}
