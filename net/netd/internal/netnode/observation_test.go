package netnode

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestObservationChangesPreserveDisconnectAcrossReconnect(t *testing.T) {
	changes := newObservationChanges()
	changes.signal(true, true, false)
	query := changes.take()
	changes.signal(false, true, true)
	changes.signal(true, false, false)
	if changes.current(query.revision) {
		t.Fatal("response from before disconnect was accepted")
	}
	next := changes.take()
	if !next.connected || !next.full || !next.invalidate {
		t.Fatal("reconnection lost its invalidation or full resynchronization", next)
	}
	if !changes.current(next.revision) {
		t.Fatal("fresh reconnect observation was rejected")
	}
	changes.signal(true, true, false)
	changes.signal(true, false, false)
	if !changes.take().full {
		t.Fatal("self notification erased pending peer removal")
	}
}

func TestSelfObservationPreservesDNSUntilIdentityExpires(t *testing.T) {
	n := newTestNode(t, Options{Identity: &ExpectedIdentity{Owner: "user:7", Tailnet: "fixture", Suffix: "tail.test"}, Declaration: policy.TailscaleDecl{Hostname: "dev"}})
	expiry := time.Now().Add(time.Hour)
	status := &ipnstate.Status{BackendState: "Running", CurrentTailnet: &ipnstate.TailnetStatus{Name: "fixture", MagicDNSSuffix: "tail.test"},
		Self: &ipnstate.PeerStatus{ID: "self", UserID: 7, DNSName: "dev.tail.test.", KeyExpiry: &expiry},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): {DNSName: "peer.tail.test."}}}
	n.observe(status)
	ip := netip.MustParseAddr("10.0.0.9")
	n.provenance[ip] = time.Now().Add(time.Minute)
	n.observeStatus(status, false)
	if name, classified := n.DNSName("peer"); name != "peer.tail.test" || !classified {
		t.Fatal("self observation lost peer classification", name, classified)
	}
	if _, ok := n.provenance[ip]; !ok {
		t.Fatal("unchanged self observation invalidated a live DNS answer")
	}
	expiry = time.Now().Add(-time.Second)
	n.observeStatus(status, false)
	if _, classified := n.DNSName("peer"); !classified || n.running {
		t.Fatal("expiry lost tailnet classification or left traffic enabled")
	}
	if len(n.provenance) != 0 || !n.IsDestination(ip) {
		t.Fatal("expiry must quarantine cached addresses, not leak them to host routing")
	}
}

func TestSnapshotFreshnessAndTransitionsAreNotSuppressed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tailscale")
	n := newTestNode(t, Options{Dir: dir, VMID: "vm", RunID: "run"})
	status := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "self", DNSName: "dev.tail.test."}}
	read := func() Snapshot {
		t.Helper()
		data, err := os.ReadFile(dir + ".status.json")
		if err != nil {
			t.Fatal(err)
		}
		var snapshot Snapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	n.observe(status)
	first := read()
	n.observeStatus(status, false)
	if !read().ObservedAt.Equal(first.ObservedAt) {
		t.Fatal("unchanged notification unnecessarily rewrote the freshness lease")
	}
	// Advance the publication deadline without sleeping or changing wall time.
	n.published.ObservedAt = first.ObservedAt.Add(-2 * observationInterval)
	n.observeStatus(status, false)
	if !read().ObservedAt.After(first.ObservedAt) {
		t.Fatal("fresh backend evidence did not renew the observation lease")
	}
	n.observe(nil)
	if snapshot := read(); snapshot.State == "ready" || snapshot.NodeID != "" {
		t.Fatal("disconnect was suppressed by publication throttling", snapshot)
	}
}
