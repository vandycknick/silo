package netnode

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
)

func certificateLifecycleNode(t *testing.T) *Node {
	t.Helper()
	n := newTestNode(t, Options{AttachmentScope: policy.AttachmentScopeDedicatedVM, Forwards: []policy.Forward{
		{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS},
		{Name: "admin", ListenPort: 9443, GuestPort: 9000, Protocol: policy.ForwardProtocolHTTPS},
	}})
	n.ctx, n.cancel = context.WithCancel(context.Background())
	t.Cleanup(n.cancel)
	return n
}

func certificateLifecycleStatus() *ipnstate.Status {
	return &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "node-one", DNSName: "web.tail.ts.net."}, CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSEnabled: true}, CertDomains: []string{"web.tail.ts.net"}}
}

func TestForwardCertificateIdentityEpoch(t *testing.T) {
	for _, change := range []struct {
		name     string
		apply    func(*ipnstate.Status)
		eligible bool
	}{
		{"disconnect", func(s *ipnstate.Status) { s.BackendState = "NeedsLogin" }, false},
		{"expired", func(s *ipnstate.Status) { s.Self.Expired = true }, false},
		{"magicdns_disabled", func(s *ipnstate.Status) { s.CurrentTailnet.MagicDNSEnabled = false }, false},
		{"domain_removed", func(s *ipnstate.Status) { s.CertDomains = nil }, false},
		{"node_replaced_same_dns", func(s *ipnstate.Status) { s.Self.ID = "node-two" }, true},
		{"dns_changed", func(s *ipnstate.Status) {
			s.Self.DNSName = "new.tail.ts.net"
			s.CertDomains = []string{"new.tail.ts.net"}
		}, true},
	} {
		t.Run(change.name, func(t *testing.T) {
			n := certificateLifecycleNode(t)
			s := certificateLifecycleStatus()
			n.observe(s)
			original, identity, err := n.certificateState()
			if err != nil {
				t.Fatal(err)
			}
			// Frequent peer/status observations must not cancel or restart provisioning.
			same := certificateLifecycleStatus()
			same.Self.DNSName = "WEB.TAIL.TS.NET."
			n.observe(same)
			unchanged, current, err := n.certificateState()
			if err != nil || current != identity || unchanged != original || original.Err() != nil {
				t.Fatalf("unchanged identity interrupted acquisition: %v", err)
			}
			change.apply(s)
			n.observe(s)
			if !errors.Is(original.Err(), context.Canceled) {
				t.Fatal("old identity still permits certificate work")
			}
			next, _, err := n.certificateState()
			if change.eligible {
				if err != nil || next == original || next.Err() != nil {
					t.Fatalf("replacement identity unavailable: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("ineligible identity permits certificate work")
				}
				n.observe(certificateLifecycleStatus())
				next, _, err = n.certificateState()
				if err != nil || next == original || next.Err() != nil {
					t.Fatalf("reconnected identity unavailable: %v", err)
				}
			}
			n.cancel()
			if _, _, err := n.certificateState(); !errors.Is(err, context.Canceled) {
				t.Fatalf("node shutdown still permits acquisition: %v", err)
			}
		})
	}
}

func TestForwardCertificateTCPDoesNotProvision(t *testing.T) {
	n := newTestNode(t, Options{AttachmentScope: policy.AttachmentScopeDedicatedVM, Forwards: []policy.Forward{{Name: "raw", ListenPort: 443, GuestPort: 8443, Protocol: policy.ForwardProtocolTCP}}})
	n.ctx, n.cancel = context.WithCancel(context.Background())
	defer n.cancel()
	n.observe(certificateLifecycleStatus())
	if _, _, err := n.certificateState(); err == nil {
		t.Fatal("raw TLS passthrough acquired a certificate identity")
	}
	n.startCertificateMaintenance(n.ctx)()
}

func TestForwardCertificateWaitBudgetAndNodeCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "node_shutdown", "identity_loss"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := certificateLifecycleNode(t)
				n.observe(certificateLifecycleStatus())
				// Occupy the production semaphore, as an in-progress background request
				// would. No certificate API or ACME issuer is substituted.
				n.certSlot <- struct{}{}
				result := make(chan error, 1)
				go func() {
					_, err := n.forwardCertificate(&tls.ClientHelloInfo{ServerName: "web.tail.ts.net"})
					result <- err
				}()
				synctest.Wait()
				time.Sleep(31 * time.Second)
				select {
				case err := <-result:
					t.Fatalf("certificate wait ended at the old deadline: %v", err)
				default:
				}
				want := context.Canceled
				switch mode {
				case "deadline":
					time.Sleep(30 * time.Second)
					want = context.DeadlineExceeded
				case "node_shutdown":
					n.cancel()
				case "identity_loss":
					n.observe(nil)
				}
				synctest.Wait()
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("certificate wait error=%v, want %v", err, want)
					}
				default:
					t.Fatal("certificate wait ignored cancellation/deadline")
				}
				if len(n.certSlot) != 1 {
					t.Fatal("canceled waiter released another request's acquisition slot")
				}
			})
		})
	}
}

func TestForwardCertificateMaintenanceShutdownJoinsWaitingAcquisition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := certificateLifecycleNode(t)
		n.observe(certificateLifecycleStatus())
		n.certSlot <- struct{}{}
		stop := n.startCertificateMaintenance(n.ctx)
		synctest.Wait()
		joined := make(chan struct{})
		go func() { stop(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
		default:
			t.Fatal("maintenance shutdown did not join certificate work")
		}
		if n.ctx.Err() != nil {
			t.Fatal("maintenance cleanup canceled its parent node")
		}
		if len(n.certSlot) != 1 {
			t.Fatal("maintenance cleanup released another request's acquisition slot")
		}
	})
}
