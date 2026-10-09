package netnode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

// localForwardTLSCallback follows localForwardTLS's real-socket, trusted test
// certificate setup. The callback exercises TLS handshake ownership and timing,
// not certificate issuance: no Tailscale certificate API or issuer is replaced.
func localForwardTLSCallback(t *testing.T, n *Node, callback func(*tls.ClientHelloInfo, *tls.Certificate) (*tls.Certificate, error)) (*http.Client, func()) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &admissionListener{Listener: raw, node: n, forward: policy.Forward{
		Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS,
	}}
	cleanup := n.serveForwardTLS(n.ctx, listener, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return callback(hello, &cert)
		},
	})
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", raw.Addr().String())
		},
	}
	// Do not let a client-side handshake timeout hide the production server's
	// deadline. This still bounds an unexpectedly stalled test request.
	client := &http.Client{Transport: transport, Timeout: 65 * time.Second}
	return client, func() {
		transport.CloseIdleConnections()
		cleanup()
	}
}

func TestForwardTLSCertificateDelayBeyondOldHeaderDeadline(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.URL.Path != "/after-certificate" {
			t.Errorf("unexpected backend request: host=%q path=%q", r.Host, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "certificate-delay-backend")
	}))
	defer backend.Close()
	guest := &forwardGuest{address: strings.TrimPrefix(backend.URL, "http://")}
	n, events := forwardNode(t, guest)
	elapsed := make(chan time.Duration, 1)
	client, cleanup := localForwardTLSCallback(t, n, func(hello *tls.ClientHelloInfo, cert *tls.Certificate) (*tls.Certificate, error) {
		if hello.ServerName != "example.com" {
			t.Errorf("unexpected SNI: %q", hello.ServerName)
		}
		started := time.Now()
		timer := time.NewTimer(31 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			elapsed <- time.Since(started)
			return cert, nil
		case <-hello.Context().Done():
			return nil, hello.Context().Err()
		}
	})
	defer cleanup()

	res, err := client.Get("https://example.com/after-certificate")
	if err != nil {
		t.Fatalf("production TLS forward rejected delayed certificate: %v", err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != http.StatusCreated || string(body) != "certificate-delay-backend" {
		t.Fatalf("backend response: status=%d body=%q err=%v", res.StatusCode, body, err)
	}
	if delay := <-elapsed; delay <= 30*time.Second || delay >= 75*time.Second {
		t.Fatalf("certificate callback delay %s is outside regression window", delay)
	}
	if guest.calls.Load() != 1 || guest.port.Load() != 8080 {
		t.Fatalf("guest calls=%d port=%d", guest.calls.Load(), guest.port.Load())
	}
	cleanup()
	select {
	case event := <-events:
		if event.Forward != "web" || event.Protocol != "https" || event.Decision != "allow" || event.Reason != "connected" {
			t.Fatalf("terminal event: %+v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing terminal event after delayed handshake")
	}
}

func TestForwardTLSCertificateCallbackCancellation(t *testing.T) {
	for _, mode := range []string{"node_context", "force_close"} {
		t.Run(mode, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				io.WriteString(w, "must not be reached")
			}))
			defer backend.Close()
			guest := &forwardGuest{address: strings.TrimPrefix(backend.URL, "http://")}
			n, events := forwardNode(t, guest)
			entered := make(chan struct{})
			exited := make(chan error, 1)
			client, cleanup := localForwardTLSCallback(t, n, func(hello *tls.ClientHelloInfo, _ *tls.Certificate) (*tls.Certificate, error) {
				close(entered)
				<-hello.Context().Done()
				err := hello.Context().Err()
				exited <- err
				return nil, err
			})
			defer cleanup()
			requestDone := make(chan error, 1)
			go func() {
				res, err := client.Get("https://example.com/")
				if res != nil {
					res.Body.Close()
				}
				requestDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("certificate callback was not entered")
			}
			if guest.calls.Load() != 0 || n.options.Flows.(*forwardFlows).active.Load() != 1 {
				t.Fatal("handshake must hold admission without contacting guest")
			}

			if mode == "node_context" {
				n.cancel()
			}
			joined := make(chan struct{})
			join := func() {
				cleanup()
				n.relays.Wait()
				close(joined)
			}
			if mode == "force_close" {
				go join()
			}
			select {
			case err := <-exited:
				if err != context.Canceled {
					t.Fatalf("callback cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("certificate callback did not observe cancellation")
			}
			if mode == "node_context" {
				// Observe root cancellation before cleanup can independently
				// cancel the HTTP server's BaseContext.
				go join()
			}
			select {
			case <-joined:
			case <-time.After(5 * time.Second):
				t.Fatal("force-close did not join the TLS server and admission owners")
			}
			select {
			case err := <-requestDone:
				if err == nil {
					t.Fatal("canceled handshake unexpectedly returned an HTTP response")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled TLS client did not return")
			}
			if guest.calls.Load() != 0 || n.options.Flows.(*forwardFlows).active.Load() != 0 || len(n.slots) != 0 {
				t.Fatal("canceled callback contacted guest or leaked admission")
			}
			select {
			case event := <-events:
				if event.Forward != "web" || event.Decision != "deny" || event.Reason != "tls_handshake_failed" {
					t.Fatalf("terminal cancellation event: %+v", event)
				}
			default:
				t.Fatal("TLS server joined before terminal audit")
			}
			select {
			case event := <-events:
				t.Fatalf("duplicate terminal event: %+v", event)
			default:
			}
		})
	}
}
