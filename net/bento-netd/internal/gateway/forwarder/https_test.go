package forwarder

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	"github.com/nickvan/bentobox/net/bento-netd/internal/policy"
)

func TestHTTPSProxyInterceptsAllowedRequest(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, caPool := writeTestCA(t, dir)
	policyPath := filepath.Join(dir, "policy.hcl")
	if err := os.WriteFile(policyPath, []byte(`
endpoint "https" "local" {
  hosts = ["localhost"]
}

rule "local-reads" {
  endpoint = https.local
  condition = "http.method == 'GET'"
  verdict = "allow"
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFile returned error: %v", err)
	}
	route := router.New(hooks.NewPolicyHook(compiled), nil)
	proxy, err := NewHTTPSProxy(route, caCert, caKey, nil)
	if err != nil {
		t.Fatalf("NewHTTPSProxy returned error: %v", err)
	}
	proxy.upstreamRootCAs = caPool

	requestCh := make(chan *http.Request, 1)
	upstreamAddress, stopUpstream := startTLSUpstream(t, caCert, caKey, requestCh)
	defer stopUpstream()

	clientConn, proxyConn := net.Pipe()
	flow := hooks.Flow{
		Protocol:   "tcp",
		SourceIP:   net.ParseIP("192.168.127.2"),
		SourcePort: 53100,
		DestIP:     net.ParseIP("127.0.0.1"),
		DestPort:   443,
	}
	done := make(chan error, 1)
	go func() {
		done <- proxy.Handle(context.Background(), proxyConn, flow, upstreamAddress)
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    caPool,
		ServerName: "localhost",
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.Write(clientTLS); err != nil {
		t.Fatalf("write client request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientTLS), request)
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	_ = clientTLS.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxy returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy")
	}
	select {
	case upstreamRequest := <-requestCh:
		if upstreamRequest.URL.Path != "/private" {
			t.Fatalf("expected upstream request path /private, got %q", upstreamRequest.URL.Path)
		}
	default:
		t.Fatal("upstream did not receive request")
	}
}

func TestCertificateForReusesFreshCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCA(t, dir)
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cached, err := ca.mint("localhost", time.Now())
	if err != nil {
		t.Fatalf("mint returned error: %v", err)
	}
	cached.Leaf = nil
	ca.cache["localhost"] = cached

	returned, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if returned != cached {
		t.Fatal("expected fresh cached certificate to be reused")
	}
	if returned.Leaf == nil {
		t.Fatal("expected cached certificate leaf to be populated")
	}
}

func TestCertificateForRefreshesNearExpiryCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCA(t, dir)
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	nearExpiry, err := ca.mint("localhost", time.Now().Add(-23*time.Hour-30*time.Minute))
	if err != nil {
		t.Fatalf("mint near-expiry certificate: %v", err)
	}
	ca.cache["localhost"] = nearExpiry

	refreshed, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if refreshed == nearExpiry {
		t.Fatal("expected near-expiry certificate to be refreshed")
	}
	if ca.cache["localhost"] != refreshed {
		t.Fatal("expected refreshed certificate to replace cache entry")
	}
	if !refreshed.Leaf.NotAfter.After(nearExpiry.Leaf.NotAfter) {
		t.Fatalf("expected refreshed certificate to expire later than cached certificate, old=%s new=%s", nearExpiry.Leaf.NotAfter, refreshed.Leaf.NotAfter)
	}
}

func TestCertificateForReusesCALimitedCachedCertificate(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _ := writeTestCAExpiringAt(t, dir, time.Now().Add(30*time.Minute))
	ca, err := loadCertificateAuthority(caCert, caKey)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cached, err := ca.mint("localhost", time.Now())
	if err != nil {
		t.Fatalf("mint returned error: %v", err)
	}
	if !cached.Leaf.NotAfter.Equal(ca.cert.NotAfter) {
		t.Fatalf("expected cached certificate expiry to be limited by CA, leaf=%s ca=%s", cached.Leaf.NotAfter, ca.cert.NotAfter)
	}
	ca.cache["localhost"] = cached

	returned, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	if returned != cached {
		t.Fatal("expected CA-limited cached certificate to be reused")
	}
}

func startTLSUpstream(t *testing.T, caCertPath string, caKeyPath string, requestCh chan<- *http.Request) (string, func()) {
	t.Helper()
	ca, err := loadCertificateAuthority(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("loadCertificateAuthority returned error: %v", err)
	}
	cert, err := ca.CertificateFor("localhost")
	if err != nil {
		t.Fatalf("CertificateFor returned error: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		requestCh <- request
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func writeTestCA(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	return writeTestCAExpiringAt(t, dir, time.Now().Add(24*time.Hour))
}

func writeTestCAExpiringAt(t *testing.T, dir string, notAfter time.Time) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "BentoBox Test CA",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to append test CA")
	}
	return certPath, keyPath, pool
}
