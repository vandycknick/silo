package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nickvan/bentobox/net/bento-netd/internal/credentials"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	"github.com/nickvan/bentobox/net/bento-netd/internal/secrets"
)

const (
	httpsPort                      uint16 = 443
	certificateRefreshBeforeExpiry        = time.Hour
)

type HTTPSProxy struct {
	route             *router.Router
	ca                *certificateAuthority
	credentialManager *credentials.Manager
	upstreamRootCAs   *x509.CertPool
}

func NewHTTPSProxy(route *router.Router, certPath string, keyPath string, store secrets.Store) (*HTTPSProxy, error) {
	if route == nil || !route.HasHTTPS() {
		return nil, nil
	}
	ca, err := loadCertificateAuthority(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &HTTPSProxy{route: route, ca: ca, credentialManager: credentials.NewManager(store)}, nil
}

func (p *HTTPSProxy) ShouldHandle(port uint16) bool {
	return p != nil && p.route.HasHTTPS() && port == httpsPort
}

func (p *HTTPSProxy) Handle(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string) error {
	sni, replayed, err := peekClientHello(inbound)
	if err != nil || !p.route.MatchHTTPSHost(sni) {
		return p.proxyDirect(replayed, target)
	}
	return p.proxyHTTPS(ctx, replayed, flow, target, sni)
}

func (p *HTTPSProxy) proxyDirect(inbound net.Conn, target string) error {
	outbound, err := net.Dial("tcp", target)
	if err != nil {
		_ = inbound.Close()
		return err
	}
	proxyTCP(inbound, outbound)
	return nil
}

func (p *HTTPSProxy) proxyHTTPS(ctx context.Context, inbound net.Conn, flow hooks.Flow, target string, serverName string) error {
	serverTLS := tls.Server(inbound, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = serverName
			}
			return p.ca.CertificateFor(host)
		},
	})
	if err := serverTLS.HandshakeContext(ctx); err != nil {
		_ = serverTLS.Close()
		return err
	}

	upstreamTLS, err := tls.DialWithDialer(&net.Dialer{}, "tcp", target, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		RootCAs:    p.upstreamRootCAs,
		ServerName: serverName,
	})
	if err != nil {
		_ = serverTLS.Close()
		return err
	}
	return p.proxyHTTP(ctx, serverTLS, upstreamTLS, flow, serverName)
}

func (p *HTTPSProxy) proxyHTTP(ctx context.Context, client *tls.Conn, upstream *tls.Conn, flow hooks.Flow, serverName string) error {
	defer client.Close()
	defer upstream.Close()

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(clientReader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		host := req.Host
		if host == "" {
			host = serverName
		}
		policyHost := host
		if !p.route.MatchHTTPSHost(policyHost) {
			policyHost = serverName
		}
		decision, err := p.route.DecideHTTP(ctx, hooks.HTTPRequest{
			Flow:   flow,
			Host:   policyHost,
			Method: req.Method,
			Path:   req.URL.RequestURI(),
			Header: req.Header.Clone(),
		})
		if err != nil {
			_ = req.Body.Close()
			return err
		}
		if decision.Action == hooks.RouteDeny {
			_ = req.Body.Close()
			return writeDeny(client, decision.Reason)
		}
		if err := p.credentialManager.Apply(ctx, req, decision.Credential); err != nil {
			_ = req.Body.Close()
			return err
		}

		req.RequestURI = ""
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" {
			req.URL.Host = host
		}
		if err := req.Write(upstream); err != nil {
			_ = req.Body.Close()
			return err
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return err
		}
		closeAfterResponse := req.Close || resp.Close
		if err := resp.Write(client); err != nil {
			_ = resp.Body.Close()
			return err
		}
		_ = resp.Body.Close()
		if closeAfterResponse {
			return nil
		}
	}
}

func writeDeny(conn net.Conn, reason string) error {
	if reason == "" {
		reason = "request denied by network policy"
	}
	_, err := fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", len(reason), reason)
	return err
}

type replayConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func peekClientHello(conn net.Conn) (string, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var header [5]byte
	read := make([]byte, 0, 5+4096)
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", &replayConn{Conn: conn, reader: bytes.NewReader(read)}, err
	}
	read = append(read, header[:]...)
	if header[0] != 0x16 {
		return "", &replayConn{Conn: conn, reader: bytes.NewReader(read)}, fmt.Errorf("not a tls handshake record")
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length <= 0 || length > 65535 {
		return "", &replayConn{Conn: conn, reader: bytes.NewReader(read)}, fmt.Errorf("invalid tls record length %d", length)
	}
	body := make([]byte, length)
	if n, err := io.ReadFull(conn, body); err != nil {
		read = append(read, body[:n]...)
		return "", &replayConn{Conn: conn, reader: bytes.NewReader(read)}, err
	}
	read = append(read, body...)
	sni, err := parseClientHelloSNI(body)
	return sni, &replayConn{Conn: conn, reader: bytes.NewReader(read)}, err
}

func parseClientHelloSNI(body []byte) (string, error) {
	if len(body) < 4 || body[0] != 0x01 {
		return "", fmt.Errorf("not a tls client hello")
	}
	handshakeLength := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if handshakeLength+4 > len(body) {
		return "", fmt.Errorf("truncated tls client hello")
	}
	pos := 4
	if pos+34 > len(body) {
		return "", fmt.Errorf("truncated tls client hello random")
	}
	pos += 34
	if pos+1 > len(body) {
		return "", fmt.Errorf("truncated tls session id")
	}
	sessionIDLength := int(body[pos])
	pos++
	if pos+sessionIDLength+2 > len(body) {
		return "", fmt.Errorf("truncated tls session id")
	}
	pos += sessionIDLength
	cipherSuiteLength := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+cipherSuiteLength+1 > len(body) {
		return "", fmt.Errorf("truncated tls cipher suites")
	}
	pos += cipherSuiteLength
	compressionMethodsLength := int(body[pos])
	pos++
	if pos+compressionMethodsLength+2 > len(body) {
		return "", fmt.Errorf("truncated tls compression methods")
	}
	pos += compressionMethodsLength
	extensionsLength := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extensionsLength
	if end > len(body) {
		return "", fmt.Errorf("truncated tls extensions")
	}
	for pos+4 <= end {
		extensionType := binary.BigEndian.Uint16(body[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extensionLength > end {
			return "", fmt.Errorf("truncated tls extension")
		}
		if extensionType == 0x00 {
			return parseServerNameExtension(body[pos : pos+extensionLength])
		}
		pos += extensionLength
	}
	return "", fmt.Errorf("tls client hello has no sni")
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("truncated server name extension")
	}
	listLength := int(binary.BigEndian.Uint16(data[0:2]))
	pos := 2
	end := pos + listLength
	if end > len(data) {
		return "", fmt.Errorf("truncated server name list")
	}
	for pos+3 <= end {
		nameType := data[pos]
		nameLength := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLength > end {
			return "", fmt.Errorf("truncated server name")
		}
		if nameType == 0 {
			return strings.ToLower(string(data[pos : pos+nameLength])), nil
		}
		pos += nameLength
	}
	return "", fmt.Errorf("server name extension has no dns name")
}

type certificateAuthority struct {
	cert  *x509.Certificate
	key   crypto.Signer
	cache map[string]*tls.Certificate
	mu    sync.Mutex
}

func loadCertificateAuthority(certPath string, keyPath string) (*certificateAuthority, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls ca material: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("tls ca certificate is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse tls ca certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("tls ca certificate is not a CA")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls ca private key does not implement crypto.Signer")
	}
	return &certificateAuthority{cert: cert, key: signer, cache: make(map[string]*tls.Certificate)}, nil
}

func (ca *certificateAuthority) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" {
		host = "bento-intercept.invalid"
	}
	now := time.Now()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert := ca.cache[host]; ca.cachedCertificateUsable(cert, now) {
		return cert, nil
	}
	cert, err := ca.mint(host, now)
	if err != nil {
		return nil, err
	}
	ca.cache[host] = cert
	return cert, nil
}

func (ca *certificateAuthority) cachedCertificateUsable(cert *tls.Certificate, now time.Time) bool {
	if cert == nil {
		return false
	}
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return false
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return false
		}
		cert.Leaf = parsed
		leaf = parsed
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	if now.Add(certificateRefreshBeforeExpiry).Before(leaf.NotAfter) {
		return true
	}
	return leaf.NotAfter.Equal(ca.cert.NotAfter)
}

func (ca *certificateAuthority) mint(host string, now time.Time) (*tls.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              ca.leafNotAfter(now),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse minted tls certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: leafKey, Leaf: leaf}, nil
}

func (ca *certificateAuthority) leafNotAfter(now time.Time) time.Time {
	notAfter := now.Add(24 * time.Hour)
	if ca.cert.NotAfter.Before(notAfter) {
		return ca.cert.NotAfter
	}
	return notAfter
}
