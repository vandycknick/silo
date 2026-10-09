package forwarder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func caSource(t *testing.T, certificatePath, keyPath string) *credentials.Static {
	t.Helper()
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return credentials.NewStatic(map[string][]byte{
		"silo.tls_ca.certificate": certificate,
		"silo.tls_ca.private_key": key,
	}, nil)
}

func TestTLSCAPolicyConstraintsAndValidity(t *testing.T) {
	for _, variant := range []string{"leaf", "usage", "expired", "future", "absent-usage"} {
		t.Run(variant, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(6), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: variant != "leaf", BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			switch variant {
			case "usage":
				template.KeyUsage = x509.KeyUsageDigitalSignature
			case "expired":
				template.NotAfter = time.Now().Add(-time.Minute)
			case "future":
				template.NotBefore = time.Now().Add(time.Minute)
			case "absent-usage":
				template.KeyUsage = 0
			}
			cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			private, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			source := credentials.NewStatic(map[string][]byte{
				"silo.tls_ca.certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
				"silo.tls_ca.private_key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
			}, nil)
			_, err = LoadCertificateAuthority(source)
			if (err == nil) != (variant == "absent-usage") {
				t.Fatalf("CA acceptance mismatch: %v", err)
			}
			// Invalid or absent infrastructure is irrelevant to non-terminating policy.
			proxy, err := NewHTTPSProxy(router.New(policy.Default(), nil), source, nil)
			if err != nil || proxy != nil {
				t.Fatalf("non-terminating policy read CA: %v", err)
			}
		})
	}
}

func TestCertificateAuthoritySourceFailsClosed(t *testing.T) {
	certificatePath, keyPath, _ := writeTestCA(t, t.TempDir())
	source := caSource(t, certificatePath, keyPath)
	certificate, _ := source.Lookup("silo.tls_ca.certificate")
	key, _ := source.Lookup("silo.tls_ca.private_key")
	_, otherKeyPath, _ := writeTestCA(t, t.TempDir())
	otherKey, err := os.ReadFile(otherKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range []map[string][]byte{
		nil,
		{"silo.tls_ca.certificate": certificate},
		{"silo.tls_ca.private_key": key},
		{"silo.tls_ca.certificate": certificate, "silo.tls_ca.private_key": otherKey},
		{"silo.tls_ca.certificate": []byte("malformed"), "silo.tls_ca.private_key": key},
		{"silo.tls_ca.certificate": append(append([]byte{}, certificate...), []byte("garbage")...), "silo.tls_ca.private_key": key},
		{"silo.tls_ca.certificate": append(append([]byte{}, certificate...), certificate...), "silo.tls_ca.private_key": key},
		{"silo.tls_ca.certificate": append([]byte("garbage"), certificate...), "silo.tls_ca.private_key": key},
		{"silo.tls_ca.certificate": certificate, "silo.tls_ca.private_key": append(append([]byte{}, key...), []byte("garbage")...)},
		{"silo.tls_ca.certificate": certificate, "silo.tls_ca.private_key": append(append([]byte{}, key...), key...)},
	} {
		if _, err := LoadCertificateAuthority(credentials.NewStatic(values, nil)); err == nil {
			t.Fatal("accepted absent, partial, malformed or mismatched CA")
		}
	}
	ca, err := LoadCertificateAuthority(source)
	if err != nil {
		t.Fatal(err)
	}
	// Material is captured once, before request handling. Removing its input
	// files cannot change the signer or cause subsequent filesystem reads.
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.CertificateFor("source.example.test"); err != nil {
		t.Fatal(err)
	}
}
