package testfixture

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Registry is a real read-only local OCI distribution endpoint. Native SDK
// clients verify the manifests, config, compressed layer and diff-ID, then
// materialize an ext4 image with the existing OCI implementation. It is not an
// SDK substitute. Its ephemeral TLS certificate is trusted only by this test.
type Registry struct {
	Reference      string
	Requests       atomic.Int64
	BeforeManifest func()
}

func OCIRegistry(t *testing.T, rootfs string) *Registry {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if rootfs == "" {
		for _, dir := range []string{"etc", "bin", "home", "root", "tmp", "var", "var/lib", "proc", "sys", "dev", "run"} {
			if e := tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0755}); e != nil {
				t.Fatal(e)
			}
		}
		for name, data := range map[string]string{"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "etc/group": "root:x:0:\n"} {
			if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); e != nil {
				t.Fatal(e)
			}
			if _, e := io.WriteString(tw, data); e != nil {
				t.Fatal(e)
			}
		}
	} else {
		e := filepath.WalkDir(rootfs, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == rootfs {
				return nil
			}
			info, e := entry.Info()
			if e != nil {
				return e
			}
			link := ""
			if info.Mode()&os.ModeSymlink != 0 {
				link, e = os.Readlink(path)
				if e != nil {
					return e
				}
			}
			header, e := tar.FileInfoHeader(info, link)
			if e != nil {
				return e
			}
			name, e := filepath.Rel(rootfs, path)
			if e != nil {
				return e
			}
			header.Name = filepath.ToSlash(name)
			if e = tw.WriteHeader(header); e != nil {
				return e
			}
			if info.Mode().IsRegular() {
				f, e := os.Open(path)
				if e != nil {
					return e
				}
				_, e = io.Copy(tw, f)
				ce := f.Close()
				if e != nil {
					return e
				}
				return ce
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	if _, e := gz.Write(archive.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	digest := func(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
	config, e := json.Marshal(map[string]any{"architecture": runtime.GOARCH, "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{digest(archive.Bytes())}}, "config": map[string]any{}})
	if e != nil {
		t.Fatal(e)
	}
	descriptor := func(kind string, b []byte) map[string]any {
		return map[string]any{"mediaType": kind, "digest": digest(b), "size": len(b)}
	}
	const media = "application/vnd.oci.image.manifest.v1+json"
	manifest, e := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": media, "config": descriptor("application/vnd.oci.image.config.v1+json", config), "layers": []any{descriptor("application/vnd.oci.image.layer.v1.tar+gzip", layer.Bytes())}})
	if e != nil {
		t.Fatal(e)
	}
	r := &Registry{}
	blobs := map[string][]byte{digest(config): config, digest(layer.Bytes()): layer.Bytes()}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Requests.Add(1)
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		if req.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(req.URL.Path, "/v2/fixture/rootfs/manifests/") {
			if r.BeforeManifest != nil {
				r.BeforeManifest()
			}
			ref := strings.TrimPrefix(req.URL.Path, "/v2/fixture/rootfs/manifests/")
			if ref != "latest" && ref != digest(manifest) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", media)
			w.Header().Set("Docker-Content-Digest", digest(manifest))
			w.Header().Set("Content-Length", fmt.Sprint(len(manifest)))
			if req.Method == http.MethodGet {
				_, _ = w.Write(manifest)
			}
			return
		}
		if data, ok := blobs[strings.TrimPrefix(req.URL.Path, "/v2/fixture/rootfs/blobs/")]; ok {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			if req.Method == http.MethodGet {
				_, _ = w.Write(data)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral local OCI fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "registry-ca.pem")
	if e := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	r.Reference = strings.TrimPrefix(server.URL, "https://") + "/fixture/rootfs:latest"
	return r
}
