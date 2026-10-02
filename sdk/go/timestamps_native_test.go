package silo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func dateNearCreate(t *testing.T, date, before, after time.Time) {
	t.Helper()
	if date.Before(before.Truncate(time.Second)) || date.After(after) {
		t.Fatalf("native date %s outside creation window [%s, %s]", date.UTC(), before.UTC(), after.UTC())
	}
}

func TestNativeMachineTimestampsNearCreate(t *testing.T) {
	r, home := phase7Runtime(t)
	ctx := context.Background()
	disk := filepath.Join(home, "input.raw")
	if err := os.WriteFile(disk, []byte("root-disk"), 0600); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	machine, err := r.CreateMachine(ctx, DiskImage(disk), WithName("timestamps"))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	check := func(data *MachineData) {
		t.Helper()
		if data == nil || data.RootFS == nil {
			t.Fatal("missing native data/rootfs")
		}
		for _, date := range []time.Time{data.CreatedAt, data.ModifiedAt, data.UpdatedAt, data.RootFS.CreatedAt} {
			dateNearCreate(t, date, before, time.Now())
		}
		if data.StartedAt != nil {
			t.Fatal("stopped machine has start date", data.StartedAt)
		}
	}
	check(data)
	dateNearCreate(t, data.CreatedAt, before, after)
	entries, err := r.Inventory(ctx)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	check(entries[0].Data)
	name := "timestamps-updated"
	updated, err := machine.Update(ctx, MachineUpdate{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	check(updated)
	if !updated.CreatedAt.Equal(data.CreatedAt) || updated.Name != name {
		t.Fatal(updated)
	}
	if err := machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNativeImageTimestampsNearPull(t *testing.T) {
	reference := timestampOCIRegistry(t)
	r, _ := phase7Runtime(t)
	ctx := context.Background()
	before := time.Now()
	image, err := r.Images().Pull(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	check := func(image *ImageHandle) {
		t.Helper()
		if image == nil {
			t.Fatal("missing native image")
		}
		dateNearCreate(t, image.CreatedAt, before, time.Now())
		dateNearCreate(t, image.UpdatedAt, before, time.Now())
		if image.LastUsedAt != nil {
			dateNearCreate(t, *image.LastUsedAt, before, time.Now())
		}
	}
	check(image)
	lookup, err := r.Images().Lookup(ctx, reference)
	if err != nil {
		t.Fatal(err)
	}
	check(lookup)
	list, err := r.Images().List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatal(list, err)
	}
	check(&list[0])
	detail, err := r.Images().Inspect(ctx, reference)
	if err != nil || detail == nil {
		t.Fatal(detail, err)
	}
	check(&detail.Handle)
	machine, err := r.CreateMachine(ctx, OCIImage(reference), WithName("oci-timestamps"))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	data, err := machine.Inspect(ctx)
	if err != nil || data.RootFS == nil {
		t.Fatal(data, err)
	}
	dateNearCreate(t, data.RootFS.CreatedAt, before, time.Now())
	used, err := r.Images().Lookup(ctx, reference)
	if err != nil || used.LastUsedAt == nil {
		t.Fatal(used, err)
	}
	check(used)
	if err := machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
}

// Real loopback OCI distribution: the native client validates digests, downloads
// the layer and materializes a filesystem in the test's fresh Home.
func timestampOCIRegistry(t *testing.T) string {
	t.Helper()
	var archive, compressed bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "etc", Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest := func(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }
	config, err := json.Marshal(struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}{Architecture: runtime.GOARCH, OS: "linux", RootFS: struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}{"layers", []string{digest(archive.Bytes())}}})
	if err != nil {
		t.Fatal(err)
	}
	type descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	}
	const media = "application/vnd.oci.image.manifest.v1+json"
	manifest, err := json.Marshal(struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{2, media, descriptor{"application/vnd.oci.image.config.v1+json", digest(config), len(config)}, []descriptor{{"application/vnd.oci.image.layer.v1.tar+gzip", digest(compressed.Bytes()), compressed.Len()}}})
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string][]byte{digest(config): config, digest(compressed.Bytes()): compressed.Bytes()}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		if req.URL.Path == "/v2/" {
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(req.URL.Path, "/v2/fixture/rootfs/manifests/") {
			w.Header().Set("Content-Type", media)
			w.Header().Set("Docker-Content-Digest", digest(manifest))
			_, _ = w.Write(manifest)
			return
		}
		if data, ok := blobs[strings.TrimPrefix(req.URL.Path, "/v2/fixture/rootfs/blobs/")]; ok {
			_, _ = w.Write(data)
			return
		}
		w.WriteHeader(404)
	}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "timestamp OCI fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "registry.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	return strings.TrimPrefix(server.URL, "https://") + "/fixture/rootfs:latest"
}
