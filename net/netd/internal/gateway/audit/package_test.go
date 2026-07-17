package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

func TestPackageMetadataPreservesPolicyFacets(t *testing.T) {
	metadata := packageMetadata(hooks.RouteDecision{Package: &hooks.Package{
		Ecosystem:            "npm",
		Operation:            "download",
		Name:                 "example",
		Version:              "1.0.0",
		IdentityKnown:        true,
		AgeKnown:             true,
		AgeHours:             48,
		AgeSource:            "registry",
		MalwareDataAvailable: true,
	}})
	if metadata == nil || metadata.Ecosystem != "npm" || metadata.Name != "example" || metadata.AgeHours == nil || *metadata.AgeHours != 48 || metadata.AgeSource != "registry" {
		t.Fatalf("unexpected package metadata: %#v", metadata)
	}
	if metadata.AgeKnown == nil || !*metadata.AgeKnown || metadata.MalwareDataAvailable == nil || !*metadata.MalwareDataAvailable || metadata.Malware == nil || *metadata.Malware {
		t.Fatalf("exact package booleans = %#v", metadata)
	}
	if family := httpFamily("registries"); family != "package" {
		t.Fatalf("registry audit family = %q", family)
	}
	if scheme := httpScheme("registries"); scheme != "https" {
		t.Fatalf("registry audit scheme = %q", scheme)
	}
}

func TestRegistryAuditDoesNotInventPackageObject(t *testing.T) {
	var output bytes.Buffer
	logger := newLogger(&output, nil, "", 1)
	logger.RecordHTTPRequest(
		hooks.HTTPRequest{EndpointKind: "registries"},
		hooks.RouteDecision{Action: hooks.RouteDeny, Reason: "host_mismatch"},
		421,
		nil,
	)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Family != "package" || event.Package != nil || event.Verdict != "deny" {
		t.Fatalf("unexpected registry audit event: %#v", event)
	}
	if bytes.Contains(output.Bytes(), []byte("package_filter")) {
		t.Fatalf("registry audit retained package_filter: %s", output.Bytes())
	}
}

func TestRegistryMetadataAuditOmitsCandidateFacts(t *testing.T) {
	var output bytes.Buffer
	logger := newLogger(&output, nil, "", 1)
	logger.RecordHTTPRequest(
		hooks.HTTPRequest{EndpointKind: "registries"},
		hooks.RouteDecision{Action: hooks.RouteAllowDirect, Package: &hooks.Package{Ecosystem: "npm", Operation: "resolve", Name: "example"}},
		200,
		nil,
	)
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{[]byte(`"age_known"`), []byte(`"age_hours"`), []byte(`"malware_data_available"`), []byte(`"malware"`)} {
		if bytes.Contains(output.Bytes(), field) {
			t.Fatalf("identity-less package audit contains %s: %s", field, output.Bytes())
		}
	}
}
