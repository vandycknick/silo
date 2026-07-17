package policy

import "testing"

func TestBuiltinRegistry(t *testing.T) {
	registry := BuiltinRegistry()

	https, ok := registry.Endpoint("https")
	if !ok {
		t.Fatal("https endpoint is not registered")
	}
	if https.Family != EndpointFamilyHTTP || https.Transport != TransportHTTPSMITM || https.TLSMode != TLSModeTerminate || https.DefaultPort != 443 || !https.SupportsCredentials {
		t.Fatalf("unexpected https definition: %#v", https)
	}

	ip, ok := registry.Endpoint("ip")
	if !ok {
		t.Fatal("ip endpoint is not registered")
	}
	if ip.Schema != EndpointSchemaIP || ip.SupportsCredentials {
		t.Fatalf("unexpected ip definition: %#v", ip)
	}

	registries, ok := registry.Endpoint("registries")
	if !ok {
		t.Fatal("registries endpoint is not registered")
	}
	if registries.Family != EndpointFamilyPackage || registries.Transport != TransportTLSTerminate || registries.TLSMode != TLSModeTerminate || registries.Schema != EndpointSchemaRegistries {
		t.Fatalf("unexpected registries definition: %#v", registries)
	}
}
