package silo

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestForwardNativeRoundTrip(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		if os.Getenv("SILO_TAILD_REQUIRE_FIXTURES") == "1" {
			t.Fatal("SILO_GO_FFI_PATH is required")
		}
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	target, listen := "self", ":00443"
	port := uint16(8080)
	for _, protocol := range []NetworkForwardProtocol{"", NetworkForwardTCP, NetworkForwardHTTPS} {
		t.Run(string(protocol), func(t *testing.T) {
			forward := NetworkForward{Name: "web", Kind: NetworkForwardTailscale,
				Target: &target, TargetPort: &port, Listen: &listen, Protocol: protocol}
			if protocol == NetworkForwardHTTPS {
				forward.TLS = &NetworkForwardTLS{Provider: NetworkForwardTLSTailscale}
			}
			policy, err := BuildNetworkPolicy(NetworkPolicyConfig{Forwards: []NetworkForward{forward}})
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Forwards []NetworkForward `json:"forwards"`
			}
			if err := json.Unmarshal([]byte(policy.JSON()), &document); err != nil {
				t.Fatal(err)
			}
			if len(document.Forwards) != 1 {
				t.Fatalf("lost forward: %s", policy.JSON())
			}
			got := document.Forwards[0]
			wantProtocol := protocol
			if wantProtocol == "" {
				wantProtocol = NetworkForwardTCP
			}
			if got.Kind != NetworkForwardTailscale || got.Tunnel != nil || got.Protocol != wantProtocol || got.Listen == nil || *got.Listen != ":443" {
				t.Fatalf("lost forward semantics: %#v", got)
			}
			if protocol == NetworkForwardHTTPS && (got.TLS == nil || got.TLS.Provider != NetworkForwardTLSTailscale) {
				t.Fatalf("lost TLS: %#v", got)
			}
			reparsed, err := ParseNetworkPolicyJSON(policy.JSON())
			if err != nil {
				t.Fatal(err)
			}
			if reparsed.JSON() != policy.JSON() {
				t.Fatal("canonical JSON changed on reparse")
			}
			hcl, err := policy.HCL()
			if err != nil {
				t.Fatal(err)
			}
			fromHCL, err := ParseNetworkPolicyHCL(hcl)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip struct {
				Forwards []NetworkForward `json:"forwards"`
			}
			if err := json.Unmarshal([]byte(fromHCL.JSON()), &roundtrip); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(roundtrip.Forwards, document.Forwards) {
				t.Fatal("HCL roundtrip changed forward semantics")
			}
			secrets, err := policy.SecretMetadata()
			if err != nil {
				t.Fatal(err)
			}
			if len(secrets.Slots) != 0 || len(secrets.Requirements) != 0 {
				t.Fatalf("forward added secret requirements: %#v", secrets)
			}
		})
	}
}

func TestForwardNativeRejectsUnknownKind(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		if os.Getenv("SILO_TAILD_REQUIRE_FIXTURES") == "1" {
			t.Fatal("SILO_GO_FFI_PATH is required")
		}
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	target, listen := "name:web", "127.0.0.1:8080"
	port := uint16(8080)
	_, err := BuildNetworkPolicy(NetworkPolicyConfig{Forwards: []NetworkForward{{
		Name: "web", Kind: "unknown", Target: &target, TargetPort: &port, Listen: &listen,
	}}})
	if err == nil {
		t.Fatal("unknown forward kind became host")
	}
}
