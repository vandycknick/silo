package silo

import (
	"encoding/json"
	"os"
	"testing"
)

func TestBuildNetworkPolicyUsesRustCanonicalization(t *testing.T) {
	if os.Getenv("SILO_GO_FFI_PATH") == "" {
		t.Skip("SILO_GO_FFI_PATH is not set")
	}
	endpointName := "api"
	policy, err := BuildNetworkPolicy(NetworkPolicyConfig{DefaultAction: NetworkDeny, Metadata: map[string]string{"source": "go"}, Endpoints: []NetworkEndpoint{{Name: endpointName, Kind: NetworkEndpointHTTPS, Hosts: []string{"api.openai.com"}}}, Rules: []NetworkRule{{Endpoints: []string{endpointName}, Verdict: NetworkVerdictAllow}}})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal([]byte(policy.JSON()), &value); err != nil {
		t.Fatalf("canonical policy is invalid JSON: %v", err)
	}
	parsed, err := ParseNetworkPolicyJSON(policy.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.JSON() != policy.JSON() {
		t.Fatalf("reparse changed canonical JSON")
	}
}
