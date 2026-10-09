package policytest

import (
	"slices"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestForwardFixturePreservesProtocolAndTLS(t *testing.T) {
	compiled, err := LoadPolicyFromString("forward.hcl", `
tailscale "vm" {
  hostname = "web"
}
forward "tailscale" "web" {
  listen = ":443"
  target = "self"
  target_port = 8080
  protocol = "https"
  tls {
    provider = "tailscale"
  }
}
forward "tailscale" "raw" {
  listen = ":18080"
  target = "self"
  target_port = 8080
  tunnel = tailscale.vm
}
`)
	if err != nil {
		t.Fatal(err)
	}
	want := []policy.Forward{
		{Name: "web", ListenPort: 443, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS},
		{Name: "raw", ListenPort: 18080, GuestPort: 8080, Protocol: policy.ForwardProtocolTCP},
	}
	if !slices.Equal(compiled.Forwards(), want) {
		t.Fatalf("forwards = %#v, want %#v", compiled.Forwards(), want)
	}
}
