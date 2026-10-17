package policytest

import (
	"fmt"
	"slices"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestForwardFixturePreservesProtocolAndTLS(t *testing.T) {
	t.Parallel()
	for _, port := range []uint16{443, 9443} {
		t.Run(fmt.Sprintf("https port %d", port), func(t *testing.T) {
			compiled, err := LoadPolicyFromString("forward.hcl", fmt.Sprintf(`
tailscale "vm" {
  hostname = "web"
}
forward "tailscale" "web" {
  listen = ":%d"
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
`, port))
			if err != nil {
				t.Fatal(err)
			}
			want := []policy.Forward{
				{Name: "web", ListenPort: port, GuestPort: 8080, Protocol: policy.ForwardProtocolHTTPS},
				{Name: "raw", ListenPort: 18080, GuestPort: 8080, Protocol: policy.ForwardProtocolTCP},
			}
			if !slices.Equal(compiled.Forwards(), want) {
				t.Fatalf("forwards = %#v, want %#v", compiled.Forwards(), want)
			}
		})
	}

}
