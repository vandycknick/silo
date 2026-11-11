// Package testnet starts a real offline Tailscale control plane for seam tests.
// It is linked only by tests and the non-shipped tsgate-testnet helper.
package testnet

import (
	"net/http/httptest"
	"testing"

	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
)

func Start(t testing.TB, capability, value string) string {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	control := &testcontrol.Server{
		DERPMap:        integration.RunDERPAndSTUN(t, t.Logf, "127.0.0.1"),
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
		TagOwners:      map[string][]string{},
		Logf:           t.Logf,
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{tailcfg.PeerCapability(capability): []tailcfg.RawMessage{tailcfg.RawMessage(value)}})
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	return control.HTTPTestServer.URL
}
