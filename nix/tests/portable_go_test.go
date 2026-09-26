package portablego

import (
	"mime"
	"net"
	"testing"
	"time"
	_ "time/tzdata"
)

// Link the runtime database lookups affected by Nixpkgs' Go patches. The
// toolchain's install check also checks this compiled binary for store paths.
func TestRuntimeDatabases(t *testing.T) {
	t.Run("services", func(t *testing.T) {
		port, err := net.LookupPort("tcp", "http")
		if err != nil || port != 80 {
			t.Fatalf("LookupPort(tcp, http) = %d, %v", port, err)
		}
	})

	t.Run("protocols", func(t *testing.T) {
		address, err := net.ResolveIPAddr("ip4:icmp", "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("unexpected resolved address: %v", address)
		}
	})

	t.Run("mime", func(t *testing.T) {
		if got := mime.TypeByExtension(".html"); got != "text/html; charset=utf-8" {
			t.Fatalf("TypeByExtension(.html) = %q", got)
		}
	})

	t.Run("timezone", func(t *testing.T) {
		location, err := time.LoadLocation("America/New_York")
		if err != nil {
			t.Fatal(err)
		}
		_, offset := time.Date(2026, time.January, 1, 0, 0, 0, 0, location).Zone()
		if offset != -5*60*60 {
			t.Fatalf("unexpected New York winter offset: %d", offset)
		}
	})
}
