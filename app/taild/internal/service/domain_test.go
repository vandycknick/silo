package service

import (
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestRemoteSurfacePureDomain(t *testing.T) {
	for _, tt := range []struct {
		ref   string
		valid bool
	}{
		{"ghcr.io/vandycknick/silo/devbox:latest", true},
		{"ghcr.io/vandycknick/silo/devbox:Release_1", true},
		{"ghcr.io/vandycknick/silo/devbox@sha256:" + strings.Repeat("a", 64), true},
		{"ghcr.io/vandycknick.evil/devbox:latest", false},
		{"ghcr.io.evil/vandycknick/devbox:latest", false},
		{"ghcr.io/vandycknick/../../etc/passwd", false},
		{"ghcr.io/vandycknick/devbox\x00", false},
		{"ghcr.io/vandycknick/devbox\n", false},
		{"ghcr.io/vandycknick/devbox?path=/etc", false},
		{"https://ghcr.io/vandycknick/devbox", false},
		{"disk:/etc/passwd", false},
		{"/etc/passwd", false},
	} {
		if got := imageAllowed(tt.ref, []string{"ghcr.io/vandycknick"}); got != tt.valid {
			t.Errorf("%q: %v", tt.ref, got)
		}
	}
	for _, key := range []string{"GOOD", "_X", "a1"} {
		if !envKey(key) {
			t.Fatal(key)
		}
	}
	for _, key := range []string{"1bad", "x=y", "a\x00", "a-b", ""} {
		if envKey(key) {
			t.Fatal(key)
		}
	}
	diagnostic := redact("file=/var/lib/silo-taild/keys/key.pem\nAuthorization: Bearer synthetic-value\n{\"client_secret\":\"synthetic-secret\"}\ntskey-auth-synthetic\nordinary line\n")
	if strings.Contains(diagnostic, "/var/lib") || strings.Contains(diagnostic, "synthetic") || !strings.Contains(diagnostic, "ordinary line") {
		t.Fatal(diagnostic)
	}
	s := &Service{Config: testfixture.Config()}
	limits := s.Config.Limits()
	p := identity.Peer{Permissions: identity.Permissions{Limits: limits}}
	if e := s.resources(p, 8, 32<<30, 200<<30); e != nil {
		t.Fatal(e)
	}
	p.Permissions.Limits = identity.Limits{CPUs: 100, Memory: 100 << 30, Disk: 1000 << 30}
	if e := s.resources(p, 9, 32<<30, 200<<30); Categorize(e).Exit != 6 {
		t.Fatal("capability exceeded operator ceiling", e)
	}
	p.Permissions.Limits.CPUs = 0
	if e := s.resources(p, 1, 32<<30, 200<<30); Categorize(e).Exit != 6 {
		t.Fatal("explicit zero cap ignored", e)
	}
}
