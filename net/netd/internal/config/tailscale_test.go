package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestTailscaleFlagsExactlyWhenDeclared(t *testing.T) {
	p, err := policy.LoadReader("test.json", strings.NewReader(`{"version":1,"tailscale":[{"name":"vm"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &Config{TailscaleStateDir: dir, VsockMux: filepath.Join(dir, "not-created.sock")}
	if err := ValidateTailscale(cfg, p); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTailscale(cfg, policy.Default()); err == nil {
		t.Fatal("flags accepted without declaration")
	}
	if err := ValidateTailscale(&Config{}, p); err == nil {
		t.Fatal("missing flags accepted")
	}
	cfg.TailscaleStateDir = filepath.Join(dir, "missing")
	if err := ValidateTailscale(cfg, p); err == nil {
		t.Fatal("missing state directory accepted")
	}
	cfg.TailscaleStateDir = dir
	cfg.VsockMux = filepath.Join(dir, "missing", "mux")
	if err := ValidateTailscale(cfg, p); err == nil {
		t.Fatal("missing mux parent accepted")
	}
}
