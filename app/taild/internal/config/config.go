package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/units"
	silo "github.com/vandycknick/silo/sdk/go"
)

type Resources struct {
	CPUs   uint64     `yaml:"cpus"`
	Memory units.Size `yaml:"memory"`
	Disk   units.Size `yaml:"disk"`
}

// Ceilings bound every principal; capability grants can only lower them.
type Ceilings struct {
	Resources `yaml:",inline"`
	VMs       uint64 `yaml:"vms_per_principal"`
}
type Config struct {
	TemplatesDir string `yaml:"templates_dir"`
	PoliciesDir  string `yaml:"policies_dir"`
	Home         string `yaml:"home"`
	Components   silo.RuntimeComponents
	BridgePath   string
	DiskReserve  units.Size `yaml:"disk_reserve"`
	Shutdown     struct {
		StopBudget units.Duration `yaml:"stop_budget"`
		Margin     units.Duration `yaml:"margin"`
	} `yaml:"shutdown"`
	Tailnet struct {
		Hostname   string `yaml:"hostname"`
		Tag        string `yaml:"tag"`
		Capability string `yaml:"capability"`
		ControlURL string `yaml:"control_url"`
	} `yaml:"tailnet"`
	Enrollment struct {
		Mode             string `yaml:"mode"`
		DisableKeyExpiry bool   `yaml:"disable_key_expiry"`
	} `yaml:"enrollment"`
	VM struct {
		DefaultImage      string    `yaml:"default_image"`
		AllowedRegistries []string  `yaml:"allowed_registries"`
		Defaults          Resources `yaml:"defaults"`
		Ceilings          Ceilings  `yaml:"ceilings"`
	} `yaml:"vm"`
	Sessions struct {
		Global  int `yaml:"global"`
		PerPeer int `yaml:"per_peer"`
	} `yaml:"sessions"`
}
type Secrets struct {
	ClientSecret string
	AppSecret    string
	APIToken     string
}

func (Secrets) String() string     { return "frontend credentials (redacted)" }
func (s Secrets) GoString() string { return s.String() }

// Limits is the operator ceiling as a capability grant, the shape every
// per-peer grant is intersected with.
func (c Config) Limits() identity.Limits {
	return identity.Limits{VMs: c.VM.Ceilings.VMs, CPUs: c.VM.Ceilings.CPUs, Memory: uint64(c.VM.Ceilings.Memory), Disk: uint64(c.VM.Ceilings.Disk)}
}
func (c Config) Validate() error {
	budget, margin := c.Shutdown.StopBudget.Duration, c.Shutdown.Margin.Duration
	if budget <= 0 || budget > time.Minute || margin <= 0 || margin > time.Second {
		return errors.New("invalid shutdown stop_budget or margin")
	}
	if !ValidName(c.Tailnet.Hostname) {
		return errors.New("invalid tailnet hostname")
	}
	if _, e := identity.ParsePrincipal(c.Tailnet.Tag); e != nil || !strings.HasPrefix(c.Tailnet.Tag, "tag:") {
		return errors.New("invalid tailnet tag")
	}
	if c.Tailnet.Capability == "" {
		return errors.New("capability is required")
	}
	switch c.Enrollment.Mode {
	case "oauth-app", "interactive", "none":
	default:
		return errors.New("invalid enrollment mode")
	}
	if !filepath.IsAbs(c.Home) {
		return errors.New("home must be absolute")
	}
	for _, p := range []string{c.TemplatesDir, c.PoliciesDir} {
		if p != "" && !filepath.IsAbs(p) {
			return errors.New("document directories must be absolute")
		}
	}
	l, d := c.Limits(), c.VM.Defaults
	if l.VMs == 0 || l.CPUs == 0 || l.CPUs > 255 || l.Memory == 0 || l.Disk == 0 || d.CPUs == 0 || d.CPUs > l.CPUs || d.Memory == 0 || uint64(d.Memory) > l.Memory || d.Disk == 0 || uint64(d.Disk) > l.Disk {
		return errors.New("invalid resource defaults or ceilings")
	}
	if c.Sessions.Global < 1 || c.Sessions.PerPeer < 1 || c.Sessions.PerPeer > c.Sessions.Global {
		return errors.New("invalid session limits")
	}
	return nil
}

func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[len(s)-1] == '-' {
		return false
	}
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0 {
			continue
		}
		return false
	}
	return true
}
func ResolveHome(path string, uid int) (string, error) {
	if uid == 0 {
		return "", errors.New("taild refuses to run as root")
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", fmt.Errorf("resolve home: %w", e)
	}
	info, e := os.Stat(resolved)
	if e != nil {
		return "", e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || int(st.Uid) != uid {
		return "", errors.New("home is not owned by the process uid")
	}
	if info.Mode().Perm()&0022 != 0 {
		return "", errors.New("home must not be writable by group or others")
	}
	return resolved, nil
}
