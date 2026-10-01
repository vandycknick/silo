package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/units"
	"go.yaml.in/yaml/v3"
)

type Resources struct {
	CPUs   uint64 `yaml:"cpus"`
	Memory string `yaml:"memory"`
	Disk   string `yaml:"disk"`
}
type Config struct {
	TemplatesDir   string `yaml:"templates_dir"`
	PoliciesDir    string `yaml:"policies_dir"`
	Home           string `yaml:"home"`
	RuntimeRoot    string `yaml:"runtime_root"`
	InstallRoot    string `yaml:"install_root"`
	RuntimeArchive string `yaml:"runtime_archive"`
	DiskReserve    string `yaml:"disk_reserve"`
	Shutdown       struct {
		StopBudget string `yaml:"stop_budget"`
		Margin     string `yaml:"margin"`
	} `yaml:"shutdown"`
	SecretsDir string `yaml:"secrets_dir"`
	Tailnet    struct {
		Hostname   string `yaml:"hostname"`
		Tag        string `yaml:"tag"`
		Capability string `yaml:"capability"`
		ControlURL string `yaml:"control_url"`
	} `yaml:"tailnet"`
	Enrollment struct {
		Mode             string `yaml:"mode"`
		Timeout          string `yaml:"timeout"`
		DisableKeyExpiry bool   `yaml:"disable_key_expiry"`
		DeleteDevices    bool   `yaml:"delete_devices"`
	} `yaml:"enrollment"`
	VM struct {
		DefaultImage      string    `yaml:"default_image"`
		AllowedRegistries []string  `yaml:"allowed_registries"`
		Defaults          Resources `yaml:"defaults"`
		Ceilings          struct {
			CPUs   uint64 `yaml:"cpus"`
			Memory string `yaml:"memory"`
			Disk   string `yaml:"disk"`
			VMs    uint64 `yaml:"vms_per_principal"`
		} `yaml:"ceilings"`
		GuestUser struct {
			Name string `yaml:"name"`
			UID  uint32 `yaml:"uid"`
			GID  uint32 `yaml:"gid"`
			Home string `yaml:"home"`
		} `yaml:"guest_user"`
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

func Defaults() Config {
	var c Config
	c.Home = "/var/lib/silo-taild"
	c.DiskReserve = "1GiB"
	c.Shutdown.StopBudget = "4s"
	c.Shutdown.Margin = "250ms"
	c.SecretsDir = "/etc/silo-taild/secrets"
	c.TemplatesDir = "/etc/silo-taild/templates"
	c.PoliciesDir = "/etc/silo-taild/policies"
	c.Tailnet.Hostname = "silo"
	c.Tailnet.Tag = "tag:silo"
	c.Tailnet.Capability = "github.com/vandycknick/silo/cap/taild"
	c.Enrollment.Mode = "oauth-app"
	c.Enrollment.Timeout = "5m"
	c.Enrollment.DeleteDevices = true
	c.VM.DefaultImage = "ghcr.io/vandycknick/silo/devbox:latest"
	c.VM.AllowedRegistries = []string{"ghcr.io/vandycknick"}
	c.VM.Defaults = Resources{2, "4GiB", "20GiB"}
	c.VM.Ceilings.CPUs = 8
	c.VM.Ceilings.Memory = "32GiB"
	c.VM.Ceilings.Disk = "200GiB"
	c.VM.Ceilings.VMs = 5
	c.VM.GuestUser.Name = "silo"
	c.VM.GuestUser.UID = 1000
	c.VM.GuestUser.GID = 1000
	c.VM.GuestUser.Home = "/home/silo"
	c.Sessions.Global = 64
	c.Sessions.PerPeer = 8
	return c
}
func Load(path string) (Config, error) {
	c := Defaults()
	if home := os.Getenv("SILO_HOME"); home != "" {
		c.Home = home
	}
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return c, e
	}
	if len(b) > 65536 {
		return c, errors.New("config exceeds 64KiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra yaml.Node
	if e = d.Decode(&extra); e != io.EOF {
		return c, errors.New("config must contain one YAML document")
	}
	return c, c.Validate()
}
func (c Config) Limits() (identity.Limits, error) {
	mem, e := units.Bytes(c.VM.Ceilings.Memory)
	if e != nil {
		return identity.Limits{}, e
	}
	disk, e := units.Bytes(c.VM.Ceilings.Disk)
	if e != nil {
		return identity.Limits{}, e
	}
	return identity.Limits{VMs: c.VM.Ceilings.VMs, CPUs: c.VM.Ceilings.CPUs, Memory: uint64(mem), Disk: uint64(disk)}, nil
}
func (c Config) Validate() error {
	if _, e := units.Bytes(c.DiskReserve); e != nil {
		return errors.New("invalid disk_reserve")
	}
	budget, e := time.ParseDuration(c.Shutdown.StopBudget)
	margin, me := time.ParseDuration(c.Shutdown.Margin)
	if e != nil || me != nil || budget <= 0 || budget > time.Minute || margin <= 0 || margin > time.Second {
		return errors.New("invalid shutdown stop_budget or margin")
	}
	for _, p := range []string{c.InstallRoot, c.RuntimeArchive} {
		if p != "" && !filepath.IsAbs(p) {
			return errors.New("install_root and runtime_archive must be absolute")
		}
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
	timeout, e := time.ParseDuration(c.Enrollment.Timeout)
	if e != nil || timeout <= 0 || timeout > 5*time.Minute {
		return errors.New("enrollment timeout must be positive and at most 5m")
	}
	for _, p := range []string{c.Home, c.SecretsDir, c.TemplatesDir, c.PoliciesDir} {
		if !filepath.IsAbs(p) {
			return errors.New("home and secrets_dir must be absolute")
		}
	}
	if c.RuntimeRoot != "" && !filepath.IsAbs(c.RuntimeRoot) {
		return errors.New("runtime_root must be absolute")
	}
	l, e := c.Limits()
	if e != nil {
		return e
	}
	m, e := units.Bytes(c.VM.Defaults.Memory)
	if e != nil {
		return e
	}
	disk, e := units.Bytes(c.VM.Defaults.Disk)
	if e != nil {
		return e
	}
	if l.VMs == 0 || l.CPUs == 0 || l.CPUs > 255 || l.Memory == 0 || l.Disk == 0 || c.VM.Defaults.CPUs == 0 || c.VM.Defaults.CPUs > l.CPUs || uint64(m) == 0 || uint64(m) > l.Memory || uint64(disk) == 0 || uint64(disk) > l.Disk {
		return errors.New("invalid resource defaults or ceilings")
	}
	if c.VM.GuestUser.Name == "" || c.VM.GuestUser.UID == 0 || c.VM.GuestUser.GID == 0 || !filepath.IsAbs(c.VM.GuestUser.Home) {
		return errors.New("guest_user must be nonroot with an absolute home")
	}
	if c.Sessions.Global < 1 || c.Sessions.PerPeer < 1 || c.Sessions.PerPeer > c.Sessions.Global {
		return errors.New("invalid session limits")
	}
	return nil
}

func (c Config) RuntimeStore() string {
	if c.InstallRoot != "" {
		return c.InstallRoot
	}
	return filepath.Join(c.Home, "runtimes")
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
func ReadSecrets(dir string) (Secrets, error) {
	var s Secrets
	for _, v := range []struct {
		name string
		out  *string
	}{{"oauth-client-secret", &s.ClientSecret}, {"oauth-app-secret", &s.AppSecret}, {"api-token", &s.APIToken}} {
		path := filepath.Join(dir, v.name)
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return s, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return s, fmt.Errorf("secret %s must be a regular 0600 file", v.name)
		}
		f, e := os.Open(path)
		if e != nil {
			return s, e
		}
		b, e := io.ReadAll(io.LimitReader(f, 16385))
		closeErr := f.Close()
		if e != nil {
			return s, e
		}
		if closeErr != nil {
			return s, closeErr
		}
		if len(b) > 16384 || strings.TrimSpace(string(b)) == "" {
			return s, fmt.Errorf("secret %s is empty or oversized", v.name)
		}
		*v.out = strings.TrimSpace(string(b))
	}
	return s, nil
}
