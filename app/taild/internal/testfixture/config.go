package testfixture

import (
	"os"
	"path/filepath"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/units"
	silo "github.com/vandycknick/silo/sdk/go"
)

// Config is explicit test data, not a second production configuration source.
func Config() config.Config {
	var c config.Config
	c.Home = "/fixture/home"
	c.BridgePath = os.Getenv("SILO_GO_FFI_PATH")
	c.TemplatesDir, c.PoliciesDir = "/fixture/templates", "/fixture/policies"
	c.DiskReserve = 1 << 30
	c.Shutdown.StopBudget = units.Duration{Duration: 4 * time.Second}
	c.Shutdown.Margin = units.Duration{Duration: 250 * time.Millisecond}
	c.Tailnet.Hostname, c.Tailnet.Tag = "silo", "tag:silo"
	c.Tailnet.Capability = "github.com/vandycknick/silo/cap/taild"
	c.Enrollment.Mode = "oauth-app"
	c.VM.DefaultImage = "ghcr.io/vandycknick/silo/devbox:latest"
	c.VM.AllowedRegistries = []string{"ghcr.io/vandycknick"}
	c.VM.Defaults = config.Resources{CPUs: 2, Memory: 4 << 30, Disk: 20 << 30}
	c.VM.Ceilings = config.Ceilings{Resources: config.Resources{CPUs: 8, Memory: 32 << 30, Disk: 200 << 30}, VMs: 5}
	c.Sessions.Global, c.Sessions.PerPeer = 64, 8
	return c
}

// Components uses only the explicitly selected real portable SDK fixture.
func Components(root string) silo.RuntimeComponents {
	return silo.RuntimeComponents{
		SupervisorPath: filepath.Join(root, "bin", "silo-vmm"),
		NetdPath:       filepath.Join(root, "bin", "netd"),
		KernelPath:     filepath.Join(root, "assets", "kernel-default"),
		InitramfsPath:  filepath.Join(root, "assets", "initramfs"),
		AgentPath:      filepath.Join(root, "assets", "agent"),
		AssetDir:       filepath.Join(root, "assets"),
	}
}
