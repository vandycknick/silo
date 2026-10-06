package config_test

import (
	"os"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestResolvedFrontendValidation(t *testing.T) {
	if err := testfixture.Config().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config.Config){
		func(c *config.Config) { c.Tailnet.Hostname = "trailing-" },
		func(c *config.Config) { c.Tailnet.Tag = "user:1" },
		func(c *config.Config) { c.Enrollment.Mode = "unknown" },
		func(c *config.Config) { c.VM.Defaults.CPUs = 99 },
		func(c *config.Config) { c.Sessions.PerPeer = c.Sessions.Global + 1 },
		func(c *config.Config) { c.Shutdown.StopBudget.Duration = 0 },
		func(c *config.Config) { c.Home = "relative" },
	} {
		c := testfixture.Config()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatal("invalid resolved configuration accepted")
		}
	}
}

func TestHomeOwnership(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ResolveHome(home, 0); err == nil {
		t.Fatal("root accepted")
	}
	if os.Geteuid() != 0 {
		if _, err := config.ResolveHome(home, os.Geteuid()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := config.ResolveHome(home, os.Geteuid()+1); err == nil {
		t.Fatal("foreign UID accepted")
	}
	if err := os.Chmod(home, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ResolveHome(home, os.Geteuid()); err == nil {
		t.Fatal("group-writable Home accepted")
	}
}
