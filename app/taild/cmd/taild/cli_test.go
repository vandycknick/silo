package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	silo "github.com/vandycknick/silo/sdk/go"
)

func TestOfflineVersionCommandsNeverStartTailnet(t *testing.T) {
	if os.Getenv("SILO_TAILD_VERSION_CHILD") == "1" {
		if err := runArgs([]string{os.Getenv("SILO_TAILD_VERSION_COMMAND"), "--config", os.Getenv("SILO_TAILD_VERSION_CONFIG")}); err != nil {
			t.Fatal(err)
		}
		return
	}
	home := t.TempDir()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("home: %q\n", home)), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"version", "--version"} {
		cmd := exec.Command(exe, "-test.run=^TestOfflineVersionCommandsNeverStartTailnet$")
		cmd.Env = append(os.Environ(), "SILO_TAILD_VERSION_CHILD=1", "SILO_TAILD_VERSION_COMMAND="+command, "SILO_TAILD_VERSION_CONFIG="+p)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "SDK "+silo.Version+" runtime unavailable") {
			t.Fatalf("%v %s", err, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, "taild", "tsnet")); !os.IsNotExist(err) {
		t.Fatal("version created tailnet state", err)
	}
}

func TestVersionRejectsMissingRuntimeManifest(t *testing.T) {
	home, root := t.TempDir(), t.TempDir()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("home: %q\nruntime_root: %q\n", home, root)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runArgs([]string{"version", "--config", p}); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatal("unverified runtime version accepted", err)
	}
}

func TestOfflineInstallerUsesConfigAndRequiresArchive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("installer requires nonroot home")
	}
	home := t.TempDir()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("home: %q\n", home)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runArgs([]string{"install-runtime", "--config", p}); err == nil || !strings.Contains(err.Error(), "requires --runtime-archive") {
		t.Fatal(err)
	}
	if err := runArgs([]string{"install-runtime", "--config", p, "--runtime-archive", filepath.Join(home, "missing"), "--install-root", filepath.Join(home, "store")}); err == nil || !strings.Contains(err.Error(), "offline SDK runtime installation failed") {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "taild", "tsnet")); !os.IsNotExist(err) {
		t.Fatal("installer created tailnet state", err)
	}
}
