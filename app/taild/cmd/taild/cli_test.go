package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	silo "github.com/vandycknick/silo/sdk/go"
)

func TestOfflineCommandsHaveNoRuntimeOrConnectionSideEffects(t *testing.T) {
	if os.Getenv("SILO_TAILD_VERSION_CHILD") == "1" {
		if err := runArgs([]string{os.Getenv("SILO_TAILD_VERSION_COMMAND")}); err != nil {
			t.Fatal(err)
		}
		return
	}
	home := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"version", "--version", "help", "--help"} {
		cmd := exec.Command(exe, "-test.run=^TestOfflineCommandsHaveNoRuntimeOrConnectionSideEffects$")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SILO_HOME=" + home, "SILO_GO_FFI_PATH=" + filepath.Join(home, "missing-bridge"), "SILO_TAILD_VERSION_CHILD=1", "SILO_TAILD_VERSION_COMMAND=" + command}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		if strings.Contains(command, "version") && (!strings.Contains(string(out), "SDK "+silo.Version+" runtime unavailable") || !strings.Contains(string(out), "verified unavailable")) {
			t.Fatal(string(out))
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("offline command wrote Home", entries, err)
	}
}

func TestManagedInvocationOnly(t *testing.T) {
	for _, args := range [][]string{nil, {"install-runtime"}, {"stop-vms"}, {"--config", "/tmp/config"}, {"--check"}, {"--runtime-archive", "/tmp/archive"}, {"--bootstrap-fd", "-1"}, {"--version", "--bootstrap-fd", "0"}} {
		err := runArgs(args)
		var deterministic *deterministicError
		if !errors.As(err, &deterministic) {
			t.Fatal("unsafe invocation accepted", args, err)
		}
	}
	iv, err := parseArgs([]string{"--bootstrap-fd", "0"})
	if err != nil || iv.bootstrapFD != 0 {
		t.Fatal("stdin bootstrap not accepted", iv, err)
	}
}
