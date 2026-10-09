package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tailscale.com/envknob"
)

func assertEarlyBootstrapTrace(t *testing.T, trace string) {
	t.Helper()
	guard := strings.Index(trace, "init github.com/vandycknick/silo/net/netd/internal/bootenv @")
	upstream := strings.Index(trace, "init tailscale.com/envknob @")
	if guard < 0 || upstream < 0 || guard > upstream {
		t.Fatal("bootstrap did not precede upstream environment registration")
	}
	if index := strings.Index(trace, "init tailscale.com/wgengine/magicsock @"); index < 0 || index < guard {
		t.Fatal("regression did not include actual magicsock initialization")
	}
}

func TestBootstrapDependencyContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "go", "list", "-deps", "-json", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	const guard = "github.com/vandycknick/silo/net/netd/internal/bootenv"
	found := false
	for {
		var pkg struct {
			ImportPath    string
			Imports, Deps []string
		}
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if pkg.ImportPath == guard {
			found = true
			if len(pkg.Imports) != 1 || pkg.Imports[0] != "os" {
				t.Fatal("bootstrap acquired imports that invalidate early eligibility")
			}
		}
		if strings.HasPrefix(pkg.ImportPath, "tailscale.com/") && pkg.ImportPath <= guard {
			t.Fatal("upstream import path no longer sorts after bootstrap")
		}
	}
	if !found {
		t.Fatal("binary dependency graph lost bootstrap")
	}
}

func TestBootstrapCachesInActualChildProcess(t *testing.T) {
	for _, integer := range []string{"314159", "invalid-private-knob-sentinel"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "-test.run=^TestBootstrapCacheChild$", "-test.v")
		command.Env = append(os.Environ(), "SILO_TEST_BOOTENV_CHILD=1", "GODEBUG=inittrace=1", "TS_DEBUG_DISCO=invalid-private-knob-sentinel", "TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES="+integer, "TS_DEBUG_RING_BUFFER_SIZE="+integer, "TS_CLIENT_SECRET=private-knob-sentinel", "TSNET_FORCE_LOGIN=invalid-private-knob-sentinel", "AWS_PROFILE=ordinary")
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatal("actual upstream initialization/cache child failed")
		}
		if strings.Contains(string(output), "private-knob-sentinel") || !strings.Contains(string(output), "BOOTENV_CACHES_CLEAN") {
			t.Fatal("ambient values were logged or influenced upstream caches")
		}
		assertEarlyBootstrapTrace(t, string(output))
	}
}

func TestBootstrapCacheChild(t *testing.T) {
	if os.Getenv("SILO_TEST_BOOTENV_CHILD") != "1" {
		return
	}
	if envknob.RegisterInt("TS_DEBUG_MAGICSOCK_RING_BUFFER_MAX_SIZE_BYTES")() != 0 || envknob.RegisterInt("TS_DEBUG_RING_BUFFER_SIZE")() != 0 || envknob.RegisterBool("TS_DEBUG_DISCO")() || envknob.RegisterString("TS_CLIENT_SECRET")() != "" {
		t.Fatal("upstream registered caches retained ambient inputs")
	}
	for _, entry := range os.Environ() {
		if isolatedEnvironmentName(entry) {
			t.Fatal("isolated environment survived initialization")
		}
	}
	if os.Getenv("AWS_PROFILE") != "ordinary" {
		t.Fatal("bootstrap lost ordinary AWS environment")
	}
	t.Log("BOOTENV_CACHES_CLEAN")
}
