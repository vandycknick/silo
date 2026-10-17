//go:build silo_e2e

package integration_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func TestGuestClockFollowsHost(t *testing.T) {
	runtimeRoot := os.Getenv("SILO_TEST_RUNTIME_ROOT")
	image := os.Getenv("SILO_TEST_IMAGE")
	if runtimeRoot == "" || image == "" {
		t.Fatal("SILO_TEST_RUNTIME_ROOT and SILO_TEST_IMAGE are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runtime, err := silo.Open(ctx, silo.WithHome(t.TempDir()), silo.WithRuntimeRoot(runtimeRoot))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err = runtime.Images().Pull(ctx, image, silo.WithImagePullPolicy(silo.ImagePullIfMissing)); err != nil {
		t.Fatal(err)
	}
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := runtime.CreateMachine(ctx, silo.OCIImage(image), silo.WithName("go-sdk-clock-e2e"), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		t.Fatal(err)
	}
	defer machine.Close()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = machine.Stop(cleanupCtx)
		_ = machine.Remove(cleanupCtx)
	}()
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForReady(t, ctx, machine)

	// Throw the guest an hour into the past, the way a closed lid does.
	skew, err := machine.Exec(ctx, "/bin/sh", []string{"-c", "date -u -s @$(( $(date +%s) - 3600 ))"}, silo.WithExecUser("root"))
	if err != nil {
		t.Fatal(err)
	}
	if result := skew.Result(); result.Kind != silo.ExecutionResultExited || result.Code == nil || *result.Code != 0 {
		t.Fatalf("setting guest clock back failed: %#v stderr=%q", result, skew.Stderr())
	}
	if offset := guestOffset(t, ctx, machine); offset < 3000 {
		t.Fatalf("guest clock was not set back, offset %ds", offset)
	}

	deadline := time.Now().Add(75 * time.Second)
	var offset int64
	for time.Now().Before(deadline) {
		offset = guestOffset(t, ctx, machine)
		if offset >= -2 && offset <= 2 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("guest clock did not follow host, last offset %ds", offset)
}

// guestOffset returns host seconds minus guest seconds.
func guestOffset(t *testing.T, ctx context.Context, machine *silo.Machine) int64 {
	t.Helper()
	output, err := machine.Exec(ctx, "date", []string{"+%s"})
	if err != nil {
		t.Fatal(err)
	}
	host := time.Now().Unix()
	guest, err := strconv.ParseInt(strings.TrimSpace(output.Stdout()), 10, 64)
	if err != nil {
		t.Fatalf("parse guest date %q: %v", output.Stdout(), err)
	}
	return host - guest
}
