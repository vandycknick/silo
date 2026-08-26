//go:build silo_e2e

package integration_test

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/vandycknick/silo/sdk/go"
)

func TestGoSDKLifecycleExecutionLogsAndImages(t *testing.T) {
	runtimeRoot := os.Getenv("SILO_TEST_RUNTIME_ROOT")
	image := os.Getenv("SILO_TEST_IMAGE")
	if runtimeRoot == "" || image == "" {
		t.Fatal("SILO_TEST_RUNTIME_ROOT and SILO_TEST_IMAGE are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	runtime, err := silo.Open(ctx, silo.WithDataRoot(t.TempDir()), silo.WithRuntimeRoot(runtimeRoot))
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
	machine, err := runtime.CreateMachine(ctx, silo.OCIImage(image), silo.WithName("go-sdk-e2e"), silo.WithCPUs(1), silo.WithMemory(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
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
	output, err := machine.Exec(ctx, "/bin/sh", []string{"-c", "printf go-sdk; printf error >&2; exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	if output.Stdout() != "go-sdk" || output.Stderr() != "error" {
		t.Fatalf("unexpected output: %q %q", output.Stdout(), output.Stderr())
	}
	result := output.Result()
	if result.Kind != silo.ExecutionResultExited || result.Code == nil || *result.Code != 7 {
		t.Fatalf("unexpected result: %#v", result)
	}
	attachStatus, err := machine.Attach(ctx, "/bin/true", nil)
	if err != nil {
		t.Fatal(err)
	}
	if attachStatus.Kind != silo.ExecutionResultExited || attachStatus.Code == nil || *attachStatus.Code != 0 {
		t.Fatalf("unexpected attach result: %#v", attachStatus)
	}
	session, err := machine.Spawn(ctx, "/bin/cat", nil, silo.WithExecStdinPipe())
	if err != nil {
		t.Fatal(err)
	}
	stdin := session.Stdin()
	if stdin == nil {
		t.Fatal("spawn did not expose requested stdin pipe")
	}
	if _, err = stdin.Write([]byte{0, 1, 255}); err != nil {
		t.Fatal(err)
	}
	if err = stdin.Close(); err != nil {
		t.Fatal(err)
	}
	streamed, err := session.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := streamed.StdoutBytes(); len(got) != 3 || got[2] != 255 {
		t.Fatalf("streamed stdout = %v", got)
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	pty, err := machine.Spawn(ctx, "/bin/sleep", []string{"30"}, silo.WithExecTTY(true))
	if err != nil {
		t.Fatal(err)
	}
	for {
		event, recvErr := pty.Recv(ctx)
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		if event.Kind == silo.ExecutionEventStarted {
			break
		}
	}
	if err = pty.ResizePTY(ctx, 40, 120); err != nil {
		t.Fatal(err)
	}
	if err = pty.Signal(ctx, 15); err != nil {
		t.Fatal(err)
	}
	if _, err = pty.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err = pty.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, err := machine.Spawn(ctx, "/bin/sleep", []string{"30"})
	if err != nil {
		t.Fatal(err)
	}
	if err = cancelled.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err = cancelled.Close(); err != nil {
		t.Fatal(err)
	}
	logs, err := machine.Logs(ctx, silo.MachineLogExec, silo.MachineLogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	for {
		_, err = logs.Recv(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	follow, err := machine.Logs(ctx, silo.MachineLogMonitor, silo.MachineLogOptions{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	followCtx, followCancel := context.WithTimeout(ctx, 30*time.Second)
	if _, err = follow.Recv(followCtx); err != nil {
		followCancel()
		t.Fatal(err)
	}
	followCancel()
	if _, err = machine.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitForReady(t, ctx, machine)
	followCtx, followCancel = context.WithTimeout(ctx, 30*time.Second)
	if _, err = follow.Recv(followCtx); err != nil {
		followCancel()
		t.Fatal(err)
	}
	followCancel()
	if err = follow.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = machine.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err = machine.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	detail, err := runtime.Images().Inspect(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("pulled image disappeared before explicit removal")
	}
	if err = runtime.Images().Remove(ctx, image, silo.ForceImageRemoval()); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Images().Prune(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitForReady(t *testing.T, ctx context.Context, machine *silo.Machine) {
	t.Helper()
	readyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var lastStatus silo.MachineStatus
	for {
		data, err := machine.Inspect(readyCtx)
		if err != nil {
			t.Fatal(err)
		}
		lastStatus = data.Status
		if data.Status.Ready != nil && *data.Status.Ready {
			return
		}
		select {
		case <-readyCtx.Done():
			t.Fatalf("machine did not become ready: status=%#v: %v", lastStatus, readyCtx.Err())
		case <-ticker.C:
		}
	}
}
