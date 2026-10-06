package control

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// This opt-in fixture runs a real daemon, OCI registry and KVM guest under an idle UID.
func TestNativeControlLifecycle(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("requires explicit KVM admission")
	}
	bin := os.Getenv("SILO_TEST_BIN_DIR")
	rootfs := os.Getenv("SILO_TEST_ROOTFS")
	if !filepath.IsAbs(bin) || !filepath.IsAbs(rootfs) {
		t.Fatal("absolute SILO_TEST_BIN_DIR and SILO_TEST_ROOTFS required")
	}
	lock, err := os.OpenFile(filepath.Join(os.TempDir(), fmt.Sprintf("silo-control-fixture-%d.lock", os.Getuid())), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("use an idle dedicated test UID:", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if err := exec.Command("pgrep", "-x", "silod").Run(); err == nil {
		t.Fatal("live silod found; use an idle dedicated test UID")
	}
	registry := testfixture.OCIRegistry(t, rootfs)
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := exec.Command(filepath.Join(bin, "silod"), "--system-enabled=false", "--tailscale-enabled=false")
	command.Env = []string{"HOME=" + home, "SILO_HOME=" + filepath.Join(home, "state"), "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "PATH=" + os.Getenv("PATH")}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "SILO_RUNTIME_DIR"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Signal(unix.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(90 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("daemon failed to drain")
		}
	}()
	endpoint := fmt.Sprintf("/tmp/silo-%d/silod/control.sock", os.Getuid())
	var client *Client
	for {
		client, err = New(endpoint, "")
		if err == nil {
			var status *w.DaemonStatus
			status, err = client.Daemon.GetStatus(ctx, &emptypb.Empty{})
			if err == nil && status.Core == w.CorePhase_CORE_PHASE_READY {
				break
			}
			_ = client.Close()
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer client.Close()
	status, err := client.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if string(status.Home) != filepath.Join(home, "state") || status.Core != w.CorePhase_CORE_PHASE_READY {
		t.Fatalf("unexpected daemon: %v", status)
	}
	info, err := client.Daemon.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Generation != status.Generation || string(info.Home) != string(status.Home) || info.Components == nil {
		t.Fatal("runtime selection identity mismatch")
	}
	if _, err := os.Stat(filepath.Join(home, "state", "state.db")); !os.IsNotExist(err) {
		t.Fatalf("status or component resolution initialized the store: %v", err)
	}
	images, err := client.Runtime.ResolveImage(ctx, &w.ResolveImageRequest{Reference: registry.Reference, PullPolicy: w.PullPolicy_PULL_POLICY_ALWAYS})
	if err != nil {
		t.Fatal(err)
	}
	var image *w.ResolvedImage
	for {
		event, err := images.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.GetImage() != nil {
			image = event.GetImage()
		}
	}
	if image == nil {
		t.Fatal("missing immutable image")
	}
	created, err := client.Machines.CreateMachine(ctx, &w.CreateMachineRequest{Configuration: &w.NormalizedMachineCreate{Name: proto.String("control-smoke"), Cpus: proto.Uint32(2), MemoryBytes: proto.Uint64(512 << 20), Retention: w.Retention_RETENTION_PERSISTENT, Process: &w.ProcessConfig{}, Labels: map[string]string{"smoke": "control"}, Network: &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_None{None: &emptypb.Empty{}}}, Agent: &w.Agent{Mode: &w.Agent_DefaultAgent{DefaultAgent: &emptypb.Empty{}}}}, Source: &w.CreateMachineRequest_Oci{Oci: image.Identity}})
	if err != nil {
		t.Fatal(err)
	}
	var machine *w.MachineSnapshot
	for {
		event, err := created.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.GetMachine() != nil {
			machine = event.GetMachine()
		}
	}
	if machine == nil {
		t.Fatal("missing created machine")
	}
	ref := &w.MachineRef{Reference: &w.MachineRef_Id{Id: machine.Id}}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		_, _ = client.Machines.StopMachine(cleanup, &w.StopMachineRequest{Machine: ref, Force: true, Timeout: durationpb.New(10 * time.Second)})
		_, err := client.Machines.RemoveMachine(cleanup, &w.RemoveMachineRequest{Machine: ref})
		if err != nil {
			t.Error("fixture cleanup:", err)
		}
	}()
	inspected, err := client.Machines.InspectMachine(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Name != "control-smoke" || inspected.Labels["smoke"] != "control" || inspected.Spec.Hardware.GetCpus() != 2 {
		t.Fatalf("snapshot mismatch: %v", inspected)
	}
	started, err := client.Machines.StartMachine(ctx, &w.StartMachineRequest{Machine: ref, Options: &w.StartOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := client.Machines.WaitReady(ctx, &w.WaitReadyRequest{Id: machine.Id, ExpectedRun: &started.RunId, Timeout: durationpb.New(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if ready.Outcome != w.ReadinessOutcome_READINESS_OUTCOME_READY {
		t.Fatalf("guest not ready: %v", ready)
	}
	selected := info.Components
	t.Setenv("SILO_GO_FFI_PATH", filepath.Join(bin, "libsilo_go_ffi.so"))
	sessions, err := silo.Open(ctx, silo.WithHome(string(info.Home)), silo.WithRuntimeComponents(silo.RuntimeComponents{SupervisorPath: string(selected.SupervisorPath), NetdPath: string(selected.NetdPath), KernelPath: string(selected.KernelPath), InitramfsPath: string(selected.InitramfsPath), AgentPath: string(selected.AgentPath), AssetDir: string(selected.AssetDir)}))
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	handle, err := sessions.Machine(ctx, machine.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	process, err := handle.Spawn(ctx, "/bin/sh", []string{"-c", "printf out; printf err >&2; exit 7"})
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	output, err := process.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := output.Result()
	if string(output.Stdout()) != "out" || string(output.Stderr()) != "err" || result.Kind != silo.ExecutionResultExited || result.Code == nil || *result.Code != 7 {
		t.Fatalf("direct native execution mismatch: stdout=%q stderr=%q result=%+v", output.Stdout(), output.Stderr(), result)
	}
	if _, err := client.Machines.StopMachine(ctx, &w.StopMachineRequest{Machine: ref, ExpectedRun: &started.RunId, Timeout: durationpb.New(15 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	updated, err := client.Machines.UpdateMachine(ctx, &w.UpdateMachineRequest{Machine: ref, Update: &w.MachineUpdate{Name: proto.String("control-renamed")}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Id != machine.Id || updated.Name != "control-renamed" {
		t.Fatalf("update changed identity: %v", updated)
	}
	t.Logf("real OCI/UDS lifecycle passed: machine=%s run=%s", machine.Id, started.RunId)
}
