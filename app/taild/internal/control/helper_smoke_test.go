package control

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/emptypb"
)

// This is a real process/VM fixture. The local control-plane socket deliberately
// never answers, exercising helper ownership while enrollment cannot complete.
func TestIntegratedHelperLifetime(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("requires explicit KVM admission")
	}
	bin, rootfs := os.Getenv("SILO_TEST_BIN_DIR"), os.Getenv("SILO_TEST_ROOTFS")
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

	blocked, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	registry := testfixture.OCIRegistry(t, rootfs)
	home := t.TempDir()
	configDir := filepath.Join(home, "config", "silo")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf("daemon:\n  version: '1'\n  system:\n    enabled: false\n  tailscale:\n    enabled: true\n    control-url: 'http://%s'\n    enrollment:\n      mode: none\n", blocked.Addr())
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	environment := []string{"HOME=" + home, "SILO_HOME=" + filepath.Join(home, "state"), "XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "PATH=" + os.Getenv("PATH")}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	hostProbe, finishProbe := context.WithTimeout(ctx, 3*time.Second)
	hostState, _ := exec.CommandContext(hostProbe, "systemctl", "is-system-running").Output()
	finishProbe()
	guardAvailable := false
	switch strings.TrimSpace(string(hostState)) {
	case "running", "degraded", "starting", "initializing", "maintenance", "offline":
		guardAvailable = true
	case "stopping":
		t.Skip("host is actually shutting down")
	default:
		t.Log("actual host-state guard unavailable; helper lifetime checks still run")
	}
	runCLI := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, filepath.Join(bin, "silo"), args...)
		command.Env = environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("silo %v: %v: %s", args, err, output)
		}
	}
	machineCreated := false
	t.Cleanup(func() {
		if !machineCreated {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, args := range [][]string{{"stop", "--force", "helper-lifetime"}, {"rm", "helper-lifetime"}} {
			command := exec.CommandContext(cleanup, filepath.Join(bin, "silo"), args...)
			command.Env = environment
			if output, err := command.CombinedOutput(); err != nil {
				t.Errorf("fixture cleanup %v: %v: %s", args, err, output)
			}
		}
	})

	var daemon *exec.Cmd
	var exited chan error
	var reaped bool
	var helpers []*os.Process
	t.Cleanup(func() {
		if daemon != nil && !reaped {
			_ = daemon.Process.Kill()
			<-exited
		}
		for _, helper := range helpers {
			if helperAlive(helper.Pid) {
				_ = helper.Kill()
			}
			_ = helper.Release()
		}
	})
	startDaemon := func() *Client {
		t.Helper()
		daemon = exec.Command(filepath.Join(bin, "silod"))
		daemon.Env, daemon.Stderr = environment, os.Stderr
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
		reaped = false
		exited = make(chan error, 1)
		command, done := daemon, exited
		go func() { done <- command.Wait() }()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case err := <-exited:
				reaped = true
				t.Fatalf("daemon exited during startup: %v", err)
			default:
			}
			client, err := New(fmt.Sprintf("/tmp/silo-%d/silod/control.sock", os.Getuid()), "")
			if err == nil {
				probe, cancel := context.WithTimeout(ctx, time.Second)
				status, err := client.Daemon.GetStatus(probe, &emptypb.Empty{})
				cancel()
				if err == nil && status.Core == w.CorePhase_CORE_PHASE_READY {
					return client
				}
				_ = client.Close()
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("core did not become ready independently of enrollment")
		return nil
	}
	waitHelper := func(exclude int) int {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			output, err := exec.Command("pgrep", "-P", strconv.Itoa(daemon.Process.Pid), "-x", "taild").Output()
			if err == nil {
				ids := strings.Fields(string(output))
				if len(ids) > 1 {
					t.Fatalf("multiple helper children: %s", output)
				}
				if len(ids) == 1 {
					pid, err := strconv.Atoi(ids[0])
					_, stateErr := os.Stat(filepath.Join(home, "state", "taild", "tsnet"))
					if err == nil && pid != exclude && stateErr == nil {
						process, err := os.FindProcess(pid)
						if err != nil {
							t.Fatal(err)
						}
						helpers = append(helpers, process)
						return pid
					}
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("helper did not start or replace its failed generation")
		return 0
	}
	client := startDaemon()
	defer func() { _ = client.Close() }()
	first := waitHelper(0)
	mappings, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", first))
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.EvalSymlinks(filepath.Join(bin, "libsilo_go_ffi.so"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mappings), bridge) {
		t.Fatal("actual helper did not map the manager-selected native bridge")
	}
	instance, err := state.ReadInstance(filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.Daemon.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	selected := info.Components
	t.Setenv("SILO_GO_FFI_PATH", filepath.Join(bin, "libsilo_go_ffi.so"))
	sessions, err := silo.Open(ctx, silo.WithHome(string(info.Home)), silo.WithRuntimeComponents(silo.RuntimeComponents{SupervisorPath: string(selected.SupervisorPath), NetdPath: string(selected.NetdPath), KernelPath: string(selected.KernelPath), InitramfsPath: string(selected.InitramfsPath), AgentPath: string(selected.AgentPath), AssetDir: string(selected.AssetDir)}))
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	// Spawn through silod after its owner writer exists. A leaked descriptor in
	// this surviving VMM would keep the orphan helper alive after silod dies.
	runCLI("create", "--name", "helper-lifetime", "--cpus", "1", "--memory", "512MiB", "--network", "none", registry.Reference)
	machineCreated = true
	if _, err := client.Machines.UpdateMachine(ctx, &w.UpdateMachineRequest{
		Machine: &w.MachineRef{Reference: &w.MachineRef_Name{Name: "helper-lifetime"}},
		Update: &w.MachineUpdate{Labels: &w.StringMap{Values: map[string]string{
			"io.silo.taild.owner": "user:7", "io.silo.taild.name": "helper-lifetime",
			"io.silo.taild.instance": instance, "io.silo.taild.node.mode": "none",
		}}},
	}); err != nil {
		t.Fatal(err)
	}
	runCLI("start", "helper-lifetime")
	machine, err := client.Machines.InspectMachine(ctx, &w.MachineRef{Reference: &w.MachineRef_Name{Name: "helper-lifetime"}})
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sessions.Machine(ctx, machine.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	assertRun := func() {
		t.Helper()
		data, err := handle.Inspect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if data.Status.Kind != silo.MachineStatusRunning || data.RunID == nil || *data.RunID != machine.GetRunId() {
			t.Fatalf("helper lifetime changed VM generation: %+v", data)
		}
		current, err := state.ReadInstance(filepath.Join(home, "state"))
		if err != nil || current != instance {
			t.Fatalf("helper instance changed: %q -> %q (%v)", instance, current, err)
		}
	}
	guardShutdown := func(scenario string) {
		t.Helper()
		if !guardAvailable {
			return
		}
		guard, finish := context.WithTimeout(ctx, 20*time.Second)
		defer finish()
		command := exec.CommandContext(guard, filepath.Join(bin, "silod"), "--host-shutdown")
		command.Env = append(append([]string(nil), environment...),
			"SILO_RUNTIME_DIR="+filepath.Join(home, "absent-runtime"),
			"SILO_GO_FFI_PATH="+filepath.Join(home, "absent-bridge"))
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s host-shutdown guard: %v: %s", scenario, err, output)
		}
		assertRun()
		if _, err := os.Lstat(filepath.Join(home, "state", "taild", "shutdown")); !os.IsNotExist(err) {
			t.Fatalf("%s created a shutdown marker on a non-stopping host: %v", scenario, err)
		}
		t.Logf("%s guarded shutdown preserved managed VM on actual host state %s", scenario, strings.TrimSpace(string(hostState)))
	}
	if err := unix.Kill(first, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	replacement := waitHelper(first)
	status, err := client.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if status.Core != w.CorePhase_CORE_PHASE_READY || status.Tailscale.GetRestartCount() == 0 {
		t.Fatalf("helper failure did not preserve core/report restart: %v", status)
	}
	assertRun()
	guardShutdown("live manager")
	currentStatus, err := client.Daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil || currentStatus.GetGeneration() != status.Generation || !helperAlive(replacement) {
		t.Fatalf("one-shot shutdown replaced the live manager/helper: %v %v", currentStatus, err)
	}
	if err := daemon.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-exited
	reaped = true
	deadline := time.Now().Add(5 * time.Second)
	for helperAlive(replacement) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if helperAlive(replacement) {
		t.Fatal("owner EOF left helper alive beyond five seconds")
	}
	assertRun()
	_ = client.Close()
	guardShutdown("crashed manager with stale socket")
	client = startDaemon()
	gracefulHelper := waitHelper(0)
	if err := daemon.Process.Signal(unix.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		reaped = true
		if err != nil {
			t.Fatalf("graceful daemon exit: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("idle helper did not drain promptly")
	}
	if helperAlive(gracefulHelper) {
		t.Fatal("normal shutdown did not reap helper")
	}
	assertRun()
	guardShutdown("stopped manager without socket")
	t.Logf("helper replacement %d -> %d; owner EOF and normal drain preserved instance=%s VM=%s run=%s", first, replacement, instance, machine.Id, machine.GetRunId())
}

func helperAlive(pid int) bool {
	if err := unix.Kill(pid, 0); err == unix.ESRCH {
		return false
	}
	// A killed parent cannot reap its orphan. A transient zombie has exited and
	// no longer holds the Home lock or descriptors, so it satisfies EOF exit.
	if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		_, suffix, found := strings.Cut(string(stat), ") ")
		if found && strings.HasPrefix(suffix, "Z ") {
			return false
		}
	}
	return true
}
