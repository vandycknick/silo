// Run from app/taild's module against an already-running packaged manager.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func canonical(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("absolute paths required")
	}
	return filepath.EvalSymlinks(path)
}

func run() error {
	endpoint := flag.String("endpoint", "", "running manager's same-user Unix socket")
	home := flag.String("home", "", "manager's canonical fresh Home")
	bridge := flag.String("bridge", "", "explicit product bridge adjacent to silod")
	configDir := flag.String("config-dir", "", "manager's canonical configuration directory")
	root := flag.String("components-root", "", "portable root or Silo.app for exact component admission")
	inspect := flag.Bool("inspect", false, "admit manager/components/native SDK and print JSON; no VM")
	statusOnly := flag.Bool("status-only", false, "admit the live core without resolving native assets")
	disk := flag.String("disk", "", "disposable bootable Linux disk image with /bin/sh")
	memory := flag.Uint64("memory-mib", 1024, "guest memory budget")
	flag.Parse()
	if *inspect && *statusOnly {
		return errors.New("inspect and status-only are mutually exclusive")
	}
	for _, value := range []string{*endpoint, *home, *bridge, *root, *configDir} {
		if !filepath.IsAbs(value) {
			return errors.New("endpoint, home, bridge, components-root and config-dir must be absolute")
		}
	}
	info, err := os.Lstat(*endpoint)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return errors.New("manager endpoint is not a Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o077 != 0 {
		return errors.New("manager endpoint is not private to this UID")
	}
	for _, path := range []string{*home, *configDir, *root, *bridge} {
		resolved, err := canonical(path)
		if err != nil || resolved != path {
			return fmt.Errorf("noncanonical admission path %q: %v", path, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	var dialMu sync.Mutex
	connected := false
	connection, err := grpc.NewClient("passthrough:///packaged-silod", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableRetry(), grpc.WithIdleTimeout(0), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		if connected {
			return nil, errors.New("admitted manager connection lost; replacement refused")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", *endpoint)
		if err == nil {
			connected = true
		}
		return conn, err
	}))
	if err != nil {
		return err
	}
	defer connection.Close()
	daemon := w.NewDaemonServiceClient(connection)
	status, err := daemon.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	if status.Core != w.CorePhase_CORE_PHASE_READY || status.ProductVersion != silo.Version || status.ProtocolMajor != 1 || string(status.Home) != *home || string(status.ConfigDir) != *configDir || string(status.ControlEndpoint) != *endpoint || status.Pid == 0 || status.Generation == "" {
		return errors.New("manager identity/readiness mismatch")
	}
	if *statusOnly {
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	selected, err := daemon.GetRuntimeInfo(ctx, &emptypb.Empty{})
	if err != nil {
		return err
	}
	if selected.Generation != status.Generation || string(selected.Home) != *home || selected.Components == nil {
		return errors.New("runtime selection identity mismatch")
	}
	c := selected.Components
	components := silo.RuntimeComponents{SupervisorPath: string(c.SupervisorPath), NetdPath: string(c.NetdPath), KernelPath: string(c.KernelPath), InitramfsPath: string(c.InitramfsPath), AgentPath: string(c.AgentPath), AssetDir: string(c.AssetDir)}
	bin, assets := filepath.Join(*root, "bin"), filepath.Join(*root, "assets")
	if filepath.Ext(*root) == ".app" {
		bin, assets = filepath.Join(*root, "Contents", "Helpers"), filepath.Join(*root, "Contents", "Resources", "assets")
	}
	for _, component := range [...]struct{ actual, expected string }{
		{components.SupervisorPath, filepath.Join(bin, "silo-vmm")},
		{components.NetdPath, filepath.Join(bin, "netd")},
		{components.KernelPath, filepath.Join(assets, "kernel-default")},
		{components.InitramfsPath, filepath.Join(assets, "initramfs")},
		{components.AgentPath, filepath.Join(assets, "agent")},
		{components.AssetDir, assets},
	} {
		actual, expected := component.actual, component.expected
		path, err := canonical(expected)
		if err != nil || actual != path {
			return fmt.Errorf("manager selected unexpected component %q, expected %q: %v", actual, path, err)
		}
	}
	library := "libsilo_go_ffi.so"
	if runtime.GOOS == "darwin" {
		library = "libsilo_go_ffi.dylib"
	}
	expectedBridge, err := canonical(filepath.Join(bin, library))
	if err != nil || expectedBridge != *bridge {
		return errors.New("bridge is not the canonical product sibling")
	}
	if err := os.Setenv("SILO_GO_FFI_PATH", *bridge); err != nil {
		return err
	}
	sessions, err := silo.Open(ctx, silo.WithHome(*home), silo.WithRuntimeComponents(components))
	if err != nil {
		return err
	}
	defer sessions.Close()
	if *inspect {
		return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"generation": status.Generation, "components": components, "bridge": *bridge, "home": *home})
	}
	if os.Getenv("SILO_E2E_VM") != "1" || !filepath.IsAbs(*disk) || *memory == 0 {
		return errors.New("VM execution requires SILO_E2E_VM=1, absolute disposable disk and positive memory")
	}
	if runtime.GOOS == "linux" {
		kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("KVM prerequisite: %w", err)
		}
		kvm.Close()
	} else if runtime.GOOS != "darwin" {
		return errors.New("native Linux KVM or macOS HVF required")
	}
	agent, err := os.Stat(components.AgentPath)
	if err != nil {
		return err
	}
	if *memory <= 256 && agent.Size() > 64<<20 {
		return errors.New("oversized agent requires more than 256MiB")
	}
	machines := w.NewMachineServiceClient(connection)
	name, cpus, bytes, diskSize := "packaged-native-acceptance", uint32(1), *memory<<20, uint64(1<<30)
	stream, err := machines.CreateMachine(ctx, &w.CreateMachineRequest{Configuration: &w.NormalizedMachineCreate{Name: &name, Cpus: &cpus, MemoryBytes: &bytes, RootDiskSizeBytes: &diskSize, Retention: w.Retention_RETENTION_PERSISTENT, Process: &w.ProcessConfig{}, Agent: &w.Agent{Mode: &w.Agent_DefaultAgent{DefaultAgent: &emptypb.Empty{}}}, Network: &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_None{None: &emptypb.Empty{}}}}, Source: &w.CreateMachineRequest_DiskPath{DiskPath: []byte(*disk)}})
	if err != nil {
		return err
	}
	var id string
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if machine := event.GetMachine(); machine != nil {
			id = machine.Id
		}
	}
	if id == "" {
		return errors.New("create RPC returned no exact machine ID")
	}
	ref := &w.MachineRef{Reference: &w.MachineRef_Id{Id: id}}
	runID := ""
	removed := false
	defer func() {
		if removed {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if runID == "" {
			if _, err := machines.RemoveMachine(cleanup, &w.RemoveMachineRequest{Machine: ref}); err != nil {
				fmt.Fprintln(os.Stderr, "cleanup remove:", err)
			}
			return
		}
		if _, err := machines.StopMachine(cleanup, &w.StopMachineRequest{Machine: ref, ExpectedRun: &runID, Force: true}); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup stop:", err)
		}
		if _, err := machines.RemoveAfterRun(cleanup, &w.MachineRunRef{Id: id, RunId: runID}); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup remove:", err)
		}
	}()
	started, err := machines.StartMachine(ctx, &w.StartMachineRequest{Machine: ref, Options: &w.StartOptions{}})
	if err != nil {
		return err
	}
	runID = started.RunId
	if runID == "" {
		return errors.New("start RPC returned no run identity")
	}
	machine, err := sessions.Machine(ctx, id)
	if err != nil {
		return err
	}
	defer machine.Close()
	if _, err := machines.WaitReady(ctx, &w.WaitReadyRequest{Id: id, ExpectedRun: &runID, Timeout: durationpb.New(90 * time.Second)}); err != nil {
		return err
	}
	data, err := machines.InspectMachine(ctx, ref)
	if err != nil {
		return err
	}
	if data.RunId == nil || *data.RunId != runID {
		return errors.New("SDK exact-ID session changed managed run")
	}
	result, err := machine.Exec(ctx, "/bin/sh", []string{"-c", "printf packaged-native-ok"})
	if err != nil {
		return err
	}
	exit := result.Result()
	if result.Stdout() != "packaged-native-ok" || exit.Kind != silo.ExecutionResultExited || exit.Code == nil || *exit.Code != 0 {
		return errors.New("actual packaged guest execution failed")
	}
	if _, err := machines.StopMachine(ctx, &w.StopMachineRequest{Machine: ref, ExpectedRun: &runID}); err != nil {
		return err
	}
	if _, err := machines.RemoveAfterRun(ctx, &w.MachineRunRef{Id: id, RunId: runID}); err != nil {
		return err
	}
	removed = true
	fmt.Printf("PASS native %s management RPC + exact-ID SDK guest exec: machine=%s run=%s memory=%dMiB\n", runtime.GOOS, id, started.RunId, *memory)
	return nil
}
