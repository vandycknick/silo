// Run against the isolated qualified SDK source, never the development bridge.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	archive := flag.String("archive", "", "actual packaged runtime archive")
	disk := flag.String("disk", "", "disposable bootable Linux disk image with /bin/sh")
	home := flag.String("home", "", "new isolated evidence directory (retained)")
	memory := flag.Uint64("memory-mib", 1024, "guest memory budget to qualify")
	flag.Parse()
	if *archive == "" || *disk == "" || !filepath.IsAbs(*home) || *memory == 0 {
		return errors.New("archive, disk, absolute new home and positive memory are required")
	}
	if os.Getenv("SILO_GO_FFI_PATH") != "" {
		return errors.New("unset SILO_GO_FFI_PATH; qualification requires the embedded bridge")
	}
	if err := os.Mkdir(*home, 0o700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
	defer cancel()
	installed, err := silo.InstallRuntime(ctx, silo.WithInstallRoot(filepath.Join(*home, "runtimes")), silo.WithRuntimeArchive(*archive))
	if err != nil {
		return err
	}
	agent, err := os.Stat(filepath.Join(installed.Root, "assets/agent"))
	if err != nil {
		return err
	}
	// Refuse the known oversized debug-artifact case before reproducing an OOM.
	if *memory <= 256 && agent.Size() > 64<<20 {
		return errors.New("unqualified low-memory artifact: agent exceeds 64MiB; use at least 1GiB")
	}
	runtime, err := silo.Open(ctx, silo.WithHome(*home), silo.WithRuntimeRoot(installed.Root))
	if err != nil {
		return err
	}
	defer runtime.Close()
	policy, err := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{DefaultAction: silo.NetworkDeny})
	if err != nil {
		return err
	}
	machine, err := runtime.CreateMachine(ctx, silo.DiskImage(*disk), silo.WithName("packaged-memory-acceptance"), silo.WithCPUs(1), silo.WithMemory(silo.Mebibytes(*memory)), silo.WithRootDiskSize(silo.Gibibytes(1)), silo.WithMachineNetwork(silo.PrivateNetwork(policy)))
	if err != nil {
		return err
	}
	defer machine.Close()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if _, err := machine.Stop(cleanup); err != nil {
			fmt.Fprintln(os.Stderr, "cleanup stop:", err)
		}
	}()
	if _, err = machine.Start(ctx); err != nil {
		return err
	}
	if _, err = machine.WaitReady(ctx, 90*time.Second); err != nil {
		return err
	}
	result, err := machine.Exec(ctx, "/bin/sh", []string{"-c", "printf packaged-memory-ok"})
	if err != nil {
		return err
	}
	status := result.Result()
	if result.Stdout() != "packaged-memory-ok" || status.Kind != silo.ExecutionResultExited || status.Code == nil || *status.Code != 0 {
		return errors.New("packaged guest execution proof failed")
	}
	if _, err = machine.Stop(ctx); err != nil {
		return err
	}
	fmt.Printf("PASS actual packaged runtime guest execution at %dMiB, agent bytes=%d, evidence=%s\n", *memory, agent.Size(), *home)
	return nil
}
