package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/vandycknick/silo/net/netd/internal/config"
	"golang.org/x/sys/unix"
)

// The launcher is deliberately short lived. Its worker is adopted by the host
// orphan reaper, not by the CLI/API service that requested this network.
func launchWorker(cfg *config.Config, args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	files := make([]*os.File, 0, 5)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, fd := range []int{cfg.LogDirFD, cfg.RuntimeDirFD, cfg.StartupFD, cfg.ExitFD} {
		file := os.NewFile(uintptr(fd), "netd-inherited")
		if file == nil {
			return fmt.Errorf("invalid inherited descriptor %d", fd)
		}
		files = append(files, file)
		unix.CloseOnExec(fd)
	}
	if err := validatePipe(cfg.StartupFD, unix.O_WRONLY); err != nil {
		return fmt.Errorf("startup pipe: %w", err)
	}
	if err := validatePipe(cfg.ExitFD, unix.O_RDONLY); err != nil {
		return fmt.Errorf("exit pipe: %w", err)
	}
	// ExtraFiles allowlist: log directory 3, runtime directory 4, startup writer
	// 5, lifetime reader 6, unread secrets reader 7 (when present).
	workerArgs := append([]string{}, args...)
	workerArgs = append(workerArgs, "--daemonize=false", "--log-dir-fd=3", "--runtime-dir-fd=4", "--startup-fd=5", "--exit-fd=6")
	if cfg.SecretsFD != -1 {
		if err := validatePipe(cfg.SecretsFD, unix.O_RDONLY); err != nil {
			return fmt.Errorf("secrets pipe: %w", err)
		}
		unix.CloseOnExec(cfg.SecretsFD)
		files = append(files, os.NewFile(uintptr(cfg.SecretsFD), "netd-secrets"))
		workerArgs = append(workerArgs, "--secrets-fd=7")
	}
	command := exec.Command(executable, workerArgs...)
	command.Env = sanitizedEnvironment(os.Environ())
	command.ExtraFiles = files
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Nil standard streams are /dev/null, never pipes owned by a departing CLI.
	if err := command.Start(); err != nil {
		return fmt.Errorf("spawn netd worker: %w", err)
	}
	return command.Process.Release()
}

func sanitizedEnvironment(environment []string) []string {
	clean := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "SILO_NET_") {
			clean = append(clean, entry)
		}
	}
	return clean
}

func sanitizeLegacyEnvironment() error {
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "SILO_NET_") {
			if err := os.Unsetenv(name); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePipe(fd int, access int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("descriptor is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_ACCMODE != access {
		return errors.New("incorrect pipe access mode")
	}
	return nil
}

type startupReport struct {
	PID       int    `json:"pid"`
	VMID      string `json:"vm_id"`
	RunID     string `json:"run_id"`
	NetworkID string `json:"network_id"`
	Ready     bool   `json:"ready"`
	Error     string `json:"error,omitempty"`
}

// A worker reports readiness once, after binding its endpoint, not when its
// launcher exits. Closing this descriptor also bounds the reader on failures.
func reportWorkerStartup(cfg *config.Config, startupErr error) error {
	if cfg.StartupFD < 3 {
		return nil
	}
	fd := cfg.StartupFD
	cfg.StartupFD = -1
	if err := validatePipe(fd, unix.O_WRONLY); err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "netd-startup")
	defer file.Close()
	report := startupReport{PID: os.Getpid(), VMID: cfg.Metadata.VMID, RunID: cfg.Metadata.RunID, NetworkID: cfg.Metadata.NetworkID, Ready: startupErr == nil}
	if startupErr != nil {
		report.Error = startupErr.Error()
	}
	return json.NewEncoder(file).Encode(report)
}

// Only managed workers have an exit pipe. EOF means the last owner of the VM
// lifetime writer is gone; no heartbeat or networking-health policy is involved.
func watchOwner(fd int, cancel func()) (func(), error) {
	if fd < 3 {
		return func() {}, nil
	}
	if err := validatePipe(fd, unix.O_RDONLY); err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "netd-owner-"+strconv.Itoa(fd))
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, file)
		cancel()
	}()
	return func() { _ = file.Close(); <-done }, nil
}
