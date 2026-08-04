package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	log "github.com/sirupsen/logrus"
	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/logfile"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"github.com/vandycknick/silo/net/netd/internal/registry"
	"github.com/vandycknick/silo/net/netd/internal/session"
)

const (
	gracefulShutdownTimeout = 10 * time.Second
	forcedShutdownTimeout   = 2 * time.Second
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		writeErrorRecords(os.Stderr, err)
		os.Exit(1)
	}
	logDirectory, err := logfile.OpenDirectory(cfg.LogDirFD)
	if err != nil {
		writeErrorRecords(os.Stderr, fmt.Errorf("open network log directory: %w", err))
		os.Exit(1)
	}
	runtimeDirectory, err := logfile.OpenDirectory(cfg.RuntimeDirFD)
	if err != nil {
		_ = logDirectory.Close()
		writeErrorRecords(os.Stderr, fmt.Errorf("open network runtime directory: %w", err))
		os.Exit(1)
	}
	serviceLog, err := configureLogging(logDirectory, cfg.LogFile)
	if err != nil {
		exitWithStartupError(cfg, nil, logDirectory, runtimeDirectory, fmt.Errorf("configure logging: %w", err))
	}
	compiledPolicy, err := config.LoadPolicy(cfg)
	if err != nil {
		exitWithStartupError(cfg, serviceLog, logDirectory, runtimeDirectory, err)
	}
	auditFile, err := openAuditLog(logDirectory, cfg.AuditLogFile)
	if err != nil {
		exitWithStartupError(cfg, serviceLog, logDirectory, runtimeDirectory, err)
	}
	auditLog := audit.New(auditFile, compiledPolicy.PolicyHash())
	runErr := run(cfg, compiledPolicy, auditLog, runtimeDirectory)
	if auditLog != nil {
		runErr = errors.Join(runErr, auditLog.Close())
	}
	if auditFile != nil {
		runErr = errors.Join(runErr, auditFile.Close())
	}
	if runErr != nil {
		slog.Error("netd failed", "error", runErr)
	}
	runErr = errors.Join(runErr, closeServiceLog(serviceLog))
	runErr = errors.Join(runErr, logDirectory.Close(), runtimeDirectory.Close())
	if runErr != nil {
		writeErrorRecords(os.Stderr, runErr)
		os.Exit(1)
	}
}

func reportStartupError(writer io.Writer, cfg *config.Config, err error) {
	if cfg != nil && cfg.LogFile != "" {
		slog.Error("netd failed", "error", err)
	}
	writeErrorRecords(writer, err)
}

func exitWithStartupError(cfg *config.Config, serviceLog *os.File, logDirectory, runtimeDirectory *logfile.Directory, err error) {
	reportStartupError(os.Stderr, cfg, err)
	if closeErr := errors.Join(closeServiceLog(serviceLog), logDirectory.Close(), runtimeDirectory.Close()); closeErr != nil {
		writeErrorRecords(os.Stderr, closeErr)
	}
	os.Exit(1)
}

func run(cfg *config.Config, compiledPolicy *policy.Policy, auditLog *audit.Logger, runtimeDirectory *logfile.Directory) (runErr error) {
	if cfg == nil {
		return errors.New("missing configuration")
	}
	if compiledPolicy == nil {
		return errors.New("missing compiled policy")
	}
	if runtimeDirectory == nil {
		return errors.New("network runtime directory is required")
	}
	var captureFile *os.File
	if cfg.CaptureFile != "" {
		file, err := runtimeDirectory.OpenTruncate(cfg.CaptureFile)
		if err != nil {
			return fmt.Errorf("open packet capture %s: %w", cfg.CaptureFile, err)
		}
		captureFile = file
		defer func() {
			if captureFile != nil {
				runErr = errors.Join(runErr, logfile.SyncClose(captureFile))
			}
		}()
	}
	logPolicyDiagnostics(compiledPolicy)
	slog.Info("netd service generation started", "vm_id", cfg.Metadata.VMID, "run_id", cfg.Metadata.RunID, "network_id", cfg.Metadata.NetworkID)
	defer slog.Info("netd service generation stopped", "vm_id", cfg.Metadata.VMID, "run_id", cfg.Metadata.RunID, "network_id", cfg.Metadata.NetworkID)
	auditLog.RecordGenerationBoundary("start", cfg.Metadata.VMID, cfg.Metadata.RunID, cfg.Metadata.NetworkID)
	defer auditLog.RecordGenerationBoundary("stop", cfg.Metadata.VMID, cfg.Metadata.RunID, cfg.Metadata.NetworkID)
	if cfg.PIDFile != "" {
		if err := writePIDFile(runtimeDirectory, cfg.PIDFile); err != nil {
			return err
		}
		defer func() {
			if err := runtimeDirectory.Remove(cfg.PIDFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				runErr = errors.Join(runErr, err)
			}
		}()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	intelligencePool := registry.NewIntelligencePool(nil)
	vmSession, err := session.New(session.Spec{
		VMID:        cfg.Metadata.VMID,
		RunID:       cfg.Metadata.RunID,
		NetworkID:   cfg.Metadata.NetworkID,
		CaptureFile: captureFile,
		Stack:       cfg.Stack,
		Policy:      compiledPolicy,
		CACert:      cfg.TLS.CACert,
		CAKey:       cfg.TLS.CAKey,
	}, session.Shared{Audit: auditLog, Intelligence: intelligencePool})
	captureFile = nil
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, vmSession.Close())
	}()
	intelligenceCtx, stopIntelligence := context.WithCancel(context.Background())
	intelligenceDone := make(chan error, 1)
	go func() {
		intelligenceDone <- intelligencePool.Run(intelligenceCtx)
	}()
	defer func() {
		stopIntelligence()
		runErr = errors.Join(runErr, <-intelligenceDone)
	}()

	conn, err := transport.ListenUnixgram(cfg.ListenVfkit)
	if err != nil {
		return fmt.Errorf("vfkit listen error: %w", err)
	}
	if err := secureEndpoint(cfg.ListenVfkit); err != nil {
		_ = conn.Close()
		removeEndpoint(cfg.ListenVfkit)
		return err
	}
	defer conn.Close()
	defer removeEndpoint(cfg.ListenVfkit)

	slog.Info("netd ready", "listen_vfkit", cfg.ListenVfkit, "subnet", cfg.Stack.Subnet)
	acceptDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-acceptDone:
		}
	}()
	vfkitConn, err := transport.AcceptVfkit(conn)
	close(acceptDone)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("vfkit accept error: %w", err)
	}

	sessionDone := make(chan error, 1)
	go func() {
		sessionDone <- vmSession.Run(context.Background(), vfkitConn)
	}()
	select {
	case err := <-sessionDone:
		return err
	case <-ctx.Done():
	}
	stopIntelligence()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	shutdownErr := vmSession.Shutdown(shutdownCtx)
	shutdownCancel()
	if shutdownErr != nil {
		slog.Warn("session graceful shutdown did not complete", "error", shutdownErr)
		shutdownErr = errors.Join(shutdownErr, vmSession.Close())
	}
	forceTimer := time.NewTimer(forcedShutdownTimeout)
	defer forceTimer.Stop()
	select {
	case err := <-sessionDone:
		return errors.Join(shutdownErr, err)
	case <-forceTimer.C:
		return errors.Join(shutdownErr, fmt.Errorf("session forced shutdown timed out after %s", forcedShutdownTimeout))
	}
}

type errorRecord struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

func writeErrorRecords(writer io.Writer, err error) {
	encoder := json.NewEncoder(writer)
	var loadErr *policy.LoadError
	if errors.As(err, &loadErr) {
		wrote := false
		for _, diagnostic := range loadErr.Diagnostics {
			if diagnostic.Severity != "error" {
				continue
			}
			_ = encoder.Encode(policyDiagnosticToErrorRecord(loadErr.Filename, diagnostic))
			wrote = true
		}
		if wrote {
			return
		}
	}
	_ = encoder.Encode(errorRecord{Type: "startup_error", Message: err.Error()})
}

func policyDiagnosticToErrorRecord(filename string, diagnostic policy.Diagnostic) errorRecord {
	record := errorRecord{Type: "policy_error", Message: "Invalid policy"}
	if diagnostic.Summary != "" {
		record.Message = diagnostic.Summary
	}
	record.Detail = diagnostic.Detail
	record.File = diagnostic.File
	record.Line = diagnostic.Line
	record.Column = diagnostic.Column
	if record.File == "" {
		record.File = filename
	}
	return record
}

func logPolicyDiagnostics(compiled *policy.Policy) {
	if compiled == nil {
		return
	}
	for _, diagnostic := range compiled.Diagnostics() {
		if diagnostic.Severity != "warning" {
			continue
		}
		slog.Warn(
			"policy load warning",
			"summary", diagnostic.Summary,
			"detail", diagnostic.Detail,
			"file", diagnostic.File,
			"line", diagnostic.Line,
			"column", diagnostic.Column,
		)
	}
}

func openAuditLog(directory *logfile.Directory, name string) (*os.File, error) {
	if name == "" {
		return nil, errors.New("audit log path is required")
	}
	file, err := directory.OpenAppend(name)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", name, err)
	}
	return file, nil
}

func configureLogging(directory *logfile.Directory, logFile string) (*os.File, error) {
	var output io.Writer = os.Stderr
	if logFile == "" {
		configureStructuredLoggers(output)
		return nil, nil
	}
	f, err := directory.OpenAppend(logFile)
	if err != nil {
		return nil, fmt.Errorf("open service log %s: %w", logFile, err)
	}
	output = f
	configureStructuredLoggers(output)
	return f, nil
}

func closeServiceLog(file *os.File) error {
	return logfile.SyncClose(file)
}

func configureStructuredLoggers(output io.Writer) {
	log.SetOutput(output)
	log.SetFormatter(&log.JSONFormatter{})
	slog.SetDefault(slog.New(slog.NewJSONHandler(output, nil)))
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(false)
	log.StandardLogger().ExitFunc = os.Exit
}

func writePIDFile(directory *logfile.Directory, name string) error {
	return directory.Write(name, []byte(strconv.Itoa(os.Getpid())))
}

func removeEndpoint(endpoint string) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return
	}
	if parsed.Path != "" {
		_ = os.Remove(parsed.Path)
	}
}

func secureEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse vfkit endpoint: %w", err)
	}
	if parsed.Path == "" {
		return errors.New("vfkit endpoint has no socket path")
	}
	if err := os.Chmod(parsed.Path, 0o600); err != nil {
		return fmt.Errorf("set vfkit socket permissions: %w", err)
	}
	info, err := os.Lstat(parsed.Path)
	if err != nil {
		return fmt.Errorf("inspect vfkit socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("vfkit endpoint %s is not a socket", parsed.Path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("vfkit endpoint %s is not owned by the effective user", parsed.Path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("vfkit endpoint %s has mode %04o, want 0600", parsed.Path, info.Mode().Perm())
	}
	return nil
}
