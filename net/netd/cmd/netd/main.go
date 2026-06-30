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
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	log "github.com/sirupsen/logrus"
	"github.com/vandycknick/bentobox/net/netd/internal/config"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/audit"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/forwarder"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/router"
	"github.com/vandycknick/bentobox/net/netd/internal/policy"
	"github.com/vandycknick/bentobox/net/netd/internal/secrets"
	"github.com/vandycknick/bentobox/net/netd/internal/virtualnetwork"
	"golang.org/x/sync/errgroup"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	logFile := ""
	if cfg != nil {
		logFile = cfg.LogFile
	}
	logCloser, logErr := configureLogging(logFile)
	if logErr != nil {
		writeErrorRecords(os.Stderr, fmt.Errorf("configure logging: %w", logErr))
		os.Exit(1)
	}
	if logCloser != nil {
		defer logCloser.Close()
	}
	if err != nil {
		reportAndExitStartupError(os.Stderr, cfg, logCloser, err)
	}
	if err := config.LoadPolicy(cfg); err != nil {
		reportAndExitStartupError(os.Stderr, cfg, logCloser, err)
	}
	if err := run(cfg); err != nil {
		reportAndExitStartupError(os.Stderr, cfg, logCloser, err)
	}
}

func reportStartupError(writer io.Writer, cfg *config.Config, err error) {
	if cfg != nil && cfg.LogFile != "" {
		slog.Error("netd failed", "error", err)
	}
	writeErrorRecords(writer, err)
}

func reportAndExitStartupError(writer io.Writer, cfg *config.Config, logCloser io.Closer, err error) {
	reportStartupError(writer, cfg, err)
	if logCloser != nil {
		_ = logCloser.Close()
	}
	os.Exit(1)
}

func run(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("missing configuration")
	}
	if cfg.Policy == nil {
		if err := config.LoadPolicy(cfg); err != nil {
			return err
		}
	}
	logPolicyDiagnostics(cfg.Policy)
	if cfg.PIDFile != "" {
		if err := writePIDFile(cfg.PIDFile); err != nil {
			return err
		}
		defer os.Remove(cfg.PIDFile)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	hook := hooks.NewPolicyHook(cfg.Policy)
	auditLog, err := openAuditLogger(cfg.LogFile, cfg.Policy.PolicyHash())
	if err != nil {
		return err
	}
	defer auditLog.Close()
	route := router.New(hook, auditLog)
	var secretStore secrets.Store
	if cfg.SecretStore != "" {
		secretStore = secrets.NewFileStore(cfg.SecretStore)
	}
	httpProxy := forwarder.NewHTTPProxy(route)
	httpsProxy, err := forwarder.NewHTTPSProxy(route, cfg.TLS.CACert, cfg.TLS.CAKey, secretStore)
	if err != nil {
		return err
	}
	vn, err := virtualnetwork.New(&cfg.Stack, route, httpProxy, httpsProxy, virtualnetwork.Metadata{
		VMID:      cfg.Metadata.VMID,
		NetworkID: cfg.Metadata.NetworkID,
	})
	if err != nil {
		return err
	}

	conn, err := transport.ListenUnixgram(cfg.ListenVfkit)
	if err != nil {
		return fmt.Errorf("vfkit listen error: %w", err)
	}
	defer conn.Close()
	defer removeEndpoint(cfg.ListenVfkit)

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		<-ctx.Done()
		return conn.Close()
	})
	group.Go(func() error {
		vfkitConn, err := transport.AcceptVfkit(conn)
		if err != nil {
			return fmt.Errorf("vfkit accept error: %w", err)
		}
		return vn.AcceptVfkit(ctx, vfkitConn)
	})
	slog.Info("netd ready", "listen_vfkit", cfg.ListenVfkit, "subnet", cfg.Stack.Subnet)
	return group.Wait()
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

func openAuditLogger(logFile string, policyHash string) (*audit.Logger, error) {
	auditPath := auditPathForLogFile(logFile)
	if auditPath == "" {
		return nil, nil
	}
	auditLog, err := audit.Open(auditPath, policyHash)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", auditPath, err)
	}
	return auditLog, nil
}

func auditPathForLogFile(logFile string) string {
	if logFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(logFile), "audit.jsonl")
}

func configureLogging(logFile string) (io.Closer, error) {
	var output io.Writer = os.Stderr
	if logFile == "" {
		configureStructuredLoggers(output)
		return nil, nil
	}
	f, err := openLogFile(logFile)
	if err != nil {
		return nil, err
	}
	output = f
	configureStructuredLoggers(output)
	return f, nil
}

func openLogFile(logFile string) (*os.File, error) {
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", logFile, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("set log file permissions %s: %w", logFile, err)
	}
	return f, nil
}

func configureStructuredLoggers(output io.Writer) {
	log.SetOutput(output)
	log.SetFormatter(&log.JSONFormatter{})
	slog.SetDefault(slog.New(slog.NewJSONHandler(output, nil)))
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(false)
	log.StandardLogger().ExitFunc = os.Exit
}

func writePIDFile(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644)
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
