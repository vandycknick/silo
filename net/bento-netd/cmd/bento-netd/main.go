package main

import (
	"context"
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
	"github.com/vandycknick/bentobox/net/bento-netd/internal/config"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/audit"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/forwarder"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/router"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/policy"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/secrets"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/virtualnetwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func main() {
	if err := configureLogging(""); err != nil {
		fmt.Fprintf(os.Stderr, "configure logging: %v\n", err)
		os.Exit(1)
	}
	if err := run(os.Args[1:]); err != nil {
		slog.Error("netd failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}
	if err := configureLogging(cfg.LogFile); err != nil {
		return err
	}
	logPolicyWarnings(cfg.Policy)
	if cfg.PIDFile != "" {
		if err := writePIDFile(cfg.PIDFile); err != nil {
			return err
		}
		defer os.Remove(cfg.PIDFile)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	hook := hooks.NewPolicyHook(cfg.Policy)
	auditLog, err := openAuditLogger(cfg.LogFile)
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

func logPolicyWarnings(compiled *policy.Policy) {
	if compiled == nil {
		return
	}
	for _, warning := range compiled.Warnings() {
		slog.Warn("policy load warning", "warning", warning)
	}
}

func openAuditLogger(logFile string) (*audit.Logger, error) {
	auditPath := auditPathForLogFile(logFile)
	if auditPath == "" {
		return nil, nil
	}
	auditLog, err := audit.Open(auditPath)
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

func configureLogging(logFile string) error {
	var output io.Writer = os.Stderr
	if logFile == "" {
		configureStructuredLoggers(output)
		return nil
	}
	f, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logFile, err)
	}
	output = f
	configureStructuredLoggers(output)
	return nil
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
