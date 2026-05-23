package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/nickvan/bentobox/net/bento-netd/internal/config"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/audit"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/router"
	"github.com/nickvan/bentobox/net/bento-netd/internal/virtualnetwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
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
	if cfg.PIDFile != "" {
		if err := writePIDFile(cfg.PIDFile); err != nil {
			return err
		}
		defer os.Remove(cfg.PIDFile)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	auditLog, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer auditLog.Close()

	hook := hooks.NewStaticHook(cfg.Policy.DefaultAction, cfg.Policy.CIDRRules)
	route := router.New(hook, auditLog)
	vn, err := virtualnetwork.New(&cfg.Stack, route, virtualnetwork.Metadata{
		VMID:        cfg.Metadata.VMID,
		NetworkID:   cfg.Metadata.NetworkID,
		ProfileName: cfg.Metadata.ProfileName,
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
	slog.Info("bento-netd ready", "listen_vfkit", cfg.ListenVfkit, "subnet", cfg.Stack.Subnet)
	return group.Wait()
}

func configureLogging(logFile string) error {
	if logFile == "" {
		return nil
	}
	f, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", logFile, err)
	}
	log.SetOutput(f)
	slog.SetDefault(slog.New(slog.NewJSONHandler(f, nil)))
	return nil
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
