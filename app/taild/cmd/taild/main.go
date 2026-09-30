package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/vandycknick/silo/app/taild/internal/bootenv"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/httpd"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "taild:", e)
		os.Exit(1)
	}
}
func run() error {
	configPath := flag.String("config", "/etc/silo-taild/config.yaml", "operator YAML file")
	check := flag.Bool("check", false, "validate config, home, secrets and installed runtime")
	version := flag.Bool("version", false, "print versions")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *version {
		fmt.Printf("taild %s SDK %s tailscale %s\n", service.Versions().Taild, service.Versions().SDK, service.Versions().Tailscale)
		return nil
	}
	c, e := config.Load(*configPath)
	if e != nil {
		return e
	}
	c.Home, e = config.ResolveHome(c.Home, os.Geteuid())
	if e != nil {
		return e
	}
	secrets, e := config.ReadSecrets(c.SecretsDir)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if *check {
		r, err := runtime.Open(ctx, c, "")
		if err != nil {
			return err
		}
		if err = r.Close(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "taild: configuration and runtime ready")
		return nil
	}
	lock, e := state.LockHome(c.Home)
	if e != nil {
		return e
	}
	defer lock.Close()
	for _, dir := range []string{filepath.Join(c.Home, "taild"), filepath.Join(c.Home, "taild", "principals")} {
		if e = state.PrivateDir(dir); e != nil {
			return e
		}
	}
	instance, e := state.Instance(c.Home)
	if e != nil {
		return e
	}
	audit, e := state.OpenAudit(c.Home, 10<<20, 5)
	if e != nil {
		return e
	}
	defer audit.Close()
	r, e := runtime.Open(ctx, c, instance)
	if e != nil {
		return e
	}
	closeRuntime := true
	defer func() {
		if closeRuntime {
			closing, done := context.WithTimeout(context.Background(), 90*time.Second)
			defer done()
			_ = closeRuntimeAfterDrain(closing, nil, nil, r.Close)
		}
	}()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	node, e := tailnet.Start(ctx, c, secrets, log)
	if e != nil {
		return e
	}
	defer node.Close()
	if e = node.WaitReady(ctx); e != nil {
		return e
	}
	snapshot, e := r.Reconcile(ctx)
	if e != nil {
		return e
	}
	log.Info("reconciled", "managed", len(snapshot.VMs), "unmanaged", snapshot.Unmanaged, "unreadable", snapshot.Unreadable)
	// Operations outlive sessions and graceful listener shutdown, but are owned
	// by this daemon and cancelled when its bounded drain budget expires.
	jobctx, stopJobs := context.WithCancel(context.Background())
	defer stopJobs()
	s := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(jobctx, c.Sessions.Global), Capability: c.Tailnet.Capability, Config: c, VisibleNames: node.VisibleNames}
	sshListener, e := node.Server.ListenSSH(":22")
	if e != nil {
		return e
	}
	defer sshListener.Close()
	tlsListener, e := node.Server.ListenTLS("tcp", ":443")
	if e != nil {
		return e
	}
	defer tlsListener.Close()
	ssh := &sshd.Server{Service: s, Resolver: node, Global: c.Sessions.Global, PerPeer: c.Sessions.PerPeer}
	web := httpd.Server(s, node)
	results := make(chan error, 2)
	go func() { results <- ssh.Serve(ctx, sshListener) }()
	go func() {
		err := web.Serve(tlsListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		results <- err
	}()
	select {
	case <-ctx.Done():
	case e = <-results:
		cancel()
	}
	shutdown, done := context.WithTimeout(context.Background(), 90*time.Second)
	defer done()
	deadlineCancellation := context.AfterFunc(shutdown, stopJobs)
	defer deadlineCancellation()
	s.Jobs.Seal()
	// Native SDK Close waits for native calls. If the drain budget expires,
	// process exit releases handles instead of extending the shutdown deadline.
	closeRuntime = false
	_ = sshListener.Close()
	ssh.CloseSessions()
	webError := web.Shutdown(shutdown)
	if webError != nil {
		_ = web.Close()
	}
	sshError := ssh.Wait(shutdown)
	jobError := s.Jobs.Wait(shutdown)
	// Closing SDK handles and this service node never stops machine supervisors.
	runtimeError := closeRuntimeAfterDrain(shutdown, sshError, jobError, r.Close)
	return errors.Join(e, webError, sshError, jobError, runtimeError)
}

var errRuntimeCleanupIncomplete = errors.New("runtime cleanup incomplete")

// SDK Close can wait on session calls or library workers. Never enter it while
// either drain is incomplete, and never let that wait extend the shutdown budget.
// On timeout the process exits with incomplete cleanup, without stopping VMs.
func closeRuntimeAfterDrain(ctx context.Context, sessionError, jobError error, closeRuntime func() error) error {
	if sessionError != nil || jobError != nil {
		return fmt.Errorf("%w: session or job drain failed", errRuntimeCleanupIncomplete)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", errRuntimeCleanupIncomplete, err)
	}
	done := make(chan error, 1)
	go func() { done <- closeRuntime() }()
	select {
	case err := <-done:
		if deadlineError := ctx.Err(); deadlineError != nil {
			return fmt.Errorf("%w: %w", errRuntimeCleanupIncomplete, deadlineError)
		}
		return err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", errRuntimeCleanupIncomplete, ctx.Err())
	}
}
