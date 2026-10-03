package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/vandycknick/silo/app/taild/internal/bootenv"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/httpd"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/redact"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/supervision"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	silo "github.com/vandycknick/silo/sdk/go"
)

const usageLine = "usage: taild [version|install-runtime|stop-vms] [--config FILE] [--check|--version] [--runtime-archive FILE] [--install-root DIR] [--only-when-shutting-down]"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "taild:", redact.Text(e.Error()))
		os.Exit(1)
	}
}
func run() error {
	return runArgs(os.Args[1:])
}

// invocation is the parsed command line. The subcommand may precede or follow
// the flags; without one the daemon serves.
type invocation struct {
	command      string
	configPath   string
	check        bool
	archive      string
	installRoot  string
	onlyShutdown bool
}

func parseArgs(args []string) (invocation, error) {
	var iv invocation
	if len(args) > 0 && isCommand(args[0]) {
		iv.command, args = args[0], args[1:]
	}
	flags := flag.NewFlagSet("taild", flag.ContinueOnError)
	// Flag errors reach main's redaction boundary rather than being printed raw.
	flags.SetOutput(io.Discard)
	flags.StringVar(&iv.configPath, "config", "/etc/silo-taild/config.yaml", "operator YAML file")
	flags.BoolVar(&iv.check, "check", false, "validate config, home, secrets and installed runtime")
	version := flags.Bool("version", false, "print build and installed runtime versions")
	flags.StringVar(&iv.archive, "runtime-archive", "", "offline SDK runtime archive (install-runtime)")
	flags.StringVar(&iv.installRoot, "install-root", "", "SDK runtime store parent")
	flags.BoolVar(&iv.onlyShutdown, "only-when-shutting-down", false, "stop-vms only when systemctl reports stopping")
	if e := flags.Parse(args); e != nil {
		return iv, e
	}
	if flags.NArg() == 1 && iv.command == "" {
		iv.command = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return iv, errors.New("unexpected arguments")
	}
	if iv.command != "" && !isCommand(iv.command) {
		return iv, errors.New("unknown command")
	}
	if *version {
		iv.command = "version"
	}
	if iv.onlyShutdown && iv.command != "stop-vms" {
		return iv, errors.New("--only-when-shutting-down requires stop-vms")
	}
	return iv, nil
}

func isCommand(s string) bool {
	return s == "version" || s == "install-runtime" || s == "stop-vms"
}

func runArgs(args []string) error {
	iv, e := parseArgs(args)
	if errors.Is(e, flag.ErrHelp) {
		_, _ = fmt.Fprintln(os.Stdout, usageLine)
		return nil
	}
	if e != nil {
		return e
	}
	if iv.command == "stop-vms" && iv.onlyShutdown {
		host, e := supervision.SystemState(context.Background())
		if e != nil {
			return e
		}
		if host != "stopping" {
			fmt.Fprintln(os.Stderr, "taild: host is not shutting down; no VMs stopped")
			return nil
		}
	}
	c, e := config.Load(iv.configPath)
	if iv.command == "version" && errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	if e != nil {
		return e
	}
	if iv.installRoot != "" {
		c.InstallRoot = iv.installRoot
	}
	if iv.archive != "" {
		c.RuntimeArchive = iv.archive
	}
	if e := c.Validate(); e != nil {
		return e
	}
	if iv.command == "version" {
		return printVersion(c)
	}
	c.Home, e = config.ResolveHome(c.Home, os.Geteuid())
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	switch iv.command {
	case "install-runtime":
		return installRuntime(ctx, c)
	case "stop-vms":
		return stopVMs(ctx, c, iv.onlyShutdown)
	}
	secrets, e := config.ReadSecrets(c.SecretsDir)
	if e != nil {
		return e
	}
	if c.Enrollment.DisableKeyExpiry && secrets.APIToken == "" {
		return errors.New("disable_key_expiry requires api-token")
	}
	if iv.check {
		return checkReady(ctx, c)
	}
	return serve(ctx, cancel, c, secrets)
}

func printVersion(c config.Config) error {
	v := service.Versions()
	root, err := runtime.Root(c)
	if err != nil && !errors.Is(err, runtime.ErrMissingRuntime) {
		return err
	}
	if err == nil {
		manifest, err := runtime.ValidateManifest(root)
		if err != nil {
			return err
		}
		v.Runtime = manifest.Version
	}
	if v.ABIVerified, err = silo.VerifiedNativeABIVersion(); err != nil {
		return err
	}
	fmt.Printf("taild %s SDK %s runtime %s tailscale %s ABI expected %d verified %d\n", v.Taild, v.SDK, v.Runtime, v.Tailscale, v.ABIExpected, v.ABIVerified)
	return nil
}

func installRuntime(ctx context.Context, c config.Config) error {
	if c.RuntimeArchive == "" {
		return errors.New("install-runtime requires --runtime-archive or runtime_archive")
	}
	installed, err := silo.InstallRuntime(ctx, silo.WithInstallRoot(c.RuntimeStore()), silo.WithRuntimeArchive(c.RuntimeArchive))
	if err != nil {
		var sdkError *silo.Error
		if errors.As(err, &sdkError) {
			return fmt.Errorf("offline SDK runtime installation failed (%s)", sdkError.Kind)
		}
		return errors.New("offline SDK runtime installation failed")
	}
	manifest, err := runtime.ValidateManifest(installed.Root)
	if err != nil {
		return err
	}
	fmt.Printf("runtime %s target %s installed\n", manifest.Version, manifest.Target)
	return nil
}

// stopVMs is the ExecStop helper. It seals admission, then stops every managed
// VM within the configured budget. Its process exit reclaims the SDK handles;
// Close must not wait on native calls beyond the already-spent host budget.
func stopVMs(ctx context.Context, c config.Config, onlyShutdown bool) error {
	if _, e := state.LockShutdownHelper(c.Home); e != nil {
		return errors.New("another shutdown helper is active or helper lock unavailable")
	}
	budget, _ := time.ParseDuration(c.Shutdown.StopBudget)
	stopping, done := context.WithTimeout(ctx, budget)
	defer done()
	// The initial guard may precede config/home I/O. Recheck after taking the
	// helper lease so a cancelled shutdown cannot launch a late stop process.
	if onlyShutdown {
		host, err := supervision.SystemState(stopping)
		if err != nil {
			return err
		}
		if host != "stopping" {
			fmt.Fprintln(os.Stderr, "taild: shutdown cancelled; no VMs stopped")
			return nil
		}
	}
	if e := state.MarkShutdown(c.Home); e != nil {
		return errors.New("cannot seal host shutdown admission")
	}
	instance, e := state.ReadInstance(c.Home)
	if e != nil {
		return e
	}
	type opened struct {
		runtime *runtime.Runtime
		err     error
	}
	ready := make(chan opened, 1)
	go func() { r, err := runtime.Open(stopping, c, instance); ready <- opened{r, err} }()
	var r *runtime.Runtime
	select {
	case opened := <-ready:
		if opened.err != nil {
			return opened.err
		}
		r = opened.runtime
	case <-stopping.Done():
		return errors.New("shutdown runtime open deadline reached; no completion guarantee")
	}
	result, e := supervision.Sweep(stopping, r)
	fmt.Fprintf(os.Stderr, "taild: stops issued=%d finished=%d failed=%d\n", result.Issued, result.Finished, result.Failed)
	return e
}

func checkReady(ctx context.Context, c config.Config) error {
	r, err := runtime.Open(ctx, c, "")
	if err != nil {
		return err
	}
	documentError := (&service.Service{Config: c}).ReloadDocuments()
	if err = r.Close(); err != nil {
		return err
	}
	if documentError != nil {
		return documentError
	}
	fmt.Fprintln(os.Stderr, "taild: configuration and runtime ready")
	return nil
}

// serve owns the daemon lifetime: home lock, runtime, shutdown supervision,
// tailnet node, enrollment, and the SSH and HTTPS listeners, then the bounded
// drain in reverse.
func serve(ctx context.Context, cancel context.CancelFunc, c config.Config, secrets config.Secrets) error {
	lock, e := state.LockHome(c.Home)
	if e != nil {
		return e
	}
	defer func() { _ = lock.Close() }()
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
	defer func() { _ = audit.Close() }()
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
	log := slog.New(redact.New(slog.NewJSONHandler(os.Stderr, nil), secrets.ClientSecret, secrets.AppSecret, secrets.APIToken))
	jobctx, stopJobs := context.WithCancel(context.Background())
	defer stopJobs()
	registryJobs := jobs.New(jobctx, c.Sessions.Global)
	gate := &state.ShutdownGate{}
	registryJobs.Shutdown = gate
	registryJobs.Metrics = r.Metrics
	registryJobs.Admission = func() bool { return !state.ShutdownPending(c.Home) }
	inhibitor, preparing, inhibitErr := supervision.Acquire(ctx, c)
	if inhibitErr != nil {
		log.Warn("logind shutdown protection unavailable; ExecStop fallback required")
		if state.ShutdownPending(c.Home) {
			if e := recoverShutdownSeal(ctx, c.Home, gate); e != nil {
				return e
			}
		}
	} else {
		defer inhibitor.Close()
		inhibitor.Start(ctx, c, r, preparing, gate,
			func() { registryJobs.InterruptIf(func() bool { return true }) },
			registryJobs.Resume, registryJobs.Drained, log)
		if !preparing {
			if e := recoverShutdownSeal(ctx, c.Home, gate); e != nil {
				return e
			}
		}
	}
	// Start after crash-retained marker recovery, so a stale marker cannot
	// pause this fresh registry permanently before admission is established.
	// ExecStop runs before SIGTERM; cancellation releases enrollment leases.
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				registryJobs.InterruptIf(func() bool { return state.ShutdownPending(c.Home) })
			}
		}
	}()
	node, e := tailnet.Start(ctx, c, secrets, log)
	if e != nil {
		return e
	}
	node.Metrics = r.Metrics
	defer func() { _ = node.Close() }()
	if e = node.WaitReady(ctx); e != nil {
		return e
	}
	observed, e := node.Status(ctx)
	if e != nil {
		return e
	}
	pin := state.NodePin{Tailnet: observed.CurrentTailnet.Name, Suffix: observed.CurrentTailnet.MagicDNSSuffix, ControlURL: c.Tailnet.ControlURL}
	if e = state.PinNodeControl(c.Home, pin); e != nil {
		return e
	}
	r.NodePin = &pin
	registry := enroll.NewRegistry()
	enrollment := &enroll.Manager{Config: c, Secrets: secrets, Pin: pin, Registry: registry, Devices: enroll.NewDevices(secrets.APIToken), Visible: node.Status, Metrics: r.Metrics}
	if secrets.AppSecret != "" {
		enrollment.OAuth, e = enroll.NewOAuth(registry, secrets.AppSecret, "https://"+c.Tailnet.Hostname+"."+pin.Suffix+"/oauth/callback")
		if e != nil {
			return e
		}
	}
	snapshot, e := r.Reconcile(ctx)
	if e != nil {
		return e
	}
	log.Info("reconciled", "managed", len(snapshot.VMs), "unmanaged", snapshot.Unmanaged, "unreadable", snapshot.Unreadable)
	// Operations outlive sessions and graceful listener shutdown, but are owned
	// by this daemon and cancelled when its bounded drain budget expires.
	s := &service.Service{Runtime: r, Audit: audit, Jobs: registryJobs, Shutdown: gate, Capability: c.Tailnet.Capability, Config: c, VisibleNames: node.VisibleNames, VMNodesEnabled: true, Enrollment: enrollment}
	if e = s.ReloadDocuments(); e != nil {
		return e
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if e := s.ReloadDocuments(); e != nil {
					log.Error("operator documents reload failed", "error", e)
				}
			}
		}
	}()
	sshListener, e := node.Server.ListenSSH(":22")
	if e != nil {
		return e
	}
	defer func() { _ = sshListener.Close() }()
	tlsListener, e := node.Server.ListenTLS("tcp", ":443")
	if e != nil {
		return e
	}
	defer func() { _ = tlsListener.Close() }()
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
	// Restore default signal behavior before bounded cleanup, so a second signal
	// can terminate blocked native cleanup rather than remaining swallowed.
	cancel()
	signal.Stop(hup)
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

func recoverShutdownSeal(ctx context.Context, home string, gate *state.ShutdownGate) error {
	revision := gate.Revision()
	if gate.Pending() {
		return nil
	}
	if !state.ShutdownPending(home) {
		return nil
	}
	if e := state.WaitShutdownHelpers(ctx, home); e != nil {
		return errors.New("shutdown helper still active; admission sealed")
	}
	if gate.Revision() != revision || gate.Pending() {
		return nil
	}
	host, err := supervision.SystemState(ctx)
	if err != nil || host == "stopping" {
		return errors.New("shutdown marker retained; host state not safe for admission")
	}
	_, err = gate.Recover(home, revision)
	return err
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
