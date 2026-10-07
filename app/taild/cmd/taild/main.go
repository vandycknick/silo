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
	"github.com/vandycknick/silo/app/taild/internal/bootstrap"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
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
	daemonv1 "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

const usageLine = "usage: taild [help|version|--version] | --bootstrap-fd N"

type deterministicError struct{ error }

func main() {
	if e := runArgs(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "taild:", redact.LogText(e.Error()))
		var invalid *deterministicError
		if errors.As(e, &invalid) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// invocation has no standalone configuration or management mode.
type invocation struct {
	command     string
	bootstrapFD int
}

func parseArgs(args []string) (invocation, error) {
	iv := invocation{bootstrapFD: -1}
	if len(args) == 1 && (args[0] == "version" || args[0] == "help") {
		iv.command = args[0]
		return iv, nil
	}
	flags := flag.NewFlagSet("taild", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.Bool("version", false, "print build versions without loading native runtime")
	flags.IntVar(&iv.bootstrapFD, "bootstrap-fd", -1, "manager bootstrap and owner pipe")
	if err := flags.Parse(args); err != nil {
		return iv, err
	}
	if flags.NArg() != 0 {
		return iv, errors.New("unexpected arguments")
	}
	if *version {
		if iv.bootstrapFD != -1 {
			return iv, errors.New("version cannot consume bootstrap")
		}
		iv.command = "version"
		return iv, nil
	}
	if iv.bootstrapFD < 0 {
		return iv, errors.New("--bootstrap-fd is required")
	}
	return iv, nil
}

func runArgs(args []string) error {
	iv, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) || err == nil && iv.command == "help" {
		_, _ = fmt.Fprintln(os.Stdout, usageLine)
		return nil
	}
	if err != nil {
		return &deterministicError{err}
	}
	if iv.command == "version" {
		v := service.Versions()
		fmt.Printf("taild %s SDK %s runtime %s tailscale %s ABI expected %d verified unavailable\n", v.Taild, v.SDK, v.Runtime, v.Tailscale, v.ABIExpected)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	input, pipe, err := bootstrap.Read(ctx, iv.bootstrapFD)
	if err != nil {
		return &deterministicError{err}
	}
	ownerLost := make(chan struct{})
	finished := make(chan struct{})
	defer close(finished)
	stopOwner := bootstrap.Watch(pipe, func() { close(ownerLost); cancel() })
	defer stopOwner()
	// A process-level deadline also bounds native/library cleanup on orphaning.
	go func() {
		select {
		case <-ownerLost:
		case <-finished:
			return
		}
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			os.Exit(1)
		case <-finished:
		}
	}()
	client, err := control.New(input.Endpoint, input.HelperGeneration)
	if err != nil {
		return &deterministicError{err}
	}
	defer client.Close()
	admission, done := context.WithTimeout(ctx, 10*time.Second)
	status, err := client.Admit(admission, service.Versions().Taild, input.DaemonGeneration, input.Config.Home, input.ConfigDir)
	done()
	if err != nil {
		if errors.Is(err, control.ErrIdentityMismatch) {
			return &deterministicError{err}
		}
		return err
	}
	report := func(state daemonv1.ComponentState, diagnostic, url, dns, instance string, protection daemonv1.ShutdownProtection) {
		reportCtx, finish := context.WithTimeout(context.Background(), 2*time.Second)
		defer finish()
		component := &daemonv1.ComponentStatus{Enabled: true, State: state, ShutdownProtection: protection}
		if diagnostic != "" {
			component.Diagnostic = &diagnostic
		}
		if url != "" {
			component.ApprovalUrl = &url
		}
		if dns != "" {
			component.DnsName = &dns
		}
		request := &daemonv1.TailscaleStatusReport{HelperGeneration: input.HelperGeneration, Status: component}
		if instance != "" {
			request.Instance = &instance
		}
		_, _ = client.Daemon.ReportTailscaleStatus(reportCtx, request)
	}
	report(daemonv1.ComponentState_COMPONENT_STATE_STARTING, "", "", "", "", daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNAVAILABLE)
	err = serve(ctx, cancel, input.Config, input.Secrets, ownerLost, client, status, report)
	if err != nil && ctx.Err() == nil {
		report(daemonv1.ComponentState_COMPONENT_STATE_FAILED, redact.LogText(err.Error(), input.Secrets.ClientSecret, input.Secrets.AppSecret, input.Secrets.APIToken), "", "", "", daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNAVAILABLE)
	}
	return err
}

// serve owns the daemon lifetime: home lock, runtime, shutdown supervision,
// tailnet node, enrollment, and the SSH and HTTPS listeners, then the bounded
// drain in reverse.
type statusReporter func(daemonv1.ComponentState, string, string, string, string, daemonv1.ShutdownProtection)

func serve(ctx context.Context, cancel context.CancelFunc, c config.Config, secrets config.Secrets, ownerLost <-chan struct{}, client *control.Client, daemon *daemonv1.DaemonStatus, report statusReporter) error {
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
	report(daemonv1.ComponentState_COMPONENT_STATE_STARTING, "", "", "", instance, daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNAVAILABLE)
	audit, e := state.OpenAudit(c.Home, 10<<20, 5)
	if e != nil {
		return e
	}
	defer func() { _ = audit.Close() }()
	r, e := runtime.Open(ctx, c, instance, client)
	if e != nil {
		for _, kind := range []silo.ErrorKind{silo.ErrorFFILoad, silo.ErrorABIMismatch, silo.ErrorUnsupportedTarget, silo.ErrorInvalidArgument, silo.ErrorRuntimeComponentInvalid, silo.ErrorRuntimeComponentsNotFound} {
			if silo.IsErrorKind(e, kind) {
				return &deterministicError{e}
			}
		}
		return e
	}
	closeRuntime := true
	defer func() {
		if closeRuntime {
			closing, done := context.WithTimeout(context.Background(), cleanupBudget(ownerLost))
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
	go func() {
		select {
		case <-ownerLost:
			stopJobs()
		case <-jobctx.Done():
		}
	}()
	registryJobs.Metrics = r.Metrics
	registryJobs.Admission = func() bool { return !state.ShutdownPending(c.Home) }
	inhibitor, preparing, inhibitErr := supervision.Acquire(ctx, c)
	if inhibitErr != nil {
		log.Warn("logind shutdown protection unavailable")
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
	protection := daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_UNAVAILABLE
	if inhibitErr == nil {
		protection = daemonv1.ShutdownProtection_SHUTDOWN_PROTECTION_ACTIVE
	}
	reportCtx, stopReports := context.WithCancel(ctx)
	defer stopReports()
	listenersReady := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-reportCtx.Done():
				return
			case <-ticker.C:
				observation, err := node.Client.StatusWithoutPeers(reportCtx)
				if err != nil {
					report(daemonv1.ComponentState_COMPONENT_STATE_DEGRADED, "tailnet status unavailable", "", "", instance, protection)
					continue
				}
				if observation.AuthURL != "" {
					report(daemonv1.ComponentState_COMPONENT_STATE_NEEDS_AUTH, "", observation.AuthURL, "", instance, protection)
				} else if observation.BackendState != "Running" {
					report(daemonv1.ComponentState_COMPONENT_STATE_STARTING, "", "", "", instance, protection)
				} else {
					select {
					case <-listenersReady:
						if verified, err := node.Status(reportCtx); err == nil {
							report(daemonv1.ComponentState_COMPONENT_STATE_READY, "", "", verified.Self.DNSName, instance, protection)
						} else {
							report(daemonv1.ComponentState_COMPONENT_STATE_DEGRADED, "tagged tailnet identity unavailable", "", "", instance, protection)
						}
					default:
						report(daemonv1.ComponentState_COMPONENT_STATE_STARTING, "", "", "", instance, protection)
					}
				}
			}
		}
	}()
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
	enrollment := &enroll.Manager{Config: c, Secrets: secrets, Pin: pin, Registry: registry, Metrics: r.Metrics}
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
	s := &service.Service{Runtime: r, DaemonVersion: daemon.ProductVersion, ManagementProtocol: daemon.ProtocolMajor, Audit: audit, Jobs: registryJobs, Shutdown: gate, Capability: c.Tailnet.Capability, Config: c, VisibleNames: node.VisibleNames, VMNodesEnabled: true, Enrollment: enrollment}
	if e = s.ReloadDocuments(ctx); e != nil {
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
				if e := s.ReloadDocuments(ctx); e != nil {
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
	sessions, cancelSessions := context.WithCancel(context.Background())
	defer cancelSessions()
	go func() {
		select {
		case <-ownerLost:
			cancelSessions()
			ssh.CloseSessions()
		case <-sessions.Done():
		}
	}()
	go func() { results <- ssh.Serve(sessions, sshListener) }()
	go func() {
		err := web.Serve(tlsListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		results <- err
	}()
	report(daemonv1.ComponentState_COMPONENT_STATE_READY, "", "", observed.Self.DNSName, instance, protection)
	close(listenersReady)
	select {
	case <-ctx.Done():
	case e = <-results:
		cancel()
	}
	// Restore default signal behavior before bounded cleanup, so a second signal
	// can terminate blocked native cleanup rather than remaining swallowed.
	cancel()
	signal.Stop(hup)
	shutdown, done := context.WithTimeout(context.Background(), cleanupBudget(ownerLost))
	defer done()
	deadlineCancellation := context.AfterFunc(shutdown, func() { stopJobs(); cancelSessions(); ssh.CloseSessions() })
	defer deadlineCancellation()
	s.Jobs.Seal()
	// Native SDK Close waits for native calls. If the drain budget expires,
	// process exit releases handles instead of extending the shutdown deadline.
	closeRuntime = false
	_ = sshListener.Close()
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

func cleanupBudget(ownerLost <-chan struct{}) time.Duration {
	select {
	case <-ownerLost:
		return 3 * time.Second
	default:
		return 80 * time.Second
	}
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
