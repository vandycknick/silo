package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
)

// domainCaller is explicit principal input at the domain boundary, below WhoIs.
func domainCaller(s *Service, owner identity.Principal) Caller {
	p := daemon.Peer(s.Config, "explicit-domain-"+string(owner), owner)
	return Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}
}
func actualService(t *testing.T) *Service {
	t.Helper()
	c := daemon.Config(t, nil)
	n := daemon.Open(t, c, "native-service", 32)
	return &Service{Runtime: n.Runtime, Audit: n.Audit, Config: c, Jobs: n.Jobs}
}
func TestCreateValidationAndOperatorCapabilityIntersection(t *testing.T) {
	s := actualService(t)
	c := domainCaller(s, "user:1")
	for _, tt := range []struct {
		name   string
		change func(*CreateRequest)
		exit   int
	}{
		{"host-disk", func(q *CreateRequest) { q.Image = "/etc/passwd" }, 2},
		{"registry-boundary", func(q *CreateRequest) { q.Image = "ghcr.io/vandycknick-evil/x:latest" }, 2},
		{"registry-parent", func(q *CreateRequest) { q.Image = "ghcr.io/vandycknick/../x" }, 2},
		{"registry-control", func(q *CreateRequest) { q.Image = "ghcr.io/vandycknick/x\x00" }, 2},
		{"forged-owner", func(q *CreateRequest) { q.Owner = "tag:foreign" }, 4},
		{"human-owner-flag", func(q *CreateRequest) { q.Owner = "user:1" }, 4},
		{"reserved-label", func(q *CreateRequest) { q.Labels = map[string]string{"io.silo.taild.owner": "user:2"} }, 2},
		{"control-label", func(q *CreateRequest) { q.Labels = map[string]string{"x": "bad\n"} }, 2},
		{"userdata", func(q *CreateRequest) { q.Userdata = strings.Repeat("x", 16385) }, 2},
		{"operator-cpus", func(q *CreateRequest) { q.CPUs = 9 }, 6},
		{"operator-disk", func(q *CreateRequest) { q.Disk = 201 << 30 }, 6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := CreateRequest{Name: "safe"}
			tt.change(&q)
			_, e := s.ValidateCreate(c.Peer, q)
			var a *authz.Error
			if !errors.As(e, &a) || a.Exit != tt.exit {
				t.Fatalf("%v", e)
			}
		})
	}
	c.Peer.Permissions.Limits.CPUs = 1
	if _, e := s.ValidateCreate(c.Peer, CreateRequest{Name: "safe", CPUs: 2}); Categorize(e).Exit != 6 {
		t.Fatal(e)
	}
	c.Peer.Principals = []identity.Principal{"tag:ci", "tag:team"}
	if _, e := s.ValidateCreate(c.Peer, CreateRequest{Name: "safe"}); e == nil {
		t.Fatal("missing owner accepted")
	}
	q, e := s.ValidateCreate(c.Peer, CreateRequest{Name: "safe", Owner: "tag:team"})
	if e != nil || q.Owner != "tag:team" {
		t.Fatal(q, e)
	}
}
func TestActualOCICreateDisconnectIsolationQuotaAndMutations(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.Ceilings.VMs = 1
	one, two := domainCaller(s, "user:1"), domainCaller(s, "user:2")
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePull := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releasePull)
	var once sync.Once
	registry.BeforeManifest = func() { once.Do(func() { close(entered); <-release }) }
	disconnected, cancel := context.WithCancel(context.Background())
	op, e := s.Create(disconnected, one, CreateRequest{Name: "one", NoStart: true})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		v := daemon.WaitOperation(t, s.Jobs, one.Peer, op, nil)
		t.Fatalf("native registry manifest not reached: %+v %+v", v, v.Error)
	}
	cancel()
	if _, _, e := s.Jobs.Observe(two.Peer, op.ID); Categorize(e).Exit != 3 {
		t.Fatal("foreign op visible", e)
	}
	quota, e := s.Create(context.Background(), one, CreateRequest{Name: "over", NoStart: true})
	if e == nil || Categorize(e).Exit != 6 || quota.ID != "" {
		t.Fatal("quota must reject before publication", quota, e)
	}
	collision, e := s.Create(context.Background(), two, CreateRequest{Name: "one", NoStart: true})
	if e == nil || Categorize(e).Exit != 5 || collision.ID != "" {
		t.Fatal("collision must reject before publication", collision, e)
	}
	releasePull()
	daemon.Succeeded(t, s.Jobs, one.Peer, op, nil)
	if registry.Requests.Load() < 3 {
		t.Fatal("native OCI did not use real registry")
	}
	op, e = s.Create(context.Background(), two, CreateRequest{Name: "two", NoStart: true})
	daemon.Succeeded(t, s.Jobs, two.Peer, op, e)
	for _, c := range []Caller{one, two} {
		v, e := s.List(context.Background(), c.Peer)
		if e != nil || len(v) != 1 {
			t.Fatal(v, e)
		}
	}
	if _, e := s.Show(context.Background(), one.Peer, "two"); Categorize(e).Exit != 3 {
		t.Fatal("foreign machine visible", e)
	}
	name := "renamed"
	op, e = s.Set(context.Background(), one, "one", SetRequest{Name: &name})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	v, e := s.Show(context.Background(), one.Peer, name)
	if e != nil || v.Name != name || v.State != "stopped" {
		t.Fatal(v, e)
	}
	reopened, e := runtime.Open(context.Background(), s.Config, s.Runtime.Instance)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := reopened.Reconcile(context.Background())
	_ = reopened.Close()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, vm := range recovered.VMs {
		if vm.ID == v.ID {
			found = vm.Name == name
		}
	}
	if !found {
		t.Fatal("atomic name/label rename did not survive native reopen", recovered)
	}
	// Queue a set behind actual daemon work, then revoke its domain capability.
	hold := make(chan struct{})
	started := make(chan struct{})
	block, e := s.Jobs.Submit("hold", v.ID, "user:1", func(context.Context, func(string)) error { close(started); <-hold; return nil })
	if e != nil {
		t.Fatal(e)
	}
	<-started
	revoked := one
	revoked.Resolve = func(context.Context) (identity.Peer, error) {
		p := one.Peer
		p.Permissions.Actions = nil
		return p, nil
	}
	op, e = s.Set(context.Background(), revoked, name, SetRequest{Name: &name})
	if e != nil {
		t.Fatal(e)
	}
	close(hold)
	daemon.Succeeded(t, s.Jobs, one.Peer, block, nil)
	if got := daemon.WaitOperation(t, s.Jobs, one.Peer, op, nil); got.Error == nil || got.Error.Exit != 4 {
		t.Fatal("queued revoked mutation ran", got)
	}
	op, e = s.Remove(context.Background(), one, name, RemoveRequest{})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	op, e = s.Create(context.Background(), one, CreateRequest{Name: "one", NoStart: true})
	daemon.Succeeded(t, s.Jobs, one.Peer, op, e)
	third := domainCaller(s, "user:3")
	failed, e := s.Create(context.Background(), third, CreateRequest{Name: "retry", Image: strings.Split(registry.Reference, "/fixture/")[0] + "/fixture/missing:latest", NoStart: true})
	if e != nil {
		t.Fatal(e)
	}
	if got := daemon.WaitOperation(t, s.Jobs, third.Peer, failed, nil); got.Error == nil || got.Error.Exit != 7 {
		t.Fatal("failed OCI pull did not report category 7", got)
	}
	op, e = s.Create(context.Background(), third, CreateRequest{Name: "retry", NoStart: true})
	daemon.Succeeded(t, s.Jobs, third.Peer, op, e)
	tagged := domainCaller(s, "tag:team")
	tagged.Peer.Principals = []identity.Principal{"tag:team", "tag:ci"}
	tagged.Resolve = func(context.Context) (identity.Peer, error) { return tagged.Peer, nil }
	op, e = s.Create(context.Background(), tagged, CreateRequest{Name: "tagged", Owner: "tag:ci", NoStart: true})
	daemon.Succeeded(t, s.Jobs, tagged.Peer, op, e)
	op, e = s.Create(context.Background(), tagged, CreateRequest{Name: "tagged-over", Owner: "tag:ci", NoStart: true})
	if e == nil || Categorize(e).Exit != 6 || op.ID != "" {
		t.Fatal("selected tag quota bypass", op, e)
	}
}

func TestInterruptedCreateKeepsDurableStoppedTruth(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Jobs = jobs.New(ctx, 4)
	c := domainCaller(s, "user:1")
	persisted := make(chan struct{})
	calls := 0
	c.Resolve = func(ctx context.Context) (identity.Peer, error) {
		calls++
		if calls == 3 {
			close(persisted)
			<-ctx.Done()
			return identity.Peer{}, ctx.Err()
		}
		return c.Peer, ctx.Err()
	}
	op, e := s.Create(context.Background(), c, CreateRequest{Name: "interrupted"})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-persisted:
	case <-time.After(20 * time.Second):
		t.Fatal("durable create not reached")
	}
	cancel()
	v := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil)
	if v.State != "failed" {
		t.Fatal(v)
	}
	if e = s.Jobs.Wait(context.Background()); e != nil {
		t.Fatal(e)
	}
	instance := s.Runtime.Instance
	if e = s.Runtime.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := runtime.Open(context.Background(), s.Config, instance)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	reader := &Service{Runtime: reopened, Audit: s.Audit, Config: s.Config, Jobs: jobs.New(context.Background(), 4)}
	vm, e := reader.Show(context.Background(), c.Peer, "interrupted")
	if e != nil || vm.State != silo.MachineStatusStopped || len(reader.Jobs.List(c.Peer)) != 0 {
		t.Fatal("interrupted operation did not reconcile durable truth", vm, e)
	}
	release, e := reader.Runtime.Reserve(context.Background(), "fresh-after-restart", nil)
	if e != nil {
		t.Fatal(e)
	}
	release()
}

func TestCreateCountRevokedDuringActualPull(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	caller := domainCaller(s, "user:1")
	var current atomic.Pointer[identity.Peer]
	peer := caller.Peer
	current.Store(&peer)
	caller.Resolve = func(ctx context.Context) (identity.Peer, error) { return *current.Load(), ctx.Err() }
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	registry.BeforeManifest = func() { once.Do(func() { close(entered); <-release }) }
	op, e := s.Create(context.Background(), caller, CreateRequest{Name: "revoked-quota", NoStart: true})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("actual pull did not reach registry")
	}
	revoked := peer
	revoked.Permissions.Limits.VMs = 0
	current.Store(&revoked)
	close(release)
	if got := daemon.WaitOperation(t, s.Jobs, caller.Peer, op, nil); got.Error == nil || got.Error.Exit != 6 {
		t.Fatal("stale reserved quota was used at materialization", got)
	}
	if v, e := s.List(context.Background(), peer); e != nil || len(v) != 0 {
		t.Fatal("revoked quota created a VM", v, e)
	}
	releaseName, e := s.Runtime.Reserve(context.Background(), "revoked-quota", nil)
	if e != nil {
		t.Fatal("failed create retained reservation", e)
	}
	releaseName()
}

func TestActualSDKBoundedLogsFiltersAndRedaction(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.DefaultImage = registry.Reference
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	c := domainCaller(s, "user:1")
	op, e := s.Create(context.Background(), c, CreateRequest{Name: "logs", NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, e)
	v, e := s.Show(context.Background(), c.Peer, "logs")
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(s.Config.Home, "logs", "machines", v.ID, "serial.log")
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	data := "obsolete-first-line\n" + strings.Repeat("ordinary log line\n", 600000) + "host-path=" + s.Config.Home + "/keys/test\nAuthorization: Bearer synthetic-fixture-token\nlast-line\n"
	if e = os.WriteFile(path, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = s.Logs(context.Background(), c, "logs", LogsRequest{Source: silo.MachineLogSerial}, &out); e != nil {
		t.Fatal(e)
	}
	if out.Len() > logLimit || !strings.Contains(out.String(), "last-line") || strings.Contains(out.String(), "obsolete-first-line") || strings.Contains(out.String(), s.Config.Home) || strings.Contains(out.String(), "synthetic-fixture-token") {
		t.Fatal("unbounded/unredacted logs", out.Len())
	}
	out.Reset()
	if e = s.Logs(context.Background(), c, "logs", LogsRequest{Source: silo.MachineLogSerial, Output: silo.MachineLogStderr}, &out); e != nil || out.Len() != 0 {
		t.Fatal("log output filter", e, out.Len())
	}
	if e = s.Logs(context.Background(), c, "logs", LogsRequest{Source: "../../secrets"}, &out); Categorize(e).Exit != 2 {
		t.Fatal("unsafe source accepted", e)
	}
	m, e := s.Runtime.SDK.Machine(context.Background(), "logs")
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	policy, e := silo.ParseNetworkPolicyHCL("tailscale \"vm\" {\n hostname = \"logs\"\n}\n")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Update(context.Background(), silo.MachineUpdate{Policy: policy}); e != nil {
		t.Fatal(e)
	}
	name := "declared-pending"
	op, e = s.Set(context.Background(), c, "logs", SetRequest{Name: &name})
	if e != nil {
		t.Fatal(e)
	}
	if got := daemon.WaitOperation(t, s.Jobs, c.Peer, op, nil); got.Error == nil || got.Error.Exit != 5 {
		t.Fatal("pending tailscale declaration renamed", got)
	}
}
