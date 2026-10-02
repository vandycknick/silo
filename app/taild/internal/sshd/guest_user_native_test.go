package sshd

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestNativeCreateProvisionUserParser(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: "256MiB", Disk: "1GiB"}
	c.VM.DefaultImage = registry.Reference
	c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := runtime.Open(ctx, c, "guest-user-parser")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	audit, err := state.OpenAudit(c.Home, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	s := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(ctx, 8), Config: c}
	defer func() { _ = s.Jobs.Wait(context.Background()) }()
	limits, err := c.Limits()
	if err != nil {
		t.Fatal(err)
	}
	p := identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "explicit-guest-user-parser", ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: limits}}
	caller := service.Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}
	for _, flags := range []string{"--provision-user", "--provision-user nickvd", "--provision-user root:0:0:/root", "--provision-user nickvd:1000:1000:/home/x:extra", "--provision-user nickvd:1000:1000:/home/x --provision-user other:1001:1001:/home/y"} {
		if code := DispatchSession(ctx, s, caller, "create invalid-user --no-start "+flags, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 2 {
			t.Fatalf("%s: %d", flags, code)
		}
	}
	if len(s.Jobs.List(p)) != 0 {
		t.Fatal("invalid create admitted jobs")
	}
	if registry.Requests.Load() != 0 {
		t.Fatal("invalid account pulled a VM image")
	}
	for _, test := range []struct{ name, flags, user string }{{"default-root", "", ""}, {"opt-in", "--provision-user nickvd:1000:1000:/home/nickvd", "nickvd"}} {
		if code := DispatchSession(ctx, s, caller, "create "+test.name+" --no-start "+test.flags, service.IO{Stdout: io.Discard, Stderr: io.Discard}); code != 0 {
			t.Fatal(test.name, code)
		}
		m, err := r.SDK.Machine(ctx, test.name)
		if err != nil {
			t.Fatal(err)
		}
		d, err := m.Inspect(ctx)
		_ = m.Close()
		if err != nil {
			t.Fatal(err)
		}
		if test.user == "" && d.GuestUser != nil || test.user != "" && (d.GuestUser == nil || d.GuestUser.Name != test.user || d.GuestUser.UID != 1000 || d.GuestUser.Home != "/home/nickvd") {
			t.Fatal(test.name, d.GuestUser)
		}
	}
}
