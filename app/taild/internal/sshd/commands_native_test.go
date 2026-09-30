package sshd

import (
	"bytes"
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

func TestActualSDKCRLFCommandRemovalConfirmation(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: "256MiB", Disk: "1GiB"}
	c.VM.DefaultImage = registry.Reference
	c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, e := runtime.Open(ctx, c, "crlf-native")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	reg := jobs.New(ctx, 8)
	defer func() {
		if e := reg.Wait(context.Background()); e != nil {
			t.Error(e)
		}
	}()
	s := &service.Service{Runtime: r, Audit: audit, Jobs: reg, Config: c}
	limits, e := c.Limits()
	if e != nil {
		t.Fatal(e)
	}
	p := identity.Peer{Principals: []identity.Principal{"user:7"}, NodeID: "explicit-domain-crlf", ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: limits}}
	caller := service.Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}
	var diagnostic bytes.Buffer
	if code := DispatchSession(ctx, s, caller, "create crlf-vm --no-start", service.IO{Stdout: io.Discard, Stderr: &diagnostic}); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	input := newInput(ctx, strings.NewReader("rm crlf-vm\r\nyes\r\nls --json\r\n"))
	reader := input.Reader(ctx)
	command, e := readLine(reader)
	if e != nil {
		t.Fatal(e)
	}
	diagnostic.Reset()
	if code := DispatchSession(ctx, s, caller, command, service.IO{Stdin: reader, Input: input.Reader, Stdout: io.Discard, Stderr: &diagnostic, Terminal: service.Terminal{Present: true}}); code != 0 {
		t.Fatal("actual CRLF confirmation rejected", code, diagnostic.String())
	}
	if _, e = s.Show(ctx, p, "crlf-vm"); e == nil || service.Categorize(e).Exit != 3 {
		t.Fatal("confirmed machine was not removed", e)
	}
	command, e = readLine(input.Reader(ctx))
	if e != nil || command != "ls --json" {
		t.Fatal("confirmation left an LF for the next command", command, e)
	}
	var out bytes.Buffer
	if code := DispatchSession(ctx, s, caller, command, service.IO{Stdout: &out, Stderr: io.Discard}); code != 0 || out.String() != "{\"ok\":true,\"data\":[]}\n" {
		t.Fatal(code, out.String())
	}
}
