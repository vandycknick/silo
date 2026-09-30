package sshd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
)

func TestDocumentCommandsActualRuntimeJSONCRUDAndFiniteInput(t *testing.T) {
	c := config.Defaults()
	c.Home = t.TempDir()
	c.TemplatesDir = t.TempDir()
	c.PoliciesDir = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	ctx := context.Background()
	r, e := runtime.Open(ctx, c, "documents-cli")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	s := &service.Service{Runtime: r, Audit: audit, Config: c}
	limits, e := c.Limits()
	if e != nil {
		t.Fatal(e)
	}
	p := identity.Peer{Principals: []identity.Principal{"tag:one", "tag:two"}, NodeID: "explicit-doc-input", ObservedAt: time.Now(), Permissions: identity.Permissions{Actions: identity.Actions(), Limits: limits}}
	caller := service.Caller{Peer: p, Resolve: func(ctx context.Context) (identity.Peer, error) { return p, ctx.Err() }}
	run := func(line, input string, want int) string {
		t.Helper()
		var out, err bytes.Buffer
		code := DispatchSession(ctx, s, caller, line, service.IO{Stdin: strings.NewReader(input), Stdout: &out, Stderr: &err})
		if code != want {
			t.Fatalf("%s exit %d: %s %s", line, code, out.String(), err.String())
		}
		if strings.Contains(line, "--json") {
			var v map[string]json.RawMessage
			if e = json.Unmarshal(out.Bytes(), &v); e != nil {
				t.Fatal(e, out.String())
			}
			if string(v["ok"]) != map[bool]string{true: "true", false: "false"}[want == 0] {
				t.Fatal(out.String())
			}
		}
		return out.String() + err.String()
	}
	for _, kind := range []string{"template", "policy"} {
		raw := "version: '1'"
		if kind == "policy" {
			raw = `settings { default_action = "deny" }`
		}
		run(kind+" create same --json", raw, 2)
		run(kind+" create same --owner tag:one --json", raw, 0)
		run(kind+" create same --owner tag:one --json", raw, 5)
		run(kind+" create same --owner tag:two --json", raw, 0)
		run(kind+" show same --json", "", 2)
		run(kind+" show same --owner tag:foreign --json", "", 4)
		run(kind+" show same --owner tag:one --json", "", 0)
		listed := run(kind+" ls --json", "", 0)
		if !strings.Contains(listed, `"owner":"tag:one"`) || !strings.Contains(listed, `"owner":"tag:two"`) {
			t.Fatal(listed)
		}
		run(kind+" edit same --owner tag:one --json", raw, 0)
		run(kind+" edit absent --owner tag:one --json", raw, 3)
		run(kind+" validate --json", raw, 0)
		run(kind+" validate --json", strings.Repeat("x", service.DocumentLimit+1), 2)
		run(kind+" rm same --owner tag:one --json", "", 0)
		run(kind+" show same --owner tag:one --json", "", 3)
		run(kind+" show same --owner tag:two --json", "", 0)
	}
	// A cancelled session interrupts the production contextual input reader.
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	expired, cancel := context.WithCancel(ctx)
	cancel()
	input := newInput(expired, read)
	if _, e := documentInput(expired, service.IO{Input: input.Reader}, service.DocumentLimit); e == nil {
		t.Fatal("cancelled finite input succeeded")
	}
}
