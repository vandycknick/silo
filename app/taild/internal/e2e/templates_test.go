//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/sshd"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestNativeKVMTemplatesPolicyAndMissingSecrets(t *testing.T) {
	if os.Getenv("SILO_E2E_KVM") != "1" {
		t.Skip("SILO_E2E_KVM=1 required")
	}
	rootfs := testfixture.Path(t, "SILO_TAILD_TEST_ROOTFS", true)
	registry := testfixture.OCIRegistry(t, rootfs)
	c := config.Defaults()
	c.Home = t.TempDir()
	c.RuntimeRoot = testfixture.Path(t, "SILO_TEST_RUNTIME_ROOT", true)
	c.TemplatesDir = t.TempDir()
	c.PoliciesDir = t.TempDir()
	c.VM.Defaults = config.Resources{CPUs: 1, Memory: "1GiB", Disk: "1GiB"}
	c.VM.DefaultImage = registry.Reference
	c.VM.AllowedRegistries = []string{strings.Split(registry.Reference, "/")[0] + "/fixture"}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	audit, e := state.OpenAudit(c.Home, 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer audit.Close()
	r, e := runtime.Open(ctx, c, "native-phase12")
	if e != nil {
		t.Fatal(e)
	}
	s := &service.Service{Runtime: r, Audit: audit, Jobs: jobs.New(ctx, 8), Config: c, VMNodesEnabled: true}
	defer func() {
		cancel()
		drain, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_ = s.Jobs.Wait(drain)
		entries, _ := r.SDK.Inventory(drain)
		for _, entry := range entries {
			m, e := r.SDK.Machine(drain, entry.ID)
			if e == nil {
				_, _ = m.StopWith(drain, silo.StopOptions{Force: true, Timeout: time.Second})
				_ = m.Remove(drain)
				_ = m.Close()
			}
		}
		_ = r.Close()
	}()
	one, two := principal(t, c, "user:12"), principal(t, c, "user:24")
	run := func(caller service.Caller, line, input string, want int) string {
		t.Helper()
		var out, err bytes.Buffer
		code := sshd.DispatchSession(ctx, s, caller, line, service.IO{Stdin: strings.NewReader(input), Stdout: &out, Stderr: &err})
		if code != want {
			t.Fatalf("%s exit %d want %d\n%s\n%s", line, code, want, out.String(), err.String())
		}
		return out.String() + err.String()
	}
	var allowedCalls, deniedCalls atomic.Int64
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedCalls.Add(1)
		fmt.Fprint(w, "phase12-allowed-http")
	}))
	defer allowed.Close()
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { deniedCalls.Add(1); fmt.Fprint(w, "phase12-denied-http") }))
	defer denied.Close()
	port := func(server *httptest.Server) string {
		_, p, e := net.SplitHostPort(server.Listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	policy := fmt.Sprintf(`settings { default_action = "deny" }
endpoint "http" "local-http" {
 hosts = ["allowed.test:%s"]
}
rule "allow-local-http" {
 endpoints = [http["local-http"]]
 verdict = "allow"
}
`, port(allowed))
	run(one, "policy create local --json", policy, 0)
	template := fmt.Sprintf("version: '1'\nimage: %s\nresources: {cpus: 1, memory: 1GiB}\ndisk_size: 1GiB\nvsock: true\nnetwork: {kind: private, policy_ref: local, publish: [8080]}\nlabels: {team: phase12}\nuserdata: |\n  #!/bin/sh\n  /bin/echo phase12-userdata\n", registry.Reference)
	run(one, "template create dev --json", template, 0)
	if e = os.WriteFile(filepath.Join(c.TemplatesDir, "operator.yaml"), []byte("version: '1'"), 0644); e != nil {
		t.Fatal(e)
	}
	listed := run(one, "template ls --json", "", 0)
	if !strings.Contains(listed, `"tier":"yours"`) || !strings.Contains(listed, `"tier":"operator"`) {
		t.Fatal(listed)
	}
	run(two, "template show dev --json", "", 3)
	run(two, "policy show local --json", "", 3)
	run(one, "create templated --template dev --no-tailnet --provision-user silo:1000:1000:/home/silo --json", "", 0)
	m, e := r.SDK.Machine(ctx, "templated")
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	d, e := m.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if d.Network.Tailscale != nil || d.Network.Publish != nil || d.Network.Policy == nil || d.Labels[service.TemplateLabel] != "dev" || d.Labels[service.PolicyLabel] != "local" {
		t.Fatalf("authority drift %+v", d)
	}
	if d.RunID == nil {
		t.Fatal("missing actual run ID")
	}
	t.Logf("actual VM %s run %s, template=%s policy=%s no TS or host publication", d.ID, *d.RunID, d.Labels[service.TemplateLabel], d.Labels[service.PolicyLabel])
	if text := run(one, "exec --json templated -- /bin/id", "", 2); text == "" {
		t.Fatal(text)
	} // exec JSON remains unsupported
	proof := run(one, "exec templated -- /bin/id", "", 0)
	// Exec streams stdout, unlike management human output, included by run above.
	if !strings.Contains(proof, "uid=1000(silo)") {
		t.Fatal(proof)
	}
	fetch := func(p, host string, want int) string {
		script := fmt.Sprintf("exec 3<>/dev/tcp/192.168.105.254/%s || exit 23; printf 'GET /phase12 HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n' >&3; /bin/cat <&3", p, host)
		// Quoting below is the actual SSH management tokenizer contract.
		return run(one, "exec templated -- /bin/bash -c '"+strings.ReplaceAll(script, "'", "'\\''")+"'", "", want)
	}
	if result := fetch(port(allowed), "allowed.test:"+port(allowed), 0); !strings.Contains(result, "phase12-allowed-http") {
		t.Fatal(result)
	}
	if result := fetch(port(allowed), "denied.test:"+port(allowed), 0); !strings.Contains(result, "403 Forbidden") {
		t.Fatal("denied host did not receive policy refusal", result)
	}
	fetch(port(denied), "denied.test:"+port(denied), 23)
	if allowedCalls.Load() != 1 || deniedCalls.Load() != 0 {
		t.Fatalf("real HTTP requests allowed=%d denied=%d", allowedCalls.Load(), deniedCalls.Load())
	}
	missing := `endpoint "https" "github" { hosts = ["api.github.com"] }
credential "bearer_token" "github-api" { endpoint = https.github }
rule "github" {
 endpoints = [https.github]
 credential = bearer_token["github-api"]
 verdict = "allow"
}`
	run(one, "policy create needs-token --json", missing, 0)
	before, e := r.SDK.Inventory(ctx)
	if e != nil {
		t.Fatal(e)
	}
	result := run(one, "create must-not-exist --template dev --policy needs-token --no-tailnet --json", "", 2)
	if !strings.Contains(result, "github-api.token") || !strings.Contains(result, "bearer_token.github-api.token") {
		t.Fatal(result)
	}
	after, e := r.SDK.Inventory(ctx)
	if e != nil || len(after) != len(before) {
		t.Fatal(after, e)
	}
	if _, e = r.SDK.Machine(ctx, "must-not-exist"); !silo.IsErrorKind(e, silo.ErrorMachineNotFound) {
		t.Fatal(e)
	}
	run(one, "rm templated --force --yes --json", "", 0)
	if v, e := s.List(ctx, one.Peer); e != nil || len(v) != 0 {
		t.Fatal(v, e)
	}
	t.Logf("real TCP/HTTP allow=%d deny=%d; missing token rejected before VM creation; registry requests=%d", allowedCalls.Load(), deniedCalls.Load(), registry.Requests.Load())
}
