package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

func TestRemoteTemplateStrictAllowlist(t *testing.T) {
	s := &Service{Config: testfixture.Config()}
	good := `version: '1'
description: Daily driver
image: ghcr.io/vandycknick/silo/devbox:latest
resources: {cpus: 4}
vsock: true
userdata: |
  #!/bin/sh
  id
network: {kind: private, policy_ref: dev-egress, publish: [1, 22, 65535]}
labels: {team: runtime}
`
	if _, e := s.ParseTemplate(context.Background(), good); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"mounts", "disks", "kernel", "initramfs", "guest_agent", "forwards", "mount", "disk", "user", "unknown"} {
		if _, e := s.ParseTemplate(context.Background(), "version: '1'\n"+field+": []\n"); e == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	for _, raw := range []string{
		"version: '1'\nuserdata: ''",
		"version: 1", "version: '2'", "version: null", "version: ['1']", "[]", "version: '1'\n---\n", "version: '1'\nversion: '1'",
		"version: '1'\nresources: {cpus: null}", "version: '1'\nresources: {cpus: '4'}", "version: '1'\nresources: {cpus: 0}", "version: '1'\nresources: {cpus: 256}",
		"version: '1'\nnetwork: {kind: none}", "version: '1'\nnetwork: {kind: named, target: private}", "version: '1'\nnetwork: {kind: private, target: /etc/passwd}", "version: '1'\nnetwork: {kind: private, policy_ref: ../x}", "version: '1'\nnetwork: {kind: private, publish: [0]}", "version: '1'\nnetwork: {kind: private, publish: [65536]}", "version: '1'\nnetwork: {kind: private, publish: [22,22]}", "version: '1'\nnetwork: {kind: private, publish: {bind: any}}", "version: '1'\nnetwork: {kind: private, publish: ['127.0.0.1:8080:80']}",
		"version: '1'\nvsock: false", "version: '1'\nuserdata: /etc/passwd", "version: '1'\nuserdata: {file: /etc/passwd}", "version: '1'\nlabels: {io.silo.taild.owner: forged}", "version: '1'\nlabels: {n: 7}", "version: '1'\nlabels: {n: one, n: two}", "version: &v '1'\ndescription: *v", "version: '1'\n<<: {image: bad}", strings.Repeat("x", DocumentLimit+1),
	} {
		if _, e := s.ParseTemplate(context.Background(), raw); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestRemoteTemplateResourceValidationThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	if _, err := s.ParseTemplate(ctx, "version: '1'\nresources: {memory: 8GiB}\ndisk_size: 20GiB"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"version: '1'\nresources: {memory: 1.5GiB}",
		"version: '1'\ndisk_size: 18446744073709551615GiB",
		"version: '1'\ndisk_size: 0GiB",
	} {
		if _, err := s.ParseTemplate(ctx, raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestPrincipalDocumentsRealFilesTiersAndReload(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	one, two := domainCaller(s, "user:1"), domainCaller(s, "user:2")
	s.Config.TemplatesDir = t.TempDir()
	s.Config.PoliciesDir = t.TempDir()
	operator := filepath.Join(s.Config.TemplatesDir, "dev.yaml")
	own, _, _ := s.documentPaths("template", "user:1")
	probe, probeErr := documentDir(own, filepath.Join(s.Config.Home, "taild"), true)
	if probeErr != nil {
		t.Fatal("open owned documents", probeErr)
	}
	_ = probe.Close()
	if e := os.WriteFile(operator, []byte("version: '1'\ndescription: operator"), 0644); e != nil {
		t.Fatal(e)
	}
	call := func(c Caller, verb, name, raw string) ([]Document, error) {
		return s.Documents(ctx, c, "template", verb, name, "", raw)
	}
	d, e := call(one, "show", "dev", "")
	if e != nil || d[0].Tier != "operator" {
		t.Fatalf("%+v %v", d, e)
	}
	for _, verb := range []string{"edit", "rm"} {
		_, e = call(one, verb, "dev", "version: '1'")
		if Categorize(e).Exit != 4 {
			t.Fatal(e)
		}
	}
	_, e = call(one, "create", "dev", "version: '1'\ndescription: yours")
	if e != nil {
		t.Fatal(e)
	}
	d, e = call(one, "show", "dev", "")
	if e != nil || *d[0].Template.Description != "yours" {
		t.Fatal(d, e)
	}
	d, e = call(two, "show", "dev", "")
	if e != nil || *d[0].Template.Description != "operator" {
		t.Fatal(d, e)
	}
	_, e = call(one, "create", "private", "version: '1'")
	if e != nil {
		t.Fatal(e)
	}
	_, e = call(two, "show", "private", "")
	if Categorize(e).Exit != 3 {
		t.Fatal(e)
	}
	d, e = call(one, "ls", "", "")
	if e != nil || len(d) != 3 {
		t.Fatal(d, e)
	}
	// Reload on every list and explicit SIGHUP hook, no stale snapshot.
	if e = os.WriteFile(operator, []byte("version: '1'\ndescription: refreshed"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = s.ReloadDocuments(ctx); e != nil {
		t.Fatal(e)
	}
	d, e = call(two, "show", "dev", "")
	if e != nil || *d[0].Template.Description != "refreshed" {
		t.Fatal(d, e)
	}
	if e = os.WriteFile(operator, []byte("version: '1'\nmounts: []"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = s.ReloadDocuments(ctx); e == nil {
		t.Fatal("invalid operator reload accepted")
	}
	if _, e = call(one, "ls", "", ""); Categorize(e).Exit != 9 {
		t.Fatal(e)
	}
	if e = os.WriteFile(operator, []byte("version: '1'"), 0644); e != nil {
		t.Fatal(e)
	}
	denied := one
	denied.Peer.Permissions.Actions = []identity.Action{identity.Read}
	denied.Resolve = func(context.Context) (identity.Peer, error) { return denied.Peer, nil }
	_, e = call(denied, "edit", "private", "version: '1'")
	if Categorize(e).Exit != 4 {
		t.Fatal(e)
	}
	// One exact-create winner under concurrent callers, with atomic durable files.
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := call(one, "create", "concurrent", "version: '1'"); results <- e })
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		} else if Categorize(e).Exit != 5 {
			t.Fatal(e)
		}
	}
	if wins != 1 {
		t.Fatal(wins)
	}
	path, _, _ := s.documentPaths("template", "user:1")
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal(info, e)
	}
	info, e = os.Stat(filepath.Join(path, "private.yaml"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, e)
	}
	// Reject file and ancestor symlinks, oversized files and unsafe modes.
	target := filepath.Join(t.TempDir(), "outside.yaml")
	if e = os.WriteFile(target, []byte("version: '1'"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, filepath.Join(path, "link.yaml")); e != nil {
		t.Fatal(e)
	}
	_, e = call(one, "show", "link", "")
	if Categorize(e).Exit != 9 {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(path, "link.yaml")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(path, "large.yaml"), []byte(strings.Repeat("x", DocumentLimit+1)), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = call(one, "show", "large", "")
	if Categorize(e).Exit != 9 {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(path, "large.yaml")); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(path, "private.yaml"), 0644); e != nil {
		t.Fatal(e)
	}
	_, e = call(one, "show", "private", "")
	if Categorize(e).Exit != 9 {
		t.Fatal(e)
	}
	if e = os.Rename(path, path+"-saved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(path+"-saved", path); e != nil {
		t.Fatal(e)
	}
	_, e = call(one, "show", "dev", "")
	if Categorize(e).Exit != 9 {
		t.Fatal(e)
	}
}

func TestRemotePoliciesCanonicalInjectionPreservesConfigAndDenies(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	c := domainCaller(s, "user:1")
	for _, raw := range []string{`tailscale "vm" {}`, `tailscale "other" { tags = ["tag:a"] }`, `forward "host" "x" { target = "127.0.0.1" target_port = 80 }`} {
		if _, e := s.Documents(ctx, c, "policy", "validate", "", "", raw); e == nil {
			t.Fatal(raw)
		}
	}
	// Normalize valid declarations through the real daemon first, then reject
	// their remote authority rather than relying on malformed HCL syntax.
	for _, declaration := range []string{
		`forward "host" "host" {
 target = "name:other-vm"
 target_port = 80
}`,
		`tailscale "vm" {}
forward "tailscale" "tail" {
 tunnel = tailscale.vm
 target = "name:peer"
 target_port = 80
}`,
	} {
		built, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: declaration}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.parseRemotePolicy(ctx, built.HCL); e == nil {
			t.Fatal("accepted authority", built.HCL)
		}
	}
	raw := `settings { default_action = "deny" }
endpoint "ip" "all" {
 protocol = "tcp"
 destination_cidrs = ["0.0.0.0/0", "::/0"]
}

endpoint "https" "plugin" {
 hosts = ["api.example.test"]
}
credential "openai_codex_oauth" "plugin-auth" {
 endpoint = https.plugin
}
rule "deny" {
 endpoints = [ip.all]
 priority = -2147483648
 verdict = "deny"
}
rule "allow" {
 endpoints = [ip.all]
 priority = 10
 verdict = "allow"
 reason = "keep me"
 disabled = true
}
rule "plugin-rule" {
 endpoints = [https.plugin]
 credential = openai_codex_oauth.plugin-auth
 condition = "http.method == 'POST'"
 verdict = "allow"
}
`
	p, e := s.parseRemotePolicy(ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	injected, e := s.InjectTailnet(ctx, p, "exact-name", "user:1", "")
	if e != nil {
		t.Fatal(e)
	}
	hcl := injected.HCL
	round, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: hcl}})
	if e != nil || hcl != round.HCL {
		t.Fatal(e, hcl, round)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal([]byte(p.CanonicalJSON), &before)
	_ = json.Unmarshal([]byte(injected.CanonicalJSON), &after)
	for _, key := range []string{"metadata", "settings", "credentials", "forwards"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatalf("lost %s", key)
		}
	}
	var beforeEndpoints, afterEndpoints []json.RawMessage
	if err := json.Unmarshal(before["endpoints"], &beforeEndpoints); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after["endpoints"], &afterEndpoints); err != nil {
		t.Fatal(err)
	}
	if len(afterEndpoints) != len(beforeEndpoints)+2 || !reflect.DeepEqual(beforeEndpoints, afterEndpoints[:len(beforeEndpoints)]) {
		t.Fatal("lost canonical endpoint plugin fields")
	}
	// Canonical metadata is not an HCL declaration, but JSON injection must
	// retain even nested values the convenient Go config does not model.
	before["metadata"] = json.RawMessage(`{"nested":{"numbers":[1,2],"flag":true}}`)
	canonical, e := json.Marshal(before)
	if e != nil {
		t.Fatal(e)
	}
	withMetadata, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: string(canonical)}})
	if e != nil {
		t.Fatal(e)
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal([]byte(withMetadata.CanonicalJSON), &original)
	withMetadata, e = s.InjectTailnet(ctx, withMetadata, "exact-name", "user:1", "")
	if e != nil {
		t.Fatal(e)
	}
	var kept map[string]json.RawMessage
	_ = json.Unmarshal([]byte(withMetadata.CanonicalJSON), &kept)
	if !reflect.DeepEqual(kept["metadata"], original["metadata"]) {
		t.Fatal("lost metadata")
	}
	var rules []map[string]json.RawMessage
	_ = json.Unmarshal(after["rules"], &rules)
	var old []map[string]json.RawMessage
	_ = json.Unmarshal(before["rules"], &old)
	if len(rules) != 5 || !reflect.DeepEqual(rules[0], old[0]) || !reflect.DeepEqual(rules[2], old[2]) {
		t.Fatal(rules)
	}
	old[1]["tunnel"] = json.RawMessage(`"vm"`)
	if !reflect.DeepEqual(rules[1], old[1]) {
		t.Fatal(rules)
	}
	if !strings.Contains(hcl, "100.64.0.0/10") || !strings.Contains(hcl, "fd7a:115c:a1e0::/48") || !strings.Contains(hcl, `hostname = "exact-name"`) {
		t.Fatal(hcl)
	}
	if _, e = s.parseRemotePolicy(ctx, hcl); e == nil {
		t.Fatal("accepted injected authority as remote policy")
	}
	// Omitting --tailscale cannot bypass remote authority checks on operator files.
	s.Config.PoliciesDir = t.TempDir()
	if e = os.WriteFile(filepath.Join(s.Config.PoliciesDir, "evil.hcl"), []byte(hcl), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Create(ctx, c, CreateRequest{Image: "ghcr.io/vandycknick/silo/devbox:latest", Name: "no-bypass", PolicyRef: "evil"}); e == nil {
		t.Fatal("remote authority bypass")
	}
}

func TestCanonicalInjectionCarriesVerifiedOwnerAndPinnedControl(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.VMNodesEnabled = true
	s.Config.Tailnet.ControlURL = "https://wrong-config.example.test"
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: "https://pinned-control.example.test"}}
	for _, owner := range []identity.Principal{"tag:owner", "user:7"} {
		caller := domainCaller(s, owner)
		selected := owner
		if owner == "user:7" {
			selected = ""
		}
		ctx := context.Background()
		op, e := s.Create(ctx, caller, CreateRequest{Image: registry.Reference, Name: "exact", Owner: selected, NoStart: true, Tailscale: true})
		daemon.Succeeded(t, s.Jobs, caller.Peer, op, e)
		data, e := s.Runtime.Control.Inspect(ctx, "exact")
		if e != nil {
			t.Fatal(e)
		}
		var authority struct {
			Metadata map[string]json.RawMessage `json:"metadata"`
		}
		if err := json.Unmarshal([]byte(data.PolicyJSON), &authority); err != nil {
			t.Fatal(err)
		}
		// Canonical metadata can contain objects; node authority itself is a
		// JSON string consumed by netd, not an object-valued metadata entry.
		var nodeAuthority string
		if err := json.Unmarshal(authority.Metadata["io.silo.taild.node"], &nodeAuthority); err != nil {
			t.Fatal(err)
		}
		var expected struct {
			Owner   string `json:"owner"`
			Tailnet string `json:"tailnet"`
			Suffix  string `json:"suffix"`
		}
		if err := json.Unmarshal([]byte(nodeAuthority), &expected); err != nil || expected.Owner != string(owner) || expected.Tailnet != "fixture" || expected.Suffix != "fixture.test" {
			t.Fatal("lost managed identity", expected, err)
		}
		reserved, err := json.Marshal(map[string]any{"version": 1, "metadata": authority.Metadata})
		if err != nil {
			t.Fatal(err)
		}
		injected, err := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: string(reserved)}})
		if err != nil || remotePolicy(injected) == nil {
			t.Fatal("reserved identity accepted without a tunnel", err)
		}
		round, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: data.PolicyJSON}})
		if removeErr := s.Runtime.Control.Remove(ctx, data.ID); removeErr != nil {
			t.Fatal(removeErr)
		}
		if e != nil {
			t.Fatal(e)
		}
		var root struct {
			Tailscale []silo.TailscaleTunnel `json:"tailscale"`
		}
		if e = json.Unmarshal([]byte(round.CanonicalJSON), &root); e != nil {
			t.Fatal(e)
		}
		if len(root.Tailscale) != 1 {
			t.Fatal("injected node declaration missing")
		}
		node := root.Tailscale[0]
		want := []string(nil)
		if owner == "tag:owner" {
			want = []string{"tag:owner"}
		}
		if node.Hostname == nil || *node.Hostname != "exact" || node.ControlURL == nil || *node.ControlURL != s.Enrollment.Pin.ControlURL || !slices.Equal(node.Tags, want) {
			t.Fatal("lost verified node handoff settings")
		}
		if _, e = s.parseRemotePolicy(ctx, round.HCL); e == nil {
			t.Fatal("caller could override injected node authority")
		}
	}
}

func TestShippedOperatorExamplesThroughRPC(t *testing.T) {
	s := actualService(t)
	_, source, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	examples := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../../packaging/silo-taild/examples"))
	template, e := os.ReadFile(filepath.Join(examples, "devbox.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := s.ParseTemplate(context.Background(), string(template))
	if e != nil {
		t.Fatal(e)
	}
	policy, e := os.ReadFile(filepath.Join(examples, "dev-egress.hcl"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.parseRemotePolicy(context.Background(), string(policy))
	if e != nil {
		t.Fatal(e)
	}
	if parsed.Network == nil || parsed.Network.PolicyRef == nil || *parsed.Network.PolicyRef != "dev-egress" {
		t.Fatal(parsed)
	}
	check, e := s.Runtime.Control.CheckPolicySecrets(context.Background(), p, "")
	if e != nil || check.State != w.PolicySecretsState_POLICY_SECRETS_STATE_MISSING || check.Slots[0].Name != "github-api.token" {
		t.Fatal(check, e)
	}
}

func TestTemplateCreationOverridesAndStampedAuthority(t *testing.T) {
	// Install fixture TLS trust before the real daemon inherits its environment.
	fixture := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	ctx := context.Background()
	c := domainCaller(s, "user:1")
	// A real tiny OCI image, materialized into a stopped VM through silod.
	registry := fixture.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry, "/")[0] + "/fixture"}
	raw := "version: '1'\nimage: " + registry + "\nresources: {cpus: 2, memory: 512MiB}\ndisk_size: 1GiB\nnetwork: {kind: private, publish: [8080]}\nlabels: {team: template, x: original}"
	if _, e := s.Documents(ctx, c, "template", "create", "dev", "", raw); e != nil {
		t.Fatal(e)
	}
	op, e := s.Create(ctx, c, CreateRequest{Name: "overridden", Template: "dev", CPUs: 1, Labels: map[string]string{"x": "override"}, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, e)
	d, e := s.Runtime.Control.Inspect(ctx, "overridden")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if err := s.Runtime.Control.Remove(ctx, d.ID); err != nil {
			t.Error(err)
		}
	}()
	if *d.CPUs != 1 || d.Memory.Bytes() != 512<<20 || d.Labels[TemplateLabel] != "dev" || d.Labels[GuestPortsLabel] != "[8080]" || d.Labels["team"] != "template" || d.Labels["x"] != "override" || d.Network.Publish != nil || d.Network.Tailscale != nil {
		t.Fatalf("%+v", d)
	}
	v, e := s.Show(ctx, c.Peer, "overridden")
	if e != nil || v.Template != "dev" || len(v.GuestTCPPorts) != 1 {
		t.Fatal(v, e)
	}
}

func TestPolicySecretAlternativesThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	p, err := s.parseRemotePolicy(ctx, `endpoint "https" "aws" {
 hosts = ["sts.amazonaws.com"]
}
credential "aws_credential" "prod" {
 endpoint = https.aws
}
`)
	if err != nil {
		t.Fatal(err)
	}
	check, err := s.Runtime.Control.CheckPolicySecrets(ctx, p, "")
	if err != nil {
		t.Fatal(err)
	}
	if check.State != w.PolicySecretsState_POLICY_SECRETS_STATE_MISSING || len(check.Requirements) != 1 {
		t.Fatalf("lost requirements: %+v", check)
	}
	alternatives := check.Requirements[0].Alternatives
	profile, static := false, false
	for _, alternative := range alternatives {
		profile = profile || slices.Equal(alternative.Slots, []string{"prod.profile"})
		static = static || slices.Equal(alternative.Slots, []string{"prod.access_key_id", "prod.secret_access_key"})
	}
	if !profile || !static || len(p.Secrets.Requirements) != 1 {
		t.Fatalf("lost alternatives: %+v %+v", check, p.Secrets)
	}
	diagnostic := Categorize(s.checkSecrets(ctx, p))
	if diagnostic.Exit != 2 || !strings.Contains(diagnostic.Error(), "prod.profile") || !strings.Contains(diagnostic.Error(), "prod.access_key_id + prod.secret_access_key") || !strings.Contains(diagnostic.Error(), " or ") {
		t.Fatalf("lost alternative diagnostics: %v", diagnostic)
	}
	// Policy documents expose metadata, never resolved credential values.
	caller := domainCaller(s, "user:1")
	docs, err := s.Documents(ctx, caller, "policy", "validate", "", "", p.HCL)
	if err != nil || len(docs) != 1 || docs[0].Secrets == nil || len(docs[0].Secrets.Requirements) != 1 {
		t.Fatal(docs, err)
	}
}

func TestPolicyDocumentOwnershipAndOperatorPrecedenceThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	s.Config.PoliciesDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(s.Config.PoliciesDir, "egress.hcl"), []byte(`settings { default_action = "deny" }`), 0644); err != nil {
		t.Fatal(err)
	}
	one, two := domainCaller(s, "user:1"), domainCaller(s, "user:2")
	if _, err := s.Documents(ctx, one, "policy", "create", "egress", "", `settings { default_action = "allow" }`); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		caller Caller
		tier   string
		action string
	}{{one, "yours", "allow"}, {two, "operator", "deny"}} {
		docs, err := s.Documents(ctx, test.caller, "policy", "show", "egress", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 1 || docs[0].Tier != test.tier || !strings.Contains(docs[0].Content, `default_action = "`+test.action+`"`) {
			t.Fatal(docs)
		}
	}
	for _, verb := range []string{"edit", "rm"} {
		if _, err := s.Documents(ctx, two, "policy", verb, "egress", "", `settings { default_action = "allow" }`); Categorize(err).Exit != 4 {
			t.Fatal(err)
		}
	}
	if err := s.ReloadDocuments(ctx); err != nil {
		t.Fatal(err)
	}
}
