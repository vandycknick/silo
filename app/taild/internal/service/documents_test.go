package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	silo "github.com/vandycknick/silo/sdk/go"
)

func TestRemoteTemplateStrictAllowlist(t *testing.T) {
	s := &Service{Config: config.Defaults()}
	good := `version: '1'
description: Daily driver
image: ghcr.io/vandycknick/silo/devbox:latest
resources: {cpus: 4, memory: 8GiB}
disk_size: 20GiB
vsock: true
userdata: |
  #!/bin/sh
  id
network: {kind: private, policy_ref: dev-egress, publish: [1, 22, 65535]}
labels: {team: runtime}
`
	if _, e := s.ParseTemplate(good); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"mounts", "disks", "kernel", "initramfs", "guest_agent", "forwards", "mount", "disk", "user", "unknown"} {
		if _, e := s.ParseTemplate("version: '1'\n" + field + ": []\n"); e == nil {
			t.Fatalf("accepted %s", field)
		}
	}
	for _, raw := range []string{
		"version: '1'\nuserdata: ''",
		"version: 1", "version: '2'", "version: null", "version: ['1']", "[]", "version: '1'\n---\n", "version: '1'\nversion: '1'",
		"version: '1'\nresources: {cpus: null}", "version: '1'\nresources: {cpus: '4'}", "version: '1'\nresources: {cpus: 0}", "version: '1'\nresources: {cpus: 256}", "version: '1'\nresources: {memory: 1.5GiB}", "version: '1'\ndisk_size: 18446744073709551615GiB", "version: '1'\ndisk_size: 0GiB",
		"version: '1'\nnetwork: {kind: none}", "version: '1'\nnetwork: {kind: named, target: private}", "version: '1'\nnetwork: {kind: private, target: /etc/passwd}", "version: '1'\nnetwork: {kind: private, policy_ref: ../x}", "version: '1'\nnetwork: {kind: private, publish: [0]}", "version: '1'\nnetwork: {kind: private, publish: [65536]}", "version: '1'\nnetwork: {kind: private, publish: [22,22]}", "version: '1'\nnetwork: {kind: private, publish: {bind: any}}", "version: '1'\nnetwork: {kind: private, publish: ['127.0.0.1:8080:80']}",
		"version: '1'\nvsock: false", "version: '1'\nuserdata: /etc/passwd", "version: '1'\nuserdata: {file: /etc/passwd}", "version: '1'\nlabels: {io.silo.taild.owner: forged}", "version: '1'\nlabels: {n: 7}", "version: '1'\nlabels: {n: one, n: two}", "version: &v '1'\ndescription: *v", "version: '1'\n<<: {image: bad}", strings.Repeat("x", DocumentLimit+1),
	} {
		if _, e := s.ParseTemplate(raw); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, name := range []string{"a", "0", strings.Repeat("x", 63), "a-"} {
		if !documentName(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"", "../x", "A", "-a", "a_b", strings.Repeat("x", 64)} {
		if documentName(name) {
			t.Fatal(name)
		}
	}
}

func TestPrincipalDocumentsRealFilesTiersAndReload(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	one, two := domainCaller(t, s, "user:1"), domainCaller(t, s, "user:2")
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
	if e = s.ReloadDocuments(); e != nil {
		t.Fatal(e)
	}
	d, e = call(two, "show", "dev", "")
	if e != nil || *d[0].Template.Description != "refreshed" {
		t.Fatal(d, e)
	}
	if e = os.WriteFile(operator, []byte("version: '1'\nmounts: []"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = s.ReloadDocuments(); e == nil {
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
	c := domainCaller(t, s, "user:1")
	for _, raw := range []string{`tailscale "vm" {}`, `tailscale "other" { tags = ["tag:a"] }`, `forward "host" "x" { target = "127.0.0.1" target_port = 80 }`} {
		if _, e := s.Documents(ctx, c, "policy", "validate", "", "", raw); e == nil {
			t.Fatal(raw)
		}
	}
	// Valid SDK policies with either forward kind or a tunnel reference are
	// rejected for their authority, not merely because of malformed HCL syntax.
	for _, forward := range []silo.NetworkForward{{Name: "host", Kind: silo.NetworkForwardHost, Target: ptr("name:other-vm"), TargetPort: ptr(uint16(80))}, {Name: "tail", Kind: silo.NetworkForwardTailscale, Tunnel: ptr("vm"), Target: ptr("name:peer"), TargetPort: ptr(uint16(80))}} {
		var tunnels []silo.TailscaleTunnel
		if forward.Kind == silo.NetworkForwardTailscale {
			tunnels = []silo.TailscaleTunnel{{Name: "vm"}}
		}
		built, e := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{Tunnels: tunnels, Forwards: []silo.NetworkForward{forward}})
		if e != nil {
			t.Fatal(e)
		}
		hcl, e := built.HCL()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = parseRemotePolicy(hcl); e == nil {
			t.Fatal("accepted authority", hcl)
		}
	}
	raw := `settings { default_action = "deny" }
endpoint "ip" "all" {
 protocol = "tcp"
 destination_cidrs = ["0.0.0.0/0", "::/0"]
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
`
	p, e := parseRemotePolicy(raw)
	if e != nil {
		t.Fatal(e)
	}
	injected, e := InjectTailnet(p, "exact-name")
	if e != nil {
		t.Fatal(e)
	}
	hcl, e := injected.HCL()
	if e != nil {
		t.Fatal(e)
	}
	round, e := silo.ParseNetworkPolicyHCL(hcl)
	if e != nil {
		t.Fatal(e)
	}
	again, e := round.HCL()
	if e != nil || hcl != again {
		t.Fatal(e, hcl, again)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal([]byte(p.JSON()), &before)
	_ = json.Unmarshal([]byte(injected.JSON()), &after)
	for _, key := range []string{"metadata", "settings", "credentials", "forwards"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatalf("lost %s", key)
		}
	}
	// Canonical metadata is not an HCL declaration, but JSON injection must
	// retain even nested values the convenient Go config does not model.
	before["metadata"] = json.RawMessage(`{"nested":{"numbers":[1,2],"flag":true}}`)
	canonical, e := json.Marshal(before)
	if e != nil {
		t.Fatal(e)
	}
	withMetadata, e := silo.ParseNetworkPolicyJSON(string(canonical))
	if e != nil {
		t.Fatal(e)
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal([]byte(withMetadata.JSON()), &original)
	withMetadata, e = InjectTailnet(withMetadata, "exact-name")
	if e != nil {
		t.Fatal(e)
	}
	var kept map[string]json.RawMessage
	_ = json.Unmarshal([]byte(withMetadata.JSON()), &kept)
	if !reflect.DeepEqual(kept["metadata"], original["metadata"]) {
		t.Fatal("lost metadata")
	}
	var rules []map[string]json.RawMessage
	_ = json.Unmarshal(after["rules"], &rules)
	var old []map[string]json.RawMessage
	_ = json.Unmarshal(before["rules"], &old)
	if len(rules) != 4 || !reflect.DeepEqual(rules[0], old[0]) {
		t.Fatal(rules)
	}
	old[1]["tunnel"] = json.RawMessage(`"vm"`)
	if !reflect.DeepEqual(rules[1], old[1]) {
		t.Fatal(rules)
	}
	if !strings.Contains(hcl, "100.64.0.0/10") || !strings.Contains(hcl, "fd7a:115c:a1e0::/48") || !strings.Contains(hcl, `hostname = "exact-name"`) {
		t.Fatal(hcl)
	}
	if _, e = parseRemotePolicy(hcl); e == nil {
		t.Fatal("accepted injected authority as remote policy")
	}
	// Even --no-tailnet cannot bypass remote authority checks on operator files.
	s.Config.PoliciesDir = t.TempDir()
	if e = os.WriteFile(filepath.Join(s.Config.PoliciesDir, "evil.hcl"), []byte(hcl), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Create(ctx, c, CreateRequest{Name: "no-bypass", PolicyRef: "evil", NoTailnet: true}); e == nil {
		t.Fatal("no-tailnet bypass")
	}
}

func TestShippedOperatorExamplesThroughPublicSDK(t *testing.T) {
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
	parsed, e := s.ParseTemplate(string(template))
	if e != nil {
		t.Fatal(e)
	}
	policy, e := os.ReadFile(filepath.Join(examples, "dev-egress.hcl"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := parseRemotePolicy(string(policy))
	if e != nil {
		t.Fatal(e)
	}
	if parsed.Network == nil || parsed.Network.PolicyRef == nil || *parsed.Network.PolicyRef != "dev-egress" {
		t.Fatal(parsed)
	}
	check, e := s.Runtime.SDK.CheckPolicySecrets(context.Background(), p, "", nil)
	if e != nil || check.Status != silo.PolicySecretsMissing || check.Slots[0].Name != "github-api.token" {
		t.Fatal(check, e)
	}
}

func TestTemplateCreationOverridesAndStampedAuthority(t *testing.T) {
	s := actualService(t)
	ctx := context.Background()
	c := domainCaller(t, s, "user:1")
	// A real tiny OCI image, materialized into a stopped VM by the native SDK.
	fixture := testfixture.OCIRegistry(t, "")
	registry := fixture.Reference
	s.Config.VM.AllowedRegistries = []string{strings.Split(registry, "/")[0] + "/fixture"}
	raw := "version: '1'\nimage: " + registry + "\nresources: {cpus: 2, memory: 512MiB}\ndisk_size: 1GiB\nnetwork: {kind: private, publish: [8080]}\nlabels: {team: template, x: original}"
	if _, e := s.Documents(ctx, c, "template", "create", "dev", "", raw); e != nil {
		t.Fatal(e)
	}
	op, e := s.Create(ctx, c, CreateRequest{Name: "overridden", Template: "dev", CPUs: 1, Labels: map[string]string{"x": "override"}, NoStart: true})
	succeeded(t, s, c, op, e)
	m, e := s.Runtime.SDK.Machine(ctx, "overridden")
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	defer m.Remove(ctx)
	d, e := m.Inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if *d.CPUs != 1 || d.Memory.Bytes() != 512<<20 || d.Labels[TemplateLabel] != "dev" || d.Labels[GuestPortsLabel] != "[8080]" || d.Labels["team"] != "template" || d.Labels["x"] != "override" || d.Network.Publish != nil || d.Network.Tailscale != nil {
		t.Fatalf("%+v", d)
	}
	v, e := s.Show(ctx, c.Peer, "overridden")
	if e != nil || v.Template != "dev" || len(v.GuestTCPPorts) != 1 {
		t.Fatal(v, e)
	}
}
