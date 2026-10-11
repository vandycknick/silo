package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/testfixture"
	"github.com/vandycknick/silo/app/taild/internal/testfixture/daemon"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const forwardWebPolicy = `forward "tailscale" "web" {
  listen = ":443"
  target = "self"
  target_port = 8080
  protocol = "https"
  tls {
    provider = "tailscale"
  }
}
forward "tailscale" "raw" {
  listen = ":18080"
  target = "self"
  target_port = 8080
}
`

func TestForwardNodeViewConfigurationAndReadiness(t *testing.T) {
	s := &Service{Enrollment: &enroll.Manager{Pin: state.NodePin{Suffix: "tail.test"}}}
	d := &control.Snapshot{
		MachineData: &silo.MachineData{
			ID: "vm", Name: "web", Labels: map[string]string{},
			Network: silo.MachineNetwork{Tailscale: &silo.MachineTailscale{Hostname: "web"}},
			Status:  silo.MachineStatus{Kind: silo.MachineStatusStopped},
		},
		PolicyJSON: `{"forwards":[
			{"kind":"tailscale","name":"web","listen":":443","target":"self","target_port":8080,"protocol":"https"},
			{"kind":"host","name":"ignored","listen":":80","target_port":80},
			{"kind":"tailscale","name":"database","listen":":15432","target":"self","target_port":5432},
			{"kind":"tailscale","name":"alternate","listen":":8443","target":"self","target_port":8080,"protocol":"https"}
		]}`,
	}
	want := []ForwardView{
		{Name: "web", Protocol: "https", ListenPort: 443, TargetPort: 8080, URL: "https://web.tail.test/"},
		{Name: "database", Protocol: "tcp", ListenPort: 15432, TargetPort: 5432, URL: "tcp://web.tail.test:15432"},
		{Name: "alternate", Protocol: "https", ListenPort: 8443, TargetPort: 8080, URL: "https://web.tail.test:8443/"},
	}
	if v := s.nodeView(d); !reflect.DeepEqual(v.Forwards, want) {
		t.Fatal(v.Forwards)
	}
	run, node, dns := "run", "node", "web.tail.test"
	d.RunID = &run
	d.Status.Kind = silo.MachineStatusRunning
	d.NetworkObservation = &w.NetworkObservation{Live: &w.NodeStatus{
		MachineId: "vm", RunId: run, State: w.NodeState_NODE_STATE_READY,
		NodeId: &node, DnsName: &dns, UpdatedAt: timestamppb.Now(),
	}}
	if v := s.nodeView(d); !reflect.DeepEqual(v.Forwards, want) {
		t.Fatal(v.Forwards)
	}
	d.NetworkObservation.Live.KeyExpiry = timestamppb.New(time.Now().Add(-time.Hour))
	for i := range want {
		want[i].URL = ""
	}
	if v := s.nodeView(d); v.Node != "" || !reflect.DeepEqual(v.Forwards, want) {
		t.Fatal("expired DNS exposed forward URLs", v)
	}
	s.Enrollment = nil
	d.Status.Kind = silo.MachineStatusStopped
	if v := s.nodeView(d); !reflect.DeepEqual(v.Forwards, want) {
		t.Fatal("missing pin exposed forward URLs", v)
	}
	d.Network.Tailscale = nil
	if v := s.nodeView(d); v.Forwards != nil {
		t.Fatal("non-Tailscale VM exposed forwards", v)
	}
	d.Network.Tailscale = &silo.MachineTailscale{Hostname: "web"}
	for _, raw := range []string{"", "{", `{"forwards":[]}`, `{"forwards":[{"kind":"tailscale","listen":":65536"}]}`} {
		d.PolicyJSON = raw
		v := s.nodeView(d)
		if v.Forwards != nil {
			t.Fatal(raw, v.Forwards)
		}
		b, err := json.Marshal(v)
		if err != nil || strings.Contains(string(b), `"forwards"`) {
			t.Fatal("empty forwards not omitted", string(b), err)
		}
	}
}

func TestForwardRemoteDocumentsAuthorityThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := t.Context()
	c := domainCaller(s, "user:1")
	s.Config.PoliciesDir = testfixture.TempDir(t)
	// Free-standing documents are valid without enrollment or a deployment scope.
	for _, verb := range []string{"validate", "create", "show"} {
		docs, err := s.Documents(ctx, c, "policy", verb, "web", "", forwardWebPolicy)
		if err != nil || len(docs) != 1 || !strings.Contains(docs[0].Content, `target = "self"`) {
			t.Fatal(verb, docs, err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.Config.PoliciesDir, "operator.hcl"), []byte(forwardWebPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	if docs, err := s.Documents(ctx, c, "policy", "show", "operator", "", ""); err != nil || len(docs) != 1 || docs[0].Tier != "operator" {
		t.Fatal(docs, err)
	}
	for name, raw := range map[string]string{
		"host": `forward "host" "web" {
  listen = "127.0.0.1:8080"
  target = "name:other"
  target_port = 8080
}`,
		"cross-vm": `tailscale "external" {}
forward "tailscale" "web" {
  tunnel = tailscale.external
  listen = ":8080"
  target = "name:other"
  target_port = 8080
}`,
		"explicit-tunnel": `tailscale "external" {}
forward "tailscale" "web" {
  tunnel = tailscale.external
  listen = ":8080"
  target = "self"
  target_port = 8080
}`,
		"node": `tailscale "external" {}`,
		"rule-tunnel": `tailscale "external" {}
endpoint "ip" "all" {
  protocol = "tcp"
  destination_cidrs = ["0.0.0.0/0"]
}
rule "via" {
  endpoints = [ip.all]
  tunnel = tailscale.external
  verdict = "allow"
}`,
	} {
		t.Run(name, func(t *testing.T) {
			// Prove the shared schema accepts the document before testing authority.
			p, err := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: raw}})
			if err != nil {
				t.Fatal(err)
			}
			if err = remotePolicy(p); Categorize(err).Exit != 2 {
				t.Fatal("accepted normalized authority", err)
			}
			if _, err = s.Documents(ctx, c, "policy", "create", name, "", p.HCL); Categorize(err).Exit != 2 {
				t.Fatal("accepted principal authority", err)
			}
			if err = os.WriteFile(filepath.Join(s.Config.PoliciesDir, name+".hcl"), []byte(p.HCL), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Documents(ctx, c, "policy", "show", name, "", ""); err == nil {
				t.Fatal("accepted operator authority")
			}
			if _, err = s.Create(ctx, c, CreateRequest{Image: "ghcr.io/vandycknick/silo/devbox:latest", Name: name, PolicyRef: name}); err == nil {
				t.Fatal("accepted operator authority during create")
			}
		})
	}
}

func TestForwardInjectionPreservesCanonicalFieldsThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := t.Context()
	p, err := s.parseRemotePolicy(ctx, forwardWebPolicy+`endpoint "https" "api" {
  hosts = ["api.example.test"]
}
rule "api" {
  endpoints = [https.api]
  verdict = "allow"
  reason = "preserve"
}
`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.checkSecrets(ctx, p); err != nil {
		t.Fatal("managed TLS unexpectedly requires a secret", err)
	}
	injected, err := s.InjectTailnet(ctx, p, "web", "user:1", "")
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	if err = json.Unmarshal([]byte(p.CanonicalJSON), &before); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(injected.CanonicalJSON), &after); err != nil {
		t.Fatal(err)
	}
	var original, bound []map[string]json.RawMessage
	if err = json.Unmarshal(before["forwards"], &original); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(after["forwards"], &bound); err != nil {
		t.Fatal(err)
	}
	for _, f := range original {
		f["tunnel"] = json.RawMessage(`"vm"`)
	}
	if len(bound) != 2 || !reflect.DeepEqual(original, bound) {
		t.Fatal("binding changed forward fields or order", original, bound)
	}
	for _, key := range []string{"metadata", "settings", "credentials"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Fatal("injection changed unrelated field", key)
		}
	}
	var oldEndpoints, newEndpoints, oldRules, newRules []json.RawMessage
	for _, pair := range []struct {
		raw json.RawMessage
		dst *[]json.RawMessage
	}{{before["endpoints"], &oldEndpoints}, {after["endpoints"], &newEndpoints}, {before["rules"], &oldRules}, {after["rules"], &newRules}} {
		if err = json.Unmarshal(pair.raw, pair.dst); err != nil {
			t.Fatal(err)
		}
	}
	if len(newEndpoints) != len(oldEndpoints)+2 || len(newRules) != len(oldRules)+2 || !reflect.DeepEqual(oldEndpoints, newEndpoints[:len(oldEndpoints)]) || !reflect.DeepEqual(oldRules, newRules[:len(oldRules)]) {
		t.Fatal("injection lost existing policy configuration")
	}
	round, err := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: injected.HCL}})
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip struct {
		Forwards []map[string]json.RawMessage `json:"forwards"`
	}
	if err := json.Unmarshal([]byte(round.CanonicalJSON), &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundtrip.Forwards, bound) {
		t.Fatal("HCL roundtrip changed bound forward semantics")
	}
}

func TestForwardCreateRequiresTailscaleBeforeWorkThroughRPC(t *testing.T) {
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	ctx := t.Context()
	c := domainCaller(s, "user:1")
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.Config.PoliciesDir = testfixture.TempDir(t)
	for name, raw := range map[string]string{"web": forwardWebPolicy, "plain": `settings { default_action = "allow" }`} {
		if _, err := s.Documents(ctx, c, "policy", "create", name, "", raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.Config.PoliciesDir, "operator.hcl"), []byte(forwardWebPolicy), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Documents(ctx, c, "template", "create", "web", "", "version: '1'\nimage: "+registry.Reference+"\nnetwork: {kind: private, policy_ref: web}"); err != nil {
		t.Fatal(err)
	}
	p, err := s.parseRemotePolicy(ctx, forwardWebPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []CreateRequest{
		{Name: "explicit", Image: registry.Reference, PolicyRef: "web", NoStart: true},
		{Name: "inherited", Template: "web", NoStart: true},
		{Name: "operator", Image: registry.Reference, PolicyRef: "operator", NoStart: true},
		{Name: "internal", Image: registry.Reference, policy: p, NoStart: true},
	} {
		op, err := s.Create(ctx, c, q)
		if err == nil || Categorize(err).Exit != 2 || Categorize(err).Code != "usage" || err.Error() != "policy forwards require --tailscale" || op.ID != "" {
			t.Fatal("forward policy started work without tailscale", q.Name, op, err)
		}
	}
	if registry.Requests.Load() != 0 || len(s.Jobs.List(c.Peer)) != 0 {
		t.Fatal("rejected forwards started image or job work")
	}
	s.createMu.Lock()
	pending, disks := len(s.pending), len(s.diskPending)
	s.createMu.Unlock()
	if pending != 0 || disks != 0 {
		t.Fatal("rejected forwards reserved admission", pending, disks)
	}
	if entries, err := s.Runtime.Control.Inventory(ctx); err != nil || len(entries) != 0 {
		t.Fatal("rejected forwards created durable records", entries, err)
	}
	// Selecting an ordinary policy explicitly overrides the inherited forward.
	resolved, err := s.resolveCreate(ctx, c.Peer, CreateRequest{Name: "override", Template: "web", PolicyRef: "plain"})
	if err != nil || resolved.PolicyRef != "plain" {
		t.Fatal(resolved, err)
	}
	// The admission gate does not require enrollment merely to resolve a policy.
	if _, err = s.resolveCreate(ctx, c.Peer, CreateRequest{Name: "enabled", Template: "web", Tailscale: true}); err != nil {
		t.Fatal(err)
	}
	op, err := s.Create(ctx, c, CreateRequest{Name: "override", Template: "web", PolicyRef: "plain", NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
}

func TestForwardCreateRetainsBoundPolicyThroughRPC(t *testing.T) {
	testfixture.RequireRegistryTrust(t)
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	ctx := t.Context()
	c := domainCaller(s, "user:1")
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.VMNodesEnabled = true
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: "https://pinned-control.example.test"}}
	if _, err := s.Documents(ctx, c, "policy", "create", "web", "", forwardWebPolicy); err != nil {
		t.Fatal(err)
	}
	op, err := s.Create(ctx, c, CreateRequest{Name: "bound", Image: registry.Reference, PolicyRef: "web", Tailscale: true, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	data, err := s.Runtime.Control.Inspect(ctx, "bound")
	if err != nil {
		t.Fatal(err)
	}
	var stored policyAuthority
	if err = json.Unmarshal([]byte(data.PolicyJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Forwards) != 2 || len(stored.Tailscale) != 1 {
		t.Fatal("runtime handoff lost forwards", data.PolicyJSON)
	}
	for _, f := range stored.Forwards {
		if f.Kind != "tailscale" || f.Target != "self" || f.Tunnel == nil || *f.Tunnel != "vm" {
			t.Fatal("runtime handoff lost managed binding", data.PolicyJSON)
		}
	}
	v, err := s.Show(ctx, c.Peer, "bound")
	if err != nil {
		t.Fatal(err)
	}
	node := data.Network.Tailscale.Hostname + ".fixture.test"
	want := []ForwardView{
		{Name: "web", Protocol: "https", ListenPort: 443, TargetPort: 8080, URL: "https://" + node + "/"},
		{Name: "raw", Protocol: "tcp", ListenPort: 18080, TargetPort: 8080, URL: "tcp://" + node + ":18080"},
	}
	if !reflect.DeepEqual(v.Forwards, want) {
		t.Fatal(v.Forwards, want)
	}
	inventory, err := s.List(ctx, c.Peer)
	if err != nil || len(inventory) != 1 || !reflect.DeepEqual(inventory[0].Forwards, want) {
		t.Fatal(inventory, err)
	}
	op, err = s.Create(ctx, c, CreateRequest{Name: "plain", Image: registry.Reference, NoStart: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	v, err = s.Show(ctx, c.Peer, "plain")
	if err != nil || v.Forwards != nil {
		t.Fatal(v.Forwards, err)
	}
}

func TestForwardRemoteReservedMetadataThroughRPC(t *testing.T) {
	s := actualService(t)
	ctx := t.Context()
	p, err := s.parseRemotePolicy(ctx, forwardWebPolicy)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal([]byte(p.CanonicalJSON), &root); err != nil {
		t.Fatal(err)
	}
	root["metadata"] = json.RawMessage(`{"io.silo.taild.owner":"user:other"}`)
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: string(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = remotePolicy(p); Categorize(err).Exit != 2 || !strings.Contains(err.Error(), "reserved taild metadata") {
		t.Fatal("forward policy bypassed reserved metadata authority", err)
	}
	if _, err = s.InjectTailnet(ctx, p, "web", "user:1", ""); Categorize(err).Exit != 2 {
		t.Fatal("injection accepted reserved metadata", err)
	}
}

func TestSetPolicyRetainsManagedNodeThroughRPC(t *testing.T) {
	testfixture.RequireRegistryTrust(t)
	registry := testfixture.OCIRegistry(t, "")
	s := actualService(t)
	ctx := t.Context()
	c := domainCaller(s, "user:1")
	s.Config.VM.AllowedRegistries = []string{registry.Allowed()}
	s.VMNodesEnabled = true
	s.Enrollment = &enroll.Manager{Config: s.Config, Pin: state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: "https://pinned-control.example.test"}}
	if _, err := s.Documents(ctx, c, "policy", "create", "web", "", forwardWebPolicy); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bound", "ordinary"} {
		op, err := s.Create(ctx, c, CreateRequest{Name: name, Image: registry.Reference, Tailscale: name == "bound", NoStart: true})
		daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	}
	ref := "web"
	op, err := s.Set(ctx, c, "bound", SetRequest{PolicyRef: &ref})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	data, err := s.Runtime.Control.Inspect(ctx, "bound")
	if err != nil {
		t.Fatal(err)
	}
	var stored policyAuthority
	if err := json.Unmarshal([]byte(data.PolicyJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if data.Labels[PolicyLabel] != ref || len(stored.Forwards) != 2 || len(stored.Tailscale) != 1 || len(stored.Metadata["io.silo.taild.node"]) == 0 {
		t.Fatal("set lost managed policy", data)
	}
	for _, f := range stored.Forwards {
		if f.Tunnel == nil || *f.Tunnel != "vm" {
			t.Fatal("unbound forward", data.PolicyJSON)
		}
	}
	op, err = s.Set(ctx, c, "bound", SetRequest{ClearPolicy: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	data, err = s.Runtime.Control.Inspect(ctx, "bound")
	if err != nil {
		t.Fatal(err)
	}
	stored = policyAuthority{}
	if err := json.Unmarshal([]byte(data.PolicyJSON), &stored); err != nil {
		t.Fatal(err)
	}
	if _, exists := data.Labels[PolicyLabel]; exists || len(stored.Forwards) != 0 || len(stored.Tailscale) != 1 || len(stored.Metadata["io.silo.taild.node"]) == 0 {
		t.Fatal("clear lost node or retained policy", data)
	}
	for _, tt := range []struct {
		ref     string
		code    string
		message string
	}{
		{"web", "usage", "policy forwards require a VM created with --tailscale"},
		{"missing", "not_found", "document not found"},
	} {
		op, err := s.Set(ctx, c, "ordinary", SetRequest{PolicyRef: &tt.ref})
		result := daemon.WaitOperation(t, s.Jobs, c.Peer, op, err)
		if result.Error == nil || result.Error.Code != tt.code {
			t.Fatal(tt, result)
		}
		if tt.message != "" && result.Error.Message != tt.message {
			t.Fatal(tt, result)
		}
	}
	plain := "plain"
	if _, err := s.Documents(ctx, c, "policy", "create", plain, "", `settings { default_action = "allow" }`); err != nil {
		t.Fatal(err)
	}
	renamed := "renamed"
	op, err = s.Set(ctx, c, "ordinary", SetRequest{Name: &renamed, PolicyRef: &plain})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	data, err = s.Runtime.Control.Inspect(ctx, renamed)
	if err != nil || data.Labels[PolicyLabel] != plain {
		t.Fatal(data, err)
	}
	op, err = s.Set(ctx, c, renamed, SetRequest{ClearPolicy: true})
	daemon.Succeeded(t, s.Jobs, c.Peer, op, err)
	data, err = s.Runtime.Control.Inspect(ctx, renamed)
	if err != nil || data.PolicyJSON != "" || data.Labels[PolicyLabel] != "" {
		t.Fatal(data, err)
	}
}
