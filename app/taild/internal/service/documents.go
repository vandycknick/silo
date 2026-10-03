package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	silo "github.com/vandycknick/silo/sdk/go"
	"go.yaml.in/yaml/v3"
	"tailscale.com/ipn"
)

const DocumentLimit = 64 << 10
const TemplateLabel = "io.silo.taild.template"
const PolicyLabel = "io.silo.taild.policy"
const GuestPortsLabel = "io.silo.taild.guest-tcp-ports"

type Template struct {
	Version     string             `yaml:"version" json:"version"`
	Description *string            `yaml:"description,omitempty" json:"description,omitempty"`
	Image       *string            `yaml:"image,omitempty" json:"image,omitempty"`
	Resources   *TemplateResources `yaml:"resources,omitempty" json:"resources,omitempty"`
	DiskSize    *string            `yaml:"disk_size,omitempty" json:"disk_size,omitempty"`
	Vsock       *bool              `yaml:"vsock,omitempty" json:"vsock,omitempty"`
	Userdata    *string            `yaml:"userdata,omitempty" json:"userdata,omitempty"`
	Network     *TemplateNetwork   `yaml:"network,omitempty" json:"network,omitempty"`
	Labels      map[string]string  `yaml:"labels,omitempty" json:"labels,omitempty"`
}
type TemplateResources struct {
	CPUs   *uint64 `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	Memory *string `yaml:"memory,omitempty" json:"memory,omitempty"`
}
type TemplateNetwork struct {
	Kind      string  `yaml:"kind" json:"kind"`
	PolicyRef *string `yaml:"policy_ref,omitempty" json:"policy_ref,omitempty"`
	// Guest TCP declarations are discovery hints, never host publication authority.
	Publish []uint16 `yaml:"publish,omitempty" json:"publish,omitempty"`
}

func documentName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0 {
			continue
		}
		return false
	}
	return true
}

// YAML decoding normally coerces numbers into strings and ignores null. Check
// the syntax tree against the typed allowlist first, rejecting aliases/merges.
func yamlShape(n *yaml.Node, t reflect.Type, depth int) error {
	if depth > 16 || n.Kind == yaml.AliasNode || n.Tag == "!!null" {
		return failure("usage", "null, aliases and excessive nesting are not allowed", 2)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return usageDocument()
		}
		fields := map[string]reflect.Type{}
		for i := range t.NumField() {
			f := t.Field(i)
			fields[strings.Split(f.Tag.Get("yaml"), ",")[0]] = f.Type
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			ft, ok := fields[k.Value]
			if k.Tag != "!!str" || !ok || seen[k.Value] {
				return failure("usage", "unknown or duplicate template field: "+k.Value, 2)
			}
			seen[k.Value] = true
			if e := yamlShape(n.Content[i+1], ft, depth+1); e != nil {
				return e
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return usageDocument()
		}
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Tag != "!!str" || seen[k.Value] {
				return usageDocument()
			}
			seen[k.Value] = true
			if e := yamlShape(n.Content[i+1], t.Elem(), depth+1); e != nil {
				return e
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode || len(n.Content) > 256 {
			return usageDocument()
		}
		for _, c := range n.Content {
			if e := yamlShape(c, t.Elem(), depth+1); e != nil {
				return e
			}
		}
	default:
		tag := "!!str"
		if t.Kind() == reflect.Bool {
			tag = "!!bool"
		}
		if t.Kind() == reflect.Uint16 || t.Kind() == reflect.Uint64 {
			tag = "!!int"
		}
		if n.Kind != yaml.ScalarNode || n.Tag != tag {
			return usageDocument()
		}
	}
	return nil
}
func usageDocument() error { return failure("usage", "invalid remote document field type", 2) }
func (s *Service) ParseTemplate(raw string) (Template, error) {
	var t Template
	if len(raw) == 0 || len(raw) > DocumentLimit {
		return t, failure("usage", "document must be 1..65536 bytes", 2)
	}
	d := yaml.NewDecoder(strings.NewReader(raw))
	var n yaml.Node
	if e := d.Decode(&n); e != nil || len(n.Content) != 1 {
		return t, usageDocument()
	}
	var extra yaml.Node
	if e := d.Decode(&extra); !errors.Is(e, io.EOF) {
		return t, failure("usage", "exactly one YAML document is required", 2)
	}
	if e := yamlShape(n.Content[0], reflect.TypeFor[Template](), 0); e != nil {
		return t, e
	}
	if e := n.Decode(&t); e != nil {
		return t, usageDocument()
	}
	if t.Version != "1" {
		return t, failure("usage", "template version must be the string '1'", 2)
	}
	if t.Description != nil && (len(*t.Description) > 4096 || !text(*t.Description)) {
		return t, usageDocument()
	}
	if t.Image != nil && !imageAllowed(*t.Image, s.Config.VM.AllowedRegistries) {
		return t, failure("usage", "image must be an allowlisted OCI reference", 2)
	}
	if t.Resources != nil {
		if t.Resources.CPUs != nil && (*t.Resources.CPUs == 0 || *t.Resources.CPUs > 255) {
			return t, usageDocument()
		}
		if t.Resources.Memory != nil {
			if _, e := silo.ParseMachineMemory(*t.Resources.Memory); e != nil {
				return t, failure("usage", "invalid memory size", 2)
			}
		}
	}
	if t.DiskSize != nil {
		if _, e := silo.ParseRootDiskSize(*t.DiskSize); e != nil {
			return t, failure("usage", "invalid disk_size", 2)
		}
	}
	if t.Vsock != nil && !*t.Vsock {
		return t, failure("usage", "remote guest management requires vsock: true", 2)
	}
	if t.Userdata != nil && (*t.Userdata == "" || !validUserdata(*t.Userdata)) {
		return t, failure("usage", "userdata must be an inline shebang script, at most 16KiB", 2)
	}
	if e := validateLabels(t.Labels); e != nil {
		return t, e
	}
	if t.Network != nil {
		if t.Network.Kind != "private" {
			return t, failure("usage", "only private networking is allowed", 2)
		}
		if t.Network.PolicyRef != nil && !documentName(*t.Network.PolicyRef) {
			return t, failure("usage", "invalid policy_ref", 2)
		}
		seen := map[uint16]bool{}
		for _, port := range t.Network.Publish {
			if port == 0 || seen[port] {
				return t, failure("usage", "publish requires unique fixed guest TCP ports 1..65535", 2)
			}
			seen[port] = true
		}
	}
	return t, nil
}
func validUserdata(v string) bool {
	return len(v) <= 16384 && !strings.ContainsRune(v, 0) && (v == "" || strings.HasPrefix(v, "#!"))
}
func validateLabels(labels map[string]string) error {
	if len(labels) > 32 {
		return failure("usage", "too many labels", 2)
	}
	for k, v := range labels {
		if k == "" || len(k) > 128 || len(v) > 1024 || !text(k) || !text(v) || strings.HasPrefix(k, "io.silo.") {
			return failure("usage", "invalid or reserved label", 2)
		}
	}
	return nil
}

type policyAuthority struct {
	Tailscale []json.RawMessage `json:"tailscale"`
	Forwards  []json.RawMessage `json:"forwards"`
	Rules     []struct {
		Tunnel *string `json:"tunnel"`
	} `json:"rules"`
}

func remotePolicy(p *silo.NetworkPolicy) error {
	var a policyAuthority
	if e := json.Unmarshal([]byte(p.JSON()), &a); e != nil {
		return usageDocument()
	}
	if len(a.Tailscale) > 0 || len(a.Forwards) > 0 {
		return failure("usage", "remote policies cannot declare tailscale or forwards", 2)
	}
	for _, r := range a.Rules {
		if r.Tunnel != nil {
			return failure("usage", "remote policies cannot reference tunnels", 2)
		}
	}
	return nil
}
func parseRemotePolicy(raw string) (*silo.NetworkPolicy, error) {
	if len(raw) == 0 || len(raw) > DocumentLimit {
		return nil, failure("usage", "document must be 1..65536 bytes", 2)
	}
	p, e := silo.ParseNetworkPolicyHCL(raw)
	if e != nil {
		return nil, failure("usage", "invalid network policy HCL", 2)
	}
	return p, remotePolicy(p)
}

// InjectTailnet preserves the entire canonical configuration, including plugin
// fields the convenient Go builder does not model. Explicit user deny rules keep
// their order/priority. IP allow rules gain neutral routing, which netd applies
// only to tailnet destinations; the appended lowest-priority rules exempt the
// tailnet from default deny without overriding any explicit matching rule.
func InjectTailnet(p *silo.NetworkPolicy, hostname string, owner identity.Principal, controlURL string) (*silo.NetworkPolicy, error) {
	if _, e := identity.ParsePrincipal(string(owner)); e != nil {
		return nil, usageDocument()
	}
	if controlURL == "" {
		controlURL = ipn.DefaultControlURL
	}
	tags := []string{}
	if owner.IsTag() {
		tags = append(tags, string(owner))
	}
	if p == nil {
		var e error
		p, e = silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{})
		if e != nil {
			return nil, e
		}
	}
	if e := remotePolicy(p); e != nil {
		return nil, e
	}
	var root map[string]json.RawMessage
	if e := json.Unmarshal([]byte(p.JSON()), &root); e != nil {
		return nil, e
	}
	var endpoints []map[string]json.RawMessage
	var rules []map[string]json.RawMessage
	if e := json.Unmarshal(root["endpoints"], &endpoints); e != nil {
		return nil, e
	}
	if e := json.Unmarshal(root["rules"], &rules); e != nil {
		return nil, e
	}
	ip := map[string]bool{}
	names := map[string]bool{}
	for _, ep := range endpoints {
		var name, family string
		_ = json.Unmarshal(ep["name"], &name)
		_ = json.Unmarshal(ep["family"], &family)
		names[name] = true
		ip[name] = family == "ip"
	}
	for _, r := range rules {
		var name, verdict string
		var refs []string
		_ = json.Unmarshal(r["name"], &name)
		_ = json.Unmarshal(r["verdict"], &verdict)
		_ = json.Unmarshal(r["endpoints"], &refs)
		names[name] = true
		if verdict == "allow" && len(refs) > 0 && ip[refs[0]] {
			r["tunnel"] = json.RawMessage(`"vm"`)
		}
	}
	for _, n := range []string{"silo-tailnet-v4", "silo-tailnet-v6"} {
		if names[n] {
			return nil, failure("usage", "policy uses reserved injection name "+n, 2)
		}
	}
	priority := int32(-2147483648)
	injected, e := silo.BuildNetworkPolicy(silo.NetworkPolicyConfig{Tunnels: []silo.TailscaleTunnel{{Name: "vm", Hostname: &hostname, Tags: tags, ControlURL: &controlURL}}, Endpoints: []silo.NetworkEndpoint{{Name: "silo-tailnet-v4", Kind: silo.NetworkEndpointIP, Protocol: silo.NetworkProtocolTCP, DestinationCIDRs: []string{"100.64.0.0/10"}}, {Name: "silo-tailnet-v6", Kind: silo.NetworkEndpointIP, Protocol: silo.NetworkProtocolTCP, DestinationCIDRs: []string{"fd7a:115c:a1e0::/48"}}}, Rules: []silo.NetworkRule{{Name: ptr("silo-tailnet-v4"), Endpoints: []string{"silo-tailnet-v4"}, Tunnel: ptr("vm"), Priority: &priority, Verdict: silo.NetworkVerdictAllow}, {Name: ptr("silo-tailnet-v6"), Endpoints: []string{"silo-tailnet-v6"}, Tunnel: ptr("vm"), Priority: &priority, Verdict: silo.NetworkVerdictAllow}}})
	if e != nil {
		return nil, e
	}
	var additions map[string]json.RawMessage
	_ = json.Unmarshal([]byte(injected.JSON()), &additions)
	var extraEndpoints, extraRules []map[string]json.RawMessage
	_ = json.Unmarshal(additions["endpoints"], &extraEndpoints)
	_ = json.Unmarshal(additions["rules"], &extraRules)
	root["endpoints"], e = json.Marshal(append(endpoints, extraEndpoints...))
	if e != nil {
		return nil, e
	}
	root["rules"], e = json.Marshal(append(rules, extraRules...))
	if e != nil {
		return nil, e
	}
	root["tailscale"] = additions["tailscale"]
	raw, e := json.Marshal(root)
	if e != nil {
		return nil, e
	}
	return silo.ParseNetworkPolicyJSON(string(raw))
}
func ptr[T any](v T) *T { return &v }

type Document struct {
	Name     string                      `json:"name"`
	Tier     string                      `json:"tier"`
	Owner    identity.Principal          `json:"owner,omitempty"`
	Kind     string                      `json:"kind"`
	Content  string                      `json:"content,omitempty"`
	Template *Template                   `json:"template,omitempty"`
	Secrets  *silo.NetworkSecretMetadata `json:"secrets,omitempty"`
}

func (s *Service) validateDocument(kind, raw string) (Document, error) {
	d := Document{Kind: kind}
	switch kind {
	case "template":
		t, e := s.ParseTemplate(raw)
		if e != nil {
			return d, e
		}
		b, e := yaml.Marshal(t)
		if e != nil {
			return d, e
		}
		d.Content = string(b)
		d.Template = &t
	case "policy":
		p, e := parseRemotePolicy(raw)
		if e != nil {
			return d, e
		}
		d.Content, e = p.HCL()
		if e != nil {
			return d, e
		}
		d.Secrets, e = p.SecretMetadata()
		if e != nil {
			return d, e
		}
	default:
		return d, usageDocument()
	}
	if len(d.Content) > DocumentLimit {
		return d, failure("usage", "canonical document exceeds 64KiB", 2)
	}
	return d, nil
}
func selectedOwner(p identity.Peer, owner identity.Principal) (identity.Principal, error) {
	if owner == "" {
		if len(p.Principals) != 1 {
			return "", failure("usage", "multi-tag peers require --owner tag:<name>", 2)
		}
		return p.Principals[0], nil
	}
	if !owner.IsTag() || !p.Owns(owner) {
		return "", failure("forbidden", "owner must be a verified peer tag", 4)
	}
	return owner, nil
}
func (s *Service) Documents(ctx context.Context, c Caller, kind, verb, name string, owner identity.Principal, raw string) ([]Document, error) {
	write := verb == "create" || verb == "edit" || verb == "rm"
	action := identity.Read
	if write {
		action = identity.TemplateManage
	}
	p := c.Peer
	if write {
		var e error
		p, e = c.Fresh(ctx)
		if e != nil {
			return nil, e
		}
	}
	if e := s.Authorize(p, action, nil); e != nil {
		return nil, e
	}
	if kind != "template" && kind != "policy" {
		return nil, usageDocument()
	}
	if verb == "validate" {
		d, e := s.validateDocument(kind, raw)
		return []Document{d}, e
	}
	if verb != "ls" && !documentName(name) {
		return nil, failure("usage", "invalid document name", 2)
	}
	if verb == "ls" && owner == "" && len(p.Principals) > 1 {
		out := []Document{}
		for _, principal := range p.Principals {
			docs, e := s.documentsFor(kind, verb, name, principal, raw)
			if e != nil {
				return nil, e
			}
			for _, d := range docs {
				if d.Tier == "yours" {
					out = append(out, d)
				}
			}
		}
		docs, e := s.documentsFor(kind, verb, name, p.Principals[0], raw)
		if e != nil {
			return nil, e
		}
		for _, d := range docs {
			if d.Tier == "operator" {
				out = append(out, d)
			}
		}
		return out, nil
	}
	principal, e := selectedOwner(p, owner)
	if e != nil {
		return nil, e
	}
	return s.documentsFor(kind, verb, name, principal, raw)
}
func (s *Service) resolveCreate(ctx context.Context, p identity.Peer, q CreateRequest) (CreateRequest, error) {
	owner, e := selectedOwner(p, q.Owner)
	if e != nil {
		return q, e
	}
	if q.Template != "" {
		docs, e := s.documentsFor("template", "show", q.Template, owner, "")
		if e != nil {
			return q, e
		}
		t := docs[0].Template
		if q.Image == "" && t.Image != nil {
			q.Image = *t.Image
		}
		if t.Resources != nil {
			if q.CPUs == 0 && t.Resources.CPUs != nil {
				q.CPUs = *t.Resources.CPUs
			}
			if q.Memory == 0 && q.MemoryText == "" && t.Resources.Memory != nil {
				q.MemoryText = *t.Resources.Memory
			}
		}
		if q.Disk == 0 && q.DiskText == "" && t.DiskSize != nil {
			q.DiskText = *t.DiskSize
		}
		if !q.UserdataSet && q.Userdata == "" && t.Userdata != nil {
			q.Userdata = *t.Userdata
		}
		labels := maps.Clone(t.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		maps.Copy(labels, q.Labels)
		q.Labels = labels
		if t.Network != nil {
			if q.PolicyRef == "" && t.Network.PolicyRef != nil {
				q.PolicyRef = *t.Network.PolicyRef
			}
			q.GuestPorts = append([]uint16(nil), t.Network.Publish...)
		}
	}
	if q.PolicyRef != "" {
		docs, e := s.documentsFor("policy", "show", q.PolicyRef, owner, "")
		if e != nil {
			return q, e
		}
		q.policy, e = parseRemotePolicy(docs[0].Content)
		if e != nil {
			return q, e
		}
	}
	if q.policy != nil {
		if e := s.checkSecrets(ctx, q.policy); e != nil {
			return q, e
		}
	}
	return q, nil
}
func (s *Service) checkSecrets(ctx context.Context, p *silo.NetworkPolicy) error {
	check, e := s.Runtime.SDK.CheckPolicySecrets(ctx, p, "", nil)
	if e != nil {
		return Categorize(e)
	}
	switch check.Status {
	case silo.PolicySecretsReady:
		return nil
	case silo.PolicySecretsMissing:
		var b bytes.Buffer
		for i, slot := range check.Slots {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (key %s)", slot.Name, slot.Source.Key)
		}
		return failure("usage", "missing policy secrets; satisfy an alternative: "+b.String(), 2)
	case silo.PolicySecretsUnavailable:
		return failure("unavailable", fmt.Sprintf("policy secret unavailable: slot %s, key %s (%s)", check.Slot, check.Key, check.Code), 9)
	default:
		return failure("unavailable", "secret resolver returned an unknown status", 9)
	}
}
