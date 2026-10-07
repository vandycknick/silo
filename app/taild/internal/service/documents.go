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

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/emptypb"
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

// Document names follow the VM name grammar, so a name is safe as a file stem.
var (
	errDocumentName = failure("usage", "invalid document name", 2)
	errDocumentSize = failure("usage", "document must be 1..65536 bytes", 2)
)

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
func (s *Service) ParseTemplate(ctx context.Context, raw string) (Template, error) {
	var t Template
	if len(raw) == 0 || len(raw) > DocumentLimit {
		return t, errDocumentSize
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
		return t, errImage
	}
	if t.Resources != nil {
		if t.Resources.CPUs != nil && (*t.Resources.CPUs == 0 || *t.Resources.CPUs > 255) {
			return t, usageDocument()
		}
		if t.Resources.Memory != nil {
			if _, e := s.ParseResource(ctx, "memory", *t.Resources.Memory); e != nil {
				return t, e
			}
		}
	}
	if t.DiskSize != nil {
		if _, e := s.ParseResource(ctx, "disk", *t.DiskSize); e != nil {
			return t, e
		}
	}
	if t.Vsock != nil && !*t.Vsock {
		return t, failure("usage", "remote guest management requires vsock: true", 2)
	}
	if t.Userdata != nil && (*t.Userdata == "" || !validUserdata(*t.Userdata)) {
		return t, errUserdata
	}
	if e := validateLabels(t.Labels); e != nil {
		return t, e
	}
	if t.Network != nil {
		if t.Network.Kind != "private" {
			return t, failure("usage", "only private networking is allowed", 2)
		}
		if t.Network.PolicyRef != nil && !config.ValidName(*t.Network.PolicyRef) {
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
	Metadata  map[string]json.RawMessage `json:"metadata"`
	Tailscale []json.RawMessage          `json:"tailscale"`
	Forwards  []json.RawMessage          `json:"forwards"`
	Rules     []struct {
		Tunnel *string `json:"tunnel"`
	} `json:"rules"`
}

func remotePolicy(p *control.Policy) error {
	var a policyAuthority
	if e := json.Unmarshal([]byte(p.CanonicalJSON), &a); e != nil {
		return usageDocument()
	}
	for key := range a.Metadata {
		if strings.HasPrefix(key, "io.silo.taild.") {
			return failure("usage", "remote policies cannot declare reserved taild metadata", 2)
		}
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
func (s *Service) parseRemotePolicy(ctx context.Context, raw string) (*control.Policy, error) {
	if len(raw) == 0 || len(raw) > DocumentLimit {
		return nil, errDocumentSize
	}
	p, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: raw}})
	if e != nil {
		return nil, Categorize(e)
	}
	if len(p.CanonicalJSON) > DocumentLimit || len(p.HCL) > DocumentLimit {
		return nil, failure("usage", "canonical document exceeds 64KiB", 2)
	}
	return p, remotePolicy(p)
}

// InjectTailnet preserves the entire canonical configuration, including plugin
// fields the convenient Go builder does not model. Explicit user deny rules keep
// their order/priority. IP allow rules gain neutral routing, which netd applies
// only to tailnet destinations; the appended lowest-priority rules exempt the
// tailnet from default deny without overriding any explicit matching rule.
func (s *Service) InjectTailnet(ctx context.Context, p *control.Policy, hostname string, owner identity.Principal, controlURL string, requestedTags ...string) (*control.Policy, error) {
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
	if len(requestedTags) > 0 {
		tags = append([]string{}, requestedTags...)
	}
	if p == nil {
		var e error
		p, e = s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Empty{Empty: &emptypb.Empty{}}})
		if e != nil {
			return nil, e
		}
	}
	if e := remotePolicy(p); e != nil {
		return nil, e
	}
	var root map[string]json.RawMessage
	if e := json.Unmarshal([]byte(p.CanonicalJSON), &root); e != nil {
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
	tagJSON, e := json.Marshal(tags)
	if e != nil {
		return nil, e
	}
	// Normalize a minimal HCL addition instead of serializing SDK builder
	// configuration, whose schema is not the canonical policy schema.
	addition := fmt.Sprintf(`tailscale "vm" {
  hostname = %q
  tags = %s
  control_url = %q
}
endpoint "ip" "silo-tailnet-v4" {
  protocol = "tcp"
  destination_cidrs = ["100.64.0.0/10"]
}
endpoint "ip" "silo-tailnet-v6" {
  protocol = "tcp"
  destination_cidrs = ["fd7a:115c:a1e0::/48"]
}
rule "silo-tailnet-v4" {
  endpoints = [ip.silo-tailnet-v4]
  tunnel = tailscale.vm
  priority = -2147483648
  verdict = "allow"
}
rule "silo-tailnet-v6" {
  endpoints = [ip.silo-tailnet-v6]
  tunnel = tailscale.vm
  priority = -2147483648
  verdict = "allow"
}
`, hostname, tagJSON, controlURL)
	injected, e := s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_Hcl{Hcl: addition}})
	if e != nil {
		return nil, e
	}
	var additions map[string]json.RawMessage
	if e := json.Unmarshal([]byte(injected.CanonicalJSON), &additions); e != nil {
		return nil, e
	}
	var extraEndpoints, extraRules []map[string]json.RawMessage
	if e := json.Unmarshal(additions["endpoints"], &extraEndpoints); e != nil {
		return nil, e
	}
	if e := json.Unmarshal(additions["rules"], &extraRules); e != nil {
		return nil, e
	}
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
	return s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: string(raw)}})
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

func (s *Service) validateDocument(ctx context.Context, kind, raw string) (Document, error) {
	d := Document{Kind: kind}
	switch kind {
	case "template":
		t, e := s.ParseTemplate(ctx, raw)
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
		p, e := s.parseRemotePolicy(ctx, raw)
		if e != nil {
			return d, e
		}
		d.Content = p.HCL
		d.Secrets = &p.Secrets
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
		d, e := s.validateDocument(ctx, kind, raw)
		return []Document{d}, e
	}
	if verb == "ls" && owner == "" && len(p.Principals) > 1 {
		// Every principal's own documents, then the shared operator tier once.
		yours, operator := []Document{}, []Document{}
		for _, principal := range p.Principals {
			docs, e := s.documentsFor(ctx, kind, verb, name, principal, raw)
			if e != nil {
				return nil, e
			}
			for _, d := range docs {
				if d.Tier == "yours" {
					yours = append(yours, d)
				} else if principal == p.Principals[0] {
					operator = append(operator, d)
				}
			}
		}
		return append(yours, operator...), nil
	}
	principal, e := selectedOwner(p, owner)
	if e != nil {
		return nil, e
	}
	return s.documentsFor(ctx, kind, verb, name, principal, raw)
}
func (s *Service) resolveCreate(ctx context.Context, p identity.Peer, q CreateRequest) (CreateRequest, error) {
	owner, e := selectedOwner(p, q.Owner)
	if e != nil {
		return q, e
	}
	if q.Template != "" {
		docs, e := s.documentsFor(ctx, "template", "show", q.Template, owner, "")
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
	if q.Image == "" {
		return q, errImageMissing
	}
	if q.PolicyRef != "" {
		docs, e := s.documentsFor(ctx, "policy", "show", q.PolicyRef, owner, "")
		if e != nil {
			return q, e
		}
		q.policy, e = s.parseRemotePolicy(ctx, docs[0].Content)
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
func (s *Service) checkSecrets(ctx context.Context, p *control.Policy) error {
	check, e := s.Runtime.Control.CheckPolicySecrets(ctx, p, "")
	if e != nil {
		return Categorize(e)
	}
	switch check.State {
	case w.PolicySecretsState_POLICY_SECRETS_STATE_READY:
		return nil
	case w.PolicySecretsState_POLICY_SECRETS_STATE_MISSING:
		var b bytes.Buffer
		for i, requirement := range check.Requirements {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s: ", requirement.Owner)
			for j, alternative := range requirement.Alternatives {
				if j > 0 {
					b.WriteString(" or ")
				}
				b.WriteString(strings.Join(alternative.Slots, " + "))
			}
		}
		if len(check.Requirements) > 0 && len(check.Slots) > 0 {
			b.WriteString("; slots: ")
		}
		for i, slot := range check.Slots {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (key %s)", slot.Name, slot.Key)
		}
		return failure("usage", "missing policy secrets; satisfy an alternative: "+b.String(), 2)
	case w.PolicySecretsState_POLICY_SECRETS_STATE_UNAVAILABLE:
		var b bytes.Buffer
		for i, diagnostic := range check.Diagnostics {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "slot %s, key %s (%s)", diagnostic.Slot, diagnostic.GetKey(), diagnostic.Code)
		}
		return failure("unavailable", "policy secret unavailable: "+b.String(), 9)
	default:
		return failure("unavailable", "secret resolver returned an unknown status", 9)
	}
}
