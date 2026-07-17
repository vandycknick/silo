package policy

import "encoding/json"

type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code,omitempty"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type networkPolicyFile struct {
	Version     int                  `json:"version"`
	Metadata    map[string]any       `json:"metadata"`
	Settings    SettingsDecl         `json:"settings"`
	Endpoints   []EndpointDecl       `json:"endpoints"`
	Credentials []CredentialDecl     `json:"credentials"`
	Rules       []RuleDecl           `json:"rules"`
	Tailscale   []TailscaleDecl      `json:"tailscale"`
	Forwards    []NetworkForwardDecl `json:"forwards"`
}

type SettingsDecl struct {
	DefaultAction Action            `json:"default_action"`
	Audit         AuditSettingsDecl `json:"audit"`
}

type AuditSettingsDecl struct {
	BodyBufferBytes  int64 `json:"body_buffer_bytes"`
	BodyStorageBytes int64 `json:"body_storage_bytes"`
}

type EndpointDecl struct {
	Kind             string         `json:"kind"`
	Name             string         `json:"name"`
	Family           EndpointFamily `json:"family"`
	Transport        Transport      `json:"transport"`
	TLS              TLSMode        `json:"tls"`
	Config           map[string]any `json:"config,omitempty"`
	Egress           []EgressDecl   `json:"egress,omitempty"`
	Capabilities     []string       `json:"capabilities,omitempty"`
	SourceCIDRs      []string       `json:"source_cidrs"`
	DestinationCIDRs []string       `json:"destination_cidrs"`
	Protocol         string         `json:"protocol"`
	Ports            []PortRange    `json:"ports"`
	Hosts            []string       `json:"hosts"`
}

type EgressDecl struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  bool   `json:"tls"`
}

type CredentialDecl struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	Endpoint       string `json:"endpoint"`
	Username       string `json:"username,omitempty"`
	Header         string `json:"header,omitempty"`
	Prefix         string `json:"prefix,omitempty"`
	IdempotencyKey bool   `json:"idempotency_key,omitempty"`
	Condition      string `json:"condition,omitempty"`
}

type RuleDecl struct {
	Name       string   `json:"name,omitempty"`
	Endpoints  []string `json:"endpoints"`
	Credential string   `json:"credential,omitempty"`
	Condition  string   `json:"condition,omitempty"`
	Tunnel     string   `json:"tunnel,omitempty"`
	Verdict    Action   `json:"verdict"`
	Priority   int      `json:"priority"`
	Disabled   bool     `json:"disabled"`
	Reason     string   `json:"reason"`
}

type TailscaleDecl struct {
	Name       string   `json:"name"`
	Tags       []string `json:"tags"`
	Hostname   string   `json:"hostname,omitempty"`
	ControlURL string   `json:"control_url,omitempty"`
}

type NetworkForwardDecl struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Target     string `json:"target"`
	TargetPort uint16 `json:"target_port"`
	Listen     string `json:"listen,omitempty"`
	Tunnel     string `json:"tunnel,omitempty"`
}

func (p networkPolicyFile) metadataCopy() map[string]any {
	if len(p.Metadata) == 0 {
		return nil
	}
	copy := make(map[string]any, len(p.Metadata))
	for key, value := range p.Metadata {
		copy[key] = value
	}
	return copy
}

func emptyMetadata(raw json.RawMessage) bool {
	return len(raw) == 0
}
