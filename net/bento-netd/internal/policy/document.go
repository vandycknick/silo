package policy

type PolicyDocument struct {
	ID          uint32           `json:"id"`
	Source      SourceFile       `json:"source"`
	Diagnostics []Diagnostic     `json:"diagnostics"`
	Settings    SettingsDecl     `json:"settings"`
	Endpoints   []EndpointDecl   `json:"endpoints"`
	Credentials []CredentialDecl `json:"credentials"`
	Rules       []RuleDecl       `json:"rules"`
}

type SourceFile struct {
	Filename string `json:"filename"`
}

type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code,omitempty"`
	Summary  string `json:"summary"`
	Detail   string `json:"detail"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type SettingsDecl struct {
	DefaultAction Action             `json:"default_action"`
	Audit         *AuditSettingsDecl `json:"audit,omitempty"`
}

type AuditSettingsDecl struct {
	BodyBuffer  int64 `json:"body_buffer"`
	BodyStorage int64 `json:"body_storage"`
}

type EndpointDecl struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	Family      EndpointFamily `json:"family"`
	Transport   Transport      `json:"transport"`
	DefaultPort uint16         `json:"default_port"`
	Source      []string       `json:"source,omitempty"`
	Destination []string       `json:"destination,omitempty"`
	Protocol    string         `json:"protocol,omitempty"`
	Ports       []PortRange    `json:"ports,omitempty"`
	Hosts       []string       `json:"hosts,omitempty"`
	Order       int            `json:"order"`
}

type ConditionDecl struct {
	ID     uint32 `json:"id"`
	Source string `json:"source"`
}

type CredentialDecl struct {
	Kind           string         `json:"kind"`
	Name           string         `json:"name"`
	Endpoint       Ref            `json:"endpoint"`
	Username       string         `json:"username,omitempty"`
	Header         string         `json:"header,omitempty"`
	Prefix         string         `json:"prefix,omitempty"`
	IdempotencyKey bool           `json:"idempotency_key,omitempty"`
	Condition      *ConditionDecl `json:"condition,omitempty"`
	Order          int            `json:"order"`
}

type RuleDecl struct {
	Name       string         `json:"name"`
	Endpoints  []Ref          `json:"endpoints"`
	Credential *Ref           `json:"credential,omitempty"`
	Verdict    Action         `json:"verdict"`
	Priority   int            `json:"priority"`
	Disabled   bool           `json:"disabled"`
	Condition  *ConditionDecl `json:"condition,omitempty"`
	Reason     string         `json:"reason"`
	Order      int            `json:"order"`
}

type policySnapshot struct {
	Documents   []PolicyDocument `json:"documents"`
	Diagnostics []Diagnostic     `json:"diagnostics"`
}
