package silo

import (
	"encoding/json"
	"fmt"
	"github.com/vandycknick/silo/sdk/go/internal/ffi"
)

type MachineNetworkKind string

const (
	MachineNetworkPrivate MachineNetworkKind = "private"
	MachineNetworkNone    MachineNetworkKind = "none"
	MachineNetworkNamed   MachineNetworkKind = "named"
	MachineNetworkUnknown MachineNetworkKind = "unknown"
)

type NetworkPolicy struct{ canonicalJSON string }

func (policy *NetworkPolicy) JSON() string {
	if policy == nil {
		return ""
	}
	return policy.canonicalJSON
}
func (policy *NetworkPolicy) String() string { return policy.JSON() }

// PublishBind constrains host addresses a guest may publish through netd.
type PublishBind string

const (
	PublishLoopback PublishBind = "loopback"
	PublishAny      PublishBind = "any"
)

type GuestPublish struct {
	Bind PublishBind `json:"bind"`
}

type MachineNetwork struct {
	Kind      MachineNetworkKind
	Name      string
	Policy    *NetworkPolicy
	Publish   *GuestPublish
	Tailscale *MachineTailscale
}

type MachineTailscale struct {
	StateDir  string `json:"state_dir"`
	Hostname  string `json:"hostname"`
	Ephemeral bool   `json:"ephemeral"`
}

func PrivateNetwork(policy *NetworkPolicy) MachineNetwork {
	return MachineNetwork{Kind: MachineNetworkPrivate, Policy: policy}
}

// WithPublish grants publication authority. Only private networks support it.
func (network MachineNetwork) WithPublish(bind PublishBind) MachineNetwork {
	network.Publish = &GuestPublish{Bind: bind}
	return network
}

func NoNetwork() MachineNetwork { return MachineNetwork{Kind: MachineNetworkNone} }
func NamedNetwork(name string) MachineNetwork {
	return MachineNetwork{Kind: MachineNetworkNamed, Name: name}
}

type machineNetworkWire struct {
	Kind       MachineNetworkKind `json:"kind"`
	Name       string             `json:"name,omitempty"`
	PolicyJSON string             `json:"policy_json,omitempty"`
	Publish    *GuestPublish      `json:"publish,omitempty"`
	Tailscale  *MachineTailscale  `json:"tailscale,omitempty"`
}

func (network MachineNetwork) wire() (machineNetworkWire, error) {
	wire := machineNetworkWire{Kind: network.Kind, Name: network.Name}
	if network.Publish != nil {
		if network.Kind != MachineNetworkPrivate || (network.Publish.Bind != PublishLoopback && network.Publish.Bind != PublishAny) {
			return machineNetworkWire{}, newError(ErrorInvalidArgument, "", "guest publication requires a private network and loopback or any bind policy")
		}
		publish := *network.Publish
		wire.Publish = &publish
	}
	if network.Policy != nil {
		wire.PolicyJSON = network.Policy.JSON()
	}
	switch network.Kind {
	case MachineNetworkPrivate, MachineNetworkNone:
	case MachineNetworkNamed:
		if network.Name == "" {
			return machineNetworkWire{}, newError(ErrorInvalidArgument, "", "named network requires a name")
		}
	default:
		return machineNetworkWire{}, newError(ErrorInvalidArgument, "", fmt.Sprintf("unsupported machine network kind %q", network.Kind))
	}
	return wire, nil
}

type NetworkAction string

const (
	NetworkAllow NetworkAction = "allow"
	NetworkDeny  NetworkAction = "deny"
)

type NetworkPolicyConfig struct {
	DefaultAction NetworkAction       `json:"default_action,omitempty"`
	Metadata      map[string]string   `json:"metadata,omitempty"`
	Audit         *NetworkAuditConfig `json:"audit,omitempty"`
	Endpoints     []NetworkEndpoint   `json:"endpoints,omitempty"`
	Credentials   []NetworkCredential `json:"credentials,omitempty"`
	Rules         []NetworkRule       `json:"rules,omitempty"`
	Tunnels       []TailscaleTunnel   `json:"tunnels,omitempty"`
	Forwards      []NetworkForward    `json:"forwards,omitempty"`
}
type NetworkAuditConfig struct {
	BodyBufferBytes  *uint64 `json:"body_buffer_bytes,omitempty"`
	BodyStorageBytes *uint64 `json:"body_storage_bytes,omitempty"`
}
type NetworkEndpointKind string

const (
	NetworkEndpointIP    NetworkEndpointKind = "ip"
	NetworkEndpointHTTP  NetworkEndpointKind = "http"
	NetworkEndpointHTTPS NetworkEndpointKind = "https"
)

type NetworkProtocol string

const (
	NetworkProtocolAny NetworkProtocol = "any"
	NetworkProtocolTCP NetworkProtocol = "tcp"
	NetworkProtocolUDP NetworkProtocol = "udp"
)

type NetworkPortRange struct {
	Start uint16  `json:"start"`
	End   *uint16 `json:"end,omitempty"`
}
type NetworkEndpoint struct {
	Name             string              `json:"name"`
	Kind             NetworkEndpointKind `json:"kind"`
	SourceCIDRs      []string            `json:"source_cidrs,omitempty"`
	DestinationCIDRs []string            `json:"destination_cidrs,omitempty"`
	Protocol         NetworkProtocol     `json:"protocol,omitempty"`
	Ports            []NetworkPortRange  `json:"ports,omitempty"`
	Hosts            []string            `json:"hosts,omitempty"`
}
type NetworkCredentialKind string

const (
	CredentialBasicAuth        NetworkCredentialKind = "basic_auth"
	CredentialBearerToken      NetworkCredentialKind = "bearer_token"
	CredentialHeaderToken      NetworkCredentialKind = "header_token"
	CredentialGitHubOAuth      NetworkCredentialKind = "github_oauth"
	CredentialOpenAICodexOAuth NetworkCredentialKind = "openai_codex_oauth"
	CredentialAWS              NetworkCredentialKind = "aws_credential"
)

type NetworkCredential struct {
	Name           string                `json:"name"`
	Kind           NetworkCredentialKind `json:"kind"`
	Endpoint       *string               `json:"endpoint,omitempty"`
	Username       *string               `json:"username,omitempty"`
	Header         *string               `json:"header,omitempty"`
	Prefix         *string               `json:"prefix,omitempty"`
	IdempotencyKey *bool                 `json:"idempotency_key,omitempty"`
	Condition      *string               `json:"condition,omitempty"`
}
type NetworkVerdict string

const (
	NetworkVerdictAllow NetworkVerdict = "allow"
	NetworkVerdictDeny  NetworkVerdict = "deny"
)

type NetworkRule struct {
	Name       *string        `json:"name,omitempty"`
	Endpoints  []string       `json:"endpoints,omitempty"`
	Credential *string        `json:"credential,omitempty"`
	Condition  *string        `json:"condition,omitempty"`
	Tunnel     *string        `json:"tunnel,omitempty"`
	Priority   *int32         `json:"priority,omitempty"`
	Disabled   bool           `json:"disabled"`
	Reason     *string        `json:"reason,omitempty"`
	Verdict    NetworkVerdict `json:"verdict,omitempty"`
}
type TailscaleTunnel struct {
	Name       string   `json:"name"`
	Ephemeral  bool     `json:"ephemeral"`
	Tags       []string `json:"tags,omitempty"`
	Hostname   *string  `json:"hostname,omitempty"`
	ControlURL *string  `json:"control_url,omitempty"`
}
type NetworkForwardKind string

const (
	NetworkForwardHost      NetworkForwardKind = "host"
	NetworkForwardTailscale NetworkForwardKind = "tailscale"
)

type NetworkForward struct {
	Name       string             `json:"name"`
	Kind       NetworkForwardKind `json:"kind"`
	Tunnel     *string            `json:"tunnel,omitempty"`
	Target     *string            `json:"target,omitempty"`
	TargetPort *uint16            `json:"target_port,omitempty"`
	Listen     *string            `json:"listen,omitempty"`
}

func BuildNetworkPolicy(config NetworkPolicyConfig) (*NetworkPolicy, error) {
	return policyRequest(networkPolicyRequest{Config: &config})
}
func ParseNetworkPolicyJSON(value string) (*NetworkPolicy, error) {
	if value == "" {
		return nil, newError(ErrorInvalidArgument, "", "network policy JSON must not be empty")
	}
	return policyRequest(networkPolicyRequest{JSON: &value})
}

type networkPolicyRequest struct {
	JSON   *string              `json:"json,omitempty"`
	HCL    *string              `json:"hcl,omitempty"`
	Config *NetworkPolicyConfig `json:"config,omitempty"`
	Output string               `json:"output,omitempty"`
}

func ParseNetworkPolicyHCL(value string) (*NetworkPolicy, error) {
	return policyRequest(networkPolicyRequest{HCL: &value})
}

func ValidateNetworkPolicyHCL(value string) error {
	_, err := ParseNetworkPolicyHCL(value)
	return err
}

func (policy *NetworkPolicy) HCL() (string, error) {
	if policy == nil {
		return "", newError(ErrorInvalidArgument, "", "policy is required")
	}
	value := policy.JSON()
	data, err := nativePolicyRequest(networkPolicyRequest{JSON: &value, Output: "hcl"})
	return string(data), err
}

type NetworkSecretSource struct {
	Key   string `json:"key"`
	Field string `json:"field"`
}
type NetworkSecretSlot struct {
	Name     string              `json:"name"`
	Required bool                `json:"required"`
	Kind     string              `json:"kind"`
	Source   NetworkSecretSource `json:"source"`
}
type NetworkSecretRequirement struct {
	Owner        string     `json:"owner"`
	Alternatives [][]string `json:"alternatives"`
}
type NetworkSecretMetadata struct {
	Slots        []NetworkSecretSlot        `json:"slots"`
	Requirements []NetworkSecretRequirement `json:"requirements"`
}

func (policy *NetworkPolicy) SecretMetadata() (*NetworkSecretMetadata, error) {
	if policy == nil {
		return nil, newError(ErrorInvalidArgument, "", "policy is required")
	}
	value := policy.JSON()
	data, err := nativePolicyRequest(networkPolicyRequest{JSON: &value, Output: "slots"})
	if err != nil {
		return nil, err
	}
	var result NetworkSecretMetadata
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func policyRequest(request networkPolicyRequest) (*NetworkPolicy, error) {
	data, err := nativePolicyRequest(request)
	if err != nil {
		return nil, err
	}
	return &NetworkPolicy{canonicalJSON: string(data)}, nil
}

func nativePolicyRequest(request networkPolicyRequest) ([]byte, error) {
	if err := ffi.Load(Version, ffiABIVersion); err != nil {
		return nil, fromNativeError(err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, newError(ErrorInvalidArgument, "", "encode network policy: "+err.Error())
	}
	data, err = ffi.BuildNetworkPolicy(data)
	if err != nil {
		return nil, fromNativeError(err)
	}
	return data, nil
}
