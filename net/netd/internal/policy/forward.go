package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

type ForwardProtocol string

const (
	ForwardProtocolTCP   ForwardProtocol = "tcp"
	ForwardProtocolHTTPS ForwardProtocol = "https"
)

// UnmarshalJSON distinguishes an omitted protocol (the TCP default) from an
// explicitly supplied invalid value, including an empty string or null.
func (p *ForwardProtocol) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch ForwardProtocol(value) {
	case ForwardProtocolTCP, ForwardProtocolHTTPS:
		*p = ForwardProtocol(value)
		return nil
	default:
		return fmt.Errorf("unsupported protocol %q", value)
	}
}

type ForwardCertificateProvider string

const ForwardCertificateProviderTailscale ForwardCertificateProvider = "tailscale"

type ForwardTLS struct {
	Provider ForwardCertificateProvider `json:"provider"`
}

// Forward is an executable listener targeting the dedicated attachment's guest.
// Compilation has already validated the node binding and certificate provider.
type Forward struct {
	Name       string
	ListenPort uint16
	GuestPort  uint16
	Protocol   ForwardProtocol
}

// Forwards returns a copy so runtime setup cannot mutate the compiled policy.
func (p *Policy) Forwards() []Forward {
	if p == nil {
		return nil
	}
	return slices.Clone(p.forwards)
}

// AttachmentScope is supplied by the runtime, never by a policy author or an
// attached-VM count. The zero value deliberately does not authorize self.
type AttachmentScope uint8

const (
	AttachmentScopeUnknown AttachmentScope = iota
	AttachmentScopeDedicatedVM
	AttachmentScopeSharedNetwork
)

// ValidateForwardAttachment must run before creating networking resources.
// Every executable forward currently targets self in a dedicated 1:1 process.
func ValidateForwardAttachment(scope AttachmentScope, forwards []Forward) error {
	if len(forwards) == 0 || scope == AttachmentScopeDedicatedVM {
		return nil
	}
	return fmt.Errorf("forward %q: target %q requires a dedicated 1:1 netd attachment", forwards[0].Name, "self")
}

func (p *Policy) compileForwards(declarations []NetworkForwardDecl) error {
	if len(declarations) == 0 {
		return nil
	}
	forwards := make([]Forward, 0, len(declarations))
	listeners := make(map[uint16]struct{}, len(declarations))
	names := make(map[string]struct{}, len(declarations))
	for _, decl := range declarations {
		if decl.Name == "" {
			return fmt.Errorf("forward name is required")
		}
		for _, c := range decl.Name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return fmt.Errorf("forward %q: name must use the policy identifier grammar", decl.Name)
			}
		}
		if _, exists := names[decl.Name]; exists {
			return fmt.Errorf("forward %q: duplicate name", decl.Name)
		}
		names[decl.Name] = struct{}{}
		if decl.Kind != "tailscale" {
			return fmt.Errorf("forward %q: unsupported listener kind %q; only tailscale forwards are implemented", decl.Name, decl.Kind)
		}
		if decl.Target != "self" {
			return fmt.Errorf("forward %q: unsupported target %q; only self is implemented", decl.Name, decl.Target)
		}
		if p.tailscale == nil {
			return fmt.Errorf("forward %q: requires exactly one tailscale declaration", decl.Name)
		}
		if decl.Tunnel != "" && decl.Tunnel != p.tailscale.Name {
			return fmt.Errorf("forward %q: tunnel %q does not match tailscale node %q", decl.Name, decl.Tunnel, p.tailscale.Name)
		}
		protocol := decl.Protocol
		if protocol == "" {
			protocol = ForwardProtocolTCP
		}
		switch protocol {
		case ForwardProtocolTCP:
			if decl.TLS != nil {
				return fmt.Errorf("forward %q: tcp forbids tls", decl.Name)
			}
		case ForwardProtocolHTTPS:
			if decl.TLS == nil || decl.TLS.Provider != ForwardCertificateProviderTailscale {
				return fmt.Errorf("forward %q: https requires tls.provider = tailscale", decl.Name)
			}
		default:
			return fmt.Errorf("forward %q: unsupported protocol %q", decl.Name, protocol)
		}
		port, err := forwardListenPort(decl.Listen)
		if err != nil {
			return fmt.Errorf("forward %q: %w", decl.Name, err)
		}
		if port == 22 {
			return fmt.Errorf("forward %q: listener port 22 is reserved for SSH", decl.Name)
		}
		if _, exists := listeners[port]; exists {
			return fmt.Errorf("forward %q: duplicate listener port %d", decl.Name, port)
		}
		if decl.TargetPort == 0 {
			return fmt.Errorf("forward %q: target_port must be between 1 and 65535", decl.Name)
		}
		listeners[port] = struct{}{}
		forwards = append(forwards, Forward{Name: decl.Name, ListenPort: port, GuestPort: decl.TargetPort, Protocol: protocol})
	}
	p.forwards = forwards
	return nil
}

func forwardListenPort(listen string) (uint16, error) {
	invalid := func() (uint16, error) {
		return 0, fmt.Errorf("listen must be :<decimal port> with port between 1 and 65535")
	}
	if len(listen) < 2 || listen[0] != ':' {
		return invalid()
	}
	for _, digit := range listen[1:] {
		if digit < '0' || digit > '9' {
			return invalid()
		}
	}
	port, err := strconv.ParseUint(listen[1:], 10, 16)
	if err != nil || port == 0 {
		return invalid()
	}
	return uint16(port), nil
}
