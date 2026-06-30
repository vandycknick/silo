// Package hostmatch parses and matches HTTP-family endpoint host bindings.
//
// Endpoint `hosts = [...]` entries are HTTP authorities, not URLs. They may be
// exact hostnames, IPv4 literals, bracketed IPv6 literals, or `*.<suffix>`
// wildcard suffixes, and each form may carry an explicit port. Schemes,
// credentials, paths, queries, and fragments are rejected before an entry can
// become part of a policy.
//
// Hostnames are lowercased and compared as ASCII/punycode only in v1. Default
// ports normalize away, so `example.com` and `example.com:80` are the same HTTP
// binding. IPv6 literals must use bracketed authority spelling, for example
// `[2001:db8::1]` or `[2001:db8::1]:8443`.
//
// Wildcards are routing patterns, not TLS certificate wildcards. `*.example.com`
// matches descendants such as `api.example.com` and `a.b.example.com`, but not
// the apex `example.com`. Wildcard IP-looking patterns are rejected because IP
// literals are exact-address bindings.
package hostmatch

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Authority is a normalized HTTP authority split into host and port.
//
// Host is lowercase and stores IP literals in canonical netip form without IPv6
// brackets. Port always has a concrete value: either the explicit authority port
// or the caller-supplied default port.
type Authority struct {
	Host string
	Port uint16
}

// Binding is one normalized endpoint host binding.
//
// Pattern is the canonical policy spelling used for diagnostics and duplicate
// detection. Host and Port are the normalized comparison key. Wildcard marks
// `*.<suffix>` bindings, where Host stores only the suffix.
type Binding struct {
	Pattern  string
	Host     string
	Port     uint16
	Wildcard bool
}

// DefaultPort returns the default authority port for an HTTP-family endpoint
// kind. Unknown kinds use HTTP's port 80 so plain HTTP remains the conservative
// fallback.
func DefaultPort(kind string) uint16 {
	if kind == "https" {
		return 443
	}
	return 80
}

// ParseBinding parses one endpoint `hosts = [...]` entry.
//
// Entries may be exact authorities or `*.<suffix>` wildcards. Wildcards keep
// the same authority grammar as exact entries after the `*.` prefix is removed,
// but their suffix must not look like an IP address. The returned Binding is
// canonicalized for deterministic duplicate detection and matching.
func ParseBinding(pattern string, defaultPort uint16) (Binding, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return Binding{}, fmt.Errorf("host must not be empty")
	}
	if strings.Contains(pattern, "*") && !strings.HasPrefix(pattern, "*.") {
		return Binding{}, fmt.Errorf("wildcard host %q is invalid", pattern)
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	if wildcard {
		pattern = strings.TrimPrefix(pattern, "*.")
		if pattern == "" || strings.Contains(pattern, "*") {
			return Binding{}, fmt.Errorf("wildcard host %q is invalid", "*."+pattern)
		}
	}
	parsedAuthority, err := ParseAuthority(pattern, defaultPort)
	if err != nil {
		return Binding{}, err
	}
	if wildcard && wildcardHostLooksLikeIPPattern(parsedAuthority.Host) {
		return Binding{}, fmt.Errorf("wildcard host %q cannot be an IP address", "*."+parsedAuthority.Host)
	}
	canonicalPattern := FormatAuthority(parsedAuthority, defaultPort)
	if wildcard {
		canonicalPattern = "*." + canonicalPattern
	}
	return Binding{Pattern: canonicalPattern, Host: parsedAuthority.Host, Port: parsedAuthority.Port, Wildcard: wildcard}, nil
}

// ParseAuthority parses a request or policy authority using net/url and the
// HTTP Host header grammar, then applies netd's policy-specific restrictions.
//
// The input must be an authority only. It must not include a scheme,
// credentials, path, query, or fragment. Hostnames must be ASCII/punycode and
// are lowercased. IPv4 literals are accepted as exact hosts. IPv6 literals must
// be bracketed in the original input, even though the returned Authority stores
// them without brackets.
func ParseAuthority(input string, defaultPort uint16) (Authority, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Authority{}, fmt.Errorf("authority host must not be empty")
	}
	rawBracketed := strings.HasPrefix(raw, "[")
	if !isASCII(raw) {
		return Authority{}, fmt.Errorf("authority %q must be ASCII/punycode", raw)
	}
	if strings.Contains(raw, "://") {
		return Authority{}, fmt.Errorf("authority %q must not include a scheme", raw)
	}

	parsed, err := url.Parse("http://" + raw)
	if err != nil {
		return Authority{}, fmt.Errorf("authority %q is invalid: %w", raw, err)
	}
	if parsed.User != nil {
		return Authority{}, fmt.Errorf("authority %q must not include credentials", raw)
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Authority{}, fmt.Errorf("authority %q must not include a path, query, or fragment", raw)
	}
	if parsed.Host == "" {
		return Authority{}, fmt.Errorf("authority host must not be empty")
	}
	if !httpguts.ValidHostHeader(parsed.Host) {
		return Authority{}, fmt.Errorf("authority %q is not a valid HTTP Host header", raw)
	}
	if !rawBracketed && strings.Count(parsed.Host, ":") > 1 {
		return Authority{}, fmt.Errorf("IPv6 authority %q must be bracketed", raw)
	}

	port := defaultPort
	if portValue := parsed.Port(); portValue != "" {
		decodedPort, err := ParsePort(portValue)
		if err != nil {
			return Authority{}, err
		}
		port = decodedPort
	}
	if parsed.Port() == "" && hasExplicitPortSyntax(parsed.Host) {
		return Authority{}, fmt.Errorf("authority %q has invalid host/port syntax", raw)
	}

	host := strings.ToLower(parsed.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return Authority{}, fmt.Errorf("authority host must not be empty")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is6() {
			if !rawBracketed {
				return Authority{}, fmt.Errorf("IPv6 authority %q must be bracketed", raw)
			}
			return Authority{Host: addr.String(), Port: port}, nil
		}
		if rawBracketed {
			return Authority{}, fmt.Errorf("bracketed authority %q must contain an IPv6 literal", raw)
		}
		return Authority{Host: addr.String(), Port: port}, nil
	}
	if rawBracketed {
		return Authority{}, fmt.Errorf("bracketed authority %q must contain an IPv6 literal", raw)
	}
	return Authority{Host: host, Port: port}, nil
}

// Matches reports whether a normalized authority belongs to this binding.
//
// Port equality is always required. Exact bindings compare host equality.
// Wildcards match descendants only, so `*.example.com` matches
// `api.example.com` but not `example.com`.
func (b Binding) Matches(authority Authority) bool {
	if b.Port != authority.Port {
		return false
	}
	if !b.Wildcard {
		return b.Host == authority.Host
	}
	return authority.Host != b.Host && strings.HasSuffix(authority.Host, "."+b.Host)
}

// FormatAuthority renders a normalized authority back to canonical policy
// spelling. The default port is omitted, and IPv6 literals are bracketed.
func FormatAuthority(authority Authority, defaultPort uint16) string {
	if authority.Port == defaultPort {
		return formatAuthorityHost(authority.Host)
	}
	return net.JoinHostPort(authority.Host, strconv.Itoa(int(authority.Port)))
}

func formatAuthorityHost(host string) string {
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err == nil {
			return "[" + host + "]"
		}
	}
	return host
}

func hasExplicitPortSyntax(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		return end >= 0 && len(host) > end+1
	}
	return strings.Count(host, ":") == 1
}

// ParsePort parses a TCP/UDP port in the policy range 1..65535.
func ParsePort(value string) (uint16, error) {
	if value == "" {
		return 0, fmt.Errorf("port %q is out of range", value)
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("port %q is out of range", value)
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q is out of range", value)
	}
	return uint16(port), nil
}

func wildcardHostLooksLikeIPPattern(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}
