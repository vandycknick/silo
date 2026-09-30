package netnode

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSName classifies from node status, never guessed short-name search domains.
// An empty canonical name with classified=true represents an ambiguous peer.
func (n *Node) DNSName(name string) (canonical string, classified bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dnsNameLocked(name)
}

func (n *Node) dnsNameLocked(name string) (canonical string, classified bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if full, ok := n.short[name]; ok {
		return full, true
	}
	if _, ok := n.fullNames[name]; ok {
		return name, true
	}
	if n.suffix != "" && (name == n.suffix || strings.HasSuffix(name, "."+n.suffix)) {
		return name, true
	}
	if _, known := n.knownShort[name]; known {
		return "", true
	}
	for suffix := range n.knownSuffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return "", true
		}
	}
	if n.classificationFull || name == "ts.net" || strings.HasSuffix(name, ".ts.net") {
		return "", true
	}
	return name, false
}

func (n *Node) QueryDNS(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	n.mu.Lock()
	canonical, classified := n.dnsNameLocked(name)
	client, ready, fingerprint := n.client, n.running && !n.closed, n.fingerprint
	n.mu.Unlock()
	if !classified || canonical == "" {
		return nil, errors.New("unclassified or ambiguous tailnet DNS name")
	}
	if client == nil || !ready {
		return nil, errors.New("tailscale DNS disconnected")
	}
	typeName, ok := dns.TypeToString[qtype]
	if !ok {
		return nil, errors.New("unsupported DNS type")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, _, err := client.QueryDNS(bounded, dns.Fqdn(canonical), typeName)
	if err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return nil, err
	}
	// A short-name request must receive answers with its requested owner name.
	for _, rr := range msg.Answer {
		if strings.EqualFold(rr.Header().Name, dns.Fqdn(canonical)) {
			rr.Header().Name = dns.Fqdn(name)
		}
	}
	if !n.remember(msg, fingerprint) {
		return nil, errors.New("DNS state changed or provenance capacity exhausted")
	}
	return msg, nil
}

func (n *Node) remember(msg *dns.Msg, fingerprint string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if fingerprint != n.fingerprint || !n.running || n.closed {
		return false
	}
	now := time.Now()
	n.pruneAddresses(now)
	updates := make(map[netip.Addr]time.Time)
	records := append(append(append([]dns.RR(nil), msg.Answer...), msg.Ns...), msg.Extra...)
	for _, rr := range records {
		if alias, ok := rr.(*dns.CNAME); ok {
			target, classified := n.dnsNameLocked(alias.Target)
			if !classified || target == "" {
				return false
			}
		}
		var ip netip.Addr
		switch record := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(record.A)
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(record.AAAA)
		default:
			continue
		}
		if !ip.IsValid() {
			continue
		}
		ttl := min(rr.Header().Ttl, uint32(60))
		rr.Header().Ttl = ttl
		// Zero-TTL answers cannot be cached, but their immediate connection
		// attempt still needs classification. Keep that address for one second.
		until := now.Add(time.Duration(max(ttl, uint32(1))) * time.Second)
		ip = ip.Unmap()
		if until.After(updates[ip]) {
			updates[ip] = until
		}
	}
	count := len(n.provenance) + len(n.quarantined)
	for ip := range updates {
		if _, positive := n.provenance[ip]; positive {
			continue
		}
		if _, negative := n.quarantined[ip]; !negative {
			count++
		}
	}
	if count > 4096 {
		return false
	}
	// Commit the entire answer atomically. Never return untracked addresses.
	for ip, until := range updates {
		until = maxTime(until, maxTime(n.provenance[ip], n.quarantined[ip]))
		delete(n.quarantined, ip)
		n.provenance[ip] = until
	}
	return true
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
