package virtualnetwork

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
	"github.com/vandycknick/silo/net/netd/internal/netnode"
)

// gatewayDNS owns static zones and tailnet classification before public DNS.
// Classified failures are SERVFAIL and can never fall back to a public resolver.
type gatewayDNS struct {
	ctx   context.Context
	zones []types.Zone
	node  *netnode.Node
	slots chan struct{}
}

func (h *gatewayDNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}
	if len(req.Question) != 1 || req.Question[0].Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	for _, zone := range h.zones {
		if name == dns.Fqdn(zone.Name) || strings.HasSuffix(name, "."+dns.Fqdn(zone.Name)) {
			for _, record := range zone.Records {
				if name != strings.ToLower(dns.Fqdn(record.Name+"."+strings.TrimSuffix(zone.Name, "."))) {
					continue
				}
				header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
				if q.Qtype == dns.TypeA && record.IP.To4() != nil {
					resp.Answer = append(resp.Answer, &dns.A{Hdr: header, A: record.IP.To4()})
				}
				if q.Qtype == dns.TypeAAAA && record.IP.To4() == nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: header, AAAA: record.IP})
				}
			}
			resp.Authoritative = true
			_ = w.WriteMsg(resp)
			return
		}
	}
	ctx, cancel := context.WithTimeout(h.ctx, 3*time.Second)
	defer cancel()
	if h.node != nil {
		if _, classified := h.node.DNSName(q.Name); classified {
			answer, err := h.node.QueryDNS(ctx, q.Name, q.Qtype)
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
			} else {
				resp.Answer = answer.Answer
				resp.Ns = answer.Ns
				resp.Extra = answer.Extra
				resp.Rcode = answer.Rcode
			}
			_ = w.WriteMsg(resp)
			return
		}
	}
	resolver, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		client := &dns.Client{Timeout: 3 * time.Second}
		for _, server := range resolver.Servers {
			answer, _, queryErr := client.ExchangeContext(ctx, req, net.JoinHostPort(server, resolver.Port))
			if queryErr == nil && answer.Truncated {
				tcpClient := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
				answer, _, queryErr = tcpClient.ExchangeContext(ctx, req, net.JoinHostPort(server, resolver.Port))
			}
			if queryErr == nil {
				_ = w.WriteMsg(answer)
				return
			}
		}
	}
	resp.Rcode = dns.RcodeServerFailure
	_ = w.WriteMsg(resp)
}
