package router

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestTailnetRoutingNeverEscapesOrIntercepts(t *testing.T) {
	for _, tc := range []struct {
		name, rules, destination string
		action                   hooks.RouteAction
		tunnel                   bool
	}{
		{"default allow", "", "100.64.0.2", hooks.RouteDeny, false},
		{"explicit tunnel", `{"endpoints":["all"],"tunnel":"vm","verdict":"allow"}`, "100.64.0.2", hooks.RouteAllowDirect, true},
		{"IPv6", `{"endpoints":["all"],"tunnel":"vm","verdict":"allow"}`, "fd7a:115c:a1e0::2", hooks.RouteAllowDirect, true},
		{"deny priority", `{"endpoints":["all"],"tunnel":"vm","verdict":"allow","priority":0},{"endpoints":["all"],"verdict":"deny","priority":10}`, "100.64.0.2", hooks.RouteDeny, false},
		{"tunnel cannot catch internet", `{"endpoints":["all"],"tunnel":"vm","verdict":"allow"}`, "203.0.113.8", hooks.RouteClassify, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.LoadReader("test.json", strings.NewReader(`{"version":1,"settings":{"default_action":"allow"},"tailscale":[{"name":"vm","hostname":"vm","ephemeral":true}],"endpoints":[{"name":"all","kind":"ip","family":"ip","transport":"packet-filter","tls":"none","protocol":"any","destination_cidrs":["0.0.0.0/0","::/0"]},{"name":"web","kind":"http","family":"http","transport":"http-proxy","tls":"none","hosts":["example.com"]}],"rules":[`+tc.rules+`]}`))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := New(p, nil).Decide(context.Background(), hooks.Flow{Protocol: "tcp", DestIP: net.ParseIP(tc.destination), DestPort: 80})
			if err != nil || decision.Action != tc.action || (decision.Tunnel != nil) != tc.tunnel || (tc.tunnel && decision.ClassificationOpportunity) {
				t.Fatalf("%+v %v", decision, err)
			}
		})
	}
}
