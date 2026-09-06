package publication

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

func TestPolicyValidatesPublicationRequests(t *testing.T) {
	guestIP := netip.MustParseAddr("192.168.127.2")
	tests := []struct {
		name       string
		bind       BindPolicy
		request    types.ExposeRequest
		want       types.ExposeRequest
		wantReason string
		wantError  string
	}{
		{name: "empty protocol defaults to tcp", bind: BindAny, request: request(":8080", ":80", ""), want: request("0.0.0.0:8080", "192.168.127.2:80", types.TCP)},
		{name: "tcp protocol", bind: BindAny, request: request("0.0.0.0:8080", "192.168.127.2:80", types.TCP), want: request("0.0.0.0:8080", "192.168.127.2:80", types.TCP)},
		{name: "udp protocol denied", bind: BindAny, request: request(":8080", ":80", types.UDP), wantReason: "protocol", wantError: "protocol"},
		{name: "empty host allowed by any", bind: BindAny, request: request(":8080", ":80", types.TCP), want: request("0.0.0.0:8080", "192.168.127.2:80", types.TCP)},
		{name: "IPv4 wildcard allowed by any", bind: BindAny, request: request("0.0.0.0:8080", ":80", types.TCP), want: request("0.0.0.0:8080", "192.168.127.2:80", types.TCP)},
		{name: "IPv6 wildcard allowed by any", bind: BindAny, request: request("[::]:8080", ":80", types.TCP), want: request("[::]:8080", "192.168.127.2:80", types.TCP)},
		{name: "empty host denied by loopback", bind: BindLoopback, request: request(":8080", ":80", types.TCP), wantReason: "bind_policy", wantError: "loopback"},
		{name: "IPv4 wildcard denied by loopback", bind: BindLoopback, request: request("0.0.0.0:8080", ":80", types.TCP), wantReason: "bind_policy", wantError: "loopback"},
		{name: "IPv6 wildcard denied by loopback", bind: BindLoopback, request: request("[::]:8080", ":80", types.TCP), wantReason: "bind_policy", wantError: "loopback"},
		{name: "IPv4 loopback allowed by loopback", bind: BindLoopback, request: request("127.0.0.1:8080", ":80", types.TCP), want: request("127.0.0.1:8080", "192.168.127.2:80", types.TCP)},
		{name: "IPv6 loopback allowed by loopback", bind: BindLoopback, request: request("[::1]:8080", ":80", types.TCP), want: request("[::1]:8080", "192.168.127.2:80", types.TCP)},
		{name: "non-loopback local denied", bind: BindAny, request: request("192.0.2.1:8080", ":80", types.TCP), wantReason: "address", wantError: "loopback or unspecified"},
		{name: "hostname local denied", bind: BindAny, request: request("localhost:8080", ":80", types.TCP), wantReason: "address", wantError: "IP address"},
		{name: "local port zero denied", bind: BindAny, request: request("127.0.0.1:0", ":80", types.TCP), wantReason: "address", wantError: "1..65535"},
		{name: "missing local port denied", bind: BindAny, request: request("127.0.0.1", ":80", types.TCP), wantReason: "address", wantError: "invalid local address"},
		{name: "empty remote host becomes guest", bind: BindAny, request: request("127.0.0.1:8080", ":80", types.TCP), want: request("127.0.0.1:8080", "192.168.127.2:80", types.TCP)},
		{name: "explicit guest remote allowed", bind: BindAny, request: request("127.0.0.1:8080", "192.168.127.2:80", types.TCP), want: request("127.0.0.1:8080", "192.168.127.2:80", types.TCP)},
		{name: "other remote denied", bind: BindAny, request: request("127.0.0.1:8080", "192.168.127.3:80", types.TCP), wantReason: "address", wantError: "must equal guest IP"},
		{name: "hostname remote denied", bind: BindAny, request: request("127.0.0.1:8080", "guest:80", types.TCP), wantReason: "address", wantError: "IP address"},
		{name: "remote port zero denied", bind: BindAny, request: request("127.0.0.1:8080", ":0", types.TCP), wantReason: "address", wantError: "1..65535"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, reason, err := (Policy{Bind: test.bind, GuestIP: guestIP}).Validate(test.request)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				if got != test.want || reason != "" {
					t.Fatalf("normalized request = %#v, reason = %q; want %#v", got, reason, test.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want text %q", err, test.wantError)
			}
			if reason != test.wantReason {
				t.Fatalf("deny reason = %q, want %q", reason, test.wantReason)
			}
		})
	}
}

func request(local, remote string, protocol types.TransportProtocol) types.ExposeRequest {
	return types.ExposeRequest{Local: local, Remote: remote, Protocol: protocol}
}
