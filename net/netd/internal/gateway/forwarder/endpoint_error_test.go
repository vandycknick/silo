package forwarder

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestIsExpectedCreateEndpointError(t *testing.T) {
	tests := []struct {
		name string
		err  tcpip.Error
		want bool
	}{
		{name: "connection refused", err: &tcpip.ErrConnectionRefused{}, want: true},
		{name: "connection reset", err: &tcpip.ErrConnectionReset{}, want: true},
		{name: "operation aborted", err: &tcpip.ErrAborted{}, want: true},
		{name: "connection aborted", err: &tcpip.ErrConnectionAborted{}, want: true},
		{name: "bad address", err: &tcpip.ErrBadAddress{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedCreateEndpointError(tt.err); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
