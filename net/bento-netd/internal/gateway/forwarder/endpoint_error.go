package forwarder

import (
	"log/slog"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func logCreateEndpointError(protocol string, flow hooks.Flow, err tcpip.Error) {
	attrs := []any{
		"protocol", protocol,
		"src_ip", flow.SourceIP.String(),
		"src_port", flow.SourcePort,
		"dst_ip", flow.DestIP.String(),
		"dst_port", flow.DestPort,
		"error", err.String(),
	}
	if isExpectedCreateEndpointError(err) {
		slog.Debug("network endpoint closed before creation", attrs...)
		return
	}
	slog.Error("network endpoint creation failed", attrs...)
}

func isExpectedCreateEndpointError(err tcpip.Error) bool {
	switch err.(type) {
	case *tcpip.ErrConnectionRefused, *tcpip.ErrConnectionReset, *tcpip.ErrAborted, *tcpip.ErrConnectionAborted:
		return true
	default:
		return false
	}
}
