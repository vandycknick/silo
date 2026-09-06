package publication

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

type BindPolicy string

const (
	BindLoopback BindPolicy = "loopback"
	BindAny      BindPolicy = "any"
)

type Policy struct {
	Bind    BindPolicy
	GuestIP netip.Addr
}

func (p Policy) Validate(request types.ExposeRequest) (types.ExposeRequest, string, error) {
	protocol, reason, err := validateProtocol(request.Protocol)
	if err != nil {
		return types.ExposeRequest{}, reason, err
	}
	local, reason, err := p.validateLocal(request.Local)
	if err != nil {
		return types.ExposeRequest{}, reason, err
	}
	remote, err := p.validateRemote(request.Remote)
	if err != nil {
		return types.ExposeRequest{}, "address", err
	}
	return types.ExposeRequest{Local: local, Remote: remote, Protocol: protocol}, "", nil
}

func (p Policy) ValidateUnexpose(request types.UnexposeRequest) (types.UnexposeRequest, string, error) {
	protocol, reason, err := validateProtocol(request.Protocol)
	if err != nil {
		return types.UnexposeRequest{}, reason, err
	}
	local, reason, err := p.validateLocal(request.Local)
	if err != nil {
		return types.UnexposeRequest{}, reason, err
	}
	return types.UnexposeRequest{Local: local, Protocol: protocol}, "", nil
}

func validateProtocol(protocol types.TransportProtocol) (types.TransportProtocol, string, error) {
	if protocol == "" {
		return types.TCP, "", nil
	}
	if protocol != types.TCP {
		return "", "protocol", fmt.Errorf("protocol %q is not supported; expected tcp", protocol)
	}
	return protocol, "", nil
}

func (p Policy) validateLocal(value string) (string, string, error) {
	host, port, err := splitAddress(value, "local")
	if err != nil {
		return "", "address", err
	}
	if host == "" {
		host = netip.IPv4Unspecified().String()
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", "address", fmt.Errorf("local host %q must be an IP address", host)
	}
	address = address.Unmap()
	if address.IsUnspecified() {
		if p.Bind != BindAny {
			return "", "bind_policy", errors.New("bind policy permits loopback publications only")
		}
	} else if !address.IsLoopback() {
		return "", "address", fmt.Errorf("local host %q must be loopback or unspecified", host)
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port))), "", nil
}

func (p Policy) validateRemote(value string) (string, error) {
	host, port, err := splitAddress(value, "remote")
	if err != nil {
		return "", err
	}
	guestIP := p.GuestIP.Unmap()
	if !guestIP.IsValid() {
		return "", errors.New("guest publication address is not configured")
	}
	if host != "" {
		address, err := netip.ParseAddr(host)
		if err != nil {
			return "", fmt.Errorf("remote host %q must be an IP address", host)
		}
		if address.Unmap() != guestIP {
			return "", fmt.Errorf("remote host %q must equal guest IP %s", host, guestIP)
		}
	}
	return net.JoinHostPort(guestIP.String(), strconv.Itoa(int(port))), nil
}

func splitAddress(value, field string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("invalid %s address %q: %w", field, value, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("invalid %s port %q; expected 1..65535", field, portText)
	}
	return host, uint16(port), nil
}
