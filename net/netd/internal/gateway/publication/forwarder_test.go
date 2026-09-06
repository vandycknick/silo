package publication

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTCPForwarderKeepsIPv4AndIPv6WildcardListenersIndependent(t *testing.T) {
	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(networkStack.Close)
	forwarder := NewTCPForwarder(networkStack)
	port := freeDualStackPort(t)
	ipv4Local := fmt.Sprintf("0.0.0.0:%d", port)
	ipv6Local := fmt.Sprintf("[::]:%d", port)
	remote := "192.168.127.2:80"
	t.Cleanup(func() {
		_ = forwarder.Unexpose(types.TCP, ipv4Local)
		_ = forwarder.Unexpose(types.TCP, ipv6Local)
	})

	if err := forwarder.Expose(types.TCP, ipv4Local, remote); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Expose(types.TCP, ipv6Local, remote); err != nil {
		t.Fatal(err)
	}
	assertDialSucceeds(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	assertDialSucceeds(t, "tcp6", fmt.Sprintf("[::1]:%d", port))

	if err := forwarder.Unexpose(types.TCP, ipv4Local); err != nil {
		t.Fatal(err)
	}
	assertDialFails(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	assertDialSucceeds(t, "tcp6", fmt.Sprintf("[::1]:%d", port))

	if err := forwarder.Unexpose(types.TCP, ipv6Local); err != nil {
		t.Fatal(err)
	}
	assertDialFails(t, "tcp6", fmt.Sprintf("[::1]:%d", port))
}

func freeDualStackPort(t *testing.T) int {
	t.Helper()
	ipv4Listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ipv4Listener.Addr().(*net.TCPAddr).Port
	ipv6Listener, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		_ = ipv4Listener.Close()
		t.Fatal(err)
	}
	if err := ipv6Listener.Close(); err != nil {
		_ = ipv4Listener.Close()
		t.Fatal(err)
	}
	if err := ipv4Listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func assertDialSucceeds(t *testing.T, network, address string) {
	t.Helper()
	connection, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, address, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertDialFails(t *testing.T, network, address string) {
	t.Helper()
	connection, err := net.DialTimeout(network, address, 100*time.Millisecond)
	if err != nil {
		return
	}
	_ = connection.Close()
	t.Fatalf("dial %s %s succeeded after listener closed", network, address)
}
