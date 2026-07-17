package packet

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

type recordingTCPHandler struct {
	payload []byte
}

func (*recordingTCPHandler) ShouldHandle(hooks.Flow, hooks.RouteDecision) bool {
	return true
}

func (h *recordingTCPHandler) HandleTCP(_ context.Context, inbound net.Conn, _ hooks.Flow, _ string, _ hooks.RouteDecision) error {
	defer inbound.Close()
	payload, err := io.ReadAll(inbound)
	h.payload = payload
	return err
}

func TestTCPDispatcherSelectsProtocolOnSharedPort(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected EndpointType
	}{
		{name: "plaintext HTTP", payload: []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), expected: EndpointHTTP},
		{name: "registry TLS", payload: []byte{0x16, 0x03, 0x03, 0x00, 0x00}, expected: EndpointRegistries},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpHandler := &recordingTCPHandler{}
			registryHandler := &recordingTCPHandler{}
			dispatcher := &TCPDispatcher{}
			if err := dispatcher.Register(EndpointHTTP, httpHandler); err != nil {
				t.Fatal(err)
			}
			if err := dispatcher.Register(EndpointRegistries, registryHandler); err != nil {
				t.Fatal(err)
			}

			inbound, client := net.Pipe()
			writeDone := make(chan error, 1)
			go func() {
				_, err := client.Write(test.payload)
				_ = client.Close()
				writeDone <- err
			}()

			endpointType, handled, err := dispatcher.Handle(
				context.Background(),
				inbound,
				hooks.Flow{Protocol: "tcp", DestPort: 443},
				"unused",
				hooks.RouteDecision{Action: hooks.RouteClassify},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-writeDone; err != nil {
				t.Fatal(err)
			}
			if !handled || endpointType != test.expected {
				t.Fatalf("dispatch = %q, %v", endpointType, handled)
			}
			selected := httpHandler
			if test.expected == EndpointRegistries {
				selected = registryHandler
			}
			if !bytes.Equal(selected.payload, test.payload) {
				t.Fatalf("replayed payload = %x, want %x", selected.payload, test.payload)
			}
		})
	}
}
