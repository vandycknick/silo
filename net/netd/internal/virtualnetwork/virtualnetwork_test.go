package virtualnetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/vandycknick/silo/net/netd/internal/config"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
	"github.com/vandycknick/silo/net/netd/internal/gateway/packet"
	"github.com/vandycknick/silo/net/netd/internal/gateway/publication"
	"github.com/vandycknick/silo/net/netd/internal/gateway/router"
	"github.com/vandycknick/silo/net/netd/internal/policy"
)

func TestPublicationServiceRegistersAndClosesEveryPublication(t *testing.T) {
	var auditOutput bytes.Buffer
	auditLog := audit.New(&auditOutput, "")
	network, err := New(
		context.Background(),
		testNetworkConfig(),
		nil,
		router.New(policy.Default(), nil),
		packet.NewTCPDispatcher(),
		packet.NewFlowTracker(),
		Metadata{VMID: "vm-test", RunID: "run-test", NetworkID: "network-test"},
		PublicationOptions{
			Enabled: true,
			Bind:    publication.BindAny,
			GuestIP: netip.MustParseAddr("192.168.127.2"),
			Audit:   auditLog,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if network.publications == nil {
		_ = network.Close()
		t.Fatal("publication table was not registered")
	}
	foundService := false
	for _, service := range network.services {
		if service.name == "publication endpoint" {
			foundService = true
		}
	}
	if !foundService {
		_ = network.Close()
		t.Fatalf("publication service missing from %#v", network.services)
	}

	request := types.ExposeRequest{
		Local:    freeHostAddress(t),
		Remote:   "192.168.127.2:80",
		Protocol: types.TCP,
	}
	if _, created, err := network.publications.Expose(request, publication.AttachmentScope); err != nil || !created {
		_ = network.Close()
		t.Fatalf("expose publication: created %t, error %v", created, err)
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	if len(network.publications.All()) != 0 {
		t.Fatalf("network close retained publications: %#v", network.publications.All())
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	var event audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(auditOutput.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Family != "publication" || event.Phase != "released" || event.Publication.Local != request.Local {
		t.Fatalf("unexpected attachment release audit event: %#v", event)
	}
}

func testNetworkConfig() *config.NetworkConfig {
	return &config.NetworkConfig{
		MTU:               1500,
		Subnet:            "192.168.127.0/24",
		GatewayIP:         "192.168.127.1",
		DeviceIP:          "192.168.127.2",
		HostIP:            "192.168.127.254",
		GatewayMACAddress: "5a:94:ef:e4:0c:dd",
		Forwards:          map[string]string{},
		NAT:               map[string]string{"192.168.127.254": "127.0.0.1"},
		GatewayVirtualIPs: []string{"192.168.127.254"},
		DHCPStaticLeases:  map[string]string{"192.168.127.2": "02:00:00:00:00:02"},
	}
}

func freeHostAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
