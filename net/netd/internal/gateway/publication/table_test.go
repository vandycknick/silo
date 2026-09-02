package publication

import (
	"errors"
	"net"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestTableUsesRealListenersAndTracksScope(t *testing.T) {
	networkStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(networkStack.Close)
	table := NewTable(NewTCPForwarder(networkStack))
	t.Cleanup(func() {
		if err := table.Close(); err != nil {
			t.Error(err)
		}
	})

	attachment := request(freeLoopbackAddress(t), "192.168.127.2:80", types.TCP)
	entry, created, err := table.Expose(attachment, AttachmentScope)
	if err != nil {
		t.Fatal(err)
	}
	if !created || entry.Local != attachment.Local {
		t.Fatalf("unexpected first expose result: %#v, created %t", entry, created)
	}
	if _, created, err := table.Expose(attachment, AttachmentScope); err != nil || created {
		t.Fatalf("identical expose must be idempotent: created %t, error %v", created, err)
	}
	conflict := attachment
	conflict.Remote = "192.168.127.2:81"
	if _, _, err := table.Expose(conflict, AttachmentScope); !errors.Is(err, ErrConflict) {
		t.Fatalf("different remote must conflict, got %v", err)
	}
	if _, _, err := table.Expose(attachment, SessionScope("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("different scope must conflict, got %v", err)
	}

	session := request(freeLoopbackAddress(t), "192.168.127.2:82", types.TCP)
	if _, created, err := table.Expose(session, SessionScope("one")); err != nil || !created {
		t.Fatalf("session expose failed: created %t, error %v", created, err)
	}
	all := table.All()
	if len(all) != 2 || all[0].Local > all[1].Local {
		t.Fatalf("publications are not sorted: %#v", all)
	}
	released, err := table.ReleaseScope(SessionScope("one"))
	if err != nil {
		t.Fatal(err)
	}
	if len(released) != 1 || released[0].Local != session.Local {
		t.Fatalf("unexpected released entries: %#v", released)
	}
	if got := table.All(); len(got) != 1 || got[0].Scope != AttachmentScope {
		t.Fatalf("release removed the wrong owner: %#v", got)
	}
	if _, err := table.Unexpose(types.UnexposeRequest{Local: attachment.Local, Protocol: types.TCP}); err != nil {
		t.Fatal(err)
	}
	if len(table.All()) != 0 {
		t.Fatalf("unexpose did not empty table: %#v", table.All())
	}
}

func freeLoopbackAddress(t *testing.T) string {
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
