package audit

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/vandycknick/silo/net/netd/internal/netnode"
)

func TestInboundAuditIncludesPeerPortDecisionAndZeroDuration(t *testing.T) {
	var output bytes.Buffer
	log := New(&output, "policy")
	log.RecordInbound("vm", "run", "network", netnode.InboundEvent{Peer: netip.MustParseAddrPort("100.64.0.2:1234"), Port: 22, Decision: "deny", Reason: "ssh_reserved"})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Direction != "inbound" || event.SourceIP != "100.64.0.2" || event.SourcePort != 1234 || event.DestPort != 22 || event.Verdict != "deny" || event.Reason != "ssh_reserved" || event.DurationMS == nil || *event.DurationMS != 0 {
		t.Fatalf("%+v", event)
	}
}
