package control

import (
	"math"
	"testing"
	"time"

	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validSnapshot() *w.MachineSnapshot {
	return &w.MachineSnapshot{Id: "12345678-1234-1234-1234-123456789abc", Name: "dev", Spec: &w.VmSpec{}, Process: &w.ProcessConfig{}, Retention: w.Retention_RETENTION_PERSISTENT, Observation: w.Observation_OBSERVATION_OBSERVED, Network: &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_None{None: &emptypb.Empty{}}}, Status: &w.MachineStatus{Status: &w.MachineStatus_Stopped{Stopped: &emptypb.Empty{}}}}
}
func TestSnapshotPresenceAndPurePolicy(t *testing.T) {
	v := validSnapshot()
	d, e := convertSnapshot(v)
	if e != nil {
		t.Fatal(e)
	}
	if d.CPUs != nil || d.Memory != nil || d.Process.Entrypoint != nil || d.Process.Command != nil || d.Status.Ready != nil || d.StartedAt != nil || d.RootDiskSize != nil {
		t.Fatal("absence lost")
	}
	v.Process.Entrypoint = &w.StringList{Values: []string{}}
	v.Process.Command = &w.StringList{Values: []string{"", "arg with spaces"}}
	zero := uint64(0)
	v.RootDiskSize = &zero
	cpus := uint32(255)
	v.Spec.Hardware = &w.Hardware{Cpus: &cpus, MemoryBytes: &zero}
	v.Status = &w.MachineStatus{Status: &w.MachineStatus_Running{Running: &w.RunningStatus{}}}
	raw := `{"plugin":{"unknown":true}}`
	v.Network = &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_Private{Private: &w.PrivateNetwork{PolicyJson: &raw}}}
	v.CreatedAt = timestamppb.New(time.Unix(123, 456))
	v.StartedAt = timestamppb.New(time.Unix(456, 789))
	d, e = convertSnapshot(v)
	if e != nil {
		t.Fatal(e)
	}
	if d.Network.Policy != nil || d.PolicyJSON != raw {
		t.Fatal("policy parsed or lost")
	}
	if d.Process.Entrypoint == nil || len(*d.Process.Entrypoint) != 0 || d.Process.Command == nil || (*d.Process.Command)[1] != "arg with spaces" {
		t.Fatal("argv presence lost")
	}
	if d.CPUs == nil || *d.CPUs != 255 || d.Memory == nil || d.Memory.Bytes() != 0 || d.RootDiskSize == nil || d.Status.Ready == nil || *d.Status.Ready || d.CreatedAt.UnixNano() != 123000000456 || d.StartedAt.UnixNano() != 456000000789 {
		t.Fatal("presence or timestamp lost")
	}
}
func TestInvalidSnapshotBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*w.MachineSnapshot)
	}{
		{"missing spec", func(v *w.MachineSnapshot) { v.Spec = nil }}, {"missing process", func(v *w.MachineSnapshot) { v.Process = nil }}, {"missing status", func(v *w.MachineSnapshot) { v.Status = nil }}, {"empty status", func(v *w.MachineSnapshot) { v.Status = &w.MachineStatus{} }}, {"empty network", func(v *w.MachineSnapshot) { v.Network = &w.ResolvedNetwork{} }}, {"unknown retention", func(v *w.MachineSnapshot) { v.Retention = 99 }}, {"absent retention", func(v *w.MachineSnapshot) { v.Retention = 0 }}, {"unknown observation", func(v *w.MachineSnapshot) { v.Observation = 99 }}, {"cpu overflow", func(v *w.MachineSnapshot) { n := uint32(256); v.Spec.Hardware = &w.Hardware{Cpus: &n} }}, {"bad timestamp", func(v *w.MachineSnapshot) { v.CreatedAt = &timestamppb.Timestamp{Nanos: 1000000000} }}, {"bad UUID", func(v *w.MachineSnapshot) { v.Id = "not-id" }}, {"unknown root source", func(v *w.MachineSnapshot) { v.Rootfs = &w.Rootfs{SourceKind: 99} }}, {"unknown issue", func(v *w.MachineSnapshot) { v.Issues = []*w.MachineIssue{{Component: 99}} }}, {"unknown agent", func(v *w.MachineSnapshot) { v.AgentMode = &w.Agent{} }}, {"unknown boot", func(v *w.MachineSnapshot) { v.BootReport = &w.BootReport{Mode: 99} }}, {"unknown provision", func(v *w.MachineSnapshot) { v.ProvisionReport = &w.ProvisionReport{Status: 99} }}, {"duration overflow", func(v *w.MachineSnapshot) {
			v.ProvisionReport = &w.ProvisionReport{Duration: &durationpb.Duration{Seconds: math.MaxInt64 / int64(time.Second), Nanos: 999999999}}
		}}, {"unknown live", func(v *w.MachineSnapshot) {
			v.NetworkObservation = &w.NetworkObservation{Live: &w.NodeStatus{State: 99}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := validSnapshot()
			c.change(v)
			if _, e := convertSnapshot(v); e == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	if _, e := convertSnapshot(nil); e == nil {
		t.Fatal("nil accepted")
	}
}
func TestSecretAlternativesAndEnums(t *testing.T) {
	m, e := convertSecrets([]*w.SecretSlot{{Name: "app", Required: true, Kind: w.SecretKind_SECRET_KIND_OAUTH, Key: "client", Field: w.SecretField_SECRET_FIELD_OAUTH_ACCESS_TOKEN}}, []*w.SecretRequirement{{Owner: "tunnel", Alternatives: []*w.SecretAlternative{{Slots: []string{"app"}}, {Slots: []string{"a", "b"}}}}})
	if e != nil {
		t.Fatal(e)
	}
	if m.Slots[0].Kind != "oauth" || m.Slots[0].Source.Field != "oauth_access_token" || len(m.Requirements[0].Alternatives) != 2 || len(m.Requirements[0].Alternatives[1]) != 2 {
		t.Fatal("alternatives or source flattened")
	}
	for _, s := range []*w.SecretSlot{nil, {Kind: 0, Field: 1}, {Kind: 99, Field: 1}, {Kind: 1, Field: 99}} {
		if _, e := convertSecrets([]*w.SecretSlot{s}, nil); e == nil {
			t.Fatal("invalid secret accepted")
		}
	}
}
func TestForwardProjection(t *testing.T) {
	v := validSnapshot()
	mode := uint32(0600)
	v.Spec.Forwards = []*w.Forward{{Listen: &w.Endpoint{Endpoint: &w.Endpoint_Host{Host: &w.Address{Address: &w.Address_Unix{Unix: []byte{'/', 'x', 0xff}}}}}, Connect: &w.Endpoint{Endpoint: &w.Endpoint_Vsock{Vsock: 1234}}, UnixMode: &mode}}
	d, e := convertSnapshot(v)
	if e != nil {
		t.Fatal(e)
	}
	if d.Forwards[0].Listen != silo.ForwardEndpoint("host:unix:/x\xff") || d.Forwards[0].Connect != "vsock:1234" || d.Forwards[0].Mode != "0600" {
		t.Fatal("forward grammar or path bytes lost")
	}
}
