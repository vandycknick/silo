package control

import (
	"context"
	"errors"
	"testing"

	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func liveHostFixture() *w.LiveHostReport {
	capability := func() *w.LiveCapability {
		return &w.LiveCapability{Native: new(false), Availability: &w.LiveCapability_Unsupported{Unsupported: &w.LiveUnsupportedReason{Code: new(w.LiveReasonCode_LIVE_REASON_CODE_NOT_DELIVERED)}}}
	}
	return &w.LiveHostReport{SchemaVersion: new(uint32(1)), Scope: new(w.LiveScope_LIVE_SCOPE_HOST), Backend: new(w.LiveBackend_LIVE_BACKEND_KRUN), Lane: new(w.LiveLane_LIVE_LANE_KVM_X86_64), BuildIdentity: new("revision"), QualificationIdentity: new("empty"), Live: &w.LiveCapabilityVector{Pause: capability(), Capture: capability(), Restore: capability(), Fork: capability(), Incremental: capability()}}
}

func TestLiveCapabilitiesStrictPresenceAndScope(t *testing.T) {
	v := liveHostFixture()
	if !validLiveHost(v) {
		t.Fatal("complete host rejected")
	}
	v.Live.Incremental = nil
	if validLiveHost(v) {
		t.Fatal("missing operation accepted")
	}
	v = liveHostFixture()
	v.Live.Pause.Native = nil
	if validLiveHost(v) {
		t.Fatal("missing native accepted")
	}
	v = liveHostFixture()
	v.Live.Pause.Availability = &w.LiveCapability_Unsupported{Unsupported: &w.LiveUnsupportedReason{Code: new(w.LiveReasonCode_LIVE_REASON_CODE_DEVICE_PROFILE_REJECTED), Subject: &w.LiveDeviceSubject{Subject: &w.LiveDeviceSubject_Tap{Tap: &emptypb.Empty{}}}}}
	if validLiveHost(v) {
		t.Fatal("machine-only reason accepted on host")
	}
	v = liveHostFixture()
	v.Backend = new(w.LiveBackend(999))
	if validLiveHost(v) {
		t.Fatal("unknown backend accepted")
	}
}

func TestLiveCapabilitiesTypedErrorRoundtrip(t *testing.T) {
	for operation := w.LiveOperation(1); operation <= 5; operation++ {
		detail := &w.LiveOperationUnsupported{Operation: new(operation), Backend: new(w.LiveBackend_LIVE_BACKEND_MOCK), Lane: new(w.LiveLane_LIVE_LANE_NOT_APPLICABLE), Reason: &w.LiveUnsupportedReason{Code: new(w.LiveReasonCode_LIVE_REASON_CODE_DEVICE_PROFILE_REJECTED), Subject: &w.LiveDeviceSubject{Subject: &w.LiveDeviceSubject_GuestProfile{GuestProfile: "linux-test"}}}}
		s, err := status.New(codes.FailedPrecondition, "not parsed").WithDetails(&w.ErrorDetail{Kind: w.ErrorKind_ERROR_KIND_CONFLICT, Code: w.ErrorCode_ERROR_CODE_LIVE_OPERATION_UNSUPPORTED, LiveUnsupported: detail})
		if err != nil {
			t.Fatal(err)
		}
		var refusal *LiveOperationUnsupported
		if !errors.As(rpcError(context.Background(), s.Err()), &refusal) || refusal.Detail.GetOperation() != operation || refusal.Detail.Reason.Subject.GetGuestProfile() != "linux-test" {
			t.Fatal("typed refusal lost")
		}
	}
	s, err := status.New(codes.FailedPrecondition, "not parsed").WithDetails(&w.ErrorDetail{Kind: w.ErrorKind_ERROR_KIND_CONFLICT, Code: w.ErrorCode_ERROR_CODE_LIVE_OPERATION_UNSUPPORTED})
	if err != nil {
		t.Fatal(err)
	}
	var refusal *LiveOperationUnsupported
	if errors.As(rpcError(context.Background(), s.Err()), &refusal) {
		t.Fatal("missing detail accepted")
	}
}

func TestLiveCapabilitiesDaemonRequiresNewSchema(t *testing.T) {
	v := &w.DaemonStatus{}
	if validLiveDaemon(v) {
		t.Fatal("obsolete daemon status accepted")
	}
	v.LiveSchemaVersion = new(uint32(1))
	if !validLiveDaemon(v) {
		t.Fatal("explicit unavailable reports rejected")
	}
	v.System = &w.SystemStatus{}
	if validLiveDaemon(v) {
		t.Fatal("obsolete system status accepted")
	}
	v.System.LiveSchemaVersion = new(uint32(1))
	if !validLiveDaemon(v) {
		t.Fatal("explicit unavailable appliance rejected")
	}
	v.ManagerLive = liveHostFixture()
	if !validLiveDaemon(v) {
		t.Fatal("complete manager report rejected")
	}
	v.ManagerLive.Live.Restore = nil
	if validLiveDaemon(v) {
		t.Fatal("malformed manager report accepted")
	}
}

func readinessFixture() *w.MachineReadiness {
	live := &w.LiveMachineReport{
		SchemaVersion: new(uint32(1)), Scope: new(w.LiveScope_LIVE_SCOPE_MACHINE),
		MachineId: new("00000000-0000-4000-8000-000000000001"),
		RunId:     new("00000000-0000-4000-8000-000000000002"),
		MonitorId: new("00000000-0000-4000-8000-000000000003"),
		Backend:   new(w.LiveBackend_LIVE_BACKEND_MOCK), Lane: new(w.LiveLane_LIVE_LANE_NOT_APPLICABLE),
		TopologyRevision: new(uint64(1)), Live: liveHostFixture().Live,
	}
	data := validSnapshot()
	data.Id = live.GetMachineId()
	data.RunId = new(live.GetRunId())
	data.LiveEvidence = new(w.LiveEvidenceState_LIVE_EVIDENCE_STATE_RUN)
	data.Live = proto.Clone(live).(*w.LiveMachineReport)
	return &w.MachineReadiness{
		Outcome: w.ReadinessOutcome_READINESS_OUTCOME_READY, Data: data,
		Status: &w.MonitorStatus{
			MachineId: live.GetMachineId(), RunId: new(live.GetRunId()),
			Monitor: &w.MonitorSnapshot{InstanceId: live.GetMonitorId()}, Live: live,
		},
	}
}

func TestLiveCapabilitiesReadinessValidatesSeparateStatus(t *testing.T) {
	valid := readinessFixture()
	machine, run := valid.Status.MachineId, valid.Status.GetRunId()
	got, err := convertReadiness(valid, machine, run)
	if err != nil || got.Status != valid.Status || got.Data.Live == nil {
		t.Fatalf("matching readiness evidence lost: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*w.MachineReadiness)
	}{
		{"missing status", func(v *w.MachineReadiness) { v.Status = nil }},
		{"missing live", func(v *w.MachineReadiness) { v.Status.Live = nil }},
		{"missing native", func(v *w.MachineReadiness) { v.Status.Live.Live.Pause.Native = nil }},
		{"missing operation", func(v *w.MachineReadiness) { v.Status.Live.Live.Incremental = nil }},
		{"wrong schema", func(v *w.MachineReadiness) { v.Status.Live.SchemaVersion = new(uint32(99)) }},
		{"wrong scope", func(v *w.MachineReadiness) { v.Status.Live.Scope = new(w.LiveScope_LIVE_SCOPE_HOST) }},
		{"zero topology", func(v *w.MachineReadiness) { v.Status.Live.TopologyRevision = new(uint64(0)) }},
		{"missing outer run", func(v *w.MachineReadiness) { v.Status.RunId = nil }},
		{"missing outer monitor", func(v *w.MachineReadiness) { v.Status.Monitor = nil }},
		{"outer machine", func(v *w.MachineReadiness) { v.Status.MachineId = "00000000-0000-4000-8000-000000000099" }},
		{"outer run", func(v *w.MachineReadiness) { v.Status.RunId = new("00000000-0000-4000-8000-000000000099") }},
		{"outer monitor", func(v *w.MachineReadiness) { v.Status.Monitor.InstanceId = "00000000-0000-4000-8000-000000000099" }},
		{"inner machine", func(v *w.MachineReadiness) { v.Status.Live.MachineId = new("00000000-0000-4000-8000-000000000099") }},
		{"inner run", func(v *w.MachineReadiness) { v.Status.Live.RunId = new("00000000-0000-4000-8000-000000000099") }},
		{"inner monitor", func(v *w.MachineReadiness) { v.Status.Live.MonitorId = new("00000000-0000-4000-8000-000000000099") }},
		{"snapshot monitor", func(v *w.MachineReadiness) { v.Data.Live.MonitorId = new("00000000-0000-4000-8000-000000000099") }},
		{"snapshot topology", func(v *w.MachineReadiness) { v.Data.Live.TopologyRevision = new(uint64(2)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := readinessFixture()
			test.mutate(v)
			if _, err := convertReadiness(v, machine, run); err == nil {
				t.Fatal("invalid separate monitor evidence accepted")
			}
		})
	}
	for _, request := range []struct{ machine, run string }{
		{"00000000-0000-4000-8000-000000000099", run},
		{machine, "00000000-0000-4000-8000-000000000099"},
	} {
		if _, err := convertReadiness(readinessFixture(), request.machine, request.run); err == nil {
			t.Fatal("readiness was not bound to the requested generation")
		}
	}
}

func TestLiveCapabilitiesReadinessAllowsUnobservedTerminalAndTimeout(t *testing.T) {
	for _, outcome := range []w.ReadinessOutcome{w.ReadinessOutcome_READINESS_OUTCOME_TERMINAL, w.ReadinessOutcome_READINESS_OUTCOME_TIMED_OUT} {
		data := validSnapshot()
		v := &w.MachineReadiness{Outcome: outcome, Data: data}
		if _, err := convertReadiness(v, data.Id, "00000000-0000-4000-8000-000000000002"); err != nil {
			t.Fatalf("legitimate absent monitor observation rejected: %v", err)
		}
		v.Status = &w.MonitorStatus{}
		if _, err := convertReadiness(v, data.Id, "00000000-0000-4000-8000-000000000002"); err == nil {
			t.Fatal("present malformed terminal/timeout observation accepted")
		}
	}
}

func TestLiveCapabilitiesDurableMachineIDsCompareByUUID(t *testing.T) {
	const compact = "00000000000040008000000000000001"
	v := readinessFixture()
	canonical, run := v.Status.MachineId, v.Status.GetRunId()
	v.Data.Id = compact
	snapshot, err := convertSnapshot(v.Data)
	if err != nil || snapshot.ID != compact {
		t.Fatalf("compact durable identity was not preserved: %v", err)
	}
	for _, requested := range []string{compact, canonical} {
		if _, err := convertReadiness(v, requested, run); err != nil {
			t.Fatalf("same machine UUID was rejected: %v", err)
		}
	}
	v.Status.MachineId = compact
	if _, err := convertReadiness(v, compact, run); err == nil {
		t.Fatal("monitor outer machine ID lost canonical validation")
	}
	v.Status.MachineId = canonical
	v.Status.Live.MachineId = new(compact)
	if _, err := convertReadiness(v, compact, run); err == nil {
		t.Fatal("live machine ID lost canonical validation")
	}

	matching := readinessFixture()
	daemon := &w.DaemonStatus{
		LiveSchemaVersion: new(uint32(1)),
		System: &w.SystemStatus{
			LiveSchemaVersion: new(uint32(1)),
			MachineId:         new(compact), RunId: new(run), Live: matching.Status.Live,
		},
	}
	if !validLiveDaemon(daemon) {
		t.Fatal("compact system identity did not match canonical report")
	}
	daemon.System.MachineId = new("00000000000040008000000000000099")
	if validLiveDaemon(daemon) {
		t.Fatal("different compact machine UUID was accepted")
	}
	daemon.System.MachineId = new(compact)
	daemon.System.Live.MachineId = new(compact)
	if validLiveDaemon(daemon) {
		t.Fatal("system report machine ID lost canonical validation")
	}
}
