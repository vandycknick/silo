package control

import (
	"fmt"

	"github.com/google/uuid"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
)

// LiveOperationUnsupported retains the typed precondition detail, without parsing diagnostics.
type LiveOperationUnsupported struct {
	Detail *w.LiveOperationUnsupported
}

func (e *LiveOperationUnsupported) Error() string {
	return fmt.Sprintf("%s unsupported: %s (backend=%s, lane=%s)", e.Detail.GetOperation(), e.Detail.Reason.GetCode(), e.Detail.GetBackend(), e.Detail.GetLane())
}

func validLiveSelection(backend *w.LiveBackend, lane *w.LiveLane) bool {
	if backend == nil || lane == nil || *backend < 1 || *backend > 3 || *lane < 1 || *lane > 4 {
		return false
	}
	return (*backend != w.LiveBackend_LIVE_BACKEND_KRUN || *lane != w.LiveLane_LIVE_LANE_NOT_APPLICABLE) && (*backend != w.LiveBackend_LIVE_BACKEND_VZ || *lane == w.LiveLane_LIVE_LANE_NOT_APPLICABLE)
}

func validLiveReason(v *w.LiveUnsupportedReason, host bool) bool {
	if v == nil || v.Code == nil || *v.Code < 1 || *v.Code > 7 {
		return false
	}
	if *v.Code != w.LiveReasonCode_LIVE_REASON_CODE_DEVICE_PROFILE_REJECTED {
		return v.Subject == nil
	}
	if host || v.Subject == nil {
		return false
	}
	switch subject := v.Subject.Subject.(type) {
	case *w.LiveDeviceSubject_Virtiofs:
		return subject.Virtiofs != nil
	case *w.LiveDeviceSubject_Rosetta:
		return subject.Rosetta != nil
	case *w.LiveDeviceSubject_Tap:
		return subject.Tap != nil
	case *w.LiveDeviceSubject_Gpu:
		return subject.Gpu != nil
	case *w.LiveDeviceSubject_Nested:
		return subject.Nested != nil
	case *w.LiveDeviceSubject_Tee:
		return subject.Tee != nil
	case *w.LiveDeviceSubject_GuestProfile:
		if len(subject.GuestProfile) == 0 || len(subject.GuestProfile) > 128 {
			return false
		}
		for _, c := range []byte(subject.GuestProfile) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validLiveVector(v *w.LiveCapabilityVector, backend w.LiveBackend, host bool) bool {
	if v == nil {
		return false
	}
	for _, c := range []*w.LiveCapability{v.Pause, v.Capture, v.Restore, v.Fork, v.Incremental} {
		if c == nil || c.Native == nil {
			return false
		}
		switch a := c.Availability.(type) {
		case *w.LiveCapability_Supported:
			if a.Supported == nil || !*c.Native || backend == w.LiveBackend_LIVE_BACKEND_VZ {
				return false
			}
		case *w.LiveCapability_Unsupported:
			if !validLiveReason(a.Unsupported, host) {
				return false
			}
			if backend == w.LiveBackend_LIVE_BACKEND_VZ && (*c.Native || a.Unsupported.GetCode() != w.LiveReasonCode_LIVE_REASON_CODE_BACKEND_EXCLUDED) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validLiveUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Stored MachineId display is compact; live reports retain canonical UUID text.
func sameMachineID(left, right string) bool {
	a, err := uuid.Parse(left)
	if err != nil || a == uuid.Nil {
		return false
	}
	b, err := uuid.Parse(right)
	return err == nil && b != uuid.Nil && a == b
}

func validLiveMachine(v *w.LiveMachineReport) bool {
	return v != nil && v.SchemaVersion != nil && *v.SchemaVersion == 1 && v.Scope != nil && *v.Scope == w.LiveScope_LIVE_SCOPE_MACHINE && validLiveSelection(v.Backend, v.Lane) && validLiveUUID(v.GetMachineId()) && validLiveUUID(v.GetRunId()) && validLiveUUID(v.GetMonitorId()) && v.TopologyRevision != nil && *v.TopologyRevision > 0 && validLiveVector(v.Live, *v.Backend, false)
}

func validLiveHost(v *w.LiveHostReport) bool {
	if v == nil || v.SchemaVersion == nil || *v.SchemaVersion != 1 || v.Scope == nil || *v.Scope != w.LiveScope_LIVE_SCOPE_HOST || !validLiveSelection(v.Backend, v.Lane) || !validLiveVector(v.Live, *v.Backend, true) {
		return false
	}
	for _, identity := range []*string{v.BuildIdentity, v.QualificationIdentity} {
		if identity == nil || len(*identity) == 0 || len(*identity) > 256 {
			return false
		}
		for _, c := range []byte(*identity) {
			if c < 33 || c > 126 {
				return false
			}
		}
	}
	if v.ScenarioDigest != nil {
		if *v.Backend != w.LiveBackend_LIVE_BACKEND_MOCK || len(*v.ScenarioDigest) != 64 {
			return false
		}
		for _, c := range []byte(*v.ScenarioDigest) {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

func validLiveRefusal(v *w.LiveOperationUnsupported) bool {
	if v == nil || v.Operation == nil || *v.Operation < 1 || *v.Operation > 5 || !validLiveSelection(v.Backend, v.Lane) || !validLiveReason(v.Reason, false) {
		return false
	}
	return *v.Backend != w.LiveBackend_LIVE_BACKEND_VZ || v.Reason.GetCode() == w.LiveReasonCode_LIVE_REASON_CODE_BACKEND_EXCLUDED
}

func validLiveDaemon(v *w.DaemonStatus) bool {
	if v == nil || v.LiveSchemaVersion == nil || *v.LiveSchemaVersion != 1 {
		return false
	}
	if v.ManagerLive != nil && !validLiveHost(v.ManagerLive) || v.ApplianceLive != nil && !validLiveHost(v.ApplianceLive) {
		return false
	}
	if s := v.System; s != nil {
		if s.LiveSchemaVersion == nil || *s.LiveSchemaVersion != 1 || s.ProspectiveLive != nil && !validLiveHost(s.ProspectiveLive) {
			return false
		}
		if s.Live != nil && (!validLiveMachine(s.Live) || s.MachineId == nil || s.RunId == nil || !sameMachineID(s.Live.GetMachineId(), *s.MachineId) || s.Live.GetRunId() != *s.RunId) {
			return false
		}
	}
	return true
}

func validLiveMonitor(v *w.MonitorStatus) bool {
	return v != nil && validLiveMachine(v.Live) && v.Monitor != nil &&
		v.MachineId == v.Live.GetMachineId() && v.RunId != nil && *v.RunId == v.Live.GetRunId() &&
		v.Monitor.InstanceId == v.Live.GetMonitorId()
}

// convertReadiness validates the separately supplied monitor observation, not
// just the snapshot, and binds every supplied run to the request generation.
func convertReadiness(v *w.MachineReadiness, machine, run string) (ReadinessResult, error) {
	if v == nil || v.Outcome < 1 || v.Outcome > 3 {
		return ReadinessResult{}, invalidResponse()
	}
	data, err := convertSnapshot(v.Data)
	if err != nil {
		return ReadinessResult{}, err
	}
	if !sameMachineID(data.ID, machine) || data.RunID != nil && *data.RunID != run {
		return ReadinessResult{}, invalidResponse()
	}
	if v.Status != nil {
		if !validLiveMonitor(v.Status) || !sameMachineID(v.Status.MachineId, machine) || v.Status.GetRunId() != run ||
			data.RunID == nil || v.Status.GetRunId() != *data.RunID {
			return ReadinessResult{}, invalidResponse()
		}
		if data.Live != nil && (data.Live.GetMonitorId() != v.Status.Live.GetMonitorId() ||
			data.Live.GetTopologyRevision() != v.Status.Live.GetTopologyRevision()) {
			return ReadinessResult{}, invalidResponse()
		}
	}
	if v.Outcome == w.ReadinessOutcome_READINESS_OUTCOME_READY && v.Status == nil {
		return ReadinessResult{}, invalidResponse()
	}
	return ReadinessResult{Outcome: v.Outcome, Data: data, Status: v.Status}, nil
}
