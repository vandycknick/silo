package control

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func invalidResponse() error {
	return &silo.Error{Kind: silo.ErrorUnknown, Message: "invalid or incomplete daemon response"}
}
func enum(value int32, names ...string) (string, error) {
	if value < 0 || int(value) >= len(names) || names[value] == "" {
		return "", invalidResponse()
	}
	return names[value], nil
}
func timestamp(v *timestamppb.Timestamp) (time.Time, error) {
	if v == nil {
		return time.Time{}, nil
	}
	if v.CheckValid() != nil {
		return time.Time{}, invalidResponse()
	}
	return v.AsTime(), nil
}
func duration(v *durationpb.Duration) (time.Duration, error) {
	if v == nil {
		return 0, nil
	}
	if v.CheckValid() != nil || v.Seconds > math.MaxInt64/int64(time.Second) || v.Seconds < math.MinInt64/int64(time.Second) {
		return 0, invalidResponse()
	}
	s := v.Seconds * int64(time.Second)
	n := int64(v.Nanos)
	if n > 0 && s > math.MaxInt64-n || n < 0 && s < math.MinInt64-n {
		return 0, invalidResponse()
	}
	return time.Duration(s + n), nil
}
func convertIssues(values []*w.MachineIssue) ([]silo.MachineIssue, error) {
	out := make([]silo.MachineIssue, 0, len(values))
	for _, v := range values {
		if v == nil {
			return nil, invalidResponse()
		}
		component, e := enum(int32(v.Component), "", "lifecycle", "telemetry", "network", "rootfs", "configuration")
		if e != nil {
			return nil, e
		}
		out = append(out, silo.MachineIssue{Component: component, Message: v.Message})
	}
	return out, nil
}
func convertAgent(v *w.Agent) (*silo.MachineAgent, error) {
	if v == nil {
		return nil, nil
	}
	a := &silo.MachineAgent{}
	switch m := v.Mode.(type) {
	case *w.Agent_DefaultAgent:
		if m.DefaultAgent == nil {
			return nil, invalidResponse()
		}
		a.Mode = silo.MachineAgentDefault
	case *w.Agent_None:
		if m.None == nil {
			return nil, invalidResponse()
		}
		a.Mode = silo.MachineAgentDisabled
	case *w.Agent_CustomPath:
		a.Mode = silo.MachineAgentCustom
		a.Path = string(m.CustomPath)
	default:
		return nil, invalidResponse()
	}
	return a, nil
}
func convertEndpoint(v *w.Endpoint) (silo.ForwardEndpoint, error) {
	if v == nil {
		return "", invalidResponse()
	}
	var prefix string
	var a *w.Address
	switch e := v.Endpoint.(type) {
	case *w.Endpoint_Host:
		prefix = "host:"
		a = e.Host
	case *w.Endpoint_Guest:
		prefix = "guest:"
		a = e.Guest
	case *w.Endpoint_Vsock:
		return silo.ForwardEndpoint(fmt.Sprintf("vsock:%d", e.Vsock)), nil
	default:
		return "", invalidResponse()
	}
	if a == nil {
		return "", invalidResponse()
	}
	switch address := a.Address.(type) {
	case *w.Address_Tcp:
		return silo.ForwardEndpoint(prefix + "tcp:" + address.Tcp), nil
	case *w.Address_Unix:
		return silo.ForwardEndpoint(prefix + "unix:" + string(address.Unix)), nil
	default:
		return "", invalidResponse()
	}
}
func convertSnapshot(v *w.MachineSnapshot) (*Snapshot, error) {
	if v == nil || v.Spec == nil || v.Status == nil || v.Network == nil || v.Process == nil {
		return nil, invalidResponse()
	}
	if _, e := uuid.Parse(v.Id); e != nil {
		return nil, invalidResponse()
	}
	if v.RunId != nil {
		if _, e := uuid.Parse(*v.RunId); e != nil {
			return nil, invalidResponse()
		}
	}
	d := &silo.MachineData{ID: v.Id, Name: v.Name, RunID: v.RunId, MachineDir: string(v.MachineDir), ImageRef: v.ImageRef, TemplateName: v.TemplateName, Labels: v.Labels, Metadata: v.Metadata, LastError: v.LastError}
	out := &Snapshot{MachineData: d, NetworkObservation: v.NetworkObservation}
	var e error
	retention, e := enum(int32(v.Retention), "", "persistent", "ephemeral")
	if e != nil {
		return nil, e
	}
	d.Retention = silo.MachineRetention(retention)
	d.Observation, e = enum(int32(v.Observation), "", "observed", "last_known", "unavailable")
	if e != nil {
		return nil, e
	}
	d.Issues, e = convertIssues(v.Issues)
	if e != nil {
		return nil, e
	}
	d.CreatedAt, e = timestamp(v.CreatedAt)
	if e != nil {
		return nil, e
	}
	d.ModifiedAt, e = timestamp(v.ModifiedAt)
	if e != nil {
		return nil, e
	}
	d.UpdatedAt, e = timestamp(v.UpdatedAt)
	if e != nil {
		return nil, e
	}
	if v.StartedAt != nil {
		t, e := timestamp(v.StartedAt)
		if e != nil {
			return nil, e
		}
		d.StartedAt = &t
	}
	if h := v.Spec.Hardware; h != nil {
		if h.Cpus != nil {
			if *h.Cpus > math.MaxUint8 {
				return nil, invalidResponse()
			}
			n := uint8(*h.Cpus)
			d.CPUs = &n
		}
		if h.MemoryBytes != nil {
			n := silo.Bytes(*h.MemoryBytes)
			d.Memory = &n
		}
	}
	if v.RootDiskSize != nil {
		n := silo.Bytes(*v.RootDiskSize)
		d.RootDiskSize = &n
	}
	p := v.Process
	d.Process = silo.ProcessConfig{Environment: p.Environment, WorkingDirectory: p.WorkingDirectory, User: p.User}
	if p.Entrypoint != nil {
		d.Process.Entrypoint = &p.Entrypoint.Values
	}
	if p.Command != nil {
		d.Process.Command = &p.Command.Values
	}
	d.AgentMode, e = convertAgent(v.AgentMode)
	if e != nil {
		return nil, e
	}
	if v.Guest != nil {
		a, e := convertAgent(v.Guest.Agent)
		if e != nil {
			return nil, e
		}
		if a != nil {
			d.Agent = *a
		}
		if u := v.Guest.User; u != nil {
			d.GuestUser = &silo.GuestUser{Name: u.Name, UID: u.Uid, GID: u.Gid, Home: u.Home}
		}
	}
	if r := v.Rootfs; r != nil {
		kind, e := enum(int32(r.SourceKind), "", "oci", "disk")
		if e != nil {
			return nil, e
		}
		t, e := timestamp(r.CreatedAt)
		if e != nil {
			return nil, e
		}
		d.RootFS = &silo.MachineRootFS{SourceKind: kind, RequestedReference: r.RequestedReference, SelectedReference: r.SelectedReference, SelectedManifestDigest: r.ManifestDigest, ConfigDigest: r.ConfigDigest, ImageID: r.ImageId, RootDiskPath: string(r.RootDiskPath), RootDiskSize: silo.Bytes(r.RootDiskSizeBytes), CreatedAt: t}
	}
	for _, f := range v.Spec.Forwards {
		if f == nil {
			return nil, invalidResponse()
		}
		listen, e := convertEndpoint(f.Listen)
		if e != nil {
			return nil, e
		}
		connect, e := convertEndpoint(f.Connect)
		if e != nil {
			return nil, e
		}
		forward := silo.Forward{Listen: listen, Connect: connect, Name: f.GetName()}
		if f.UnixMode != nil {
			if *f.UnixMode > 07777 {
				return nil, invalidResponse()
			}
			forward.Mode = fmt.Sprintf("%04o", *f.UnixMode)
		}
		d.Forwards = append(d.Forwards, forward)
	}
	if s := v.Spec.Vsock; s != nil {
		d.Vsock = &silo.VsockConfig{Enabled: s.Enabled, UDS: string(s.Uds)}
	}
	switch n := v.Network.Attachment.(type) {
	case *w.ResolvedNetwork_Private:
		if n.Private == nil {
			return nil, invalidResponse()
		}
		d.Network = silo.PrivateNetwork(nil)
		out.PolicyJSON = n.Private.GetPolicyJson()
		if n.Private.Publish != nil {
			bind, e := enum(int32(*n.Private.Publish), "", "loopback", "any")
			if e != nil {
				return nil, e
			}
			d.Network.Publish = &silo.GuestPublish{Bind: silo.PublishBind(bind)}
		}
	case *w.ResolvedNetwork_None:
		if n.None == nil {
			return nil, invalidResponse()
		}
		d.Network = silo.NoNetwork()
	case *w.ResolvedNetwork_Named:
		if n.Named == nil {
			return nil, invalidResponse()
		}
		d.Network = silo.NamedNetwork(n.Named.Name)
	default:
		return nil, invalidResponse()
	}
	if n := v.Tailscale; n != nil {
		d.Network.Tailscale = &silo.MachineTailscale{StateDir: string(n.StateDir), Hostname: n.Hostname, Ephemeral: n.Ephemeral}
	}
	switch s := v.Status.Status.(type) {
	case *w.MachineStatus_Stopped:
		if s.Stopped == nil {
			return nil, invalidResponse()
		}
		d.Status.Kind = silo.MachineStatusStopped
	case *w.MachineStatus_Starting:
		if s.Starting == nil {
			return nil, invalidResponse()
		}
		d.Status.Kind = silo.MachineStatusStarting
		d.Status.Message = s.Starting.Message
	case *w.MachineStatus_Running:
		if s.Running == nil {
			return nil, invalidResponse()
		}
		d.Status.Kind = silo.MachineStatusRunning
		d.Status.Ready = &s.Running.Ready
		d.Status.GuestReady = &s.Running.GuestReady
		d.Status.Message = s.Running.Message
	case *w.MachineStatus_Stopping:
		if s.Stopping == nil {
			return nil, invalidResponse()
		}
		d.Status.Kind = silo.MachineStatusStopping
		d.Status.Message = s.Stopping.Message
	case *w.MachineStatus_Error:
		if s.Error == nil {
			return nil, invalidResponse()
		}
		d.Status.Kind = silo.MachineStatusError
		d.Status.Message = s.Error.Message
	default:
		return nil, invalidResponse()
	}
	if b := v.BootReport; b != nil {
		mode, e := enum(int32(b.Mode), "unspecified", "standard", "agent-pid1", "init-child")
		if e != nil {
			return nil, e
		}
		d.BootReport = &silo.MachineBootReport{Mode: silo.MachineBootMode(mode), RequestedInit: b.RequestedInit, HandoffInitPath: b.HandoffInitPath, ProbedInitPaths: b.ProbedInitPaths, AgentPath: b.AgentPath, AgentPID: b.AgentPid, AgentIsPID1: b.AgentIsPid1, Message: b.Message}
	}
	if p := v.ProvisionReport; p != nil {
		status, e := enum(int32(p.Status), "unspecified", "succeeded", "degraded", "skipped", "failed-boot")
		if e != nil {
			return nil, e
		}
		r := &silo.MachineProvisionReport{Status: silo.MachineProvisionStatus(status), Message: p.Message}
		r.StartedAt, e = timestamp(p.StartedAt)
		if e != nil {
			return nil, e
		}
		r.FinishedAt, e = timestamp(p.FinishedAt)
		if e != nil {
			return nil, e
		}
		r.Duration, e = duration(p.Duration)
		if e != nil {
			return nil, e
		}
		for _, s := range p.Steps {
			if s == nil {
				return nil, invalidResponse()
			}
			status, e := enum(int32(s.Status), "unspecified", "succeeded", "failed", "skipped", "unsupported")
			if e != nil {
				return nil, e
			}
			failure, e := enum(int32(s.FailurePolicy), "unspecified", "best-effort", "fail-boot")
			if e != nil {
				return nil, e
			}
			elapsed, e := duration(s.Duration)
			if e != nil {
				return nil, e
			}
			r.Steps = append(r.Steps, silo.MachineProvisionStepReport{ID: s.Id, Status: silo.MachineProvisionStepStatus(status), FailurePolicy: silo.MachineProvisionFailurePolicy(failure), Changed: s.Changed, Backend: s.Backend, Duration: elapsed, Message: s.Message, ErrorChain: s.ErrorChain})
		}
		d.ProvisionReport = r
	}
	if n := v.NetworkObservation; n != nil {
		for _, issue := range n.Issues {
			if issue < 1 || issue > 6 {
				return nil, invalidResponse()
			}
		}
		if s := n.Live; s != nil {
			if s.State < 1 || s.State > 6 {
				return nil, invalidResponse()
			}
			if _, e := timestamp(s.UpdatedAt); e != nil {
				return nil, e
			}
			if _, e := timestamp(s.KeyExpiry); e != nil {
				return nil, e
			}
		}
		if h := n.Historical; h != nil {
			if _, e := timestamp(h.ObservedAt); e != nil {
				return nil, e
			}
			if _, e := timestamp(h.KeyExpiry); e != nil {
				return nil, e
			}
		}
	}
	return out, nil
}
func convertSecrets(slots []*w.SecretSlot, requirements []*w.SecretRequirement) (silo.NetworkSecretMetadata, error) {
	out := silo.NetworkSecretMetadata{}
	for _, s := range slots {
		if s == nil {
			return out, invalidResponse()
		}
		kind, e := enum(int32(s.Kind), "", "plain", "oauth")
		if e != nil {
			return out, e
		}
		field, e := enum(int32(s.Field), "", "value", "oauth_access_token", "oauth_expires_at", "oauth_account_id")
		if e != nil {
			return out, e
		}
		out.Slots = append(out.Slots, silo.NetworkSecretSlot{Name: s.Name, Required: s.Required, Kind: kind, Source: silo.NetworkSecretSource{Key: s.Key, Field: field}})
	}
	for _, r := range requirements {
		if r == nil {
			return out, invalidResponse()
		}
		requirement := silo.NetworkSecretRequirement{Owner: r.Owner}
		for _, a := range r.Alternatives {
			if a == nil {
				return out, invalidResponse()
			}
			requirement.Alternatives = append(requirement.Alternatives, a.Slots)
		}
		out.Requirements = append(out.Requirements, requirement)
	}
	return out, nil
}
