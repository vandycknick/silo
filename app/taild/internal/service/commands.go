package service

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
	"unicode"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/units"
	silo "github.com/vandycknick/silo/sdk/go"
)

// Caller contains an accepted verified observation and a production WhoIs resolver.
// Resolve must use its argument context, never capture the session's context.
// Native tests inject explicit principal/capability input at this domain boundary.
type Caller struct {
	Peer    identity.Peer
	Resolve func(context.Context) (identity.Peer, error)
}

func (c Caller) Fresh(ctx context.Context) (identity.Peer, error) {
	if c.Resolve == nil {
		return identity.Peer{}, failure("forbidden", "fresh identity resolver required", 4)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, e := c.Resolve(ctx)
	if e != nil || !p.Valid() || p.NodeID != c.Peer.NodeID {
		return identity.Peer{}, failure("forbidden", "identity unavailable or changed", 4)
	}
	return p, nil
}
func failure(code, message string, exit int) *authz.Error {
	return &authz.Error{Code: code, Message: message, Exit: exit}
}

// Categorize never exposes native diagnostics, which may contain paths or credentials.
func Categorize(err error) *authz.Error {
	if err == nil {
		return nil
	}
	var a *authz.Error
	if errors.As(err, &a) {
		return a
	}
	var e *silo.Error
	if errors.As(err, &e) {
		switch e.Kind {
		case silo.ErrorMachineNotFound:
			return failure("not_found", "VM not found", 3)
		case silo.ErrorMachineAlreadyExists:
			return failure("conflict", "name already taken locally or on the tailnet", 5)
		case silo.ErrorMachineAlreadyRunning, silo.ErrorMachineNotRunning, silo.ErrorInvalidMachineUpdate:
			return failure("conflict", "VM state does not permit this operation", 5)
		case silo.ErrorInvalidArgument, silo.ErrorInvalidCreateRequest, silo.ErrorInvalidMachineName:
			return failure("usage", "invalid request", 2)
		case silo.ErrorImage, silo.ErrorImageNotFound:
			return failure("image", "image pull or materialization failed", 7)
		case silo.ErrorMachinePreparationFailed, silo.ErrorMachineStartCleanupFailed, silo.ErrorEntrypointLaunchFailed, silo.ErrorRootDisk, silo.ErrorGuestSession, silo.ErrorNetworkRuntime:
			return failure("operation_failed", "VM operation failed; inspect VM state", 7)
		}
	}
	return failure("unavailable", "runtime operation unavailable; inspect VM state", 9)
}

type VM struct {
	NodeDiagnostics []string               `json:"node_diagnostics,omitempty"`
	NodeState       state.NodeState        `json:"node_state"`
	NodeID          string                 `json:"node_id,omitempty"`
	Addresses       []string               `json:"addresses,omitempty"`
	KeyExpiry       string                 `json:"key_expiry"`
	ApprovalURL     string                 `json:"approval_url,omitempty"`
	ApprovalExpires *time.Time             `json:"approval_expires,omitempty"`
	Template        string                 `json:"template,omitempty"`
	Policy          string                 `json:"policy,omitempty"`
	GuestTCPPorts   []uint16               `json:"guest_tcp_ports,omitempty"`
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Owner           identity.Principal     `json:"owner"`
	State           silo.MachineStatusKind `json:"state"`
	Node            string                 `json:"node"`
	Address         string                 `json:"address"`
	CPUs            uint8                  `json:"cpus"`
	Memory          uint64                 `json:"memory"`
	Disk            uint64                 `json:"disk"`
	Created         time.Time              `json:"created"`
	Image           string                 `json:"image"`
	Labels          map[string]string      `json:"labels"`
	LastOperation   *jobs.Operation        `json:"last_operation,omitempty"`
}

func project(d *silo.MachineData) VM {
	v := VM{ID: d.ID, Name: d.Name, Owner: identity.Principal(d.Labels[runtime.OwnerLabel]), State: d.Status.Kind, Created: d.CreatedAt.UTC()}
	v.Template = d.Labels[TemplateLabel]
	v.Policy = d.Labels[PolicyLabel]
	_ = json.Unmarshal([]byte(d.Labels[GuestPortsLabel]), &v.GuestTCPPorts)
	v.Labels = map[string]string{}
	for k, value := range d.Labels {
		if !strings.HasPrefix(k, "io.silo.") {
			v.Labels[k] = value
		}
	}
	if d.RootFS != nil && d.RootFS.SourceKind == "oci" {
		host, _, _ := strings.Cut(d.ImageRef, "/")
		if imageAllowed(d.ImageRef, []string{host}) {
			v.Image = d.ImageRef
		}
	}
	if d.CPUs != nil {
		v.CPUs = *d.CPUs
	}
	if d.Memory != nil {
		v.Memory = d.Memory.Bytes()
	}
	if d.RootDiskSize != nil {
		v.Disk = d.RootDiskSize.Bytes()
	}
	return v
}
func authority(d *silo.MachineData) *authz.VM {
	return &authz.VM{Owner: identity.Principal(d.Labels[runtime.OwnerLabel]), Instance: d.Labels[runtime.InstanceLabel]}
}
func (s *Service) machine(ctx context.Context, p identity.Peer, ref string, action identity.Action) (*silo.Machine, *silo.MachineData, error) {
	m, e := s.Runtime.Machine(ctx, ref)
	if e != nil {
		return nil, nil, Categorize(e)
	}
	d, e := m.Inspect(ctx)
	if e == nil {
		_, ownerErr := identity.ParsePrincipal(d.Labels[runtime.OwnerLabel])
		if ownerErr != nil || d.Labels[runtime.NameLabel] != d.Name || !config.ValidName(d.Name) {
			e = failure("not_found", "VM not found", 3)
		} else {
			e = s.Authorize(p, action, authority(d))
		}
	}
	if e != nil {
		s.Runtime.CloseMachine(m)
		return nil, nil, Categorize(e)
	}
	return m, d, nil
}
func (s *Service) List(ctx context.Context, p identity.Peer) ([]VM, error) {
	if e := s.Authorize(p, identity.Read, nil); e != nil {
		return nil, e
	}
	entries, e := s.Runtime.SDK.Inventory(ctx)
	if e != nil {
		return nil, Categorize(e)
	}
	out := []VM{}
	for _, entry := range entries {
		d := entry.Data
		if d == nil || d.Labels[runtime.InstanceLabel] != s.Runtime.Instance || !p.Owns(identity.Principal(d.Labels[runtime.OwnerLabel])) || d.Labels[runtime.NameLabel] != d.Name || !config.ValidName(d.Name) {
			continue
		}
		out = append(out, s.nodeView(ctx, d))
	}
	return out, nil
}
func (s *Service) Show(ctx context.Context, p identity.Peer, ref string) (VM, error) {
	m, d, e := s.machine(ctx, p, ref, identity.Read)
	if e != nil {
		return VM{}, e
	}
	defer s.Runtime.CloseMachine(m)
	v := s.nodeView(ctx, d)
	if s.Jobs != nil {
		for _, op := range s.Jobs.List(p) {
			if op.VM == d.ID || op.Kind == "create" && op.VM == d.Name {
				copy := op
				v.LastOperation = &copy
			}
		}
	}
	return v, nil
}
func (s *Service) Ops(p identity.Peer, id string) ([]jobs.Operation, error) {
	if e := s.Authorize(p, identity.Read, nil); e != nil {
		return nil, e
	}
	if id == "" {
		return s.Jobs.List(p), nil
	}
	op, _, e := s.Jobs.Observe(p, id)
	if e != nil {
		return nil, e
	}
	return []jobs.Operation{op}, nil
}

type CreateRequest struct {
	Template    string
	PolicyRef   string
	GuestPorts  []uint16
	UserdataSet bool
	policy      *silo.NetworkPolicy
	Name        string
	Image       string
	CPUs        uint64
	Memory      uint64
	Disk        uint64
	Userdata    string
	Labels      map[string]string
	Owner       identity.Principal
	NoTailnet   bool
	NoStart     bool
}

func text(s string) bool { return !strings.ContainsFunc(s, unicode.IsControl) }
func imageAllowed(ref string, allow []string) bool {
	if len(ref) == 0 || len(ref) > 512 || !text(ref) || strings.ContainsAny(ref, " \\?#") || strings.Contains(ref, "://") || strings.HasPrefix(ref, "/") {
		return false
	}
	parts := strings.Split(ref, "/")
	for _, c := range ref {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._/:@-", c) {
			continue
		}
		return false
	}
	if len(parts) < 2 || !(strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	for _, prefix := range allow {
		prefix = strings.TrimSuffix(prefix, "/")
		if ref != prefix && strings.HasPrefix(ref, prefix+"/") {
			return true
		}
	}
	return false
}
func (s *Service) ValidateCreate(p identity.Peer, q CreateRequest) (CreateRequest, error) {
	if e := s.Authorize(p, identity.Create, nil); e != nil {
		return q, e
	}
	if !config.ValidName(q.Name) {
		return q, failure("usage", "invalid exact name", 2)
	}
	if q.Owner == "" {
		if len(p.Principals) != 1 {
			return q, failure("usage", "multi-tag peers require --owner tag:<name>", 2)
		}
		q.Owner = p.Principals[0]
	} else if !strings.HasPrefix(string(q.Owner), "tag:") || !p.Owns(q.Owner) {
		return q, failure("forbidden", "owner must be a verified peer tag", 4)
	}
	if q.Image == "" {
		q.Image = s.Config.VM.DefaultImage
	}
	if !imageAllowed(q.Image, s.Config.VM.AllowedRegistries) {
		return q, failure("usage", "image must be an allowlisted OCI reference", 2)
	}
	if !validUserdata(q.Userdata) {
		return q, failure("usage", "userdata must be an inline shebang script, at most 16KiB", 2)
	}
	if e := validateLabels(q.Labels); e != nil {
		return q, e
	}
	q.Labels = maps.Clone(q.Labels)
	if q.CPUs == 0 {
		q.CPUs = s.Config.VM.Defaults.CPUs
	}
	if q.Memory == 0 {
		m, e := units.Bytes(s.Config.VM.Defaults.Memory)
		if e != nil {
			return q, Categorize(e)
		}
		q.Memory = uint64(m)
	}
	if q.Disk == 0 {
		d, e := units.Bytes(s.Config.VM.Defaults.Disk)
		if e != nil {
			return q, Categorize(e)
		}
		q.Disk = uint64(d)
	}
	if e := s.resources(p, q.CPUs, q.Memory, q.Disk); e != nil {
		return q, e
	}
	return q, nil
}
func (s *Service) resources(p identity.Peer, cpus, mem, disk uint64) error {
	l, e := s.Config.Limits()
	if e != nil {
		return Categorize(e)
	}
	cap := p.Permissions.Limits
	if cpus == 0 || cpus > 255 || cpus > min(l.CPUs, cap.CPUs) || mem == 0 || mem > min(l.Memory, cap.Memory) || disk == 0 || disk > min(l.Disk, cap.Disk) {
		return failure("limit", "resource ceiling exceeded", 6)
	}
	return nil
}

// ownedCountLocked counts a reservation only until its durable record appears.
// The create mutex covers both admission and the final durable SDK write.
func (s *Service) ownedCountLocked(ctx context.Context, owner identity.Principal) (uint64, error) {
	entries, e := s.Runtime.SDK.Inventory(ctx)
	if e != nil {
		return 0, Categorize(e)
	}
	count := uint64(0)
	durable := make(map[string]bool)
	for _, entry := range entries {
		if entry.Data == nil {
			return 0, failure("unavailable", "VM quota inventory unreadable", 9)
		}
		if entry.Data.Labels[runtime.InstanceLabel] == s.Runtime.Instance && entry.Data.Labels[runtime.OwnerLabel] == string(owner) {
			count++
			durable[entry.Name] = true
		}
	}
	for name, principal := range s.pending {
		if principal == owner && !durable[name] {
			count++
		}
	}
	return count, nil
}
func (s *Service) reserveCreate(ctx context.Context, p identity.Peer, q CreateRequest) (func(), error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if s.ShutdownPending() {
		return nil, failure("unavailable", "host is shutting down", 9)
	}
	if e := s.diskAdmissionLocked(q.Disk); e != nil {
		return nil, e
	}
	l, e := s.Config.Limits()
	if e != nil {
		return nil, Categorize(e)
	}
	count, e := s.ownedCountLocked(ctx, q.Owner)
	if e != nil {
		return nil, e
	}
	if count >= min(l.VMs, p.Permissions.Limits.VMs) {
		return nil, failure("limit", "VM count ceiling exceeded", 6)
	}
	var names []string
	if s.VisibleNames != nil {
		names, e = s.VisibleNames(ctx)
		if e != nil {
			return nil, failure("unavailable", "tailnet name inventory unavailable", 9)
		}
	}
	release, e := s.Runtime.Reserve(ctx, q.Name, names)
	if e != nil {
		return nil, failure("conflict", "name already taken locally or on the tailnet", 5)
	}
	if s.pending == nil {
		s.pending = make(map[string]identity.Principal)
	}
	s.pending[q.Name] = q.Owner
	if s.diskPending == nil {
		s.diskPending = make(map[string]uint64)
	}
	s.diskPending[q.Name] = q.Disk
	return func() {
		s.createMu.Lock()
		defer s.createMu.Unlock()
		release()
		delete(s.pending, q.Name)
		delete(s.diskPending, q.Name)
	}, nil
}
func (s *Service) materialize(ctx context.Context, p identity.Peer, q CreateRequest, opts []silo.MachineOption) (*silo.Machine, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if s.ShutdownPending() {
		return nil, failure("unavailable", "host is shutting down", 9)
	}
	if e := s.diskAdmissionLocked(0); e != nil {
		return nil, e
	}
	l, e := s.Config.Limits()
	if e != nil {
		return nil, Categorize(e)
	}
	count, e := s.ownedCountLocked(ctx, q.Owner)
	if e != nil {
		return nil, e
	}
	if count > min(l.VMs, p.Permissions.Limits.VMs) {
		return nil, failure("limit", "VM count ceiling exceeded", 6)
	}
	m, err := s.Runtime.SDK.CreateMachine(ctx, silo.OCIImage(q.Image), opts...)
	if err == nil {
		s.Runtime.Metrics.Handle("machine", 1)
	}
	return m, err
}
func (s *Service) Create(ctx context.Context, c Caller, q CreateRequest) (jobs.Operation, error) {
	if e := s.Authorize(c.Peer, identity.Create, nil); e != nil {
		return jobs.Operation{}, e
	}
	q, e := s.resolveCreate(ctx, c.Peer, q)
	if e != nil {
		return jobs.Operation{}, e
	}
	q, e = s.ValidateCreate(c.Peer, q)
	if e != nil {
		return jobs.Operation{}, e
	}
	return s.Jobs.Submit("create", q.Name, q.Owner, func(ctx context.Context, progress func(string)) error {
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		validated := q
		// An already selected human owner is not a client-supplied --owner tag.
		if !strings.HasPrefix(string(q.Owner), "tag:") {
			validated.Owner = ""
		}
		validated, e = s.ValidateCreate(p, validated)
		if e != nil {
			return e
		}
		if validated.Owner != q.Owner {
			return failure("forbidden", "owner identity changed", 4)
		}
		release, e := s.reserveCreate(ctx, p, q)
		if e != nil {
			return e
		}
		defer func() {
			if release != nil {
				release()
			}
		}()
		progress("pulling OCI image")
		image, pullError := s.Runtime.SDK.Images().Pull(ctx, q.Image)
		if pullError != nil {
			return Categorize(pullError)
		}
		progress("image pull complete: " + image.SelectedManifestDigest)
		progress("materializing stopped VM")
		p, e = c.Fresh(ctx)
		if e != nil {
			return e
		}
		validated = q
		if !strings.HasPrefix(string(q.Owner), "tag:") {
			validated.Owner = ""
		}
		validated, e = s.ValidateCreate(p, validated)
		if e != nil {
			return e
		}
		if validated.Owner != q.Owner {
			return failure("forbidden", "owner identity changed", 4)
		}
		labels := maps.Clone(q.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		labels[runtime.OwnerLabel] = string(q.Owner)
		labels[runtime.LoginLabel] = p.Login
		labels[runtime.NameLabel] = q.Name
		labels[runtime.ModeLabel] = "none"
		if s.VMNodesEnabled && s.Enrollment != nil {
			labels[runtime.ModeLabel] = string(s.Enrollment.Mode(q.Owner, q.NoTailnet))
		}
		labels[runtime.InstanceLabel] = s.Runtime.Instance
		if q.Template != "" {
			labels[TemplateLabel] = q.Template
		}
		if q.PolicyRef != "" {
			labels[PolicyLabel] = q.PolicyRef
		}
		if len(q.GuestPorts) > 0 {
			b, e := json.Marshal(q.GuestPorts)
			if e != nil {
				return Categorize(e)
			}
			labels[GuestPortsLabel] = string(b)
		}
		u := s.Config.VM.GuestUser
		opts := []silo.MachineOption{silo.WithName(q.Name), silo.WithLabels(labels), silo.WithCPUs(uint8(q.CPUs)), silo.WithMemory(silo.Bytes(q.Memory)), silo.WithRootDiskSize(silo.Bytes(q.Disk)), silo.WithVsock(true), silo.WithGuestUser(u.Name, u.UID, u.GID, u.Home)}
		if q.Userdata != "" {
			opts = append(opts, silo.WithUserdata(q.Userdata))
		}
		if q.policy != nil {
			if e := s.checkSecrets(ctx, q.policy); e != nil {
				return e
			}
			opts = append(opts, silo.WithMachineNetwork(silo.PrivateNetwork(q.policy)))
		}
		m, e := s.materialize(ctx, p, q, opts)
		if e != nil {
			return Categorize(e)
		}
		defer s.Runtime.CloseMachine(m)
		release()
		release = nil
		progress("VM persisted: " + m.ID())
		if q.NoStart {
			return nil
		}
		return s.Jobs.WithVM(ctx, m.ID(), func() error {
			p, e = c.Fresh(ctx)
			if e != nil {
				return e
			}
			d, e := m.Inspect(ctx)
			if e != nil {
				return Categorize(e)
			}
			if e = s.Authorize(p, identity.Create, authority(d)); e != nil {
				return e
			}
			if e = s.enroll(ctx, c, identity.Create, m, d, false, progress); e != nil {
				return e
			}
			p, e = c.Fresh(ctx)
			if e != nil {
				return e
			}
			if e = s.Authorize(p, identity.Create, authority(d)); e != nil {
				return e
			}
			progress("starting VM")
			if _, e = m.Start(ctx); e != nil {
				return Categorize(e)
			}
			progress("waiting for guest provisioning readiness")
			e = waitReady(ctx, m)
			if e != nil {
				return Categorize(e)
			}
			progress("guest ready")
			return nil
		})
	})
}

type StopRequest struct {
	Force   bool
	Timeout time.Duration
}
type RemoveRequest struct {
	Force     bool
	Confirmed bool
}
type SetRequest struct {
	Name   *string
	CPUs   *uint8
	Memory *silo.ByteSize
	Disk   *silo.ByteSize
}

func (s *Service) mutation(ctx context.Context, c Caller, ref, kind string, action identity.Action, run func(context.Context, identity.Peer, *silo.Machine, *silo.MachineData, func(string)) error) (jobs.Operation, error) {
	m, d, e := s.machine(ctx, c.Peer, ref, action)
	if e != nil {
		return jobs.Operation{}, e
	}
	s.Runtime.CloseMachine(m)
	return s.Jobs.Submit(kind, d.ID, identity.Principal(d.Labels[runtime.OwnerLabel]), func(ctx context.Context, progress func(string)) error {
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		m, d, e := s.machine(ctx, p, d.ID, action)
		if e != nil {
			return e
		}
		defer s.Runtime.CloseMachine(m)
		progress(kind + " VM")
		if e = run(ctx, p, m, d, progress); e != nil {
			return Categorize(e)
		}
		return nil
	})
}
func (s *Service) Start(ctx context.Context, c Caller, ref string) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "start", identity.Start, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		if e := s.enroll(ctx, c, identity.Start, m, d, false, f); e != nil {
			return e
		}
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		if e = s.Authorize(p, identity.Start, authority(d)); e != nil {
			return e
		}
		_, e = m.Start(ctx)
		if e != nil {
			return e
		}
		return waitReady(ctx, m)
	})
}
func (s *Service) Stop(ctx context.Context, c Caller, ref string, q StopRequest) (jobs.Operation, error) {
	if q.Timeout < 0 || q.Timeout > time.Minute {
		return jobs.Operation{}, failure("usage", "stop timeout must be 0..1m", 2)
	}
	return s.mutation(ctx, c, ref, "stop", identity.Stop, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		_, e := m.StopWith(ctx, silo.StopOptions{Force: q.Force, Timeout: q.Timeout})
		return e
	})
}
func (s *Service) Restart(ctx context.Context, c Caller, ref string) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "restart", identity.Restart, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		if _, e := m.StopWith(ctx, silo.StopOptions{}); e != nil {
			return e
		}
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		if e = s.Authorize(p, identity.Restart, authority(d)); e != nil {
			return e
		}
		if e = s.enroll(ctx, c, identity.Restart, m, d, false, f); e != nil {
			return e
		}
		p, e = c.Fresh(ctx)
		if e != nil {
			return e
		}
		if e = s.Authorize(p, identity.Restart, authority(d)); e != nil {
			return e
		}
		if _, e = m.Start(ctx); e != nil {
			return e
		}
		return waitReady(ctx, m)
	})
}

func waitReady(ctx context.Context, m *silo.Machine) error {
	if _, e := m.WaitReady(ctx, 2*time.Minute); e != nil {
		if ctx.Err() != nil {
			return failure("unavailable", "daemon operation interrupted; inspect VM state", 9)
		}
		return failure("operation_failed", "guest did not become ready; inspect VM state", 7)
	}
	return nil
}
func (s *Service) Remove(ctx context.Context, c Caller, ref string, q RemoveRequest) (jobs.Operation, error) {
	if !q.Confirmed {
		m, d, e := s.machine(ctx, c.Peer, ref, identity.Delete)
		if e != nil {
			return jobs.Operation{}, e
		}
		s.Runtime.CloseMachine(m)
		if d.Status.Kind != silo.MachineStatusStopped && !q.Force {
			return jobs.Operation{}, failure("conflict", "VM is running; use --force", 5)
		}
		return jobs.Operation{}, failure("usage", "removal requires confirmation; use --yes or --json unattended", 2)
	}
	return s.mutation(ctx, c, ref, "remove", identity.Delete, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped {
			if !q.Force {
				return failure("conflict", "VM is running; use --force", 5)
			}
			if e := s.Authorize(p, identity.Stop, authority(d)); e != nil {
				return e
			}
			if _, e := m.StopWith(ctx, silo.StopOptions{Force: true, Timeout: 10 * time.Second}); e != nil {
				return e
			}
		}
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		if e = s.Authorize(p, identity.Delete, authority(d)); e != nil {
			return e
		}
		var node state.NodeIdentity
		if d.Network.Tailscale != nil {
			lease, e := m.LeaseNodeState(ctx)
			if e != nil {
				return e
			}
			s.Runtime.Metrics.Handle("node_lease", 1)
			var pins []state.NodePin
			if s.Enrollment != nil {
				pins = []state.NodePin{s.Enrollment.Pin}
			}
			if state.RecoverNode(d.Network.Tailscale.StateDir, d.Name, identity.Principal(d.Labels[runtime.OwnerLabel]), true, pins...) == state.Unreadable {
				_ = lease.Close()
				s.Runtime.Metrics.Handle("node_lease", -1)
				f("device_retained: node state recovery required")
				return failure("conflict", "retained node state requires recovery before removal", 5)
			}
			var nodeState state.NodeState
			node, nodeState = state.ReadNode(d.Network.Tailscale.StateDir, d.Name, identity.Principal(d.Labels[runtime.OwnerLabel]), pins...)
			_ = lease.Close()
			s.Runtime.Metrics.Handle("node_lease", -1)
			if nodeState == state.Unreadable {
				f("device_retained: unknown (state unreadable)")
				return failure("conflict", "unreadable node state retained; recover before removal", 5)
			}
		}
		if e = m.Remove(ctx); e != nil {
			return e
		}
		s.removeDevice(ctx, node, f)
		return nil
	})
}
func (s *Service) Set(ctx context.Context, c Caller, ref string, q SetRequest) (jobs.Operation, error) {
	if q.Name == nil && q.CPUs == nil && q.Memory == nil && q.Disk == nil {
		return jobs.Operation{}, failure("usage", "set requires a setting", 2)
	}
	if q.Name != nil {
		name := *q.Name
		q.Name = &name
		if !config.ValidName(name) {
			return jobs.Operation{}, failure("usage", "invalid exact name", 2)
		}
	}
	if q.CPUs != nil {
		v := *q.CPUs
		q.CPUs = &v
	}
	if q.Memory != nil {
		v := *q.Memory
		q.Memory = &v
	}
	if q.Disk != nil {
		v := *q.Disk
		q.Disk = &v
	}
	return s.mutation(ctx, c, ref, "set", identity.Update, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped {
			return failure("conflict", "set requires a stopped VM", 5)
		}
		v := project(d)
		oldDisk := v.Disk
		if q.CPUs != nil {
			v.CPUs = *q.CPUs
		}
		if q.Memory != nil {
			v.Memory = q.Memory.Bytes()
		}
		if q.Disk != nil {
			if q.Disk.Bytes() < v.Disk {
				return failure("conflict", "disk may only grow", 5)
			}
			v.Disk = q.Disk.Bytes()
		}
		if e := s.resources(p, uint64(v.CPUs), v.Memory, v.Disk); e != nil {
			return e
		}
		if v.Disk > oldDisk {
			release, e := s.reserveDiskGrowth(d.ID, v.Disk-oldDisk)
			if e != nil {
				return e
			}
			defer release()
		}
		u := silo.MachineUpdate{CPUs: q.CPUs, Memory: q.Memory, RootDiskSize: q.Disk}
		if q.Name != nil && *q.Name != d.Name {
			if d.Network.Tailscale != nil {
				return failure("conflict", "cannot rename a VM with a tailscale declaration", 5)
			}
			var names []string
			var e error
			if s.VisibleNames != nil {
				names, e = s.VisibleNames(ctx)
				if e != nil {
					return failure("unavailable", "tailnet name inventory unavailable", 9)
				}
			}
			release, e := s.Runtime.Reserve(ctx, *q.Name, names)
			if e != nil {
				return failure("conflict", "name already taken locally or on the tailnet", 5)
			}
			defer release()
			labels := maps.Clone(d.Labels)
			labels[runtime.NameLabel] = *q.Name
			u.Name = q.Name
			u.Labels = &labels
		}
		_, e := m.Update(ctx, u)
		return e
	})
}
