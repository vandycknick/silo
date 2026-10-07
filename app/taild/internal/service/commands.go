package service

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/emptypb"
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

// Failures several entry points report identically.
var (
	errVMNotFound  = failure("not_found", "VM not found", 3)
	errVMRunning   = failure("conflict", "VM is running; use --force", 5)
	errInvalidName = failure("usage", "invalid exact name", 2)
	errImage       = failure("usage", "image must be an allowlisted OCI reference", 2)
	errUserdata    = failure("usage", "userdata must be an inline shebang script, at most 16KiB", 2)
)

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
			return errVMNotFound
		case silo.ErrorMachineAlreadyExists:
			return runtime.ErrNameTaken
		case silo.ErrorMachineAlreadyRunning, silo.ErrorMachineNotRunning, silo.ErrorMachineStaleGeneration, silo.ErrorInvalidMachineUpdate:
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
	OwnerLogin          string                 `json:"owner_login,omitempty"`
	KeyExpiryObservedAt *time.Time             `json:"key_expiry_observed_at,omitempty"`
	KeyExpiryLastKnown  bool                   `json:"key_expiry_last_known,omitempty"`
	Tags                []string               `json:"tags,omitempty"`
	GuestUser           *silo.GuestUser        `json:"guest_user,omitempty"`
	DefaultUser         string                 `json:"default_user"`
	NodeDiagnostics     []string               `json:"node_diagnostics,omitempty"`
	NodeState           state.NodeState        `json:"node_state"`
	NodeID              string                 `json:"node_id,omitempty"`
	Addresses           []string               `json:"addresses,omitempty"`
	KeyExpiry           string                 `json:"key_expiry"`
	ApprovalURL         string                 `json:"approval_url,omitempty"`
	Template            string                 `json:"template,omitempty"`
	Policy              string                 `json:"policy,omitempty"`
	GuestTCPPorts       []uint16               `json:"guest_tcp_ports,omitempty"`
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Owner               identity.Principal     `json:"owner"`
	State               silo.MachineStatusKind `json:"state"`
	Node                string                 `json:"node"`
	Address             string                 `json:"address"`
	CPUs                uint8                  `json:"cpus"`
	Memory              uint64                 `json:"memory"`
	Disk                uint64                 `json:"disk"`
	Created             time.Time              `json:"created"`
	Image               string                 `json:"image"`
	Labels              map[string]string      `json:"labels"`
}

func project(d *silo.MachineData) VM {
	v := VM{ID: d.ID, Name: d.Name, Owner: identity.Principal(d.Labels[runtime.OwnerLabel]), State: d.Status.Kind, Created: d.CreatedAt.UTC()}
	if !v.Owner.IsTag() {
		v.OwnerLogin = d.Labels[runtime.LoginLabel]
	}
	v.DefaultUser = "root"
	if d.GuestUser != nil {
		u := *d.GuestUser
		v.GuestUser = &u
		v.DefaultUser = u.Name
	}
	v.Template = d.Labels[TemplateLabel]
	_ = json.Unmarshal([]byte(d.Labels[runtime.TagsLabel]), &v.Tags)
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
func (s *Service) inspect(ctx context.Context, p identity.Peer, ref string, action identity.Action) (*control.Snapshot, error) {
	d, e := s.Runtime.Control.Inspect(ctx, ref)
	if e != nil {
		return nil, Categorize(e)
	}
	_, ownerErr := identity.ParsePrincipal(d.Labels[runtime.OwnerLabel])
	if ownerErr != nil || d.Labels[runtime.NameLabel] != d.Name || !config.ValidName(d.Name) {
		return nil, errVMNotFound
	}
	if e = s.Authorize(p, action, authority(d.MachineData)); e != nil {
		return nil, e
	}
	return d, nil
}
func (s *Service) List(ctx context.Context, p identity.Peer) ([]VM, error) {
	if e := s.Authorize(p, identity.Read, nil); e != nil {
		return nil, e
	}
	entries, e := s.Runtime.Control.Inventory(ctx)
	if e != nil {
		return nil, Categorize(e)
	}
	out := []VM{}
	for _, entry := range entries {
		d := entry.Data
		if d == nil || !runtime.Managed(d.MachineData, s.Runtime.Instance) || !p.Owns(identity.Principal(d.Labels[runtime.OwnerLabel])) {
			continue
		}
		d, e = s.inspect(ctx, p, d.ID, identity.Read)
		if e != nil {
			return nil, e
		}
		out = append(out, s.nodeView(d))
	}
	return out, nil
}
func (s *Service) Show(ctx context.Context, p identity.Peer, ref string) (VM, error) {
	d, e := s.inspect(ctx, p, ref, identity.Read)
	if e != nil {
		return VM{}, e
	}
	v := s.nodeView(d)
	if !v.Owner.IsTag() && p.Owns(v.Owner) && p.Login != "" {
		v.OwnerLogin = p.Login
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
	Tags        []string
	GuestUser   *silo.GuestUser
	Template    string
	PolicyRef   string
	GuestPorts  []uint16
	UserdataSet bool
	policy      *control.Policy
	Name        string
	Image       string
	CPUs        uint64
	Memory      uint64
	Disk        uint64
	MemoryText  string
	DiskText    string
	Userdata    string
	Labels      map[string]string
	Owner       identity.Principal
	Tailscale   bool
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
	if len(parts) < 2 || !strings.ContainsAny(parts[0], ".:") && parts[0] != "localhost" {
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

// Help uses the loaded config only, with the same OCI allowlist as admission.
// Never render host paths or userinfo-shaped registry credentials.
func ImageDefaultForHelp(c config.Config) string {
	ref := c.VM.DefaultImage
	host, _, _ := strings.Cut(ref, "/")
	if !imageAllowed(ref, c.VM.AllowedRegistries) || strings.Contains(host, "@") {
		return "unavailable"
	}
	if _, port, ok := strings.Cut(host, ":"); ok {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return "unavailable"
		}
	}
	return ref
}
func (s *Service) ValidateCreate(ctx context.Context, p identity.Peer, q CreateRequest) (CreateRequest, error) {
	if e := s.Authorize(p, identity.Create, nil); e != nil {
		return q, e
	}
	if q.Tailscale && (!s.VMNodesEnabled || s.Enrollment == nil || s.Config.Enrollment.Mode == "none") {
		return q, failure("usage", "Tailscale enrollment is disabled or unavailable", 2)
	}
	if len(q.Tags) > 0 && !q.Tailscale {
		return q, failure("usage", "--tag requires --tailscale", 2)
	}
	if len(q.Tags) > 32 {
		return q, failure("usage", "at most 32 tags may be requested", 2)
	}
	q.Tags = slices.Clone(q.Tags)
	for i, tag := range q.Tags {
		p, err := identity.ParsePrincipal(strings.ToLower(tag))
		if err != nil || !p.IsTag() {
			return q, failure("usage", "invalid Tailscale tag", 2)
		}
		q.Tags[i] = string(p)
	}
	slices.Sort(q.Tags)
	q.Tags = slices.Compact(q.Tags)
	if q.Name != "" && !config.ValidName(q.Name) {
		return q, errInvalidName
	}
	if q.GuestUser != nil {
		u := *q.GuestUser
		if e := u.Validate(); e != nil {
			return q, failure("usage", e.Error(), 2)
		}
		q.GuestUser = &u
	}
	owner, e := selectedOwner(p, q.Owner)
	if e != nil {
		return q, e
	}
	q.Owner = owner
	if q.Tailscale && q.Owner.IsTag() && len(q.Tags) == 0 {
		q.Tags = []string{string(q.Owner)}
	}
	if q.Image == "" {
		q.Image = s.Config.VM.DefaultImage
	}
	if !imageAllowed(q.Image, s.Config.VM.AllowedRegistries) {
		return q, errImage
	}
	if !validUserdata(q.Userdata) {
		return q, errUserdata
	}
	if e := validateLabels(q.Labels); e != nil {
		return q, e
	}
	q.Labels = maps.Clone(q.Labels)
	if q.CPUs == 0 {
		q.CPUs = s.Config.VM.Defaults.CPUs
	}
	if q.MemoryText != "" {
		v, err := s.ParseResource(ctx, "memory", q.MemoryText)
		if err != nil {
			return q, err
		}
		q.Memory = v.Bytes()
		q.MemoryText = ""
	}
	if q.DiskText != "" {
		v, err := s.ParseResource(ctx, "disk", q.DiskText)
		if err != nil {
			return q, err
		}
		q.Disk = v.Bytes()
		q.DiskText = ""
	}
	if q.Memory == 0 {
		q.Memory = uint64(s.Config.VM.Defaults.Memory)
	}
	if q.Disk == 0 {
		q.Disk = uint64(s.Config.VM.Defaults.Disk)
	}
	if e := s.resources(p, q.CPUs, q.Memory, q.Disk); e != nil {
		return q, e
	}
	return q, nil
}
func (s *Service) resources(p identity.Peer, cpus, mem, disk uint64) error {
	l, cap := s.Config.Limits(), p.Permissions.Limits
	if cpus == 0 || cpus > 255 || cpus > min(l.CPUs, cap.CPUs) || mem == 0 || mem > min(l.Memory, cap.Memory) || disk == 0 || disk > min(l.Disk, cap.Disk) {
		return failure("limit", "resource ceiling exceeded", 6)
	}
	return nil
}

// ownedCountLocked counts a reservation only until its durable record appears.
// The create mutex covers both admission and the final durable manager write.
func (s *Service) ownedCountLocked(ctx context.Context, owner identity.Principal) (uint64, error) {
	entries, e := s.Runtime.Control.Inventory(ctx)
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

// admitLocked is the create admission shared by reservation and the durable
// write, under createMu: no host shutdown, the disk floor with disk reserved
// on top, and the owner's VM count under both ceilings. Before a reservation
// the count must leave room; once this create holds one, it may fill the slot.
func (s *Service) admitLocked(ctx context.Context, p identity.Peer, owner identity.Principal, disk uint64, reserved bool) error {
	if s.ShutdownPending() {
		return failure("unavailable", "host is shutting down", 9)
	}
	if e := s.diskAdmissionLocked(disk); e != nil {
		return e
	}
	count, e := s.ownedCountLocked(ctx, owner)
	if e != nil {
		return e
	}
	limit := min(s.Config.Limits().VMs, p.Permissions.Limits.VMs)
	if count > limit || !reserved && count == limit {
		return failure("limit", "VM count ceiling exceeded", 6)
	}
	return nil
}

// visibleNames is the tailnet's current machine names when a tailnet is attached.
func (s *Service) visibleNames(ctx context.Context) ([]string, error) {
	if s.VisibleNames == nil {
		return nil, nil
	}
	names, e := s.VisibleNames(ctx)
	if e != nil {
		return nil, failure("unavailable", "tailnet name inventory unavailable", 9)
	}
	return names, nil
}
func (s *Service) reserveCreate(ctx context.Context, p identity.Peer, q *CreateRequest) (func(), error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if e := s.admitLocked(ctx, p, q.Owner, q.Disk, false); e != nil {
		return nil, e
	}
	names, e := s.visibleNames(ctx)
	if e != nil {
		return nil, e
	}
	generated := q.Name == ""
	var release func()
	for range 3 {
		if generated {
			q.Name, e = s.Runtime.Control.ProposeMachineName(ctx)
			if e != nil {
				return nil, Categorize(e)
			}
		}
		release, e = s.Runtime.Reserve(ctx, q.Name, names)
		if e == nil {
			break
		}
		if !generated {
			return nil, Categorize(e)
		}
		if Categorize(e).Code != "conflict" {
			return nil, Categorize(e)
		}
	}
	if e != nil {
		return nil, failure("conflict", "could not reserve a generated name after 3 attempts", 5)
	}
	if s.pending == nil {
		s.pending = make(map[string]identity.Principal)
	}
	s.pending[q.Name] = q.Owner
	if s.diskPending == nil {
		s.diskPending = make(map[string]uint64)
	}
	s.diskPending[q.Name] = q.Disk
	var once sync.Once
	return func() {
		once.Do(func() {
			s.createMu.Lock()
			defer s.createMu.Unlock()
			release()
			delete(s.pending, q.Name)
			delete(s.diskPending, q.Name)
		})
	}, nil
}
func (s *Service) materialize(ctx context.Context, p identity.Peer, q CreateRequest, spec *w.NormalizedMachineCreate, source *w.OciIdentity) (*control.Snapshot, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if e := s.admitLocked(ctx, p, q.Owner, 0, true); e != nil {
		return nil, e
	}
	return s.Runtime.Control.Create(ctx, spec, source)
}

// revalidateCreate re-runs admission against a fresh identity observation, as
// the peer's grants may have changed since the request was accepted.
func (s *Service) revalidateCreate(ctx context.Context, c Caller, q CreateRequest) (identity.Peer, error) {
	p, e := c.Fresh(ctx)
	if e != nil {
		return p, e
	}
	validated := q
	// An already selected human owner is not a client-supplied --owner tag.
	if !q.Owner.IsTag() {
		validated.Owner = ""
	}
	if validated, e = s.ValidateCreate(ctx, p, validated); e != nil {
		return p, e
	}
	if validated.Owner != q.Owner {
		return p, failure("forbidden", "owner identity changed", 4)
	}
	return p, nil
}

func (s *Service) Create(ctx context.Context, c Caller, q CreateRequest) (jobs.Operation, error) {
	if e := s.Authorize(c.Peer, identity.Create, nil); e != nil {
		return jobs.Operation{}, e
	}
	q, e := s.resolveCreate(ctx, c.Peer, q)
	if e != nil {
		return jobs.Operation{}, e
	}
	q, e = s.ValidateCreate(ctx, c.Peer, q)
	if e != nil {
		return jobs.Operation{}, e
	}
	release, e := s.reserveCreate(ctx, c.Peer, &q)
	if e != nil {
		return jobs.Operation{}, e
	}
	if q.Tailscale {
		controlURL := s.Config.Tailnet.ControlURL
		if s.Enrollment != nil {
			controlURL = s.Enrollment.Pin.ControlURL
		}
		q.policy, e = s.InjectTailnet(ctx, q.policy, q.Name, q.Owner, controlURL, q.Tags...)
		if e == nil {
			q.policy, e = s.bindNodeIdentity(ctx, q.policy, q.Owner, q.Tags, s.Enrollment.Mode(q.Owner))
		}
		if e != nil {
			release()
			return jobs.Operation{}, e
		}
	}
	return s.Jobs.SubmitResult("create", q.Name, q.Owner, func(ctx context.Context, progress func(string)) (*jobs.Completion, error) {
		p, e := s.revalidateCreate(ctx, c, q)
		if e != nil {
			return nil, e
		}
		var key []byte
		if q.Tailscale {
			key, e = s.Enrollment.Acquire(ctx, q.Name, q.Owner, progress)
			if e != nil {
				return nil, e
			}
			defer clear(key)
			if p, e = s.revalidateCreate(ctx, c, q); e != nil {
				return nil, e
			}
		}
		progress("creating " + q.Name)
		progress("pulling " + q.Image)
		pullError := s.Runtime.Control.PullImage(ctx, q.Image)
		if pullError != nil {
			return nil, Categorize(pullError)
		}
		progress("image pull complete")
		if p, e = s.revalidateCreate(ctx, c, q); e != nil {
			return nil, e
		}
		resolved, e := s.Runtime.Control.ResolveImage(ctx, q.Image, w.PullPolicy_PULL_POLICY_IF_MISSING)
		if e != nil {
			return nil, Categorize(e)
		}
		progress("materializing stopped VM")
		if p, e = s.revalidateCreate(ctx, c, q); e != nil {
			return nil, e
		}
		labels := maps.Clone(q.Labels)
		if labels == nil {
			labels = map[string]string{}
		}
		labels[runtime.OwnerLabel] = string(q.Owner)
		labels[runtime.LoginLabel] = p.Login
		labels[runtime.NameLabel] = q.Name
		labels[runtime.ModeLabel] = "none"
		if q.Tailscale {
			labels[runtime.ModeLabel] = string(s.Enrollment.Mode(q.Owner))
			tags, _ := json.Marshal(q.Tags)
			labels[runtime.TagsLabel] = string(tags)
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
				return nil, Categorize(e)
			}
			labels[GuestPortsLabel] = string(b)
		}
		cpus, memory, disk, vsock := uint32(q.CPUs), q.Memory, q.Disk, true
		spec := &w.NormalizedMachineCreate{Name: &q.Name, Labels: labels, Cpus: &cpus, MemoryBytes: &memory, RootDiskSizeBytes: &disk, Vsock: &vsock}
		spec.Process = &w.ProcessConfig{}
		spec.Retention = w.Retention_RETENTION_PERSISTENT
		spec.Agent = &w.Agent{Mode: &w.Agent_DefaultAgent{DefaultAgent: &emptypb.Empty{}}}
		if u := q.GuestUser; u != nil {
			spec.ProvisionUser = &w.User{Name: u.Name, Uid: u.UID, Gid: u.GID, Home: u.Home}
		}
		if q.Userdata != "" {
			spec.Userdata = &q.Userdata
		}
		if q.policy != nil {
			if e := s.checkSecrets(ctx, q.policy); e != nil {
				return nil, e
			}
			spec.Network = &w.ResolvedNetwork{Attachment: &w.ResolvedNetwork_Private{Private: &w.PrivateNetwork{PolicyJson: &q.policy.CanonicalJSON}}}
		}
		if p, e = s.revalidateCreate(ctx, c, q); e != nil {
			return nil, e
		}
		d, e := s.materialize(ctx, p, q, spec, resolved.Identity)
		if e != nil {
			return nil, Categorize(e)
		}
		if q.Tailscale {
			if e = s.storeNodeCredentials(ctx, c, identity.Create, d, q.Owner, key); e != nil {
				return nil, e
			}
		}
		release()
		progress("VM created: " + q.Name)
		user := "root"
		if q.GuestUser != nil {
			user = q.GuestUser.Name
		}
		completion := &jobs.Completion{VMID: d.ID, Name: q.Name, Image: q.Image, User: user, NodeState: "none"}
		if q.NoStart {
			if q.Tailscale {
				completion.NodeState = "enrollment starts on boot"
			}
			return completion, nil
		}
		err := s.Jobs.WithVM(ctx, d.ID, func() error {
			d, e := s.Runtime.Control.Inspect(ctx, d.ID)
			if e != nil {
				return Categorize(e)
			}
			if e = s.prepareNode(ctx, c, identity.Create, d); e != nil {
				return e
			}
			if e = s.reauthorize(ctx, c, identity.Create, d); e != nil {
				return e
			}
			progress("starting VM")
			start, e := s.Runtime.Control.Start(ctx, d.ID)
			if e != nil {
				return Categorize(e)
			}
			progress("preparing " + q.Name)
			if e = s.waitReady(ctx, d.ID, start.RunID); e != nil {
				return e
			}
			progress("guest ready")
			completion.Running = true
			s.completeNode(ctx, d.ID, completion, progress)
			return nil
		})
		return completion, err
	}, release)
}

// ParseResource uses the manager's CLI parser without exposing diagnostics.
func (s *Service) ParseResource(ctx context.Context, kind, text string) (silo.ByteSize, error) {
	resource := w.ResourceKind_RESOURCE_KIND_ROOT_DISK
	if kind == "memory" {
		resource = w.ResourceKind_RESOURCE_KIND_MEMORY
	}
	v, err := s.Runtime.Control.ParseResource(ctx, resource, text)
	if err != nil {
		if !silo.IsErrorKind(err, silo.ErrorInvalidArgument) {
			return v, Categorize(err)
		}
		message := "invalid value for --" + kind + ": expected a positive binary size (e.g. 4GiB or 8gb)"
		return v, failure("usage", message, 2)
	}
	return v, nil
}

type StopRequest struct {
	Force   bool
	Timeout time.Duration
}
type RemoveRequest struct {
	Force bool
}

// RemovalTarget contains only the authorized facts needed for confirmation.
// No job or VM lock is held during confirmation.
type RemovalTarget struct {
	ID      string
	Name    string
	Running bool
}

func (s *Service) PreflightRemove(ctx context.Context, c Caller, ref string, force bool) (RemovalTarget, error) {
	p, e := c.Fresh(ctx)
	if e != nil {
		return RemovalTarget{}, e
	}
	d, e := s.inspect(ctx, p, ref, identity.Delete)
	if e != nil {
		return RemovalTarget{}, e
	}
	running := d.Status.Kind != silo.MachineStatusStopped
	if running {
		if !force {
			return RemovalTarget{}, errVMRunning
		}
		if e := s.Authorize(p, identity.Stop, authority(d.MachineData)); e != nil {
			return RemovalTarget{}, e
		}
	}
	return RemovalTarget{ID: d.ID, Name: d.Name, Running: running}, nil
}

// SetRequest carries only the settings to change; nil leaves a value alone.
type SetRequest struct {
	Name   *string
	CPUs   *uint8
	Memory *silo.ByteSize
	Disk   *silo.ByteSize
}

// reauthorize checks the action against a fresh identity observation. Long
// operations repeat it around every step that changes the machine.
func (s *Service) reauthorize(ctx context.Context, c Caller, action identity.Action, d *control.Snapshot) error {
	p, e := c.Fresh(ctx)
	if e != nil {
		return e
	}
	_, e = s.inspect(ctx, p, d.ID, action)
	return e
}
func (s *Service) mutation(ctx context.Context, c Caller, ref, kind string, action identity.Action, run func(context.Context, identity.Peer, *control.Snapshot, func(string)) error) (jobs.Operation, error) {
	d, e := s.inspect(ctx, c.Peer, ref, action)
	if e != nil {
		return jobs.Operation{}, e
	}
	s.createMu.Lock()
	_, creating := s.pending[d.Name]
	s.createMu.Unlock()
	if creating {
		return jobs.Operation{}, failure("conflict", "VM bootstrap setup is still in progress", 5)
	}
	return s.Jobs.SubmitResult(kind, d.ID, identity.Principal(d.Labels[runtime.OwnerLabel]), func(ctx context.Context, progress func(string)) (*jobs.Completion, error) {
		p, e := c.Fresh(ctx)
		if e != nil {
			return nil, e
		}
		d, e := s.inspect(ctx, p, d.ID, action)
		if e != nil {
			return nil, e
		}
		progress(kind + " " + d.Name)
		if e = run(ctx, p, d, progress); e != nil {
			return nil, Categorize(e)
		}
		v := project(d.MachineData)
		if kind == "set" {
			updated, err := s.Runtime.Control.Inspect(ctx, d.ID)
			if err != nil {
				return nil, Categorize(err)
			}
			v = project(updated.MachineData)
		}
		completion := &jobs.Completion{VMID: d.ID, Name: v.Name, Image: v.Image, User: v.DefaultUser, NodeState: "none"}
		if kind == "start" || kind == "restart" {
			completion.Running = true
			s.completeNode(ctx, d.ID, completion, progress)
		}
		return completion, nil
	}, nil)
}
func (s *Service) Start(ctx context.Context, c Caller, ref string) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "start", identity.Start, func(ctx context.Context, _ identity.Peer, d *control.Snapshot, f func(string)) error {
		if e := s.prepareNode(ctx, c, identity.Start, d); e != nil {
			return e
		}
		if e := s.reauthorize(ctx, c, identity.Start, d); e != nil {
			return e
		}
		start, e := s.Runtime.Control.Start(ctx, d.ID)
		if e != nil {
			return e
		}
		f("preparing " + d.Name)
		return s.waitReady(ctx, d.ID, start.RunID)
	})
}
func (s *Service) Stop(ctx context.Context, c Caller, ref string, q StopRequest) (jobs.Operation, error) {
	if q.Timeout < 0 || q.Timeout > time.Minute {
		return jobs.Operation{}, failure("usage", "stop timeout must be 0..1m", 2)
	}
	return s.mutation(ctx, c, ref, "stop", identity.Stop, func(ctx context.Context, _ identity.Peer, d *control.Snapshot, _ func(string)) error {
		if d.Status.Kind == silo.MachineStatusStopped || (d.Status.Kind == silo.MachineStatusError && d.RunID == nil) {
			return nil
		}
		if d.RunID == nil {
			return failure("conflict", "VM is not running", 5)
		}
		if e := s.reauthorize(ctx, c, identity.Stop, d); e != nil {
			return e
		}
		_, e := s.Runtime.Control.Stop(ctx, d.ID, d.RunID, silo.StopOptions{Force: q.Force, Timeout: q.Timeout})
		return e
	})
}
func (s *Service) Restart(ctx context.Context, c Caller, ref string) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "restart", identity.Restart, func(ctx context.Context, _ identity.Peer, d *control.Snapshot, f func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped && !(d.Status.Kind == silo.MachineStatusError && d.RunID == nil) {
			if d.RunID == nil {
				return failure("conflict", "VM running generation unavailable", 5)
			}
			f("stopping " + d.Name)
			if e := s.reauthorize(ctx, c, identity.Restart, d); e != nil {
				return e
			}
			stopped, e := s.Runtime.Control.Stop(ctx, d.ID, d.RunID, silo.StopOptions{})
			if e != nil {
				return e
			}
			d = stopped
		}
		if e := s.prepareNode(ctx, c, identity.Restart, d); e != nil {
			return e
		}
		if e := s.reauthorize(ctx, c, identity.Restart, d); e != nil {
			return e
		}
		f("starting " + d.Name)
		start, e := s.Runtime.Control.Start(ctx, d.ID)
		if e != nil {
			return e
		}
		f("preparing " + d.Name)
		return s.waitReady(ctx, d.ID, start.RunID)
	})
}

func (s *Service) waitReady(ctx context.Context, id, run string) error {
	result, e := s.Runtime.Control.WaitReady(ctx, id, run, 2*time.Minute)
	if ctx.Err() != nil {
		return failure("unavailable", "daemon operation interrupted; inspect VM state", 9)
	}
	if e != nil || result.Outcome != w.ReadinessOutcome_READINESS_OUTCOME_READY {
		return failure("operation_failed", "guest did not become ready; inspect VM state", 7)
	}
	return nil
}

// Remove assumes the caller already confirmed through PreflightRemove.
func (s *Service) Remove(ctx context.Context, c Caller, ref string, q RemoveRequest) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "remove", identity.Delete, func(ctx context.Context, p identity.Peer, d *control.Snapshot, _ func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped {
			if !q.Force {
				return errVMRunning
			}
			if d.RunID == nil && d.Status.Kind != silo.MachineStatusError {
				return failure("conflict", "VM run identity unavailable; inspect VM state", 5)
			}
			if e := s.Authorize(p, identity.Stop, authority(d.MachineData)); e != nil {
				return e
			}
			if e := s.reauthorize(ctx, c, identity.Delete, d); e != nil {
				return e
			}
			if e := s.reauthorize(ctx, c, identity.Stop, d); e != nil {
				return e
			}
			if d.RunID != nil {
				if _, e := s.Runtime.Control.Stop(ctx, d.ID, d.RunID, silo.StopOptions{Force: true, Timeout: 10 * time.Second}); e != nil {
					return e
				}
			}
		}
		if e := s.reauthorize(ctx, c, identity.Delete, d); e != nil {
			return e
		}
		if d.RunID != nil {
			return s.Runtime.Control.RemoveAfterRun(ctx, d.ID, *d.RunID)
		}
		return s.Runtime.Control.Remove(ctx, d.ID)
	})
}
func (s *Service) Set(ctx context.Context, c Caller, ref string, q SetRequest) (jobs.Operation, error) {
	if q.Name == nil && q.CPUs == nil && q.Memory == nil && q.Disk == nil {
		return jobs.Operation{}, failure("usage", "set requires a setting", 2)
	}
	if q.Name != nil && !config.ValidName(*q.Name) {
		return jobs.Operation{}, errInvalidName
	}
	return s.mutation(ctx, c, ref, "set", identity.Update, func(ctx context.Context, p identity.Peer, d *control.Snapshot, f func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped {
			return failure("conflict", "set requires a stopped VM", 5)
		}
		v := project(d.MachineData)
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
		u := &w.MachineUpdate{}
		if q.CPUs != nil {
			value := uint32(*q.CPUs)
			u.Cpus = &value
		}
		if q.Memory != nil {
			value := q.Memory.Bytes()
			u.MemoryBytes = &value
		}
		if q.Disk != nil {
			value := q.Disk.Bytes()
			u.RootDiskSizeBytes = &value
		}
		if q.Name != nil && *q.Name != d.Name {
			if d.Network.Tailscale != nil {
				return failure("conflict", "cannot rename a VM with a tailscale declaration", 5)
			}
			names, e := s.visibleNames(ctx)
			if e != nil {
				return e
			}
			release, e := s.Runtime.Reserve(ctx, *q.Name, names)
			if e != nil {
				return runtime.ErrNameTaken
			}
			defer release()
			labels := maps.Clone(d.Labels)
			labels[runtime.NameLabel] = *q.Name
			u.Name = q.Name
			u.Labels = &w.StringMap{Values: labels}
		}
		if e := s.reauthorize(ctx, c, identity.Update, d); e != nil {
			return e
		}
		_, e := s.Runtime.Control.Update(ctx, d.ID, u)
		return e
	})
}
