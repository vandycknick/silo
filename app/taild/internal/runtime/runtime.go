// Package runtime owns one public SDK handle and projects label authority.
package runtime

import (
	"context"
	"errors"
	"sync"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/metrics"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

const (
	OwnerLabel    = "io.silo.taild.owner"
	LoginLabel    = "io.silo.taild.owner-login"
	NameLabel     = "io.silo.taild.name"
	ModeLabel     = "io.silo.taild.node.mode"
	InstanceLabel = "io.silo.taild.instance"
)

type VM struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Owner     identity.Principal     `json:"owner"`
	Status    silo.MachineStatusKind `json:"status"`
	NodeState state.NodeState        `json:"node_state"`
}
type Snapshot struct {
	VMs        []VM
	Unmanaged  int
	Unreadable int
}
type Runtime struct {
	Metrics  *metrics.Metrics
	Version  string
	ABI      uint32
	NodePin  *state.NodePin
	SDK      *silo.Runtime
	Instance string
	mu       sync.Mutex
	reserved map[string]bool
	closed   bool
}

func Open(ctx context.Context, c config.Config, instance string) (*Runtime, error) {
	root, e := Root(c)
	if e != nil {
		return nil, e
	}
	manifest, e := ValidateManifest(root)
	if e != nil {
		return nil, e
	}
	abi, e := silo.VerifiedNativeABIVersion()
	if e != nil {
		return nil, e
	}
	sdk, e := silo.Open(ctx, silo.WithHome(c.Home), silo.WithRuntimeRoot(root))
	if e != nil {
		return nil, e
	}
	m := metrics.New()
	m.Handle("runtime", 1)
	return &Runtime{SDK: sdk, Instance: instance, reserved: make(map[string]bool), Metrics: m, Version: manifest.Version, ABI: abi}, nil
}
func (r *Runtime) Close() error {
	err := r.SDK.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.Metrics.Handle("runtime", -1)
		r.closed = true
	}
	return err
}
func (r *Runtime) Machine(ctx context.Context, ref string) (*silo.Machine, error) {
	m, err := r.SDK.Machine(ctx, ref)
	if err == nil {
		r.Metrics.Handle("machine", 1)
	}
	return m, err
}
func (r *Runtime) CloseMachine(m *silo.Machine) {
	_ = m.Close()
	r.Metrics.Handle("machine", -1)
}
func (r *Runtime) Reconcile(ctx context.Context) (Snapshot, error) {
	entries, e := r.SDK.Inventory(ctx)
	if e != nil {
		return Snapshot{}, e
	}
	s := Snapshot{VMs: []VM{}}
	for _, entry := range entries {
		if entry.Data == nil {
			s.Unreadable++
			continue
		}
		d := entry.Data
		if d.Labels[InstanceLabel] != r.Instance {
			s.Unmanaged++
			continue
		}
		mode := d.Labels[ModeLabel]
		if !Managed(d, r.Instance) || mode != "user" && mode != "tag" && mode != "interactive" && mode != "none" {
			s.Unreadable++
			continue
		}
		owner := identity.Principal(d.Labels[OwnerLabel])
		node := state.NoNode
		if mode != "none" {
			node = r.nodeState(ctx, d, owner)
		}
		if len(entry.Issues) > 0 {
			s.Unreadable++
		}
		s.VMs = append(s.VMs, VM{d.ID, d.Name, owner, d.Status.Kind, node})
	}
	return s, nil
}

// Managed reports whether a machine record carries this daemon instance's
// complete label authority: instance, exact name, and a parseable owner.
func Managed(d *silo.MachineData, instance string) bool {
	if d == nil || instance == "" || d.Labels[InstanceLabel] != instance || d.Labels[NameLabel] != d.Name || !config.ValidName(d.Name) {
		return false
	}
	_, err := identity.ParsePrincipal(d.Labels[OwnerLabel])
	return err == nil
}

// nodeState reads a tailnet-declared machine's node state. Stopped machines are
// recovered under the native lease; running ones are only observed.
func (r *Runtime) nodeState(ctx context.Context, d *silo.MachineData, owner identity.Principal) state.NodeState {
	if d.Network.Tailscale == nil {
		return state.Unreadable
	}
	machine, err := r.Machine(ctx, d.ID)
	if err != nil {
		return state.Unreadable
	}
	defer r.CloseMachine(machine)
	dir := d.Network.Tailscale.StateDir
	if d.Status.Kind != silo.MachineStatusStopped {
		_, node := state.ReadNode(dir, d.Name, owner, r.NodePin)
		return node
	}
	lease, err := machine.LeaseNodeState(ctx)
	if err != nil {
		return state.Unreadable
	}
	r.Metrics.Handle("node_lease", 1)
	defer func() { _ = lease.Close(); r.Metrics.Handle("node_lease", -1) }()
	return state.RecoverNode(dir, d.Name, owner, r.NodePin)
}

// Reserve is a short in-process reservation, not a distributed claim. Create
// holds it through SDK CreateMachine, whose native exact-name home lock also
// covers CLI/SDK writers. Consent/boot must never hold that native lock.
func (r *Runtime) Reserve(ctx context.Context, name string, visibleNames []string) (func(), error) {
	if !config.ValidName(name) {
		return nil, errors.New("invalid exact name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reserved[name] {
		return nil, &authz.Error{Code: "conflict", Message: "name already taken locally or on the tailnet", Exit: 5}
	}
	entries, e := r.SDK.Inventory(ctx)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if entry.Name == name {
			return nil, &authz.Error{Code: "conflict", Message: "name already taken locally or on the tailnet", Exit: 5}
		}
	}
	for _, visible := range visibleNames {
		if visible == name {
			return nil, &authz.Error{Code: "conflict", Message: "name already taken locally or on the tailnet", Exit: 5}
		}
	}
	r.reserved[name] = true
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); delete(r.reserved, name); r.mu.Unlock() }) }, nil
}
