// Package runtime owns one public SDK handle and projects label authority.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

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
	TagsLabel     = "io.silo.taild.node.tags"
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
			node = r.nodeState(ctx, d)
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

// NodeOwner is the identity used only when reading legacy stopped node state.
// Management authority always comes from OwnerLabel, independently of tags.
func NodeOwner(d *silo.MachineData) identity.Principal {
	var tags []string
	if json.Unmarshal([]byte(d.Labels[TagsLabel]), &tags) == nil && len(tags) > 0 {
		if p, err := identity.ParsePrincipal(tags[0]); err == nil && p.IsTag() {
			return p
		}
	}
	return identity.Principal(d.Labels[OwnerLabel])
}

// nodeState reads a tailnet-declared machine's node state. Stopped machines are
// recovered under the native lease; running ones are only observed.
func (r *Runtime) nodeState(ctx context.Context, d *silo.MachineData) state.NodeState {
	if d.Network.Tailscale == nil {
		return state.Unreadable
	}
	dir := d.Network.Tailscale.StateDir
	if d.Status.Kind == silo.MachineStatusRunning {
		if d.RunID != nil {
			if status, err := state.ReadNetdStatus(dir, d.ID, *d.RunID, time.Now()); err == nil {
				if status.State == "ready" {
					return state.Enrolled
				}
				if status.State == "approval_required" {
					return state.Pending
				}
				return state.NodeState(status.State)
			}
		}
		return state.NodeState("status unavailable")
	}
	if d.Status.Kind == silo.MachineStatusStopped && state.NeedsRecovery(dir) {
		machine, err := r.Machine(ctx, d.ID)
		if err != nil {
			return state.Unreadable
		}
		defer r.CloseMachine(machine)
		lease, err := machine.LeaseNodeState(ctx)
		if err != nil {
			return state.Unreadable
		}
		defer lease.Close()
		if state.RecoverNode(dir, d.Name, NodeOwner(d), r.NodePin) == state.Unreadable {
			return state.Unreadable
		}
	}
	return state.NodeState(string(d.Status.Kind))
}

// ErrNameTaken is the one answer to every way a machine name can collide.
var ErrNameTaken = &authz.Error{Code: "conflict", Message: "name already taken locally or on the tailnet", Exit: 5}

// Reserve is a short in-process reservation, not a distributed claim. Create
// holds it through SDK CreateMachine, whose native exact-name home lock also
// covers CLI/SDK writers. Consent/boot must never hold that native lock.
func (r *Runtime) Reserve(ctx context.Context, name string, visibleNames []string) (func(), error) {
	if !config.ValidName(name) {
		return nil, errors.New("invalid exact name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, e := r.SDK.Inventory(ctx)
	if e != nil {
		return nil, e
	}
	if r.reserved[name] || slices.Contains(visibleNames, name) || slices.ContainsFunc(entries, func(entry silo.MachineInventoryEntry) bool { return entry.Name == name }) {
		return nil, ErrNameTaken
	}
	r.reserved[name] = true
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); delete(r.reserved, name); r.mu.Unlock() }) }, nil
}
