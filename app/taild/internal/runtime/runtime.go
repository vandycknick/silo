// Package runtime owns direct native session handles and RPC label authority.
package runtime

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/google/uuid"
	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/metrics"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
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
	Control  *control.Client
	sessions *silo.Runtime
	Instance string
	mu       sync.Mutex
	reserved map[string]bool
	closed   bool
}

func Open(ctx context.Context, c config.Config, instance string, manager *control.Client) (*Runtime, error) {
	if manager == nil {
		return nil, errors.New("daemon management client required")
	}
	if c.BridgePath == "" {
		return nil, errors.New("bootstrap native bridge and runtime components required")
	}
	if e := os.Setenv("SILO_GO_FFI_PATH", c.BridgePath); e != nil {
		return nil, e
	}
	abi, e := silo.VerifiedNativeABIVersion()
	if e != nil {
		return nil, e
	}
	sdk, e := silo.Open(ctx, silo.WithHome(c.Home), silo.WithRuntimeComponents(c.Components))
	if e != nil {
		return nil, e
	}
	m := metrics.New()
	m.Handle("runtime", 1)
	return &Runtime{Control: manager, sessions: sdk, Instance: instance, reserved: make(map[string]bool), Metrics: m, Version: silo.Version, ABI: abi}, nil
}
func (r *Runtime) Close() error {
	err := r.sessions.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.Metrics.Handle("runtime", -1)
		r.closed = true
	}
	return err
}

// Machine opens only an already authorized immutable ID for a guest session.
func (r *Runtime) Machine(ctx context.Context, id string) (*silo.Machine, error) {
	if !exactID(id) {
		return nil, errors.New("native session requires an exact machine ID")
	}
	m, err := r.sessions.Machine(ctx, id)
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
	entries, e := r.Control.Inventory(ctx)
	if e != nil {
		return Snapshot{}, e
	}
	s := Snapshot{VMs: []VM{}}
	for _, entry := range entries {
		if entry.Data == nil {
			s.Unreadable++
			continue
		}
		d := entry.Data.MachineData
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
			fresh, err := r.Control.Inspect(ctx, d.ID)
			if err != nil || !Managed(freshData(fresh), r.Instance) || fresh.Name != d.Name || fresh.Labels[OwnerLabel] != d.Labels[OwnerLabel] || fresh.Labels[ModeLabel] != mode {
				s.Unreadable++
				continue
			}
			d = fresh.MachineData
			node = nodeState(fresh)
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

func freshData(d *control.Snapshot) *silo.MachineData {
	if d == nil {
		return nil
	}
	return d.MachineData
}

// nodeState consumes only the manager's authoritative observation, never StateDir.
func nodeState(d *control.Snapshot) state.NodeState {
	if d.Network.Tailscale == nil {
		return state.Unreadable
	}
	if d.Status.Kind != silo.MachineStatusRunning {
		return state.NodeState(string(d.Status.Kind))
	}
	n := d.NetworkObservation
	if d.RunID == nil || n == nil || n.Live == nil || n.Live.MachineId != d.ID || n.Live.RunId != *d.RunID {
		return state.NodeState("status unavailable")
	}
	switch n.Live.State {
	case w.NodeState_NODE_STATE_READY:
		return state.Enrolled
	case w.NodeState_NODE_STATE_APPROVAL_REQUIRED:
		return state.Pending
	case w.NodeState_NODE_STATE_CONNECTING:
		return state.NodeState("connecting")
	case w.NodeState_NODE_STATE_DISCONNECTED:
		return state.NodeState("disconnected")
	case w.NodeState_NODE_STATE_FAILED:
		return state.NodeState("failed")
	case w.NodeState_NODE_STATE_STOPPED:
		return state.NodeState("stopped")
	default:
		return state.Unreadable
	}
}

// ErrNameTaken is the one answer to every way a machine name can collide.
var ErrNameTaken = &authz.Error{Code: "conflict", Message: "name already taken locally or on the tailnet", Exit: 5}

// Reserve is a short in-process reservation, not a distributed claim. Create
// holds it through RPC CreateMachine, whose native exact-name home lock also
// covers CLI/SDK writers. Consent/boot must never hold that native lock.
func (r *Runtime) Reserve(ctx context.Context, name string, visibleNames []string) (func(), error) {
	if !config.ValidName(name) {
		return nil, errors.New("invalid exact name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, e := r.Control.Inventory(ctx)
	if e != nil {
		return nil, e
	}
	if r.reserved[name] || slices.Contains(visibleNames, name) || slices.ContainsFunc(entries, func(entry control.InventoryEntry) bool { return entry.Name == name }) {
		return nil, ErrNameTaken
	}
	r.reserved[name] = true
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); delete(r.reserved, name); r.mu.Unlock() }) }, nil
}

func exactID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil && (len(id) == 32 || len(id) == 36)
}
