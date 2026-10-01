package service

import (
	"context"
	"errors"
	"sync"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

type Service struct {
	Shutdown     *state.ShutdownGate
	Enrollment   *enroll.Manager
	Runtime      *runtime.Runtime
	Audit        *state.Audit
	Jobs         *jobs.Registry
	Capability   string
	Config       config.Config
	VisibleNames func(context.Context) ([]string, error)
	createMu     sync.Mutex
	pending      map[string]identity.Principal
	diskPending  map[string]uint64
	documentMu   sync.Mutex
	// Production enables node injection; --no-tailnet and mode none omit it.
	VMNodesEnabled bool
}
type WhoAmI struct {
	Peer        identity.Peer `json:"peer"`
	Capability  string        `json:"capability"`
	Explanation string        `json:"explanation,omitempty"`
}

func (s *Service) CheckIdentity(peer identity.Peer) error {
	var denied error
	if !peer.Valid() {
		denied = &authz.Error{Code: "forbidden", Message: "verified identity required", Exit: 4}
	}
	return s.decision(peer, "identity", denied)
}

func (s *Service) decision(peer identity.Peer, action string, err error) error {
	code := ""
	var denied *authz.Error
	if errors.As(err, &denied) {
		code = denied.Code
	}
	if e := s.Audit.Append(state.Decision{Principals: peer.Principals, NodeID: peer.NodeID, Action: action, Allowed: err == nil, Code: code}); e != nil {
		return &authz.Error{Code: "unavailable", Message: "audit unavailable", Exit: 9}
	}
	return err
}

// WhoAmI is deliberately permitted without a capability, to explain denial.
// The transport must still supply a fresh WhoIs identity.
func (s *Service) WhoAmI(peer identity.Peer) (WhoAmI, error) {
	var err error
	if !peer.Valid() {
		err = &authz.Error{Code: "forbidden", Message: "verified identity required", Exit: 4}
	}
	if e := s.decision(peer, "whoami", err); e != nil {
		return WhoAmI{}, e
	}
	return WhoAmI{peer, s.Capability, peer.Permissions.Reason}, nil
}
func (s *Service) Authorize(peer identity.Peer, action identity.Action, vm *authz.VM) error {
	if action != identity.Read && action != identity.Logs && s.ShutdownPending() {
		return s.decision(peer, string(action), &authz.Error{Code: "unavailable", Message: "host is shutting down", Exit: 9})
	}
	if vm != nil && (s.Runtime == nil || vm.Instance != s.Runtime.Instance) {
		return s.decision(peer, string(action), &authz.Error{Code: "not_found", Message: "VM not found", Exit: 3})
	}
	return s.decision(peer, string(action), authz.Allow(peer, action, vm))
}

func (s *Service) ShutdownPending() bool {
	return s.Shutdown.Pending() || state.ShutdownPending(s.Config.Home)
}

type Health struct {
	Runtime bool `json:"runtime"`
	Tailnet bool `json:"tailnet"`
}

func (s *Service) Health(ctx context.Context, peer identity.Peer) (Health, error) {
	if e := s.Authorize(peer, identity.Read, nil); e != nil {
		return Health{}, e
	}
	if _, e := s.Runtime.SDK.Inventory(ctx); e != nil {
		return Health{}, &authz.Error{Code: "unavailable", Message: "runtime unavailable", Exit: 9}
	}
	return Health{true, true}, nil
}

type Version struct {
	Taild       string `json:"taild"`
	SDK         string `json:"sdk"`
	Runtime     string `json:"runtime"`
	Tailscale   string `json:"tailscale"`
	ABIExpected uint32 `json:"abi_expected"`
	ABIVerified uint32 `json:"abi_verified,omitempty"`
}

func Versions() Version {
	return Version{Taild: silo.Version, SDK: silo.Version, Runtime: "unavailable", Tailscale: "1.102.5", ABIExpected: silo.NativeABIVersion}
}
func (s *Service) Versions() Version {
	v := Versions()
	if s.Runtime != nil && s.Runtime.Version != "" {
		v.Runtime = s.Runtime.Version
		v.ABIVerified = s.Runtime.ABI
	}
	return v
}
