package service

import (
	"context"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	"os"
	"strings"
	"time"
)

func (s *Service) enroll(ctx context.Context, c Caller, action identity.Action, m *silo.Machine, d *silo.MachineData, reauth bool, progress func(string)) error {
	if d.Network.Tailscale == nil {
		return nil
	}
	if s.Enrollment == nil {
		return failure("unavailable", "enrollment unavailable", 9)
	}
	validate := func(ctx context.Context) error {
		p, e := c.Fresh(ctx)
		if e != nil {
			return e
		}
		return s.Authorize(p, action, authority(d))
	}
	return s.Enrollment.Enroll(ctx, m, d, identity.Principal(d.Labels[runtime.OwnerLabel]), reauth, progress, validate)
}
func (s *Service) Reauth(ctx context.Context, c Caller, ref string) (jobs.Operation, error) {
	return s.mutation(ctx, c, ref, "reauth", identity.Reauth, func(ctx context.Context, p identity.Peer, m *silo.Machine, d *silo.MachineData, f func(string)) error {
		if d.Status.Kind != silo.MachineStatusStopped {
			return failure("conflict", "reauth requires a stopped VM", 5)
		}
		if d.Network.Tailscale == nil {
			return failure("conflict", "VM has no tailnet node", 5)
		}
		return s.enroll(ctx, c, identity.Reauth, m, d, true, f)
	})
}
func (s *Service) nodeView(ctx context.Context, d *silo.MachineData) VM {
	v := project(d)
	v.NodeState = state.NoNode
	v.Address = "unknown"
	v.KeyExpiry = "unknown"
	if d.Network.Tailscale == nil {
		return v
	}
	owner := identity.Principal(d.Labels[runtime.OwnerLabel])
	var pins []state.NodePin
	if s.Enrollment != nil {
		pins = []state.NodePin{s.Enrollment.Pin}
	}
	node, status := state.ReadNode(d.Network.Tailscale.StateDir, d.Name, owner, pins...)
	v.NodeState = status
	if _, e := os.Lstat(d.Network.Tailscale.StateDir + ".unreadable"); e == nil {
		v.NodeState = state.Unreadable
		v.NodeDiagnostics = append(v.NodeDiagnostics, "retained unreadable node state")
	}
	if _, e := os.Lstat(d.Network.Tailscale.StateDir + ".backup"); e == nil {
		v.NodeDiagnostics = append(v.NodeDiagnostics, "node state replacement requires recovery")
	}
	if s.Enrollment != nil {
		if status == state.Enrolled {
			v.Node = d.Name + "." + s.Enrollment.Pin.Suffix
			v.NodeID = node.NodeID
			if s.Enrollment.Devices != nil {
				device, err := s.Enrollment.Devices.Get(ctx, node.NodeID)
				if err == nil && strings.EqualFold(strings.TrimSuffix(device.Name, "."), v.Node) {
					v.Addresses = device.Addresses
					v.Address = strings.Join(device.Addresses, ",")
					v.KeyExpiry = device.Expires
				}
			}
		}
		if consent := s.Enrollment.Registry.Current(d.ID, owner); consent != nil {
			v.ApprovalURL = consent.URL
			expiry := consent.Expires
			v.ApprovalExpires = &expiry
		}
	}
	return v
}
func (s *Service) removeDevice(ctx context.Context, node state.NodeIdentity, f func(string)) {
	if node.NodeID == "" {
		return
	}
	if s.Enrollment != nil && s.Config.Enrollment.DeleteDevices && s.Enrollment.Devices != nil {
		bounded, done := context.WithTimeout(ctx, 45*time.Second)
		defer done()
		if s.Enrollment.Devices.Delete(bounded, node.NodeID) == nil {
			f("device deleted: " + node.NodeID)
			return
		}
	}
	f("device_retained: " + node.NodeID)
}
