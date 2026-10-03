package service

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

// pin is the daemon's node control identity, absent when enrollment is off.
func (s *Service) pin() *state.NodePin {
	if s.Enrollment == nil {
		return nil
	}
	return &s.Enrollment.Pin
}

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
	node, status := state.ReadNode(d.Network.Tailscale.StateDir, d.Name, owner, s.pin())
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
				if errors.Is(err, enroll.ErrDeviceNotFound) {
					v.NodeState = state.Expired
					v.NodeDiagnostics = append(v.NodeDiagnostics, "device no longer registered; stop and reauth")
				}
				if err != nil && !errors.Is(err, enroll.ErrDeviceNotFound) {
					v.NodeDiagnostics = append(v.NodeDiagnostics, "device status unavailable")
				}
				if errors.Is(err, enroll.ErrInvalidDeviceResponse) || err == nil && !strings.EqualFold(strings.TrimSuffix(device.Name, "."), v.Node) {
					v.NodeState = state.Unreadable
					v.NodeDiagnostics = append(v.NodeDiagnostics, "device identity response unreadable")
				}
				if err == nil && strings.EqualFold(strings.TrimSuffix(device.Name, "."), v.Node) {
					v.Addresses = device.Addresses
					v.Address = strings.Join(device.Addresses, ",")
					v.KeyExpiry = device.Expires
					if expiry, err := time.Parse(time.RFC3339, device.Expires); err == nil && !expiry.IsZero() && !expiry.After(time.Now()) {
						v.NodeState = state.Expired
					}
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
