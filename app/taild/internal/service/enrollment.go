package service

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
)

func (s *Service) pin() *state.NodePin {
	if s.Enrollment == nil {
		return nil
	}
	return &s.Enrollment.Pin
}

// Prepare only launch metadata and legacy transaction recovery. Netd owns all
// authentication, including expired or rejected identities in ordinary state.
func (s *Service) prepareNode(ctx context.Context, c Caller, action identity.Action, m *silo.Machine, d *silo.MachineData) error {
	if d.Network.Tailscale == nil {
		return nil
	}
	if s.Enrollment == nil {
		return failure("unavailable", "enrollment unavailable", 9)
	}
	lease, err := m.LeaseNodeState(ctx)
	if err != nil {
		return Categorize(err)
	}
	defer lease.Close()
	dir := d.Network.Tailscale.StateDir
	for _, suffix := range []string{".transaction", ".pending", ".backup", ".unreadable"} {
		if _, e := os.Lstat(dir + suffix); e == nil || !os.IsNotExist(e) {
			if state.RecoverNode(dir, d.Name, runtime.NodeOwner(d), s.pin()) == state.Unreadable {
				return failure("conflict", "retained node state requires recovery", 5)
			}
			break
		}
	}
	// Updating the policy takes the native node-state lock itself.
	_ = lease.Close()
	if err = s.reauthorize(ctx, c, action, d); err != nil {
		return err
	}
	v := project(d)
	if err = s.storeNodeCredentials(ctx, m, v.Owner, nil); err != nil {
		return err
	}
	if len(v.Tags) == 0 && v.Owner.IsTag() {
		v.Tags = []string{string(v.Owner)}
	}
	policy, err := s.bindNodeIdentity(d.Network.Policy, v.Owner, v.Tags, enroll.Mode(d.Labels[runtime.ModeLabel]))
	if err != nil {
		return err
	}
	if d.Network.Policy == nil || policy.JSON() != d.Network.Policy.JSON() {
		network := d.Network
		network.Policy = policy
		if _, err = m.Update(ctx, silo.MachineUpdate{Network: &network}); err != nil {
			return Categorize(err)
		}
	}
	return nil
}

func (s *Service) storeNodeCredentials(ctx context.Context, m *silo.Machine, owner identity.Principal, key []byte) error {
	if len(key) > 0 {
		if err := m.SetSecret(ctx, "tailscale.vm.auth_key", key); err != nil {
			return Categorize(err)
		}
	}
	if owner.IsTag() && s.Enrollment.Secrets.ClientSecret != "" {
		value := []byte(s.Enrollment.Secrets.ClientSecret)
		defer clear(value)
		if err := m.SetSecret(ctx, "tailscale.vm.client_secret", value); err != nil {
			return Categorize(err)
		}
	}
	if s.Config.Enrollment.DisableKeyExpiry && s.Enrollment.Secrets.APIToken != "" {
		value := []byte(s.Enrollment.Secrets.APIToken)
		defer clear(value)
		if err := m.SetSecret(ctx, "tailscale.vm.api_token", value); err != nil {
			return Categorize(err)
		}
	}
	return nil
}

func (s *Service) bindNodeIdentity(policy *silo.NetworkPolicy, owner identity.Principal, tags []string, mode enroll.Mode) (*silo.NetworkPolicy, error) {
	if policy == nil || s.pin() == nil || s.pin().Tailnet == "" || s.pin().Suffix == "" {
		return nil, failure("unavailable", "verified tailnet identity unavailable", 9)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(policy.JSON()), &root); err != nil {
		return nil, Categorize(err)
	}
	metadata := map[string]json.RawMessage{}
	if raw := root["metadata"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, Categorize(err)
		}
	}
	if metadata == nil {
		metadata = map[string]json.RawMessage{}
	}
	bootstrap := "interactive"
	if mode == enroll.User {
		bootstrap = "auth_key"
	} else if mode == enroll.Tag {
		bootstrap = "client_secret"
	}
	expected, err := json.Marshal(struct {
		Owner            identity.Principal `json:"owner"`
		Tags             []string           `json:"tags,omitempty"`
		Tailnet          string             `json:"tailnet"`
		Suffix           string             `json:"suffix"`
		Bootstrap        string             `json:"bootstrap"`
		DisableKeyExpiry bool               `json:"disable_key_expiry,omitempty"`
	}{owner, tags, s.pin().Tailnet, s.pin().Suffix, bootstrap, s.Config.Enrollment.DisableKeyExpiry})
	if err != nil {
		return nil, Categorize(err)
	}
	if len(expected) > 4096 {
		return nil, failure("usage", "node identity metadata exceeds size limit", 2)
	}
	metadata["io.silo.taild.node"], err = json.Marshal(string(expected))
	if err != nil {
		return nil, Categorize(err)
	}
	root["metadata"], err = json.Marshal(metadata)
	if err != nil {
		return nil, Categorize(err)
	}
	raw, err := json.Marshal(root)
	if err != nil {
		return nil, Categorize(err)
	}
	return silo.ParseNetworkPolicyJSON(string(raw))
}

func (s *Service) nodeView(d *silo.MachineData) VM {
	v := project(d)
	v.NodeState = state.NoNode
	v.Address = "unknown"
	v.KeyExpiry = "unknown"
	if d.Network.Tailscale == nil {
		return v
	}
	if d.Status.Kind == silo.MachineStatusRunning {
		return s.liveNodeView(d, v)
	}
	v.NodeState = state.NodeState(string(d.Status.Kind))
	if s.pin() != nil {
		v.Node = identity.CanonicalDNS(d.Network.Tailscale.Hostname + "." + s.pin().Suffix)
	}
	if d.Status.Kind == silo.MachineStatusStopped {
		if o, err := state.ReadNodeObservation(d.Network.Tailscale.StateDir, d.ID, time.Now()); err == nil && s.pin() != nil && o.Owner == string(v.Owner) && o.Tailnet == s.pin().Tailnet && o.DNSName == v.Node && sameTags(v.Tags, o.Tags) {
			v.NodeID = o.NodeID
			setExpiry(&v, o.KeyExpiry, o.ObservedAt, true)
		}
	}
	return v
}

func sameTags(requested, actual []string) bool {
	a, b := slices.Clone(requested), slices.Clone(actual)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func setExpiry(v *VM, expiry *time.Time, observed time.Time, historical bool) {
	v.KeyExpiry = "never"
	if expiry != nil && !expiry.IsZero() {
		v.KeyExpiry = expiry.UTC().Format(time.RFC3339)
	}
	v.KeyExpiryObservedAt = &observed
	v.KeyExpiryLastKnown = historical
}

func (s *Service) liveNodeView(d *silo.MachineData, v VM) VM {
	v.NodeState = state.NodeState("status unavailable")
	if v.KeyExpiry == "" {
		v.KeyExpiry = "unknown"
	}
	if d.RunID == nil {
		return v
	}
	status, err := state.ReadNetdStatus(d.Network.Tailscale.StateDir, d.ID, *d.RunID, time.Now())
	if err != nil {
		return v
	}
	v.Tags = project(d).Tags
	switch status.State {
	case "ready":
		if s.pin() == nil || status.NodeID == "" || status.DNSName != identity.CanonicalDNS(d.Network.Tailscale.Hostname+"."+s.pin().Suffix) {
			v.NodeState = state.Unreadable
			return v
		}
		if !sameTags(v.Tags, status.Tags) {
			v.NodeState = state.Unreadable
			return v
		}
		v.NodeState, v.NodeID, v.Node = state.Enrolled, status.NodeID, status.DNSName
		for _, address := range status.Addresses {
			v.Addresses = append(v.Addresses, address.String())
		}
		if len(v.Addresses) > 0 {
			v.Address = strings.Join(v.Addresses, ",")
		}
		if status.KeyExpiryKnown {
			setExpiry(&v, status.KeyExpiry, status.ObservedAt, false)
		}
		if status.KeyExpiry != nil {
			if !status.KeyExpiry.IsZero() && !status.KeyExpiry.After(time.Now()) {
				v.NodeState, v.Node = state.Expired, ""
			}
		}
		if status.ErrorCode == "key_expiry_update_failed" {
			v.NodeDiagnostics = append(v.NodeDiagnostics, "key-expiry policy update pending; netd will retry")
		}
	case "approval_required":
		v.NodeState, v.ApprovalURL = state.Pending, status.ApprovalURL
		if status.ErrorCode == "key_expired" && status.KeyExpiryKnown && status.KeyExpiry != nil && !status.KeyExpiry.IsZero() && s.pin() != nil && status.NodeID != "" && status.DNSName == identity.CanonicalDNS(d.Network.Tailscale.Hostname+"."+s.pin().Suffix) && sameTags(v.Tags, status.Tags) {
			setExpiry(&v, status.KeyExpiry, status.ObservedAt, false)
		}
		if status.ErrorCode == "device_approval_required" {
			v.NodeDiagnostics = append(v.NodeDiagnostics, "device approval required in the Tailscale admin console")
		}
	case "failed":
		v.NodeState = state.NodeState("enrollment failed")
		v.NodeDiagnostics = append(v.NodeDiagnostics, "node enrollment failed; inspect network logs")
	default:
		v.NodeState = state.NodeState(status.State)
	}
	if v.KeyExpiry == "unknown" && status.LastKnown != nil && s.pin() != nil && status.ErrorCode != "identity_mismatch" {
		o := status.LastKnown
		if o.Owner == string(v.Owner) && o.Tailnet == s.pin().Tailnet && o.DNSName == identity.CanonicalDNS(d.Network.Tailscale.Hostname+"."+s.pin().Suffix) && sameTags(v.Tags, o.Tags) && !o.ObservedAt.IsZero() && !o.ObservedAt.After(status.ObservedAt) {
			setExpiry(&v, o.KeyExpiry, o.ObservedAt, true)
		}
	}
	return v
}

func (s *Service) completeNode(ctx context.Context, m *silo.Machine, out *jobs.Completion, progress func(string)) {
	d, err := m.Inspect(ctx)
	if err != nil || d.Network.Tailscale == nil {
		return
	}
	progress("checking Tailscale onboarding link")
	grace, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		v := s.liveNodeView(d, project(d))
		out.NodeState, out.Node, out.ApprovalURL = string(v.NodeState), v.Node, v.ApprovalURL
		if v.ApprovalURL != "" || v.NodeState == state.Enrolled || v.NodeState == state.NodeState("enrollment failed") || v.NodeState == state.Unreadable {
			return
		}
		select {
		case <-grace.Done():
			return
		case <-ticker.C:
		}
	}
}
