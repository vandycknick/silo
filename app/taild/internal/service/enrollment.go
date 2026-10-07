package service

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/control"
	"github.com/vandycknick/silo/app/taild/internal/enroll"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/jobs"
	"github.com/vandycknick/silo/app/taild/internal/runtime"
	"github.com/vandycknick/silo/app/taild/internal/state"
	silo "github.com/vandycknick/silo/sdk/go"
	w "github.com/vandycknick/silo/specs/protocol/go/silo/daemon/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Service) pin() *state.NodePin {
	if s.Enrollment == nil {
		return nil
	}
	return &s.Enrollment.Pin
}

// nodeDNS is the MagicDNS name the pinned tailnet gives this VM's node.
func (s *Service) nodeDNS(d *silo.MachineData) string {
	if s.pin() == nil {
		return ""
	}
	return identity.CanonicalDNS(d.Network.Tailscale.Hostname + "." + s.pin().Suffix)
}

// matchesNode reports whether a recorded observation describes this VM's node
// on the pinned tailnet, so historical identity is never shown for another.
func (s *Service) matchesNode(o *w.NodeObservation, v VM, dns string) bool {
	return s.pin() != nil && o.MachineId == v.ID && o.Owner == string(v.Owner) && o.Tailnet == s.pin().Tailnet && o.DnsName == dns && sameTags(v.Tags, o.Tags)
}

// Prepare launch policy and credentials; netd owns retained node state.
func (s *Service) prepareNode(ctx context.Context, c Caller, action identity.Action, d *control.Snapshot) error {
	if d.Network.Tailscale == nil {
		return nil
	}
	if s.Enrollment == nil {
		return failure("unavailable", "enrollment unavailable", 9)
	}
	v := project(d.MachineData)
	if err := s.storeNodeCredentials(ctx, c, action, d, v.Owner, nil); err != nil {
		return err
	}
	if len(v.Tags) == 0 && v.Owner.IsTag() {
		v.Tags = []string{string(v.Owner)}
	}
	if err := s.reauthorize(ctx, c, action, d); err != nil {
		return err
	}
	policy, err := s.bindNodeIdentity(ctx, &control.Policy{CanonicalJSON: d.PolicyJSON}, v.Owner, v.Tags, enroll.Mode(d.Labels[runtime.ModeLabel]))
	if err != nil {
		return err
	}
	if policy.CanonicalJSON != d.PolicyJSON {
		if err = s.reauthorize(ctx, c, action, d); err != nil {
			return err
		}
		_, err = s.Runtime.Control.Update(ctx, d.ID, &w.MachineUpdate{Policy: &w.PolicyUpdate{Update: &w.PolicyUpdate_Set{Set: policy.CanonicalJSON}}})
		if err != nil {
			return Categorize(err)
		}
	}
	return nil
}

func (s *Service) storeNodeCredentials(ctx context.Context, c Caller, action identity.Action, d *control.Snapshot, owner identity.Principal, key []byte) error {
	set := func(name string, value []byte) error {
		if err := s.reauthorize(ctx, c, action, d); err != nil {
			return err
		}
		if err := s.Runtime.Control.SetSecret(ctx, d.ID, name, value); err != nil {
			return Categorize(err)
		}
		return nil
	}
	if len(key) > 0 {
		if err := set("tailscale.vm.auth_key", key); err != nil {
			return err
		}
	}
	if owner.IsTag() && s.Enrollment.Secrets.ClientSecret != "" {
		value := []byte(s.Enrollment.Secrets.ClientSecret)
		defer clear(value)
		if err := set("tailscale.vm.client_secret", value); err != nil {
			return err
		}
	}
	if s.Config.Enrollment.DisableKeyExpiry && s.Enrollment.Secrets.APIToken != "" {
		value := []byte(s.Enrollment.Secrets.APIToken)
		defer clear(value)
		if err := set("tailscale.vm.api_token", value); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) bindNodeIdentity(ctx context.Context, policy *control.Policy, owner identity.Principal, tags []string, mode enroll.Mode) (*control.Policy, error) {
	if policy == nil || s.pin() == nil || s.pin().Tailnet == "" || s.pin().Suffix == "" {
		return nil, failure("unavailable", "verified tailnet identity unavailable", 9)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(policy.CanonicalJSON), &root); err != nil {
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
	return s.Runtime.Control.NormalizePolicy(ctx, &w.NormalizePolicyRequest{Input: &w.NormalizePolicyRequest_CanonicalJson{CanonicalJson: string(raw)}})
}

func (s *Service) nodeView(d *control.Snapshot) VM {
	v := project(d.MachineData)
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
	v.Node = s.nodeDNS(d.MachineData)
	if d.Status.Kind == silo.MachineStatusStopped {
		if o := d.NetworkObservation.GetHistorical(); o != nil && s.matchesNode(o, v, v.Node) {
			v.NodeID = o.NodeId
			setExpiry(&v, timestamp(o.KeyExpiry), o.ObservedAt.AsTime(), true)
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

func (s *Service) liveNodeView(d *control.Snapshot, v VM) VM {
	v.NodeState = state.NodeState("status unavailable")
	if v.KeyExpiry == "" {
		v.KeyExpiry = "unknown"
	}
	if d.RunID == nil {
		return v
	}
	status := d.NetworkObservation.GetLive()
	if status == nil || status.MachineId != d.ID || status.RunId != *d.RunID {
		return v
	}
	dns := s.nodeDNS(d.MachineData)
	switch status.State {
	case w.NodeState_NODE_STATE_READY:
		if dns == "" || status.GetNodeId() == "" || status.GetDnsName() != dns {
			v.NodeState = state.Unreadable
			return v
		}
		if !sameTags(v.Tags, status.Tags) {
			v.NodeState = state.Unreadable
			return v
		}
		v.NodeState, v.NodeID, v.Node = state.Enrolled, status.GetNodeId(), status.GetDnsName()
		for _, address := range status.Addresses {
			v.Addresses = append(v.Addresses, address)
		}
		if len(v.Addresses) > 0 {
			v.Address = strings.Join(v.Addresses, ",")
		}
		if status.KeyExpiryKnown {
			setExpiry(&v, timestamp(status.KeyExpiry), status.UpdatedAt.AsTime(), false)
		}
		if status.KeyExpiry != nil {
			if !status.KeyExpiry.AsTime().After(time.Now()) {
				v.NodeState, v.Node = state.Expired, ""
			}
		}
		if status.GetErrorCode() == "key_expiry_update_failed" {
			v.NodeDiagnostics = append(v.NodeDiagnostics, "key-expiry policy update pending; netd will retry")
		}
	case w.NodeState_NODE_STATE_APPROVAL_REQUIRED:
		v.NodeState, v.ApprovalURL = state.Pending, status.GetApprovalUrl()
		if status.GetErrorCode() == "key_expired" && status.KeyExpiryKnown && status.KeyExpiry != nil && dns != "" && status.GetNodeId() != "" && status.GetDnsName() == dns && sameTags(v.Tags, status.Tags) {
			setExpiry(&v, timestamp(status.KeyExpiry), status.UpdatedAt.AsTime(), false)
		}
		if status.GetErrorCode() == "device_approval_required" {
			v.NodeDiagnostics = append(v.NodeDiagnostics, "device approval required in the Tailscale admin console")
		}
	case w.NodeState_NODE_STATE_FAILED:
		v.NodeState = state.NodeState("enrollment failed")
		v.NodeDiagnostics = append(v.NodeDiagnostics, "node enrollment failed; inspect network logs")
	default:
		v.NodeState = state.NodeState(strings.ToLower(strings.TrimPrefix(status.State.String(), "NODE_STATE_")))
	}
	if o := d.NetworkObservation.GetHistorical(); v.KeyExpiry == "unknown" && o != nil && status.GetErrorCode() != "identity_mismatch" && s.matchesNode(o, v, dns) && o.ObservedAt != nil && !o.ObservedAt.AsTime().After(status.UpdatedAt.AsTime()) {
		setExpiry(&v, timestamp(o.KeyExpiry), o.ObservedAt.AsTime(), true)
	}
	return v
}

func (s *Service) completeNode(ctx context.Context, id string, out *jobs.Completion, progress func(string)) {
	d, err := s.Runtime.Control.Inspect(ctx, id)
	if err != nil || d.Network.Tailscale == nil {
		return
	}
	progress("checking Tailscale onboarding link")
	grace, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		d, err = s.Runtime.Control.Inspect(grace, id)
		if err != nil {
			return
		}
		v := s.liveNodeView(d, project(d.MachineData))
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

func timestamp(value *timestamppb.Timestamp) *time.Time {
	if value == nil {
		return nil
	}
	t := value.AsTime()
	return &t
}
