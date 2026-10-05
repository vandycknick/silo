package netnode

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/ipn/ipnstate"
)

// IdentityMetadata is host-injected policy metadata, never a guest assertion.
const IdentityMetadata = "io.silo.taild.node"

type ExpectedIdentity struct {
	Tags             []string `json:"tags,omitempty"`
	Bootstrap        string   `json:"bootstrap,omitempty"`
	DisableKeyExpiry bool     `json:"disable_key_expiry,omitempty"`
	Owner            string   `json:"owner"`
	Tailnet          string   `json:"tailnet"`
	Suffix           string   `json:"suffix"`
}

func ParseIdentity(metadata map[string]any) (*ExpectedIdentity, error) {
	v, ok := metadata[IdentityMetadata]
	if !ok {
		return nil, nil
	}
	raw, ok := v.(string)
	var expected ExpectedIdentity
	if !ok || len(raw) > 4096 || json.Unmarshal([]byte(raw), &expected) != nil || expected.Tailnet == "" || canonical(expected.Suffix) == "" {
		return nil, errors.New("invalid managed node identity")
	}
	if user, ok := strings.CutPrefix(expected.Owner, "user:"); ok {
		id, err := strconv.ParseInt(user, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != user {
			return nil, errors.New("invalid managed node owner")
		}
	} else if tag, ok := strings.CutPrefix(expected.Owner, "tag:"); !ok || tag == "" {
		return nil, errors.New("invalid managed node owner")
	}
	switch expected.Bootstrap {
	case "", "interactive", "auth_key", "client_secret":
	default:
		return nil, errors.New("invalid bootstrap mode")
	}
	if expected.Bootstrap == "client_secret" && !strings.HasPrefix(expected.Owner, "tag:") {
		return nil, errors.New("shared client credentials cannot authorize a human request")
	}
	if len(expected.Tags) > 32 {
		return nil, errors.New("too many node tags")
	}
	for _, tag := range expected.Tags {
		if !strings.HasPrefix(tag, "tag:") || len(tag) <= 4 || strings.ContainsAny(tag, " \t\r\n\x00") {
			return nil, errors.New("invalid node tag")
		}
	}
	slices.Sort(expected.Tags)
	expected.Tags = slices.Compact(expected.Tags)
	return &expected, nil
}

func canonical(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

func (e *ExpectedIdentity) verify(s *ipnstate.Status, hostname string) error {
	if e == nil {
		return nil
	}
	if s == nil || s.BackendState != "Running" || s.Self == nil || s.Self.ID == "" || s.CurrentTailnet == nil {
		return errors.New("node not connected")
	}
	if expired(s) {
		return errors.New("node key expired")
	}
	return e.verifyIdentity(s, hostname)
}

// Expired identities still carry useful display metadata. Verify that identity
// separately from the running/nonexpired checks required for guest traffic.
func (e *ExpectedIdentity) verifyIdentity(s *ipnstate.Status, hostname string) error {
	if s == nil || s.Self == nil || s.Self.ID == "" || s.CurrentTailnet == nil {
		return errors.New("node identity unavailable")
	}
	if e == nil {
		return nil
	}
	if s.CurrentTailnet.Name != e.Tailnet || canonical(s.CurrentTailnet.MagicDNSSuffix) != canonical(e.Suffix) || canonical(s.Self.DNSName) != canonical(hostname+"."+e.Suffix) {
		return errors.New("node identity mismatch")
	}
	if len(e.Tags) > 0 {
		if s.Self.Tags == nil {
			return errors.New("node tags missing")
		}
		actual := slices.Clone(s.Self.Tags.AsSlice())
		slices.Sort(actual)
		if slices.Equal(actual, e.Tags) {
			return nil
		}
		return errors.New("node tags mismatch")
	}
	if strings.HasPrefix(e.Owner, "tag:") {
		if s.Self.Tags != nil {
			for _, tag := range s.Self.Tags.AsSlice() {
				if tag == e.Owner {
					return nil
				}
			}
		}
	} else if s.Self.UserID != 0 && (s.Self.Tags == nil || s.Self.Tags.Len() == 0) && "user:"+strconv.FormatInt(int64(s.Self.UserID), 10) == e.Owner {
		return nil
	}
	return errors.New("node owner mismatch")
}

// VerifyAccess checks the live identity as well as the cached traffic gate.
// SSH calls it for authentication and periodic session reauthorization.
func (n *Node) VerifyAccess(ctx context.Context) error {
	if n.options.Identity == nil {
		return nil
	}
	client, err := n.LocalClient()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := client.StatusWithoutPeers(bounded)
	if err != nil {
		return err
	}
	return n.options.Identity.verify(status, n.options.Declaration.Hostname)
}

// Snapshot is a versioned observation, not a durable claim of connectivity.
// taild reads it only for the matching live VM run and within its freshness bound.
type Snapshot struct {
	LastKnown      *Observation `json:"last_known,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	Version        int          `json:"version"`
	VMID           string       `json:"vm_id"`
	RunID          string       `json:"run_id"`
	ObservedAt     time.Time    `json:"observed_at"`
	State          string       `json:"state"`
	ApprovalURL    string       `json:"approval_url,omitempty"`
	NodeID         string       `json:"node_id,omitempty"`
	DNSName        string       `json:"dns_name,omitempty"`
	ErrorCode      string       `json:"error_code,omitempty"`
	Addresses      []netip.Addr `json:"addresses,omitempty"`
	KeyExpiry      *time.Time   `json:"key_expiry,omitempty"`
	KeyExpiryKnown bool         `json:"key_expiry_known"`
}

// Observation is historical metadata, never a current traffic authorization.
// Its timestamp is retained when a later snapshot reports a disconnected node.
type Observation struct {
	ObservedAt time.Time  `json:"observed_at"`
	Owner      string     `json:"owner,omitempty"`
	Tailnet    string     `json:"tailnet"`
	NodeID     string     `json:"node_id"`
	DNSName    string     `json:"dns_name"`
	Tags       []string   `json:"tags,omitempty"`
	KeyExpiry  *time.Time `json:"key_expiry,omitempty"`
}

func expired(s *ipnstate.Status) bool {
	return s != nil && s.Self != nil && (s.Self.Expired || s.Self.KeyExpiry != nil && !s.Self.KeyExpiry.IsZero() && !s.Self.KeyExpiry.After(time.Now()))
}

func (n *Node) snapshot(s *ipnstate.Status) Snapshot {
	v := Snapshot{Version: 1, VMID: n.options.VMID, RunID: n.options.RunID, ObservedAt: time.Now().UTC(), State: "connecting"}
	if s == nil {
		return v
	}
	if expired(s) {
		v.State, v.ErrorCode = "approval_required", "key_expired"
		if s.Self != nil && s.Self.ID != "" && s.CurrentTailnet != nil {
			if n.options.Identity.verifyIdentity(s, n.options.Declaration.Hostname) != nil {
				v.State, v.ErrorCode = "failed", "identity_mismatch"
				return v
			}
			if s.Self.KeyExpiry != nil && !s.Self.KeyExpiry.IsZero() {
				v.NodeID, v.DNSName = string(s.Self.ID), canonical(s.Self.DNSName)
				v.KeyExpiry, v.KeyExpiryKnown = s.Self.KeyExpiry, true
				if s.Self.Tags != nil {
					v.Tags = slices.Clone(s.Self.Tags.AsSlice())
				}
			}
		}
		if validApprovalURL(s.AuthURL) {
			v.ApprovalURL = s.AuthURL
		}
		return v
	}
	switch s.BackendState {
	case "Running":
		if n.options.Identity.verify(s, n.options.Declaration.Hostname) != nil {
			v.State, v.ErrorCode = "failed", "identity_mismatch"
		} else if s.Self != nil {
			v.State, v.NodeID, v.DNSName = "ready", string(s.Self.ID), canonical(s.Self.DNSName)
			v.Addresses, v.KeyExpiry = s.Self.TailscaleIPs, s.Self.KeyExpiry
			v.KeyExpiryKnown = true
			if s.Self.Tags != nil {
				v.Tags = slices.Clone(s.Self.Tags.AsSlice())
			}
			if n.maintenanceFailed {
				v.ErrorCode = "key_expiry_update_failed"
			}
		}
	case "NeedsLogin":
		v.State = "approval_required"
	case "NeedsMachineAuth":
		v.State, v.ErrorCode = "approval_required", "device_approval_required"
	case "Stopped":
		v.State = "disconnected"
	}
	if v.State != "ready" && validApprovalURL(s.AuthURL) {
		v.State, v.ApprovalURL = "approval_required", s.AuthURL
	}
	return v
}

func validApprovalURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 1000 && u.Scheme == "https" && u.Host != "" && u.User == nil && !strings.ContainsAny(s, "\r\n\x1b")
}

func writeSnapshot(dir string, snapshot Snapshot) error {
	root, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(dir) + ".status.json"
	temp := ".node-status-" + rand.Text()
	f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	err = json.NewEncoder(f).Encode(snapshot)
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return root.Rename(temp, name)
}

// Caller serializes publication with node observations using n.mu.
func (n *Node) publish(snapshot Snapshot) {
	if (snapshot.State == "ready" || snapshot.ErrorCode == "key_expired") && snapshot.NodeID != "" && snapshot.DNSName != "" && snapshot.KeyExpiryKnown {
		o := &Observation{ObservedAt: snapshot.ObservedAt, NodeID: snapshot.NodeID, DNSName: snapshot.DNSName, Tags: slices.Clone(snapshot.Tags), KeyExpiry: snapshot.KeyExpiry}
		if n.options.Identity != nil {
			o.Owner, o.Tailnet = n.options.Identity.Owner, n.options.Identity.Tailnet
		}
		n.lastKnown = o
	} else if snapshot.ErrorCode == "identity_mismatch" {
		n.lastKnown = nil
	}
	snapshot.LastKnown = n.lastKnown
	if n.options.VMID == "" || n.options.RunID == "" {
		return
	}
	if err := writeSnapshot(n.options.Dir, snapshot); err != nil {
		slog.Warn("tailscale status unavailable", "error", err)
	}
}

// Restore only historical display metadata, not connection state or auth URLs.
func (n *Node) restoreObservation() {
	if n.options.Identity == nil {
		return
	}
	root, err := os.OpenRoot(filepath.Dir(n.options.Dir))
	if err != nil {
		return
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(n.options.Dir)+".status.json", os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Uid != uint32(os.Geteuid()) {
		return
	}
	var old Snapshot
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 || json.Unmarshal(b, &old) != nil || old.Version != 1 || old.VMID != n.options.VMID {
		return
	}
	o := old.LastKnown
	e := n.options.Identity
	if o == nil || o.ObservedAt.IsZero() || o.ObservedAt.After(time.Now()) || o.ObservedAt.After(old.ObservedAt) || o.Owner != e.Owner || o.Tailnet != e.Tailnet || o.DNSName != canonical(n.options.Declaration.Hostname+"."+e.Suffix) || o.NodeID == "" {
		return
	}
	tags := slices.Clone(o.Tags)
	slices.Sort(tags)
	expected := e.Tags
	if len(expected) == 0 && strings.HasPrefix(e.Owner, "tag:") {
		expected = []string{e.Owner}
	}
	if !slices.Equal(tags, expected) {
		return
	}
	n.lastKnown = o
}
