package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
)

type NodeState string

const (
	Pending    NodeState = "pending approval"
	Enrolled   NodeState = "enrolled"
	Expired    NodeState = "expired"
	Unreadable NodeState = "state unreadable"
	NoNode     NodeState = "none"
)

type NodeIdentity struct{ NodeID string }

type NodePin struct{ Tailnet, Suffix, ControlURL string }

// This home-wide control identity is configuration, never per-VM node identity.
func PinNodeControl(home string, pin NodePin) error {
	pin.Suffix = strings.TrimSuffix(strings.ToLower(pin.Suffix), ".")
	pin.ControlURL = controlURL(pin.ControlURL)
	if pin.Tailnet == "" || pin.Suffix == "" {
		return errors.New("missing verified node control identity")
	}
	path := filepath.Join(home, "taild", "node-control")
	info, e := os.Lstat(path)
	if e == nil {
		if !info.Mode().IsRegular() || info.Size() > 4096 {
			return errors.New("node control pin unreadable")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var old NodePin
		if json.Unmarshal(b, &old) != nil || old != pin {
			return errors.New("node control identity differs from pin")
		}
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	b, e := json.Marshal(pin)
	if e != nil {
		return e
	}
	return AtomicWrite(path, b)
}

func controlURL(s string) string {
	if s == "" || s == "https://login.tailscale.com" {
		return ipn.DefaultControlURL
	}
	return strings.TrimSuffix(s, "/")
}

// ReadNode uses the same public state/profile types as pinned tsnet. Never
// infer enrollment from a directory, cached netmap, or taild-owned record.
// A pin, when the daemon has one, must match the control plane the profile
// was issued by.
func ReadNode(dir, name string, owner identity.Principal, pin *NodePin) (NodeIdentity, NodeState) {
	directory, e := os.Lstat(dir)
	if errors.Is(e, os.ErrNotExist) {
		return NodeIdentity{}, Pending
	}
	if e != nil || !directory.IsDir() {
		return NodeIdentity{}, Unreadable
	}
	path := filepath.Join(dir, "tailscaled.state")
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return NodeIdentity{}, Pending
	}
	if e != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return NodeIdentity{}, Unreadable
	}
	if info.Size() == 0 {
		return NodeIdentity{}, Pending
	}
	st, e := store.NewFileStore(func(string, ...any) {}, path)
	if e != nil {
		return NodeIdentity{}, Unreadable
	}
	current, e := st.ReadState(ipn.CurrentProfileStateKey)
	if errors.Is(e, ipn.ErrStateNotExist) || e == nil && len(current) == 0 {
		return NodeIdentity{}, Pending
	}
	if e != nil {
		return NodeIdentity{}, Unreadable
	}
	profiles, e := st.ReadState(ipn.KnownProfilesStateKey)
	if e != nil {
		return NodeIdentity{}, Unreadable
	}
	var known map[ipn.ProfileID]ipn.LoginProfile
	if json.Unmarshal(profiles, &known) != nil {
		return NodeIdentity{}, Unreadable
	}
	var profile *ipn.LoginProfile
	for _, p := range known {
		if string(p.Key) == string(current) {
			if profile != nil {
				return NodeIdentity{}, Unreadable
			}
			copy := p
			profile = &copy
		}
	}
	if profile == nil {
		return NodeIdentity{}, Unreadable
	}
	b, e := st.ReadState(profile.Key)
	if e != nil {
		return NodeIdentity{}, Unreadable
	}
	var prefs ipn.Prefs
	if ipn.PrefsFromBytes(b, &prefs) != nil || prefs.Persist == nil {
		return NodeIdentity{}, Unreadable
	}
	p := prefs.Persist
	if pin != nil && (profile.NetworkProfile.DomainName != pin.Tailnet || identity.CanonicalDNS(profile.NetworkProfile.MagicDNSName) != identity.CanonicalDNS(pin.Suffix) || controlURL(profile.ControlURL) != controlURL(pin.ControlURL) || controlURL(prefs.ControlURL) != controlURL(pin.ControlURL)) {
		return NodeIdentity{}, Unreadable
	}
	if p.NodeID == "" && p.PrivateNodeKey.IsZero() {
		return NodeIdentity{}, Pending
	}
	if p.NodeID == "" || p.PrivateNodeKey.IsZero() || profile.NodeID != p.NodeID || profile.UserProfile.ID != p.UserProfile.ID || prefs.Hostname != name {
		return NodeIdentity{}, Unreadable
	}
	if owner.IsTag() {
		if p.UserProfile.LoginName != "tagged-devices" || !slices.Contains(prefs.AdvertiseTags, string(owner)) {
			return NodeIdentity{}, Unreadable
		}
	} else if p.UserProfile.ID == 0 || p.UserProfile.LoginName == "tagged-devices" || len(prefs.AdvertiseTags) != 0 || identity.UserPrincipal(int64(p.UserProfile.ID)) != owner {
		return NodeIdentity{}, Unreadable
	}
	return NodeIdentity{NodeID: string(p.NodeID)}, Enrolled
}
