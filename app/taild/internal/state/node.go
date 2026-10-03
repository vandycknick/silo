package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/types/key"
)

type NodeState string

const (
	Pending    NodeState = "pending approval"
	Enrolled   NodeState = "enrolled"
	Expired    NodeState = "expired"
	Unreadable NodeState = "state unreadable"
	NoNode     NodeState = "none"
)

type NodeIdentity struct {
	NodeID  string
	NodeKey key.NodePublic
}

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
	return NodeIdentity{NodeID: string(p.NodeID), NodeKey: p.PrivateNodeKey.Public()}, Enrolled
}

// BeginNodeTransaction runs under the native lease. Sync the fence before any
// pending state is created, so a writer crash cannot admit another native writer.
func BeginNodeTransaction(dir string) error {
	file, e := os.OpenFile(dir+".transaction", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = file.WriteString("node-state-v1\n")
	return errors.Join(e, file.Sync(), file.Close(), SyncDir(filepath.Dir(dir)))
}

// FinishNodeTransaction runs under the native lease only after committing or
// safely aborting a transaction. Unknown recovery material keeps the fence.
func FinishNodeTransaction(dir string) error {
	for _, suffix := range []string{".pending", ".backup", ".unreadable"} {
		if exists(dir + suffix) {
			return errors.New("node state recovery required")
		}
	}
	e := os.Remove(dir + ".transaction")
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return SyncDir(filepath.Dir(dir))
}

func exists(path string) bool {
	_, e := os.Lstat(path)
	return !errors.Is(e, os.ErrNotExist)
}

// RecoverNode completes validated replacements of a stopped machine's node
// state; callers hold the native lease, so no VM can be running. Unknown or
// conflicting recovery material is retained and reported, never blindly erased.
func RecoverNode(dir, name string, owner identity.Principal, pin *NodePin) NodeState {
	canonicalNode, canonical := ReadNode(dir, name, owner, pin)
	pendingDir, backupDir := dir+".pending", dir+".backup"
	emptyDir := func(p string) bool {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() {
			return false
		}
		entries, e := os.ReadDir(p)
		return e == nil && len(entries) == 0
	}
	if !exists(pendingDir) && !exists(backupDir) {
		if exists(dir + ".unreadable") {
			return Unreadable
		}
		if exists(dir + ".transaction") {
			if canonical != Enrolled && !emptyDir(dir) {
				return Unreadable
			}
			if FinishNodeTransaction(dir) != nil {
				return Unreadable
			}
		}
		return canonical
	}
	pendingNode, pending := ReadNode(pendingDir, name, owner, pin)
	if pending == Enrolled && !VerifiedNode(pendingDir) {
		pending = Unreadable
	}
	backupNode, backup := ReadNode(backupDir, name, owner, pin)
	if pending == Enrolled && canonical == Enrolled && pendingNode.NodeID != canonicalNode.NodeID || backup == Enrolled && canonical == Enrolled && backupNode.NodeID != canonicalNode.NodeID || pending == Enrolled && backup == Enrolled && pendingNode.NodeID != backupNode.NodeID {
		return Unreadable
	}
	if canonical == Enrolled && pending != Enrolled {
		if exists(pendingDir) {
			return Unreadable
		}
		if exists(backupDir) && backup != Enrolled && !emptyDir(backupDir) {
			return Unreadable
		}
		if backup == Enrolled || emptyDir(backupDir) {
			if e := os.RemoveAll(backupDir); e != nil {
				return Unreadable
			}
			if SyncDir(filepath.Dir(dir)) != nil {
				return Unreadable
			}
		}
		if FinishNodeTransaction(dir) != nil {
			return Unreadable
		}
		return canonical
	}
	chosen := ""
	if pending == Enrolled {
		chosen = pendingDir
	} else if backup == Enrolled {
		chosen = backupDir
	}
	if chosen == "" {
		return Unreadable
	}
	if exists(dir) {
		destination := backupDir
		if canonical != Enrolled && !emptyDir(dir) {
			destination = dir + ".unreadable"
			if exists(destination) {
				return Unreadable
			}
		} else if exists(backupDir) {
			return Unreadable
		}
		if e := os.Rename(dir, destination); e != nil {
			return Unreadable
		}
		if SyncDir(filepath.Dir(dir)) != nil {
			return Unreadable
		}
	}
	if e := os.Rename(chosen, dir); e != nil {
		return Unreadable
	}
	if SyncDir(filepath.Dir(dir)) != nil {
		return Unreadable
	}
	_, result := ReadNode(dir, name, owner, pin)
	if result == Enrolled && exists(backupDir) && (backup == Enrolled || canonical == Enrolled || emptyDir(backupDir)) {
		if e := os.RemoveAll(backupDir); e != nil {
			return Unreadable
		}
		if SyncDir(filepath.Dir(dir)) != nil {
			return Unreadable
		}
	}
	if result == Enrolled && exists(backupDir) {
		return Unreadable
	}
	if result == Enrolled && FinishNodeTransaction(dir) != nil {
		return Unreadable
	}
	return result
}

// A promotion receipt binds the closed, status-verified state bytes. It is a
// transaction marker, not an identity database. A crash during login cannot
// cause an unverified (possibly auto-suffixed) pending node to be admitted.
func MarkVerifiedNode(dir string) error {
	b, e := os.ReadFile(filepath.Join(dir, "tailscaled.state"))
	if e != nil {
		return e
	}
	sum := sha256.Sum256(b)
	file, e := os.OpenFile(filepath.Join(dir, "promotion.verified"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = file.WriteString(hex.EncodeToString(sum[:]))
	return errors.Join(e, file.Sync(), file.Close(), SyncDir(dir))
}
func VerifiedNode(dir string) bool {
	path := filepath.Join(dir, "promotion.verified")
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() != 64 {
		return false
	}
	receipt, e := os.ReadFile(path)
	if e != nil {
		return false
	}
	path = filepath.Join(dir, "tailscaled.state")
	info, e = os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return false
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return false
	}
	sum := sha256.Sum256(b)
	return string(receipt) == hex.EncodeToString(sum[:])
}
