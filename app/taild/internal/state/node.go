package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
)

type NodeState string

const (
	Pending    NodeState = "pending approval"
	Enrolled   NodeState = "enrolled"
	Unreadable NodeState = "state unreadable"
	NoNode     NodeState = "none"
)

type NodeIdentity struct {
	NodeID   string
	UserID   int64
	Hostname string
}

// ReadNode uses the same public state/profile types as pinned tsnet. Never
// infer enrollment from a directory, cached netmap, or taild-owned record.
func ReadNode(dir, name string, owner identity.Principal) (NodeIdentity, NodeState) {
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
			copy := p
			profile = &copy
			break
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
	if p.NodeID == "" && p.PrivateNodeKey.IsZero() {
		return NodeIdentity{}, Pending
	}
	if p.NodeID == "" || p.PrivateNodeKey.IsZero() || profile.NodeID != p.NodeID || profile.UserProfile.ID != p.UserProfile.ID || prefs.Hostname != name {
		return NodeIdentity{}, Unreadable
	}
	if strings.HasPrefix(string(owner), "tag:") {
		if p.UserProfile.LoginName != "tagged-devices" || !slices.Contains(prefs.AdvertiseTags, string(owner)) {
			return NodeIdentity{}, Unreadable
		}
	} else if p.UserProfile.LoginName == "tagged-devices" || identity.Principal("user:"+strconv.FormatInt(int64(p.UserProfile.ID), 10)) != owner {
		return NodeIdentity{}, Unreadable
	}
	return NodeIdentity{string(p.NodeID), int64(p.UserProfile.ID), prefs.Hostname}, Enrolled
}

// RecoverNode completes only validated stopped-machine replacements. Unknown or
// conflicting recovery material is retained and reported, never blindly erased.
func RecoverNode(dir, name string, owner identity.Principal, stopped bool) NodeState {
	_, canonical := ReadNode(dir, name, owner)
	pendingDir, backupDir := dir+".pending", dir+".backup"
	exists := func(p string) bool { _, e := os.Lstat(p); return !errors.Is(e, os.ErrNotExist) }
	if !exists(pendingDir) && !exists(backupDir) {
		return canonical
	}
	if !stopped {
		return Unreadable
	}
	_, pending := ReadNode(pendingDir, name, owner)
	_, backup := ReadNode(backupDir, name, owner)
	if canonical == Enrolled && pending != Enrolled {
		if backup == Enrolled {
			if e := os.RemoveAll(backupDir); e != nil {
				return Unreadable
			}
			if SyncDir(filepath.Dir(dir)) != nil {
				return Unreadable
			}
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
		if canonical != Enrolled {
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
	_, result := ReadNode(dir, name, owner)
	if result == Enrolled && ((chosen == pendingDir && backup == Enrolled) || canonical == Enrolled) {
		if e := os.RemoveAll(backupDir); e != nil {
			return Unreadable
		}
		if SyncDir(filepath.Dir(dir)) != nil {
			return Unreadable
		}
	}
	return result
}
