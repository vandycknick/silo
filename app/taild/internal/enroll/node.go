package enroll

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	silo "github.com/vandycknick/silo/sdk/go"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
)

type Manager struct {
	Config   config.Config
	Secrets  config.Secrets
	Pin      state.NodePin
	Registry *Registry
	OAuth    *OAuth
	Devices  *Devices
	Timeout  time.Duration
	Visible  func(context.Context) (*ipnstate.Status, error)
}

func canonicalDNS(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

func NameTaken(status *ipnstate.Status, name, ownID string, pin state.NodePin) bool {
	if status == nil {
		return true
	}
	check := func(peer *ipnstate.PeerStatus) bool {
		return peer != nil && string(peer.ID) != ownID && canonicalDNS(peer.DNSName) == canonicalDNS(name+"."+pin.Suffix)
	}
	if check(status.Self) {
		return true
	}
	for _, peer := range status.Peer {
		if check(peer) {
			return true
		}
	}
	return false
}
func Verify(status *ipnstate.Status, name string, owner identity.Principal, pin state.NodePin) error {
	if status == nil || status.BackendState != "Running" || status.Self == nil || status.Self.ID == "" || status.CurrentTailnet == nil || status.CurrentTailnet.Name != pin.Tailnet || canonicalDNS(status.CurrentTailnet.MagicDNSSuffix) != canonicalDNS(pin.Suffix) {
		return errors.New("node tailnet identity mismatch")
	}
	if canonicalDNS(status.Self.DNSName) != canonicalDNS(name+"."+pin.Suffix) {
		return errors.New("assigned node name differs from exact requested name")
	}
	if strings.HasPrefix(string(owner), "tag:") {
		if status.Self.Tags == nil || !slices.Contains(status.Self.Tags.AsSlice(), string(owner)) {
			return errors.New("node owner tag mismatch")
		}
	} else {
		if status.Self.UserID == 0 || status.Self.Tags != nil && status.Self.Tags.Len() > 0 || identity.Principal("user:"+strconv.FormatInt(int64(status.Self.UserID), 10)) != owner {
			return errors.New("node owner mismatch")
		}
	}
	return nil
}
func approvalError(message string) error {
	return &authz.Error{Code: "pending_approval", Message: message, Exit: 8}
}
func (m *Manager) Mode(owner identity.Principal, optOut bool) Mode {
	return Select(owner, m.Config.Enrollment.Mode, m.Secrets.AppSecret, optOut)
}
func (m *Manager) Enroll(ctx context.Context, machine *silo.Machine, data *silo.MachineData, owner identity.Principal, reauth bool, progress func(string), validate func(context.Context) error) error {
	if data.Network.Tailscale == nil {
		return nil
	}
	lease, err := machine.LeaseNodeState(ctx)
	if err != nil {
		return &authz.Error{Code: "conflict", Message: "VM node state busy or VM running", Exit: 5}
	}
	defer lease.Close()
	dir := data.Network.Tailscale.StateDir
	if state.RecoverNode(dir, data.Name, owner, true, m.Pin) == state.Unreadable {
		return approvalError("state unreadable; recover retained state or clean up the stale device before retrying")
	}
	old, nodeState := state.ReadNode(dir, data.Name, owner, m.Pin)
	if nodeState == state.Enrolled && !reauth {
		return m.postEnroll(ctx, old.NodeID, progress)
	}
	if nodeState == state.Unreadable {
		return approvalError("state unreadable; stale device cleanup required")
	}
	if m.Visible != nil {
		status, e := m.Visible(ctx)
		if e != nil || status == nil {
			return approvalError("tailnet name inventory unavailable")
		}
		if NameTaken(status, data.Name, old.NodeID, m.Pin) {
			return approvalError("name already taken on tailnet")
		}
	}
	mode := m.Mode(owner, false)
	if mode == None {
		return approvalError("enrollment disabled for existing node declaration")
	}
	token := ""
	if mode == User {
		if m.OAuth == nil {
			return approvalError("configured OAuth app unavailable")
		}
		nonce, c, e := m.Registry.Begin(data.ID, owner, m.OAuth.ClientID, m.OAuth.Redirect)
		if e != nil {
			return approvalError("consent unavailable")
		}
		defer m.Registry.Cancel(nonce)
		progress("approve: " + c.URL)
		token, err = c.Wait(ctx)
		if err != nil {
			return approvalError("approval expired or interrupted; start to obtain a fresh link")
		}
	} else if mode == Tag {
		token, err = tailnet.Mint(ctx, &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, "https://api.tailscale.com", m.Secrets.ClientSecret, string(owner))
		if err != nil {
			return approvalError("tag credential mint failed")
		}
	}
	if token != "" && !validToken(token) {
		return approvalError("invalid provisioning token")
	}
	if validate != nil {
		if e := validate(ctx); e != nil {
			return e
		}
	}
	pending := dir + ".pending"
	if err = state.BeginNodeTransaction(dir); err != nil {
		return approvalError("node state transaction requires recovery")
	}
	if err = os.Mkdir(pending, 0700); err != nil {
		return approvalError("pending node state requires recovery")
	}
	promoted := false
	defer func() {
		if !promoted {
			if os.RemoveAll(pending) == nil && state.SyncDir(filepath.Dir(dir)) == nil {
				_ = state.FinishNodeTransaction(dir)
			}
		}
	}()
	if old.NodeID != "" {
		if err = copyState(dir, pending); err != nil {
			return approvalError("cannot copy validated node state")
		}
		if err = os.Remove(filepath.Join(pending, "promotion.verified")); err != nil && !os.IsNotExist(err) {
			return approvalError("cannot prepare copied state")
		}
	}
	server := &tsnet.Server{Dir: pending, Hostname: data.Name, ControlURL: m.Pin.ControlURL, AuthKey: token, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
	if mode == Tag {
		server.AdvertiseTags = []string{string(owner)}
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout, _ = time.ParseDuration(m.Config.Enrollment.Timeout)
	}
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer m.Registry.ClearLink(data.ID)
	linkProgress := func(line string) {
		progress(line)
		if strings.HasPrefix(line, "approve: ") {
			deadline, _ := attempt.Deadline()
			m.Registry.Link(data.ID, owner, strings.TrimPrefix(line, "approve: "), deadline)
		}
	}
	if err = server.Start(); err != nil {
		_ = server.Close()
		return approvalError("temporary node startup failed")
	}
	closed := false
	candidateID := ""
	defer func() {
		if !closed {
			if server.Close() != nil {
				promoted = true
			}
		}
		if !promoted && candidateID == "" {
			// A device awaiting approval may persist its ID before Status has Self.
			// Capture public profile identity before removing owned pending state.
			stored, kind := state.ReadNode(pending, data.Name, owner)
			candidateID = stored.NodeID
			if kind == state.Unreadable {
				promoted = true
				progress("device_retained: unknown (state unreadable)")
			}
		}
		if !promoted {
			cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
			defer done()
			m.cleanup(cleanup, candidateID, old.NodeID, progress)
		}
	}()
	lc, err := server.LocalClient()
	if err != nil {
		return approvalError("temporary node client unavailable")
	}
	if reauth && old.NodeID != "" {
		// Start alone reuses logged-in state. Explicit interactive login forces a key refresh.
		if token != "" {
			if err = lc.Start(attempt, ipn.Options{AuthKey: token}); err != nil {
				return approvalError("reauth setup failed")
			}
		}
		watcher, e := lc.WatchIPNBus(attempt, 0)
		if e != nil {
			return approvalError("reauth watch failed")
		}
		defer watcher.Close()
		if err = lc.StartLoginInteractive(attempt); err != nil {
			return approvalError("explicit reauth failed")
		}
		for {
			n, e := watcher.Next()
			if e != nil {
				return approvalError("reauth did not complete")
			}
			if n.BrowseToURL != nil {
				publishLink(*n.BrowseToURL, linkProgress)
			}
			if n.LoginFinished != nil {
				break
			}
		}
	}
	lastLink := ""
	var status *ipnstate.Status
	for {
		if attempt.Err() != nil {
			return approvalError("node approval timed out; VM remains stopped")
		}
		call, done := context.WithTimeout(attempt, 5*time.Second)
		status, err = lc.StatusWithoutPeers(call)
		done()
		if err == nil && status != nil {
			if status.Self != nil {
				candidateID = string(status.Self.ID)
			}
			if status.AuthURL != "" && status.AuthURL != lastLink {
				publishLink(status.AuthURL, linkProgress)
				lastLink = status.AuthURL
			}
			if status.BackendState == "Running" && (!reauth || old.NodeID == "" || status.Self != nil && !status.Self.PublicKey.IsZero() && status.Self.PublicKey != old.NodeKey) {
				break
			}
		}
		select {
		case <-attempt.Done():
			return approvalError("node approval timed out; VM remains stopped")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if err = Verify(status, data.Name, owner, m.Pin); err != nil {
		return approvalError(err.Error())
	}
	if old.NodeID != "" && candidateID != old.NodeID {
		return approvalError("reauth changed stable node identity; prior state retained")
	}
	if err = server.Close(); err != nil {
		closed = true
		promoted = true
		return approvalError("temporary node close failed")
	}
	closed = true
	if err = checkClosedNode(pending, data.Name, owner, m.Pin, candidateID, status.Self.PublicKey, old, reauth); err != nil {
		return err
	}
	if err = syncTree(pending); err != nil {
		return approvalError("node state sync failed")
	}
	if err = state.MarkVerifiedNode(pending); err != nil {
		return approvalError("node promotion receipt failed")
	}
	if validate != nil {
		if e := validate(ctx); e != nil {
			return e
		}
	}
	if err = os.Rename(dir, dir+".backup"); err != nil && !os.IsNotExist(err) {
		return approvalError("node state backup failed")
	}
	promoted = true
	if err = state.SyncDir(filepath.Dir(dir)); err != nil {
		return approvalError("node state promotion requires recovery")
	}
	if err = os.Rename(pending, dir); err != nil {
		return approvalError("node state promotion requires recovery")
	}
	if err = state.SyncDir(filepath.Dir(dir)); err != nil {
		return approvalError("node state promotion requires recovery")
	}
	if state.RecoverNode(dir, data.Name, owner, true, m.Pin) != state.Enrolled {
		return approvalError("node state promotion requires recovery")
	}
	progress("node enrolled: " + data.Name + "." + m.Pin.Suffix)
	return m.postEnroll(ctx, candidateID, progress)
}

// Local API preferences redact private keys. After Close, use public IPN state
// to derive the persisted public key and bind it to the observed current netmap.
func checkClosedNode(dir, name string, owner identity.Principal, pin state.NodePin, id string, observed key.NodePublic, old state.NodeIdentity, reauth bool) error {
	stored, kind := state.ReadNode(dir, name, owner, pin)
	if kind != state.Enrolled || stored.NodeID != id || observed.IsZero() || stored.NodeKey != observed {
		return approvalError("persisted node identity or public key mismatch")
	}
	if reauth && old.NodeID != "" && (stored.NodeID != old.NodeID || stored.NodeKey == old.NodeKey) {
		return approvalError("reauth did not preserve stable identity and refresh its node key")
	}
	return nil
}
func (m *Manager) postEnroll(ctx context.Context, id string, progress func(string)) error {
	if !m.Config.Enrollment.DisableKeyExpiry {
		return nil
	}
	bounded, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	if m.Devices == nil || m.Devices.DisableExpiry(bounded, id) != nil {
		return &authz.Error{Code: "unavailable", Message: "node enrolled; configured key-expiry update failed", Exit: 9}
	}
	progress("device key expiry disabled")
	return nil
}
func publishLink(link string, progress func(string)) {
	u, err := url.Parse(link)
	if err == nil && len(link) <= 1000 && u.Scheme == "https" && u.Host != "" && u.User == nil && !strings.ContainsAny(link, "\r\n") {
		progress("approve: " + link)
	}
}
func (m *Manager) cleanup(ctx context.Context, id, old string, progress func(string)) {
	if id == "" || id == old {
		return
	}
	if m.Devices != nil && m.Config.Enrollment.DeleteDevices {
		if m.Devices.Delete(ctx, id) == nil {
			return
		}
	}
	progress("device_retained: " + id)
}
func copyState(source, dest string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
			return errors.New("invalid node state file")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, io.LimitReader(in, 4<<20+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		return errors.Join(err, syncErr, closeErr)
	})
}
func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in node state")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		return file.Sync()
	})
}
