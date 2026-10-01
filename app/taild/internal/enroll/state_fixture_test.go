package enroll

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/state"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func profileFixture(t *testing.T, dir, name, id string, pin state.NodePin, private key.NodePrivate, tags []string) {
	t.Helper()
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	st, e := store.NewFileStore(func(string, ...any) {}, filepath.Join(dir, "tailscaled.state"))
	if e != nil {
		t.Fatal(e)
	}
	user := tailcfg.UserProfile{ID: 7, LoginName: "fixture@example.test"}
	if len(tags) > 0 {
		user.LoginName = "tagged-devices"
	}
	profile := ipn.LoginProfile{ID: "fixture", Key: "profile-fixture", NodeID: tailcfg.StableNodeID(id), UserProfile: user, ControlURL: pin.ControlURL, NetworkProfile: ipn.NetworkProfile{DomainName: pin.Tailnet, MagicDNSName: pin.Suffix}}
	known, e := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profile.ID: profile})
	if e != nil {
		t.Fatal(e)
	}
	prefs := ipn.Prefs{Hostname: name, ControlURL: pin.ControlURL, AdvertiseTags: tags, Persist: &persist.Persist{NodeID: profile.NodeID, UserProfile: user, PrivateNodeKey: private}}
	for _, entry := range []struct {
		k ipn.StateKey
		b []byte
	}{{ipn.CurrentProfileStateKey, []byte(profile.Key)}, {ipn.KnownProfilesStateKey, known}, {profile.Key, prefs.ToBytes()}} {
		if e = st.WriteState(entry.k, entry.b); e != nil {
			t.Fatal(e)
		}
	}
}

func TestClosedReauthPublicStateRejectsUnchangedOrUnboundKey(t *testing.T) {
	// Pinned public serialization fixtures prove the closed-state contract only.
	// There is no simulated successful control server or registration here.
	pin := state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: ipn.DefaultControlURL}
	oldDir := t.TempDir()
	oldKey := key.NewNode()
	profileFixture(t, oldDir, "dev", "stable", pin, oldKey, nil)
	old, kind := state.ReadNode(oldDir, "dev", "user:7", pin)
	if kind != state.Enrolled {
		t.Fatal(kind)
	}
	for _, tc := range []struct {
		name, id string
		private  key.NodePrivate
		observed key.NodePublic
		want     bool
	}{
		{"unchanged", "stable", oldKey, oldKey.Public(), false},
		{"different-id", "other", key.NewNode(), key.NodePublic{}, false},
		{"unbound-status", "stable", key.NewNode(), oldKey.Public(), false},
		{"refreshed", "stable", key.NewNode(), key.NodePublic{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			profileFixture(t, dir, "dev", tc.id, pin, tc.private, nil)
			observed := tc.observed
			if observed.IsZero() {
				observed = tc.private.Public()
			}
			e := checkClosedNode(dir, "dev", identity.Principal("user:7"), pin, tc.id, observed, old, true)
			if (e == nil) != tc.want {
				t.Fatal("closed-state key/identity contract violated")
			}
		})
	}
}

func TestActualTSNetPrefsRewriteAndLocalAPIKeyRedaction(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer endpoint.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer other.Close()
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted-settings-overwrite-state", true: "explicit-settings-preserve-state"}[keep], func(t *testing.T) {
			dir := t.TempDir()
			private := key.NewNode()
			tags := []string{"tag:owner"}
			pin := state.NodePin{Tailnet: "fixture", Suffix: "fixture.test", ControlURL: endpoint.URL}
			profileFixture(t, dir, "dev", "fixture-stable", pin, private, tags)
			server := &tsnet.Server{Dir: dir, Hostname: "dev", ControlURL: other.URL, Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {}}
			if keep {
				server.ControlURL = endpoint.URL
				server.AdvertiseTags = tags
			}
			if e := server.Start(); e != nil {
				t.Fatal("offline tsnet startup failed")
			}
			defer server.Close()
			lc, e := server.LocalClient()
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			prefs, e := lc.GetPrefs(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if prefs.Persist == nil || !prefs.Persist.PrivateNodeKey.IsZero() {
				t.Fatal("pinned local API did not redact private node key")
			}
			wantTags := []string(nil)
			wantURL := other.URL
			if keep {
				wantTags = tags
				wantURL = endpoint.URL
			}
			if !slices.Equal(prefs.AdvertiseTags, wantTags) || prefs.ControlURL != wantURL {
				t.Fatal("tsnet startup did not apply explicit handoff settings")
			}
			if e = server.Close(); e != nil {
				t.Fatal(e)
			}
			st, e := store.NewFileStore(func(string, ...any) {}, filepath.Join(dir, "tailscaled.state"))
			if e != nil {
				t.Fatal(e)
			}
			current, e := st.ReadState(ipn.CurrentProfileStateKey)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := st.ReadState(ipn.StateKey(current))
			if e != nil {
				t.Fatal(e)
			}
			var stored ipn.Prefs
			if e = ipn.PrefsFromBytes(raw, &stored); e != nil {
				t.Fatal(e)
			}
			if !slices.Equal(stored.AdvertiseTags, wantTags) || stored.ControlURL != wantURL {
				t.Fatal("persisted handoff preferences were not preserved")
			}
			if stored.Persist == nil || !stored.Persist.PrivateNodeKey.Equal(private) {
				t.Fatal("serialized private state was confused with sanitized preferences")
			}
			// The HTTP endpoints only reject requests. No real enrollment is qualified.
		})
	}
}
