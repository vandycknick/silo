package netnode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/credentials"
	"github.com/vandycknick/silo/net/netd/internal/policy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func TestTaggedIdentitySeparatesManagementOwner(t *testing.T) {
	e, err := ParseIdentity(map[string]any{IdentityMetadata: `{"owner":"user:7","tags":["tag:testing","tag:dev"],"tailnet":"fixture","suffix":"tail.test","bootstrap":"auth_key"}`})
	if err != nil {
		t.Fatal(err)
	}
	tags := views.SliceOf([]string{"tag:testing", "tag:dev"})
	s := &ipnstate.Status{BackendState: "Running", Self: &ipnstate.PeerStatus{ID: "stable", DNSName: "dev.tail.test.", Tags: &tags}, CurrentTailnet: &ipnstate.TailnetStatus{Name: "fixture", MagicDNSSuffix: "tail.test"}}
	if e.verify(s, "dev") != nil {
		t.Fatal("human-managed tagged node rejected")
	}
	for _, assigned := range [][]string{nil, {"tag:dev"}, {"tag:dev", "tag:testing", "tag:admin"}} {
		v := views.SliceOf(assigned)
		s.Self.Tags = &v
		if e.verify(s, "dev") == nil {
			t.Fatal("unexpected tag assignment accepted", assigned)
		}
	}
	if _, err = ParseIdentity(map[string]any{IdentityMetadata: `{"owner":"user:7","tailnet":"fixture","suffix":"tail.test","bootstrap":"client_secret"}`}); err == nil {
		t.Fatal("shared service credential permitted for human")
	}
}

func TestTaggedBootstrapUsesOwnerAuthorityNotRequestedTags(t *testing.T) {
	n := &Node{options: Options{Identity: &ExpectedIdentity{Owner: "tag:creator", Bootstrap: "client_secret"}, Declaration: policy.TailscaleDecl{Tags: []string{"tag:requested"}}}}
	if !slices.Equal(n.bootstrapTags(), []string{"tag:creator"}) {
		t.Fatal("shared mint bypassed caller tag ownership")
	}
}

func TestPersistedIdentityDoesNotRedeemBootstrapAgain(t *testing.T) {
	dir := t.TempDir()
	private := key.NewNode()
	pin := fixturePin{Tailnet: "fixture", Suffix: "tail.test", ControlURL: "http://127.0.0.1:1"}
	profileFixture(t, dir, "dev", "existing-node", pin, private, nil)
	n, err := New(Options{Dir: dir, Declaration: policy.TailscaleDecl{Name: "vm", Hostname: "dev", ControlURL: pin.ControlURL}, Secrets: credentials.NewStatic(map[string][]byte{"vm.tailscale.auth_key": []byte("tskey-auth-already-used")}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err = n.server.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.server.Close()
	client, err := n.server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	n.authenticate(ctx, client)
	if !n.bootstrapDone || !n.lastLogin.IsZero() {
		t.Fatal("persisted identity caused a bootstrap attempt")
	}
	prefs, err := client.GetPrefs(ctx)
	if err != nil || prefs.Persist == nil || prefs.Persist.NodeID != "existing-node" {
		t.Fatal("identity replaced", err)
	}
}

// Actual HTTP protocol checks, not a simulated successful tailnet registration.
func TestOAuthMintAndDeviceMaintenanceHTTP(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			_, secret, ok := r.BasicAuth()
			if !ok || secret != "tskey-client-test" {
				t.Error("wrong client credential")
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" {
				t.Error("wrong OAuth request")
			}
			io.WriteString(w, `{"access_token":"scoped-api-token"}`)
		case "/api/v2/tailnet/-/keys":
			if r.Header.Get("Authorization") != "Bearer scoped-api-token" {
				t.Error("wrong access token")
			}
			var body struct {
				Expiry       int `json:"expirySeconds"`
				Capabilities struct {
					Devices struct {
						Create struct {
							Reusable      bool     `json:"reusable"`
							Ephemeral     bool     `json:"ephemeral"`
							Preauthorized bool     `json:"preauthorized"`
							Tags          []string `json:"tags"`
						} `json:"create"`
					} `json:"devices"`
				} `json:"capabilities"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Expiry != 300 || body.Capabilities.Devices.Create.Reusable || body.Capabilities.Devices.Create.Ephemeral || body.Capabilities.Devices.Create.Preauthorized || !slices.Equal(body.Capabilities.Devices.Create.Tags, []string{"tag:dev"}) {
				t.Error("unbounded or incorrect key request")
			}
			io.WriteString(w, `{"key":"tskey-auth-test"}`)
		case "/api/v2/tailnet/-/devices":
			io.WriteString(w, `{"devices":[{"id":"123","nodeId":"stable","name":"dev.tail.test"}]}`)
		case "/api/v2/device/123":
			io.WriteString(w, `{"id":"123","nodeId":"stable","name":"dev.tail.test"}`)
		case "/api/v2/device/123/key":
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"keyExpiryDisabled":true}` {
				t.Error(string(b))
			}
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	api := authAPI{server.URL, server.Client()}
	key, err := api.mint(t.Context(), "tskey-client-test", []string{"tag:dev"})
	if err != nil || key != "tskey-auth-test" {
		t.Fatal(key, err)
	}
	if err = api.disableExpiry(t.Context(), "api-token", "stable", "dev.tail.test."); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	observed := slices.Clone(paths)
	mu.Unlock()
	if len(observed) != 5 || observed[4] != "POST /api/v2/device/123/key" {
		t.Fatal(observed)
	}
	if err = api.disableExpiry(t.Context(), "api-token", "stable", "other.tail.test"); err == nil {
		t.Fatal("foreign node administrated")
	}
}
