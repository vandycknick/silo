package netnode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
)

// OAuth-app provisioning returns an opaque single-use registration token. It
// is sent directly to the running local backend, never tsnet credential discovery.
func delegatedKey(key string) bool {
	if key == "" || len(key) > 16384 || strings.HasPrefix(key, "tskey-client-") {
		return false
	}
	for _, r := range key {
		if r <= 32 || r >= 127 || strings.ContainsRune("?:/#\\", r) {
			return false
		}
	}
	return true
}

func (n *Node) secret(field string) string {
	if n.options.Secrets == nil {
		return ""
	}
	v, _ := n.options.Secrets.Lookup(n.options.Declaration.Name + ".tailscale." + field)
	defer clear(v)
	return string(v)
}

// Only this owner loop initiates authentication. The notification watcher just
// observes it. Bootstrap keys are not reapplied to an existing persisted node.
func (n *Node) authenticate(ctx context.Context, client *local.Client) {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !n.bootstrapDone {
		prefs, err := client.GetPrefs(bounded)
		if err != nil {
			return
		}
		if prefs.Persist != nil && prefs.Persist.NodeID != "" {
			n.bootstrapDone = true
		} else {
			mode := ""
			if n.options.Identity != nil {
				mode = n.options.Identity.Bootstrap
			}
			key := ""
			if mode == "" || mode == "auth_key" {
				key = n.secret("auth_key")
			}
			if key == "" && (mode == "client_secret" || mode == "") && len(n.options.Declaration.Tags) > 0 {
				if secret := n.secret("client_secret"); secret != "" {
					key, err = mintKey(bounded, secret, n.bootstrapTags())
					if err != nil {
						return
					}
				}
			}
			n.bootstrapDone = true
			if key != "" {
				// Browser login may have completed while an OAuth mint was in
				// flight. Never replace an identity established in the meantime.
				current, e := client.GetPrefs(bounded)
				if e != nil {
					n.bootstrapDone = false
					return
				}
				if current.Persist != nil && current.Persist.NodeID != "" {
					return
				}
				// Start is bounded by the VM lifetime, unlike Server.ClientSecret.
				if e = client.Start(bounded, ipn.Options{AuthKey: key}); e != nil {
					n.bootstrapDone = false
					return
				}
				n.bootstrapKeyActive = true
				_ = client.StartLoginInteractive(bounded)
				n.lastLogin = time.Now()
				return
			}
		}
	}
	status, err := client.StatusWithoutPeers(bounded)
	if err != nil || status == nil || time.Since(n.lastLogin) < 30*time.Second {
		return
	}
	mismatch := status.BackendState == "Running" && status.Self != nil && status.CurrentTailnet != nil && n.options.Identity.verify(status, n.options.Declaration.Hostname) != nil
	if status.BackendState == "NeedsLogin" || expired(status) || mismatch {
		n.lastLogin = time.Now()
		if n.bootstrapKeyActive {
			// A consumed/rejected bootstrap key remains in the control client's
			// options until replaced. Clear it once before browser reauthentication.
			if client.Start(bounded, ipn.Options{}) != nil {
				return
			}
			n.bootstrapKeyActive = false
		}
		// The local backend reuses an unexpired URL and refreshes a stale one.
		// Do not restart the backend or regenerate links on each observation.
		_ = client.StartLoginInteractive(bounded)
	}
}

// A shared minting client must not give callers its own broader tag authority.
// Authenticate as the selected verified owner tag; Tailscale then authorizes
// the advertised tags through that tag's tagOwners relationships.
func (n *Node) bootstrapTags() []string {
	if n.options.Identity != nil && strings.HasPrefix(n.options.Identity.Owner, "tag:") {
		return []string{n.options.Identity.Owner}
	}
	return n.options.Declaration.Tags
}

type authAPI struct {
	base   string
	client *http.Client
}

func newAuthAPI() authAPI {
	return authAPI{"https://api.tailscale.com", &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (api authAPI) request(ctx context.Context, method, path, credential string, body []byte, form bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, api.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if form {
		req.SetBasicAuth("some-client-id", credential)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Authorization", "Bearer "+credential)
		if strings.HasPrefix(credential, "tskey-api-") {
			req.SetBasicAuth(credential, "")
		}
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := api.client.Do(req)
	if err != nil {
		return errors.New("Tailscale credential service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("Tailscale credential request rejected")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(b) > 4<<20 {
		return errors.New("invalid Tailscale credential response")
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return errors.New("invalid Tailscale credential response")
	}
	return nil
}

func mintKey(ctx context.Context, secret string, tags []string) (string, error) {
	return newAuthAPI().mint(ctx, secret, tags)
}

func (api authAPI) mint(ctx context.Context, secret string, tags []string) (string, error) {
	if !strings.HasPrefix(secret, "tskey-client-") || strings.ContainsAny(secret, "?\r\n \t") || len(tags) == 0 {
		return "", errors.New("invalid OAuth client credential")
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	form := url.Values{"grant_type": {"client_credentials"}}.Encode()
	if err := api.request(ctx, "POST", "/api/v2/oauth/token", secret, []byte(form), true, &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", errors.New("OAuth returned no token")
	}
	body, err := json.Marshal(map[string]any{"expirySeconds": 300, "capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{"reusable": false, "ephemeral": false, "preauthorized": false, "tags": tags}}}})
	if err != nil {
		return "", err
	}
	var result struct {
		Key string `json:"key"`
	}
	if err = api.request(ctx, "POST", "/api/v2/tailnet/-/keys", token.AccessToken, body, false, &result); err != nil {
		return "", err
	}
	if result.Key == "" || !literalEnrollmentKey(result.Key) {
		return "", errors.New("invalid enrollment key")
	}
	return result.Key, nil
}

// Expiry policy is node maintenance, not a taild job. Failures are retried and
// exposed in status without preventing guest readiness or holding a VM lock.
func (n *Node) maintain(ctx context.Context, client *local.Client) {
	if n.options.Identity == nil || !n.options.Identity.DisableKeyExpiry {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := client.StatusWithoutPeers(bounded)
	if err != nil || n.options.Identity.verify(s, n.options.Declaration.Hostname) != nil {
		return
	}
	id := string(s.Self.ID)
	if n.maintenanceNode == id {
		return
	}
	err = newAuthAPI().disableExpiry(bounded, n.secret("api_token"), id, s.Self.DNSName)
	n.mu.Lock()
	n.maintenanceFailed = err != nil
	n.mu.Unlock()
	if err == nil {
		n.maintenanceNode = id
	}
}

func (api authAPI) disableExpiry(ctx context.Context, token, nodeID, dns string) error {
	if token == "" {
		return errors.New("device API credential unavailable")
	}
	type device struct {
		ID     string `json:"id"`
		NodeID string `json:"nodeId"`
		Name   string `json:"name"`
	}
	var list struct {
		Devices []device `json:"devices"`
	}
	if err := api.request(ctx, "GET", "/api/v2/tailnet/-/devices", token, nil, false, &list); err != nil {
		return err
	}
	id := ""
	for _, d := range list.Devices {
		if d.NodeID == nodeID {
			if id != "" || d.ID == "" || canonical(d.Name) != canonical(dns) {
				return errors.New("device identity mismatch")
			}
			id = d.ID
		}
	}
	if id == "" {
		return errors.New("device not registered")
	}
	if len(id) > 128 || strings.ContainsFunc(id, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-')
	}) {
		return errors.New("invalid device identifier")
	}
	path := "/api/v2/device/" + url.PathEscape(id)
	var current device
	if err := api.request(ctx, "GET", path, token, nil, false, &current); err != nil {
		return err
	}
	if current.ID != id || current.NodeID != nodeID || canonical(current.Name) != canonical(dns) {
		return errors.New("device identity mismatch")
	}
	return api.request(ctx, "POST", path+"/key", token, []byte(`{"keyExpiryDisabled":true}`), false, nil)
}
