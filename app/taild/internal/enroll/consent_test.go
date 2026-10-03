package enroll

import (
	"context"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestModeTable(t *testing.T) {
	for _, tc := range []struct {
		owner          identity.Principal
		config, secret string
		opt            bool
		want           Mode
	}{
		{"user:1", "oauth-app", "app", false, User}, {"user:1", "oauth-app", "", false, Interactive}, {"user:1", "interactive", "app", false, Interactive}, {"tag:ci", "interactive", "", false, Tag}, {"tag:ci", "none", "", false, None}, {"user:1", "oauth-app", "app", true, None},
	} {
		if got := Select(tc.owner, tc.config, tc.secret, tc.opt); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestProvisioningTokenDoesNotInventAnUndocumentedPrefixContract(t *testing.T) {
	for _, token := range []string{"opaque-provisioning-token", "tskey-auth-key", "tskey-app-undocumented-token", "a.jwt.payload"} {
		if !validToken(token) {
			t.Fatal("undocumented token prefix rejected")
		}
	}
	for _, token := range []string{"", "tskey-client-secret", "https://discovery.test/key", "key?scope=tag:ci", "key\n"} {
		if validToken(token) {
			t.Fatal("client/discovery material accepted")
		}
	}
}
func TestCallbackRealTLSExchangeAtomicConsumeAndOpaqueToken(t *testing.T) {
	registry := NewRegistry()
	oauth, err := NewOAuth(registry, "tskey-app-client-secret", "https://silo.tail.test/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("code") != "fresh-code" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != oauth.Redirect || r.Form.Get("client_secret") != oauth.Secret {
			t.Error("bad exchange fields")
		}
		_, _ = io.WriteString(w, `{"access_token":"opaque-undocumented-provisioning-token","expires_in":3600}`)
	}))
	defer upstream.Close()
	oauth.endpoint = upstream.URL
	oauth.client = upstream.Client()
	callback := httptest.NewTLSServer(http.HandlerFunc(oauth.Callback))
	defer callback.Close()
	nonce, c, err := registry.Begin("vm", "user:1", oauth.ClientID, oauth.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(c.URL)
	if parsed.Query().Get("scope") != "auth_keys:create:once" {
		t.Fatal(c.URL)
	}
	send := func(query string) int {
		resp, err := callback.Client().Get(callback.URL + "?" + query)
		if err != nil {
			t.Error(err)
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if send("state=wrong&code=fresh-code") != 400 || calls.Load() != 0 {
		t.Fatal("wrong state exchanged")
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if send("state="+nonce+"&code=fresh-code") == 200 {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || calls.Load() != 1 {
		t.Fatal("replay", successes.Load(), calls.Load())
	}
	token, err := c.Wait(context.Background())
	if err != nil || token != "opaque-undocumented-provisioning-token" {
		t.Fatal(token, err)
	}
	if registry.Current("vm", "user:1") != nil {
		t.Fatal("consumed consent retained")
	}
	for _, kind := range []string{"expired", "cancelled", "restart"} {
		n, c, e := registry.Begin("vm", "user:1", oauth.ClientID, oauth.Redirect)
		if e != nil {
			t.Fatal(e)
		}
		switch kind {
		case "expired":
			registry.mu.Lock()
			c.Expires = time.Now().Add(-time.Second)
			registry.mu.Unlock()
		case "cancelled":
			registry.Cancel(n)
		case "restart":
			oauth.Registry = NewRegistry()
		}
		if send("state="+n+"&code=fresh-code") != 400 || calls.Load() != 1 {
			t.Fatal(kind, "accepted")
		}
	}
}
func TestExchangeFailureIsConsumedAndBodiesBounded(t *testing.T) {
	for _, body := range []string{`{"access_token":"tskey-client-not-a-key"}`, strings.Repeat("x", 65537), `{"access_token":"https://discovery.invalid/key"}`} {
		registry := NewRegistry()
		oauth, _ := NewOAuth(registry, "tskey-app-id-secret", "https://callback.test/")
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = io.WriteString(w, body) }))
		oauth.endpoint = upstream.URL
		oauth.client = upstream.Client()
		callback := httptest.NewTLSServer(http.HandlerFunc(oauth.Callback))
		nonce, c, _ := registry.Begin("vm", "user:1", oauth.ClientID, oauth.Redirect)
		for range 2 {
			resp, err := callback.Client().Get(callback.URL + "?state=" + nonce + "&code=code")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatal(resp.StatusCode)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("failed exchange retried")
		}
		if _, err := c.Wait(context.Background()); err == nil {
			t.Fatal("invalid token accepted")
		}
		callback.Close()
		upstream.Close()
	}
}
