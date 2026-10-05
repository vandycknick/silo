package enroll

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
)

type Mode string

const (
	User        Mode = "user"
	Interactive Mode = "interactive"
	Tag         Mode = "tag"
	None        Mode = "none"
)

func Select(owner identity.Principal, configured, appSecret string) Mode {
	if configured == "none" {
		return None
	}
	if strings.HasPrefix(string(owner), "tag:") {
		return Tag
	}
	if configured != "interactive" && appSecret != "" {
		return User
	}
	return Interactive
}

type Result struct {
	Token string
	Err   error
}
type Consent struct {
	VM        string
	Principal identity.Principal
	URL       string
	Expires   time.Time
	result    chan Result
}
type Registry struct {
	mu      sync.Mutex
	entries map[string]*Consent
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]*Consent)}
}
func (r *Registry) Begin(vm string, owner identity.Principal, clientID, redirect string) (string, *Consent, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", nil, errors.New("consent entropy unavailable")
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes[:])
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "scope": {"auth_keys:create:once"}, "response_type": {"code"}, "state": {nonce}}
	c := &Consent{VM: vm, Principal: owner, URL: "https://login.tailscale.com/a/oauth_authorize?" + q.Encode(), Expires: time.Now().Add(15 * time.Minute), result: make(chan Result, 1)}
	r.mu.Lock()
	defer r.mu.Unlock()
	for n, existing := range r.entries {
		if !time.Now().Before(existing.Expires) {
			delete(r.entries, n)
		}
	}
	r.entries[nonce] = c
	return nonce, c, nil
}
func (r *Registry) Cancel(nonce string) { r.mu.Lock(); delete(r.entries, nonce); r.mu.Unlock() }

// consume happens before any exchange, including a failed exchange. Replay never retries a code.
func (r *Registry) consume(nonce string) *Consent {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.entries[nonce]
	delete(r.entries, nonce)
	if c == nil || !time.Now().Before(c.Expires) {
		return nil
	}
	return c
}
func (c *Consent) Wait(ctx context.Context) (string, error) {
	timer := time.NewTimer(time.Until(c.Expires))
	defer timer.Stop()
	select {
	case result := <-c.result:
		return result.Token, result.Err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", errors.New("consent expired")
	}
}

type OAuth struct {
	Registry                   *Registry
	ClientID, Secret, Redirect string
	endpoint                   string
	client                     *http.Client
}

func NewOAuth(registry *Registry, secret, redirect string) (*OAuth, error) {
	if !strings.HasPrefix(secret, "tskey-app-") {
		return nil, errors.New("invalid OAuth app secret")
	}
	id, rest, ok := strings.Cut(strings.TrimPrefix(secret, "tskey-app-"), "-")
	if !ok || id == "" || rest == "" || strings.ContainsAny(secret, "\r\n \t?") {
		return nil, errors.New("invalid OAuth app secret")
	}
	return &OAuth{Registry: registry, ClientID: id, Secret: secret, Redirect: redirect, endpoint: "https://api.tailscale.com/api/v2/oauth/token", client: tailnet.NewHTTPClient(30 * time.Second)}, nil
}
func validToken(token string) bool {
	return token != "" && len(token) <= 16384 && !strings.HasPrefix(token, "tskey-client-") && !strings.ContainsAny(token, " \t\r\n?#") && !strings.Contains(token, "://")
}

// Callback authenticates only the one-use state. Identity is verified from the resulting node.
func (o *OAuth) Callback(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.TLS == nil || len(req.URL.RawQuery) > 16384 || req.ContentLength != 0 {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	q, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil || len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1 {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	c := o.Registry.consume(q.Get("state"))
	if c == nil {
		http.Error(w, "expired or invalid state", http.StatusBadRequest)
		return
	}
	result := Result{}
	if q.Get("error") != "" || q.Get("code") == "" {
		result.Err = errors.New("consent denied")
	} else {
		result.Token, result.Err = o.exchange(req.Context(), q.Get("code"))
	}
	c.result <- result
	if result.Err != nil {
		http.Error(w, "approval failed; return to your terminal", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "Approved. Return to your terminal.\n")
}
func (o *OAuth) exchange(ctx context.Context, code string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {o.ClientID}, "client_secret": {o.Secret}, "redirect_uri": {o.Redirect}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, strings.NewReader(q.Encode()))
	if err != nil {
		return "", errors.New("credential exchange unavailable")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.client.Do(req)
	if err != nil {
		return "", errors.New("credential exchange unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("credential exchange rejected")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(b) > 65536 {
		return "", errors.New("invalid credential response")
	}
	var result struct {
		Token string `json:"access_token"`
	}
	if json.Unmarshal(b, &result) != nil || !validToken(result.Token) {
		return "", errors.New("invalid credential response")
	}
	return result.Token, nil
}
