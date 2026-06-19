package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/secrets"
)

const (
	kindBearerToken      = "bearer_token"
	kindOpenAICodexOAuth = "openai_codex_oauth"

	openAICodexClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	openAITokenURL      = "https://auth.openai.com/oauth/token"

	refreshSkew    = 60 * time.Second
	oauthBodyLimit = 64 << 10
)

type Manager struct {
	store          secrets.Store
	client         *http.Client
	now            func() time.Time
	openAITokenURL string

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewManager(store secrets.Store) *Manager {
	return &Manager{
		store: store,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		now:            time.Now,
		openAITokenURL: openAITokenURL,
		locks:          make(map[string]*sync.Mutex),
	}
}

func (m *Manager) Apply(ctx context.Context, req *http.Request, credential *hooks.Credential) error {
	if credential == nil {
		return nil
	}
	switch credential.Kind {
	case kindBearerToken:
		return m.applyBearerToken(req, credential)
	case kindOpenAICodexOAuth:
		return m.applyOpenAICodexOAuth(ctx, req, credential)
	default:
		return fmt.Errorf("unsupported credential kind %q", credential.Kind)
	}
}

func (m *Manager) applyBearerToken(req *http.Request, credential *hooks.Credential) error {
	store, err := m.requireStore(credential)
	if err != nil {
		return err
	}
	secret, err := store.Get(credential.Secret)
	if err != nil {
		return fmt.Errorf("read bearer_token secret %q: %w", credential.Secret, err)
	}
	value, err := secret.PlainValue()
	if err != nil {
		return fmt.Errorf("read bearer_token secret %q: %w", credential.Secret, err)
	}
	return applyBearerToken(req, value)
}

func applyBearerToken(req *http.Request, value string) error {
	if value == "" {
		return fmt.Errorf("bearer token credential is empty")
	}
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+value)
	return nil
}

func (m *Manager) applyOpenAICodexOAuth(ctx context.Context, req *http.Request, credential *hooks.Credential) error {
	store, err := m.requireStore(credential)
	if err != nil {
		return err
	}
	lock := m.lockFor(credential.Secret)
	lock.Lock()
	defer lock.Unlock()

	stored, err := store.Get(credential.Secret)
	if err != nil {
		return fmt.Errorf("read openai_codex_oauth secret %q: %w", credential.Secret, err)
	}
	token, err := stored.OAuth()
	if err != nil {
		return fmt.Errorf("read openai_codex_oauth secret %q: %w", credential.Secret, err)
	}
	if token.AccessToken == "" {
		return fmt.Errorf("openai_codex_oauth secret %q is missing access_token", credential.Secret)
	}
	if m.needsRefresh(token.ExpiresAt) {
		if token.RefreshToken == "" {
			return fmt.Errorf("openai_codex_oauth secret %q is expired and missing refresh_token", credential.Secret)
		}
		refreshed, err := m.refreshOpenAICodexToken(ctx, token)
		if err != nil {
			return err
		}
		refreshed.CreatedAt = token.CreatedAt
		if refreshed.CreatedAt == "" {
			refreshed.CreatedAt = rfc3339(m.now())
		}
		refreshed.AccountID = chatGPTAccountID(refreshed.AccessToken)
		if refreshed.AccountID == "" {
			refreshed.AccountID = token.AccountID
		}
		if err := store.UpdateOAuth(credential.Secret, refreshed); err != nil {
			return fmt.Errorf("update openai_codex_oauth secret %q: %w", credential.Secret, err)
		}
		token = refreshed
	}

	accountID := token.AccountID
	if accountID == "" {
		accountID = chatGPTAccountID(token.AccessToken)
	}
	req.Header.Del("Authorization")
	req.Header.Del("ChatGPT-Account-Id")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-Id", accountID)
	}
	return nil
}

func (m *Manager) requireStore(credential *hooks.Credential) (secrets.Store, error) {
	if credential.Secret == "" {
		return nil, fmt.Errorf("credential %q.%q is missing secret", credential.Kind, credential.Name)
	}
	if m.store == nil {
		return nil, fmt.Errorf("credential %q.%q requires a secret store", credential.Kind, credential.Name)
	}
	return m.store, nil
}

func (m *Manager) lockFor(name string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	lock := m.locks[name]
	if lock == nil {
		lock = &sync.Mutex{}
		m.locks[name] = lock
	}
	return lock
}

func (m *Manager) needsRefresh(expiresAt string) bool {
	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return true
	}
	return !m.now().Add(refreshSkew).Before(expiry)
}

func (m *Manager) refreshOpenAICodexToken(ctx context.Context, current secrets.OAuthSecret) (secrets.OAuthSecret, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	form.Set("client_id", openAICodexClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.openAITokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return secrets.OAuthSecret{}, fmt.Errorf("build OpenAI Codex token refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return secrets.OAuthSecret{}, fmt.Errorf("refresh OpenAI Codex token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, oauthBodyLimit))
	if resp.StatusCode != http.StatusOK {
		return secrets.OAuthSecret{}, fmt.Errorf("refresh OpenAI Codex token returned %d: %s", resp.StatusCode, sanitizeResponseBody(body))
	}
	var decoded struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return secrets.OAuthSecret{}, fmt.Errorf("decode OpenAI Codex token refresh response: %w", err)
	}
	if decoded.AccessToken == "" {
		return secrets.OAuthSecret{}, fmt.Errorf("OpenAI Codex token refresh response is missing access_token")
	}
	if decoded.RefreshToken == "" {
		decoded.RefreshToken = current.RefreshToken
	}
	if decoded.ExpiresIn <= 0 {
		return secrets.OAuthSecret{}, fmt.Errorf("OpenAI Codex token refresh response is missing expires_in")
	}
	now := m.now()
	return secrets.OAuthSecret{
		AccessToken:  decoded.AccessToken,
		RefreshToken: decoded.RefreshToken,
		ExpiresAt:    rfc3339(now.Add(time.Duration(decoded.ExpiresIn) * time.Second)),
		CreatedAt:    current.CreatedAt,
		UpdatedAt:    rfc3339(now),
	}, nil
}

func chatGPTAccountID(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := decodeJWTPayload(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if value, ok := claims["chatgpt_account_id"].(string); ok {
		return value
	}
	nested, ok := claims["https://api.openai.com/auth"].(map[string]any)
	if !ok {
		return ""
	}
	value, _ := nested["chatgpt_account_id"].(string)
	return value
}

func decodeJWTPayload(payload string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err == nil {
		return decoded, nil
	}
	if missing := len(payload) % 4; missing != 0 {
		payload += strings.Repeat("=", 4-missing)
	}
	return base64.URLEncoding.DecodeString(payload)
}

func rfc3339(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func sanitizeResponseBody(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "<empty>"
	}
	if len(body) > 512 {
		return string(body[:512]) + "..."
	}
	return string(body)
}
