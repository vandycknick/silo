package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
)

const (
	ReasonSecret    = "credential_secret_error"
	ReasonRefresh   = "credential_refresh_error"
	ReasonSigning   = "credential_signing_error"
	ReasonInjection = "credential_injection_error"

	networkSecretPrefix = "BENTO_NET_SECRET_"
)

type ApplyError struct {
	Reason string
	Err    error
}

func (e *ApplyError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Reason
	}
	return e.Reason + ": " + e.Err.Error()
}

func (e *ApplyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func FailureReason(err error) string {
	var applyErr *ApplyError
	if errors.As(err, &applyErr) && applyErr.Reason != "" {
		return applyErr.Reason
	}
	return ReasonInjection
}

func applyError(reason string, format string, args ...any) error {
	return &ApplyError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

type Manager struct {
	now                   func() time.Time
	awsProfileCredentials func(context.Context, string) (aws.Credentials, error)
	oauthRefreshHook      *OAuthRefreshHook

	oauthMu      sync.Mutex
	oauthSecrets map[string]oauthSecret
}

type oauthSecret struct {
	AccessToken string
	ExpiresAt   string
	AccountID   string
}

func NewManager() *Manager {
	return newManager(nil)
}

func NewManagerFromEnvironment() (*Manager, error) {
	hook, err := LoadOAuthRefreshHookFromEnvironment()
	if err != nil {
		return nil, err
	}
	return newManager(hook), nil
}

func newManager(hook *OAuthRefreshHook) *Manager {
	return &Manager{
		now:                   time.Now,
		awsProfileCredentials: retrieveAWSProfileCredentials,
		oauthRefreshHook:      hook,
		oauthSecrets:          make(map[string]oauthSecret),
	}
}

func (m *Manager) Apply(ctx context.Context, req *http.Request, credential *hooks.Credential) error {
	if credential == nil {
		return nil
	}
	if m == nil {
		return applyError(ReasonSecret, "credential manager is not configured")
	}
	switch credential.Kind {
	case "basic_auth":
		return m.applyBasicAuth(credential, req)
	case "bearer_token":
		return m.applyBearerToken(credential, req)
	case "header_token":
		return m.applyHeaderToken(credential, req)
	case "github_oauth":
		return m.applyGitHubOAuth(ctx, credential, req)
	case "openai_codex_oauth":
		return m.applyOpenAICodexOAuth(ctx, credential, req)
	case "aws_credential":
		return m.applyAWSCredential(ctx, credential, req)
	default:
		return applyError(ReasonInjection, "unsupported credential kind %q", credential.Kind)
	}
}

func (m *Manager) applyBasicAuth(credential *hooks.Credential, req *http.Request) error {
	if credential.Username == "" {
		return applyError(ReasonInjection, "basic_auth credential %q is missing username", credential.Name)
	}
	password, err := m.plainSlot(credential, "password", true)
	if err != nil {
		return applyError(ReasonSecret, "basic_auth password: %w", err)
	}
	req.SetBasicAuth(credential.Username, password)
	return nil
}

func (m *Manager) applyBearerToken(credential *hooks.Credential, req *http.Request) error {
	token, err := m.plainSlot(credential, "token", true)
	if err != nil {
		return applyError(ReasonSecret, "bearer token: %w", err)
	}
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+token)
	if credential.IdempotencyKey {
		applyIdempotencyKey(req)
	}
	return nil
}

func (m *Manager) applyHeaderToken(credential *hooks.Credential, req *http.Request) error {
	if credential.Header == "" {
		return applyError(ReasonInjection, "header_token credential %q is missing header", credential.Name)
	}
	token, err := m.plainSlot(credential, "token", true)
	if err != nil {
		return applyError(ReasonSecret, "header token: %w", err)
	}
	req.Header.Del(credential.Header)
	req.Header.Set(credential.Header, credential.Prefix+token)
	return nil
}

func (m *Manager) applyGitHubOAuth(ctx context.Context, credential *hooks.Credential, req *http.Request) error {
	secret, err := m.currentOAuth(ctx, credential)
	if err != nil {
		return applyError(ReasonSecret, "github oauth: %w", err)
	}
	if isGitHubSmartHTTP(req) {
		username, _, ok := req.BasicAuth()
		if !ok || username == "" {
			username = "x-access-token"
		}
		req.SetBasicAuth(username, secret.AccessToken)
		return nil
	}
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+secret.AccessToken)
	return nil
}

func (m *Manager) applyOpenAICodexOAuth(ctx context.Context, credential *hooks.Credential, req *http.Request) error {
	secret, err := m.currentOAuth(ctx, credential)
	if err != nil {
		return applyError(ReasonRefresh, "%w", err)
	}
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+secret.AccessToken)
	req.Header.Del("ChatGPT-Account-Id")
	if accountID := openAIAccountID(secret); accountID != "" {
		req.Header.Set("ChatGPT-Account-Id", accountID)
	}
	return nil
}

func (m *Manager) applyAWSCredential(ctx context.Context, credential *hooks.Credential, req *http.Request) error {
	if req.URL == nil || req.URL.Scheme != "https" {
		return applyError(ReasonSigning, "aws_credential requires an HTTPS request")
	}
	awsCreds, err := m.awsCredentials(ctx, credential)
	if err != nil {
		return applyError(ReasonSecret, "%w", err)
	}
	service, region, err := awsSigningScope(req)
	if err != nil {
		return applyError(ReasonSigning, "%w", err)
	}
	payloadHash, err := hashAndRestoreBody(req)
	if err != nil {
		return applyError(ReasonSigning, "hash request body: %w", err)
	}
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Security-Token")
	if err := awsv4.NewSigner().SignHTTP(ctx, awsCreds, req, payloadHash, service, region, m.now()); err != nil {
		return applyError(ReasonSigning, "sign AWS request: %w", err)
	}
	return nil
}

func (m *Manager) plainSlot(credential *hooks.Credential, slot string, required bool) (string, error) {
	key := slotKey(credential.Name, slot)
	return networkSecretString(key, required)
}

func (m *Manager) currentOAuth(ctx context.Context, credential *hooks.Credential) (oauthSecret, error) {
	secret, err := m.oauthSlot(credential)
	if err != nil {
		return oauthSecret{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, secret.ExpiresAt)
	if err != nil {
		return oauthSecret{}, fmt.Errorf("oauth slot %q has invalid expires_at: %w", oauthSlotKey(credential.Name), err)
	}
	now := m.now()
	expired := !now.Before(expiresAt)
	needsRefresh := m.oauthRefreshHook != nil && !now.Add(m.oauthRefreshHook.refreshSkew()).Before(expiresAt)
	if !expired && !needsRefresh {
		return secret, nil
	}
	if m.oauthRefreshHook == nil {
		if expired {
			return oauthSecret{}, fmt.Errorf("oauth credential %q expired at %s", credential.Name, secret.ExpiresAt)
		}
		return secret, nil
	}
	reason := "expires_soon"
	if expired {
		reason = "expired"
	}
	refreshed, err := m.oauthRefreshHook.Refresh(ctx, credential, secret.ExpiresAt, reason)
	if err != nil {
		if expired {
			return oauthSecret{}, err
		}
		return secret, nil
	}
	if _, err := time.Parse(time.RFC3339, refreshed.ExpiresAt); err != nil {
		if expired {
			return oauthSecret{}, fmt.Errorf("oauth refresh hook returned invalid expires_at: %w", err)
		}
		return secret, nil
	}
	m.setOAuthSlot(credential, refreshed)
	return refreshed, nil
}

func (m *Manager) oauthSlot(credential *hooks.Credential) (oauthSecret, error) {
	key := oauthSlotKey(credential.Name)
	m.oauthMu.Lock()
	cached, ok := m.oauthSecrets[key]
	m.oauthMu.Unlock()
	if ok {
		return cached, nil
	}
	accessToken, err := networkSecretString(key+".access_token", true)
	if err != nil {
		return oauthSecret{}, err
	}
	expiresAt, err := networkSecretString(key+".expires_at", true)
	if err != nil {
		return oauthSecret{}, err
	}
	accountID, err := networkSecretString(key+".account_id", false)
	if err != nil {
		return oauthSecret{}, err
	}
	secret := oauthSecret{AccessToken: accessToken, ExpiresAt: expiresAt, AccountID: accountID}
	m.setOAuthSlot(credential, secret)
	return secret, nil
}

func (m *Manager) setOAuthSlot(credential *hooks.Credential, secret oauthSecret) {
	m.oauthMu.Lock()
	defer m.oauthMu.Unlock()
	m.oauthSecrets[oauthSlotKey(credential.Name)] = secret
}

func slotKey(name string, slot string) string {
	return name + "." + slot
}

func oauthSlotKey(name string) string {
	return name + ".oauth"
}

func envNameForSlot(key string) string {
	var builder strings.Builder
	builder.WriteString(networkSecretPrefix)
	lastUnderscore := false
	for _, r := range key {
		if r >= 'a' && r <= 'z' {
			builder.WriteRune(r - 'a' + 'A')
			lastUnderscore = false
			continue
		}
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.TrimRight(builder.String(), "_")
}

func networkSecretString(key string, required bool) (string, error) {
	value, ok, err := networkSecretBytes(key, required)
	if err != nil || !ok {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", fmt.Errorf("slot %q is not valid UTF-8", key)
	}
	return string(value), nil
}

func networkSecretBytes(key string, required bool) ([]byte, bool, error) {
	envName := envNameForSlot(key)
	encoded, ok := os.LookupEnv(envName)
	if !ok {
		if required {
			return nil, false, fmt.Errorf("slot %q not found", key)
		}
		return nil, false, nil
	}
	if encoded == "" {
		return nil, true, fmt.Errorf("env %s is empty", envName)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, true, fmt.Errorf("env %s is not valid base64: %w", envName, err)
	}
	if len(decoded) == 0 {
		return nil, true, fmt.Errorf("slot %q is empty", key)
	}
	return decoded, true, nil
}

func applyIdempotencyKey(req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Header.Get("Idempotency-Key") != "" {
		return
	}
	hint := req.Header.Get("X-Bento-Idempotency-Hint")
	if hint == "" && req.URL != nil {
		hint = req.Method + "\n" + req.URL.Path + "\n" + req.URL.RawQuery
	}
	if hint == "" {
		hint = req.Method
	}
	sum := sha256.Sum256([]byte(hint))
	req.Header.Set("Idempotency-Key", hex.EncodeToString(sum[:16]))
}

func isGitHubSmartHTTP(req *http.Request) bool {
	if !strings.EqualFold(requestHostname(req), "github.com") || req.URL == nil {
		return false
	}
	path := req.URL.Path
	if strings.HasSuffix(path, ".git/info/refs") {
		service := req.URL.Query().Get("service")
		return service == "git-upload-pack" || service == "git-receive-pack"
	}
	return strings.HasSuffix(path, ".git/git-upload-pack") || strings.HasSuffix(path, ".git/git-receive-pack")
}

func requestHostname(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if host := req.URL.Hostname(); host != "" {
		return strings.ToLower(host)
	}
	host := req.Host
	if parsed, err := url.Parse("https://" + host); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func openAIAccountID(secret oauthSecret) string {
	if secret.AccountID != "" {
		return secret.AccountID
	}
	return accountIDFromJWT(secret.AccessToken)
}

func accountIDFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return findAccountID(claims)
}

func findAccountID(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"chatgpt_account_id", "chatgpt-account-id", "account_id"} {
			if value, ok := typed[key].(string); ok && value != "" {
				return value
			}
		}
		for _, nested := range typed {
			if accountID := findAccountID(nested); accountID != "" {
				return accountID
			}
		}
	case []any:
		for _, nested := range typed {
			if accountID := findAccountID(nested); accountID != "" {
				return accountID
			}
		}
	}
	return ""
}

func (m *Manager) awsCredentials(ctx context.Context, credential *hooks.Credential) (aws.Credentials, error) {
	profile, err := m.plainSlot(credential, "profile", false)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws profile: %w", err)
	}
	if profile != "" {
		return m.awsProfileCredentials(ctx, profile)
	}
	accessKeyID, err := m.plainSlot(credential, "access_key_id", true)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws access_key_id: %w", err)
	}
	secretAccessKey, err := m.plainSlot(credential, "secret_access_key", true)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws secret_access_key: %w", err)
	}
	sessionToken, err := m.plainSlot(credential, "session_token", false)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws session_token: %w", err)
	}
	provider := awscredentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
	return provider.Retrieve(ctx)
}

func retrieveAWSProfileCredentials(ctx context.Context, profile string) (aws.Credentials, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(profile))
	if err != nil {
		return aws.Credentials{}, err
	}
	return config.Credentials.Retrieve(ctx)
}

func awsSigningScope(req *http.Request) (string, string, error) {
	if service, region, ok := awsScopeFromAuthorization(req.Header.Get("Authorization")); ok {
		return service, region, nil
	}
	if service, region, ok := awsScopeFromHost(req.URL.Hostname()); ok {
		return service, region, nil
	}
	return "", "", fmt.Errorf("could not derive AWS SigV4 service and region")
}

func awsScopeFromAuthorization(header string) (string, string, bool) {
	_, rest, ok := strings.Cut(header, "Credential=")
	if !ok {
		return "", "", false
	}
	credential := rest
	if index := strings.IndexAny(credential, ", "); index >= 0 {
		credential = credential[:index]
	}
	parts := strings.Split(credential, "/")
	if len(parts) < 5 || parts[4] != "aws4_request" || parts[2] == "" || parts[3] == "" {
		return "", "", false
	}
	return parts[3], parts[2], true
}

func awsScopeFromHost(host string) (string, string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	base, ok := strings.CutSuffix(host, ".amazonaws.com")
	if !ok || base == "" {
		return "", "", false
	}
	labels := strings.Split(base, ".")
	if len(labels) == 1 {
		return labels[0], "us-east-1", true
	}
	if len(labels) >= 3 && labels[1] == "dualstack" {
		return labels[0], labels[2], true
	}
	return labels[0], labels[1], true
}

func hashAndRestoreBody(req *http.Request) (string, error) {
	var body []byte
	if req.Body != nil {
		read, err := io.ReadAll(req.Body)
		if err != nil {
			return "", err
		}
		body = read
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
