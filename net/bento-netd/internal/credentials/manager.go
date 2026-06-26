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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/gateway/hooks"
	"github.com/vandycknick/bentobox/net/bento-netd/internal/secrets"
)

const (
	ReasonSecret    = "credential_secret_error"
	ReasonRefresh   = "credential_refresh_error"
	ReasonSigning   = "credential_signing_error"
	ReasonInjection = "credential_injection_error"

	openAICodexClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
	openAITokenURL      = "https://auth.openai.com/oauth/token"
	refreshBeforeExpiry = 2 * time.Minute
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
	store                 secrets.Store
	client                *http.Client
	now                   func() time.Time
	openAITokenURL        string
	awsProfileCredentials func(context.Context, string) (aws.Credentials, error)
}

func NewManager(store secrets.Store) *Manager {
	return &Manager{
		store:                 store,
		client:                &http.Client{Timeout: 30 * time.Second},
		now:                   time.Now,
		openAITokenURL:        openAITokenURL,
		awsProfileCredentials: retrieveAWSProfileCredentials,
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
		return m.applyGitHubOAuth(credential, req)
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

func (m *Manager) applyGitHubOAuth(credential *hooks.Credential, req *http.Request) error {
	secret, _, err := m.oauthSlot(credential, "oauth")
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
	secret, fromEnv, err := m.oauthSlot(credential, "oauth")
	if err != nil {
		return applyError(ReasonSecret, "openai codex oauth: %w", err)
	}
	if m.oauthNeedsRefresh(secret) {
		refreshed, err := m.refreshOpenAICodexOAuth(ctx, secret)
		if err != nil {
			return applyError(ReasonRefresh, "%w", err)
		}
		if !fromEnv {
			key := slotKey(credential.Kind, credential.Name, "oauth")
			if m.store == nil {
				return applyError(ReasonRefresh, "secret store is not configured")
			}
			if err := m.store.UpdateOAuth(key, refreshed); err != nil {
				return applyError(ReasonRefresh, "update oauth slot %q: %w", key, err)
			}
		}
		secret = refreshed
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
	key := slotKey(credential.Kind, credential.Name, slot)
	if m.store != nil {
		secret, err := m.store.Get(key)
		if err == nil {
			value, err := secret.PlainValue()
			if err != nil {
				return "", fmt.Errorf("slot %q: %w", key, err)
			}
			if value == "" {
				if required {
					return "", fmt.Errorf("slot %q is empty", key)
				}
				return "", nil
			}
			return value, nil
		}
		if !errors.Is(err, secrets.ErrNotFound) {
			return "", fmt.Errorf("slot %q: %w", key, err)
		}
	}
	if value, ok := os.LookupEnv(envNameForSlot(key)); ok {
		if value == "" {
			return "", fmt.Errorf("env %s is empty", envNameForSlot(key))
		}
		return value, nil
	}
	if required {
		return "", fmt.Errorf("slot %q not found", key)
	}
	return "", nil
}

func (m *Manager) oauthSlot(credential *hooks.Credential, slot string) (secrets.OAuthSecret, bool, error) {
	key := slotKey(credential.Kind, credential.Name, slot)
	if m.store != nil {
		secret, err := m.store.Get(key)
		if err == nil {
			oauth, err := secret.OAuth()
			if err != nil {
				return secrets.OAuthSecret{}, false, fmt.Errorf("slot %q: %w", key, err)
			}
			return oauth, false, nil
		}
		if !errors.Is(err, secrets.ErrNotFound) {
			return secrets.OAuthSecret{}, false, fmt.Errorf("slot %q: %w", key, err)
		}
	}
	oauth, ok, err := oauthSecretFromEnv(key)
	if err != nil {
		return secrets.OAuthSecret{}, true, err
	}
	if ok {
		return oauth, true, nil
	}
	return secrets.OAuthSecret{}, false, fmt.Errorf("slot %q not found", key)
}

func slotKey(kind string, name string, slot string) string {
	return kind + "." + name + "." + slot
}

func envNameForSlot(key string) string {
	var builder strings.Builder
	builder.WriteString("BENTO_SECRET_")
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

func oauthSecretFromEnv(key string) (secrets.OAuthSecret, bool, error) {
	base := envNameForSlot(key)
	accessToken, hasAccessToken := os.LookupEnv(base + "_ACCESS_TOKEN")
	refreshToken, hasRefreshToken := os.LookupEnv(base + "_REFRESH_TOKEN")
	expiresAt, hasExpiresAt := os.LookupEnv(base + "_EXPIRES_AT")
	if !hasAccessToken && !hasRefreshToken && !hasExpiresAt {
		return secrets.OAuthSecret{}, false, nil
	}
	if accessToken == "" || refreshToken == "" || expiresAt == "" {
		return secrets.OAuthSecret{}, true, fmt.Errorf("env oauth slot %q is incomplete", key)
	}
	secret := secrets.OAuthSecret{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}
	secret.AccountID, _ = os.LookupEnv(base + "_ACCOUNT_ID")
	secret.CreatedAt, _ = os.LookupEnv(base + "_CREATED_AT")
	secret.UpdatedAt, _ = os.LookupEnv(base + "_UPDATED_AT")
	return secret, true, nil
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

func (m *Manager) oauthNeedsRefresh(secret secrets.OAuthSecret) bool {
	expiresAt, err := time.Parse(time.RFC3339, secret.ExpiresAt)
	if err != nil {
		return true
	}
	return !m.now().Add(refreshBeforeExpiry).Before(expiresAt)
}

func (m *Manager) refreshOpenAICodexOAuth(ctx context.Context, secret secrets.OAuthSecret) (secrets.OAuthSecret, error) {
	client := m.client
	if client == nil {
		client = http.DefaultClient
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", secret.RefreshToken)
	form.Set("client_id", openAICodexClientID)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.openAITokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return secrets.OAuthSecret{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return secrets.OAuthSecret{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 512))
		return secrets.OAuthSecret{}, fmt.Errorf("refresh endpoint returned %s", response.Status)
	}
	var token struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil {
		return secrets.OAuthSecret{}, err
	}
	if token.AccessToken == "" {
		return secrets.OAuthSecret{}, fmt.Errorf("refresh response did not include access_token")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = secret.RefreshToken
	}
	createdAt := secret.CreatedAt
	if createdAt == "" {
		createdAt = rfc3339(m.now())
	}
	return secrets.OAuthSecret{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    rfc3339(m.now().Add(time.Duration(token.ExpiresIn) * time.Second)),
		AccountID:    openAIAccountID(secrets.OAuthSecret{AccessToken: token.AccessToken, AccountID: secret.AccountID}),
		CreatedAt:    createdAt,
		UpdatedAt:    rfc3339(m.now()),
	}, nil
}

func rfc3339(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func openAIAccountID(secret secrets.OAuthSecret) string {
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
