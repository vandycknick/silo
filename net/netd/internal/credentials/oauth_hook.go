package credentials

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

const (
	OAuthRefreshHookEnv = "SILO_NET_OAUTH_REFRESH_HOOK"
	OAuthRefreshAuthEnv = "SILO_NET_OAUTH_REFRESH_AUTH"

	defaultOAuthRefreshTimeout = 10 * time.Second
	defaultOAuthRefreshSkew    = 5 * time.Minute
)

type OAuthRefreshHook struct {
	command string
	args    []string
	auth    string
	timeout time.Duration
	skew    time.Duration
}

type oauthRefreshHookConfig struct {
	Version            int      `json:"version"`
	Command            string   `json:"command"`
	Args               []string `json:"args,omitempty"`
	TimeoutMS          int64    `json:"timeout_ms,omitempty"`
	RefreshSkewSeconds int64    `json:"refresh_skew_seconds,omitempty"`
}

type oauthRefreshHookRequest struct {
	Version    int                        `json:"version"`
	Operation  string                     `json:"operation"`
	Credential oauthRefreshHookCredential `json:"credential"`
	Reason     string                     `json:"reason"`
	ExpiresAt  string                     `json:"expires_at"`
}

type oauthRefreshHookCredential struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

type oauthRefreshHookResponse struct {
	Version int                       `json:"version"`
	Status  string                    `json:"status"`
	OAuth   oauthRefreshHookOAuth     `json:"oauth,omitempty"`
	Error   oauthRefreshHookErrorBody `json:"error,omitempty"`
}

type oauthRefreshHookOAuth struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
	AccountID   string `json:"account_id,omitempty"`
}

type oauthRefreshHookErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

func LoadOAuthRefreshHookFromEnvironment() (*OAuthRefreshHook, error) {
	encoded, ok := os.LookupEnv(OAuthRefreshHookEnv)
	if !ok {
		return nil, nil
	}
	if encoded == "" {
		return nil, fmt.Errorf("%s is empty", OAuthRefreshHookEnv)
	}
	auth, ok := os.LookupEnv(OAuthRefreshAuthEnv)
	if !ok || auth == "" {
		return nil, fmt.Errorf("%s is required when %s is set", OAuthRefreshAuthEnv, OAuthRefreshHookEnv)
	}
	if _, err := base64.StdEncoding.DecodeString(auth); err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", OAuthRefreshAuthEnv, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", OAuthRefreshHookEnv, err)
	}
	var config oauthRefreshHookConfig
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode %s: %w", OAuthRefreshHookEnv, err)
	}
	if config.Version != 1 {
		return nil, fmt.Errorf("oauth refresh hook version %d is not supported", config.Version)
	}
	if config.Command == "" {
		return nil, fmt.Errorf("oauth refresh hook command is required")
	}
	if !filepath.IsAbs(config.Command) {
		return nil, fmt.Errorf("oauth refresh hook command must be absolute")
	}
	timeout := defaultOAuthRefreshTimeout
	if config.TimeoutMS > 0 {
		timeout = time.Duration(config.TimeoutMS) * time.Millisecond
	}
	refreshSkew := defaultOAuthRefreshSkew
	if config.RefreshSkewSeconds > 0 {
		refreshSkew = time.Duration(config.RefreshSkewSeconds) * time.Second
	}
	return &OAuthRefreshHook{
		command: config.Command,
		args:    append([]string(nil), config.Args...),
		auth:    auth,
		timeout: timeout,
		skew:    refreshSkew,
	}, nil
}

func (h *OAuthRefreshHook) refreshSkew() time.Duration {
	if h == nil || h.skew <= 0 {
		return defaultOAuthRefreshSkew
	}
	return h.skew
}

func (h *OAuthRefreshHook) Refresh(ctx context.Context, credential *hooks.Credential, expiresAt string, reason string) (oauthSecret, error) {
	if h == nil {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook is not configured")
	}
	timeout := h.timeout
	if timeout <= 0 {
		timeout = defaultOAuthRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := oauthRefreshHookRequest{
		Version:   1,
		Operation: "oauth_refresh",
		Credential: oauthRefreshHookCredential{
			Name:     credential.Name,
			Kind:     credential.Kind,
			Endpoint: credential.Endpoint,
		},
		Reason:    reason,
		ExpiresAt: expiresAt,
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return oauthSecret{}, err
	}

	cmd := exec.CommandContext(ctx, h.command, h.args...)
	cmd.Env = []string{OAuthRefreshAuthEnv + "=" + h.auth}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return oauthSecret{}, fmt.Errorf("prepare hook stdin: %w", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return oauthSecret{}, fmt.Errorf("start oauth refresh hook: %w", err)
	}
	writeErr := writeJSONFrame(stdin, requestBytes)
	closeErr := stdin.Close()
	if writeErr != nil {
		_ = cmd.Wait()
		return oauthSecret{}, fmt.Errorf("write oauth refresh hook request: %w", writeErr)
	}
	if closeErr != nil {
		_ = cmd.Wait()
		return oauthSecret{}, fmt.Errorf("close oauth refresh hook stdin: %w", closeErr)
	}
	waitErr := cmd.Wait()
	if ctx.Err() == context.DeadlineExceeded {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook timed out after %s", timeout)
	}
	if waitErr != nil {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook failed: %w", waitErr)
	}

	var response oauthRefreshHookResponse
	if err := readJSONFrame(bytes.NewReader(stdout.Bytes()), &response); err != nil {
		return oauthSecret{}, fmt.Errorf("read oauth refresh hook response: %w", err)
	}
	if response.Version != 1 {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook response version %d is not supported", response.Version)
	}
	switch response.Status {
	case "ok":
		if response.OAuth.AccessToken == "" || response.OAuth.ExpiresAt == "" {
			return oauthSecret{}, fmt.Errorf("oauth refresh hook success response is missing access_token or expires_at")
		}
		return oauthSecret{AccessToken: response.OAuth.AccessToken, ExpiresAt: response.OAuth.ExpiresAt, AccountID: response.OAuth.AccountID}, nil
	case "error":
		if !validOAuthRefreshErrorCode(response.Error.Code) {
			return oauthSecret{}, fmt.Errorf("oauth refresh hook returned unsupported error code %q", response.Error.Code)
		}
		if response.Error.Message == "" {
			return oauthSecret{}, fmt.Errorf("oauth refresh hook returned %s", response.Error.Code)
		}
		return oauthSecret{}, fmt.Errorf("oauth refresh hook returned %s: %s", response.Error.Code, response.Error.Message)
	default:
		return oauthSecret{}, fmt.Errorf("oauth refresh hook returned unsupported status %q", response.Status)
	}
}

func validOAuthRefreshErrorCode(code string) bool {
	switch code {
	case "unauthorized", "not_found", "provider_unavailable", "provider_rejected", "rate_limited", "invalid_request", "internal_error":
		return true
	default:
		return false
	}
}

func writeJSONFrame(writer io.Writer, payload []byte) error {
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

func readJSONFrame(reader io.Reader, target any) error {
	buffered := bufio.NewReader(reader)
	headers, err := textproto.NewReader(buffered).ReadMIMEHeader()
	if err != nil {
		return err
	}
	lengthText := headers.Get("Content-Length")
	if lengthText == "" {
		return fmt.Errorf("missing Content-Length")
	}
	length, err := strconv.Atoi(lengthText)
	if err != nil || length < 0 {
		return fmt.Errorf("invalid Content-Length %q", lengthText)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(buffered, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("hook frame contains multiple JSON values")
	}
	return nil
}
