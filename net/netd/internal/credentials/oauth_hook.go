package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/vandycknick/silo/net/netd/internal/gateway/hooks"
)

const (
	defaultOAuthRefreshTimeout = 10 * time.Second
	defaultOAuthRefreshSkew    = 5 * time.Minute
)

type OAuthRefreshHook struct {
	command string
	args    []string
	auth    string
	timeout time.Duration
}
type oauthRefreshHookRequest struct {
	Version    int                        `json:"version"`
	Operation  string                     `json:"operation"`
	Grant      string                     `json:"grant"`
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

func (h *OAuthRefreshHook) Refresh(ctx context.Context, credential *hooks.Credential, expiresAt, reason string) (oauthSecret, error) {
	timeout := h.timeout
	if timeout == 0 {
		timeout = defaultOAuthRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request := oauthRefreshHookRequest{Version: 1, Operation: "oauth_refresh", Grant: h.auth, Credential: oauthRefreshHookCredential{Name: credential.Name, Kind: credential.Kind, Endpoint: credential.Endpoint}, Reason: reason, ExpiresAt: expiresAt}
	payload, err := json.Marshal(request)
	if err != nil {
		return oauthSecret{}, err
	}
	var input bytes.Buffer
	if err := writeJSONFrame(&input, payload); err != nil {
		return oauthSecret{}, err
	}
	cmd := exec.CommandContext(ctx, h.command, h.args...)
	cmd.Env = []string{}
	cmd.WaitDelay = time.Second
	cmd.Stdin = &input
	stdout := boundedOutput{limit: 1 << 20}
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook timed out or canceled")
	}
	if err != nil {
		return oauthSecret{}, fmt.Errorf("oauth refresh hook failed: %w", err)
	}
	var response oauthRefreshHookResponse
	if err := readJSONFrame(bytes.NewReader(stdout.Bytes()), &response); err != nil {
		return oauthSecret{}, fmt.Errorf("invalid oauth refresh response")
	}
	if response.Version != 1 {
		return oauthSecret{}, fmt.Errorf("unsupported oauth refresh response version")
	}
	switch response.Status {
	case "ok":
		if response.OAuth.AccessToken == "" || response.OAuth.ExpiresAt == "" {
			return oauthSecret{}, fmt.Errorf("oauth refresh response missing access_token or expires_at")
		}
		return oauthSecret{AccessToken: response.OAuth.AccessToken, ExpiresAt: response.OAuth.ExpiresAt, AccountID: response.OAuth.AccountID}, nil
	case "error":
		if !validOAuthRefreshErrorCode(response.Error.Code) {
			return oauthSecret{}, fmt.Errorf("unsupported oauth refresh error code")
		}
		// Provider messages and stderr are untrusted and may contain secret bytes.
		return oauthSecret{}, fmt.Errorf("oauth refresh hook returned %s", response.Error.Code)
	default:
		return oauthSecret{}, fmt.Errorf("unsupported oauth refresh status")
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
	n, err := writer.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}
func readJSONFrame(reader io.Reader, target any) error {
	payload, err := readFrame(reader, 1<<20)
	if err != nil {
		return err
	}
	return decodeJSON(payload, target)
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, fmt.Errorf("provider output too large")
	}
	return b.buffer.Write(p)
}

func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }
