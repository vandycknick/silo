package tailnet

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
)

var ErrCredentialUnavailable = errors.New("Tailscale credential service unavailable")

// Mint uses the standard OAuth client-secret flow from pinned oauthkey, with
// one caller-owned deadline. tsnet.Start must receive only the literal result:
// its own ClientSecret discovery has no caller cancellation and can block Close.
func Mint(ctx context.Context, client *http.Client, base, secret, tag string) (string, error) {
	if !strings.HasPrefix(secret, "tskey-client-") || strings.ContainsAny(secret, "?\r\n \t") {
		return "", errors.New("oauth-client-secret must be a literal client secret")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "POST", base+"/api/v2/oauth/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	if e != nil {
		return "", e
	}
	request.SetBasicAuth("some-client-id", secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if e = doJSON(client, request, &token); e != nil {
		return "", e
	}
	if token.AccessToken == "" {
		return "", errors.New("OAuth returned no token")
	}
	body := struct {
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
		ExpirySeconds int `json:"expirySeconds"`
	}{ExpirySeconds: 300}
	body.Capabilities.Devices.Create.Tags = []string{tag}
	b, e := json.Marshal(body)
	if e != nil {
		return "", e
	}
	request, e = http.NewRequestWithContext(ctx, "POST", base+"/api/v2/tailnet/-/keys", bytes.NewReader(b))
	if e != nil {
		return "", e
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	var result struct {
		Key string `json:"key"`
	}
	if e = doJSON(client, request, &result); e != nil {
		return "", e
	}
	if !strings.HasPrefix(result.Key, "tskey-auth-") || strings.ContainsAny(result.Key, "?\r\n \t") {
		return "", errors.New("OAuth returned invalid auth key")
	}
	return result.Key, nil
}
func doJSON(client *http.Client, req *http.Request, out any) error {
	response, e := client.Do(req)
	if e != nil {
		return ErrCredentialUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 || response.StatusCode == http.StatusTooManyRequests {
		return ErrCredentialUnavailable
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Tailscale credential request rejected")
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(b) > 65536 {
		return errors.New("invalid Tailscale credential response")
	}
	return json.Unmarshal(b, out)
}
