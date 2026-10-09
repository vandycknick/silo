package netnode

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Qualification-only minting is separate from netd/tsnet initialization and
// bounded by the caller and an explicit HTTP deadline. No ambient discovery.
func mintEnrollmentKey(t *testing.T, parent context.Context, secret string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"some-client-id"}, "client_secret": {secret}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("qualification OAuth request failed")
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token)
	response.Body.Close()
	if response.StatusCode != 200 || err != nil || token.AccessToken == "" {
		t.Fatal("qualification OAuth response rejected")
	}
	type create struct {
		Reusable  bool     `json:"reusable"`
		Ephemeral bool     `json:"ephemeral"`
		Tags      []string `json:"tags"`
	}
	var body struct {
		Capabilities struct {
			Devices struct {
				Create create `json:"create"`
			} `json:"devices"`
		} `json:"capabilities"`
	}
	body.Capabilities.Devices.Create.Tags = []string{"tag:silo-test-vm"}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/tailnet/-/keys", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal("qualification enrollment key request failed")
	}
	var key struct {
		Key string `json:"key"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&key)
	response.Body.Close()
	if response.StatusCode/100 != 2 || err != nil || !literalEnrollmentKey(key.Key) || key.Key == "" {
		t.Fatal("qualification enrollment key response rejected")
	}
	return key.Key
}
