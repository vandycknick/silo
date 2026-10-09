package testfixture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Devices removes only a device resolved and verified by its observed stable
// node ID, following the enrollment live fixture's API-token cleanup pattern.
// Tokens and server response bodies must never enter test diagnostics.
type Devices struct {
	token  string
	client *http.Client
}

func NewDevices(token string) *Devices {
	return &Devices{token: token, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (d *Devices) request(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "https://api.tailscale.com"+path, nil)
	if err != nil {
		return errors.New("device API unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if strings.HasPrefix(d.token, "tskey-api-") {
		req.SetBasicAuth(d.token, "")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.New("device API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("device API rejected request")
	}
	if out != nil {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
		if err != nil || len(data) > 4<<20 || json.Unmarshal(data, out) != nil {
			return errors.New("invalid device API response")
		}
	}
	return nil
}

func (d *Devices) Delete(ctx context.Context, nodeID string) error {
	if nodeID == "" || d.token == "" {
		return errors.New("device identity unavailable")
	}
	type device struct {
		ID     string `json:"id"`
		NodeID string `json:"nodeId"`
	}
	var list struct {
		Devices []device `json:"devices"`
	}
	if err := d.request(ctx, http.MethodGet, "/api/v2/tailnet/-/devices", &list); err != nil {
		return err
	}
	id := ""
	for _, entry := range list.Devices {
		if entry.NodeID != nodeID {
			continue
		}
		if id != "" || entry.ID == "" {
			return errors.New("ambiguous device identity")
		}
		id = entry.ID
	}
	if id == "" || len(id) > 128 || strings.ContainsFunc(id, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-'
	}) {
		return errors.New("invalid device identity")
	}
	var fetched device
	path := "/api/v2/device/" + url.PathEscape(id)
	if err := d.request(ctx, http.MethodGet, path, &fetched); err != nil {
		return err
	}
	if fetched.ID != id || fetched.NodeID != nodeID {
		return errors.New("device identity mismatch")
	}
	return d.request(ctx, http.MethodDelete, path, nil)
}
