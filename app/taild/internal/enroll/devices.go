package enroll

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

type Device struct {
	ID        string   `json:"id"`
	NodeID    string   `json:"nodeId"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Expires   string   `json:"expires"`
}
type Devices struct {
	token, base string
	client      *http.Client
}

func NewDevices(token string) *Devices {
	if token == "" {
		return nil
	}
	return &Devices{token: token, base: "https://api.tailscale.com", client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (d *Devices) request(ctx context.Context, method, path string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, d.base+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("device API unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if strings.HasPrefix(d.token, "tskey-api-") {
		req.SetBasicAuth(d.token, "")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return errors.New("device API unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("device API rejected request")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(b) > 4<<20 {
		return errors.New("invalid device response")
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return errors.New("invalid device response")
	}
	return nil
}

// Stable node IDs are not endpoint device IDs. Resolve, then verify the fetched response.
func (d *Devices) Get(ctx context.Context, nodeID string) (Device, error) {
	if d == nil || nodeID == "" {
		return Device{}, errors.New("device API unavailable")
	}
	var list struct {
		Devices []Device `json:"devices"`
	}
	if err := d.request(ctx, "GET", "/api/v2/tailnet/-/devices", nil, &list); err != nil {
		return Device{}, err
	}
	id := ""
	for _, device := range list.Devices {
		if device.NodeID == nodeID {
			if id != "" || device.ID == "" {
				return Device{}, errors.New("ambiguous device identity")
			}
			id = device.ID
		}
	}
	if id == "" {
		return Device{}, errors.New("device not found")
	}
	var device Device
	if err := d.request(ctx, "GET", "/api/v2/device/"+url.PathEscape(id), nil, &device); err != nil {
		return Device{}, err
	}
	if device.ID != id || device.NodeID != nodeID {
		return Device{}, errors.New("device identity mismatch")
	}
	return device, nil
}
func (d *Devices) Delete(ctx context.Context, nodeID string) error {
	device, err := d.Get(ctx, nodeID)
	if err != nil {
		return err
	}
	return d.request(ctx, "DELETE", "/api/v2/device/"+url.PathEscape(device.ID), nil, nil)
}
func (d *Devices) DisableExpiry(ctx context.Context, nodeID string) error {
	device, err := d.Get(ctx, nodeID)
	if err != nil {
		return err
	}
	return d.request(ctx, "POST", "/api/v2/device/"+url.PathEscape(device.ID)+"/key", []byte(`{"keyExpiryDisabled":true}`), nil)
}
