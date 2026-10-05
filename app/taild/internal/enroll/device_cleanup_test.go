//go:build e2e

package enroll

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
	"io"
	"net/http"
	"net/netip"
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

var ErrDeviceNotFound = errors.New("device not found")
var ErrInvalidDeviceResponse = errors.New("invalid device response")

func NewDevices(token string) *Devices {
	if token == "" {
		return nil
	}
	return &Devices{token: token, base: "https://api.tailscale.com", client: tailnet.NewHTTPClient(15 * time.Second)}
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
		if resp.StatusCode == http.StatusNotFound {
			return ErrDeviceNotFound
		}
		return errors.New("device API rejected request")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(b) > 4<<20 {
		return ErrInvalidDeviceResponse
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return ErrInvalidDeviceResponse
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
	if list.Devices == nil {
		return Device{}, ErrInvalidDeviceResponse
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
		return Device{}, ErrDeviceNotFound
	}
	if len(id) > 128 || strings.ContainsFunc(id, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-'
	}) {
		return Device{}, ErrInvalidDeviceResponse
	}
	var device Device
	if err := d.request(ctx, "GET", "/api/v2/device/"+url.PathEscape(id), nil, &device); err != nil {
		return Device{}, err
	}
	if device.ID != id || device.NodeID != nodeID {
		return Device{}, ErrInvalidDeviceResponse
	}
	if len(device.Name) > 253 || strings.ContainsAny(device.Name, "/\\?@\r\n\x00 ") {
		return Device{}, ErrInvalidDeviceResponse
	}
	for _, address := range device.Addresses {
		if ip, err := netip.ParseAddr(address); err != nil || !ip.IsGlobalUnicast() {
			return Device{}, ErrInvalidDeviceResponse
		}
	}
	if device.Expires != "" {
		if _, err := time.Parse(time.RFC3339, device.Expires); err != nil {
			return Device{}, ErrInvalidDeviceResponse
		}
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
