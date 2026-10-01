package enroll

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestDeviceEndpointIdentityResolutionAndExpiry(t *testing.T) {
	var mu sync.Mutex
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			t.Error("missing token")
		}
		switch r.URL.Path {
		case "/api/v2/tailnet/-/devices":
			_, _ = io.WriteString(w, `{"devices":[{"id":"endpoint-123","nodeId":"stable-node"}]}`)
		case "/api/v2/device/endpoint-123":
			if r.Method == "GET" {
				_, _ = io.WriteString(w, `{"id":"endpoint-123","nodeId":"stable-node","name":"dev.tail.test","addresses":["100.64.1.2"],"expires":"2030-01-01T00:00:00Z"}`)
			}
		case "/api/v2/device/endpoint-123/key":
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"keyExpiryDisabled":true}` {
				t.Error(string(b))
			}
		default:
			t.Error("stable ID used as endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	d := NewDevices("admin-token")
	d.base = server.URL
	d.client = server.Client()
	device, err := d.Get(context.Background(), "stable-node")
	if err != nil || device.ID != "endpoint-123" || len(device.Addresses) != 1 {
		t.Fatal(device, err)
	}
	if err = d.DisableExpiry(context.Background(), "stable-node"); err != nil {
		t.Fatal(err)
	}
	if err = d.Delete(context.Background(), "stable-node"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 8 || paths[7] != "DELETE /api/v2/device/endpoint-123" {
		t.Fatal(paths)
	}
}
func TestDeviceMismatchNeverDeletes(t *testing.T) {
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleted = true
		}
		if r.URL.Path == "/api/v2/tailnet/-/devices" {
			_, _ = io.WriteString(w, `{"devices":[{"id":"endpoint","nodeId":"stable"}]}`)
		} else {
			_, _ = io.WriteString(w, `{"id":"endpoint","nodeId":"foreign"}`)
		}
	}))
	defer server.Close()
	d := NewDevices("token")
	d.base = server.URL
	d.client = server.Client()
	if d.Delete(context.Background(), "stable") == nil || deleted {
		t.Fatal("foreign device deleted")
	}
}
