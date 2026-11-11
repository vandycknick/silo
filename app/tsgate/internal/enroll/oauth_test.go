package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedOAuthActualHTTP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/v2/oauth/token" {
			if user, secret, ok := r.BasicAuth(); !ok || user != "some-client-id" || secret != "tskey-client-test" {
				t.Error("wrong authentication")
			}
			_, _ = io.WriteString(w, `{"access_token":"token"}`)
		} else {
			if r.Header.Get("Authorization") != "Bearer token" {
				t.Error("missing bearer")
			}
			_, _ = io.WriteString(w, `{"key":"tskey-auth-test"}`)
		}
	}))
	defer server.Close()
	key, e := Mint(context.Background(), server.Client(), server.URL, "tskey-client-test", "tag:silo")
	if e != nil || key != "tskey-auth-test" || calls.Load() != 2 {
		t.Fatalf("%s %v %d", key, e, calls.Load())
	}
	if _, e = Mint(context.Background(), server.Client(), server.URL, "tskey-client-test?baseURL=bad", "tag:silo"); e == nil || calls.Load() != 2 {
		t.Fatal("discovery accepted")
	}
	finish := make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-finish:
		}
	}))
	defer blocked.Close()
	defer close(finish)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, e = Mint(ctx, blocked.Client(), blocked.URL, "tskey-client-test", "tag:silo"); e == nil {
		t.Fatal("uncancelled OAuth")
	}
}
func TestCredentialHTTPOutageIsDistinctFromRejection(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusForbidden} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "tskey-auth-private /etc/private")
		}))
		key, err := Mint(context.Background(), server.Client(), server.URL, "tskey-client-test", "tag:silo")
		server.Close()
		wantUnavailable := status != http.StatusForbidden
		if key != "" || err == nil || errors.Is(err, ErrCredentialUnavailable) != wantUnavailable {
			t.Fatal(status, key, err)
		}
		if err.Error() != "tailnet credential service unavailable" && err.Error() != "tailnet credential request rejected" {
			t.Fatal("HTTP secret diagnostic escaped", err)
		}
	}
}

func TestOAuthResponseBoundsAndRedirects(t *testing.T) {
	for _, body := range []string{strings.Repeat("x", 65537), `broken`, `{}`, `{"access_token":1}`, `{"access_token":""}`} {
		t.Run(body[:min(len(body), 20)], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer srv.Close()
			if _, err := Mint(context.Background(), srv.Client(), srv.URL, "tskey-client-test", "tag:lobby"); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer sink.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, err := Mint(context.Background(), srv.Client(), srv.URL, "tskey-client-test", "tag:lobby"); err == nil {
		t.Fatal("redirect accepted")
	}
	for _, secret := range []string{"", "tskey-auth-test", "tskey-client-test?baseURL=bad", "tskey-client-test\n", "tskey-client-test bad"} {
		if _, err := Mint(context.Background(), srv.Client(), srv.URL, secret, "tag:lobby"); err == nil {
			t.Fatal("invalid secret accepted")
		}
	}
}
func TestMintKeyProperties(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		var body struct {
			Capabilities struct {
				Devices struct {
					Create struct {
						Reusable, Ephemeral, Preauthorized bool
						Tags                               []string
					}
				}
			}
			ExpirySeconds int
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		c := body.Capabilities.Devices.Create
		if c.Reusable || c.Ephemeral || c.Preauthorized || len(c.Tags) != 1 || c.Tags[0] != "tag:lobby" || body.ExpirySeconds != 300 {
			t.Errorf("unexpected key properties: %+v", body)
		}
		io.WriteString(w, `{"key":"tskey-auth-test"}`)
	}))
	defer srv.Close()
	if _, err := Mint(context.Background(), srv.Client(), srv.URL, "tskey-client-test", "tag:lobby"); err != nil {
		t.Fatal(err)
	}
}
