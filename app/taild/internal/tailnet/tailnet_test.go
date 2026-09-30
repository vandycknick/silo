package tailnet

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/config"
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
func TestUnregisteredRealTSNetLifecycle(t *testing.T) {
	// This endpoint never impersonates a successful control plane or WhoIs.
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unregistered offline control", 503) }))
	defer control.Close()
	c := config.Defaults()
	c.Home = t.TempDir()
	c.Tailnet.ControlURL = control.URL
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	n, e := Start(ctx, c, config.Secrets{}, log)
	if e != nil {
		t.Fatal(e)
	}
	if e = n.WaitReady(ctx); e == nil {
		t.Fatal("unregistered node admitted")
	}
	if _, e = n.WhoIs(context.Background(), "127.0.0.1:123"); e == nil {
		t.Fatal("localhost identity accepted")
	}
	if _, e = os.Stat(c.Home + "/taild/tailnet"); !os.IsNotExist(e) {
		t.Fatal("unverified tailnet was pinned")
	}
	done := make(chan error, 1)
	go func() { done <- n.Close() }()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tsnet.Close hung")
	}
}
