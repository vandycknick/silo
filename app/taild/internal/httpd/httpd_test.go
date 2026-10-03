package httpd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vandycknick/silo/app/taild/internal/config"
	"github.com/vandycknick/silo/app/taild/internal/metrics"
	"github.com/vandycknick/silo/app/taild/internal/service"
	"github.com/vandycknick/silo/app/taild/internal/tailnet"
)

func TestActualUnregisteredNodeDeniesHTTPHeaders(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "offline", http.StatusServiceUnavailable) }))
	defer control.Close()
	c := config.Defaults()
	c.Home = t.TempDir()
	c.Tailnet.ControlURL = control.URL
	node, e := tailnet.Start(context.Background(), c, config.Secrets{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	defer node.Close()
	node.Metrics = metrics.New()
	server := httptest.NewServer(Handler(&service.Service{}, node))
	defer server.Close()
	for _, path := range []string{"/healthz", "/metrics", "/oauth/callback"} {
		req, e := http.NewRequest("GET", server.URL+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("X-Forwarded-For", "100.100.100.100")
		req.Header.Set("X-Tailscale-User-Login", "admin@example.com")
		response, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		want := 403
		if path == "/oauth/callback" {
			want = 404
		}
		if response.StatusCode != want {
			t.Fatalf("%s: %d", path, response.StatusCode)
		}
	}
	var out bytes.Buffer
	node.Metrics.Write(&out)
	if !strings.Contains(out.String(), `taild_whois_duration_seconds_count{outcome="failed"} 2`) {
		t.Fatal("actual WhoIs failures not measured", out.String())
	}
}
