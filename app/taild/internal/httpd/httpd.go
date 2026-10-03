package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vandycknick/silo/app/taild/internal/authz"
	"github.com/vandycknick/silo/app/taild/internal/identity"
	"github.com/vandycknick/silo/app/taild/internal/service"
)

// Resolver is exclusively the accepted connection's tailnet WhoIs boundary.
type Resolver interface {
	WhoIs(context.Context, string) (identity.Peer, error)
}

func Handler(s *service.Service, resolver Resolver) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		if s.Enrollment == nil || s.Enrollment.OAuth == nil {
			http.NotFound(w, r)
			return
		}
		s.Enrollment.OAuth.Callback(w, r)
	})
	for _, path := range []string{"/healthz", "/metrics"} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			p, e := resolver.WhoIs(r.Context(), r.RemoteAddr)
			if e != nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			health, e := s.Health(r.Context(), p)
			if e != nil {
				status := http.StatusForbidden
				var failure *authz.Error
				if errors.As(e, &failure) && failure.Exit == 9 {
					status = http.StatusServiceUnavailable
				}
				http.Error(w, "unavailable or forbidden", status)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			if r.URL.Path == "/metrics" {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				_, _ = w.Write([]byte("taild_runtime_ready 1\ntaild_tailnet_ready 1\n"))
				s.Runtime.Metrics.Write(w)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(health)
		})
	}
	return mux
}
func Server(s *service.Service, resolver Resolver) *http.Server {
	return &http.Server{Handler: Handler(s, resolver), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
}
