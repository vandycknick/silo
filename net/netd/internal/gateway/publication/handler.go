package publication

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/google/uuid"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
)

const maxRequestBody = 64 * 1024

func Handler(table *Table, policy Policy, auditLog *audit.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /services/forwarder/expose", func(w http.ResponseWriter, r *http.Request) {
		expose(w, r, table, policy, auditLog, AttachmentScope, false)
	})
	mux.HandleFunc("POST /services/forwarder/expose/session", func(w http.ResponseWriter, r *http.Request) {
		expose(w, r, table, policy, auditLog, SessionScope(uuid.NewString()), true)
	})
	mux.HandleFunc("POST /services/forwarder/unexpose", func(w http.ResponseWriter, r *http.Request) {
		unexpose(w, r, table, policy, auditLog)
	})
	mux.HandleFunc("GET /services/forwarder/all", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(table.All()); err != nil {
			return
		}
	})
	return mux
}

func expose(w http.ResponseWriter, r *http.Request, table *Table, policy Policy, auditLog *audit.Logger, scope Scope, session bool) {
	var flusher http.Flusher
	if session {
		var ok bool
		flusher, ok = w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming responses are unavailable", http.StatusInternalServerError)
			return
		}
	}
	var request types.ExposeRequest
	if err := decodeRequest(r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	normalized, reason, err := policy.Validate(request)
	if err != nil {
		if reason != "address" {
			auditLog.RecordPublication("denied", scope.AuditName(), request.Local, request.Remote, "deny", reason)
		}
		status := http.StatusBadRequest
		if reason == "bind_policy" {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	entry, created, err := table.Expose(normalized, scope)
	if err != nil {
		reason := "bind_failed"
		status := http.StatusInternalServerError
		if errors.Is(err, ErrConflict) {
			reason = "conflict"
			status = http.StatusConflict
		}
		auditLog.RecordPublication("denied", scope.AuditName(), normalized.Local, normalized.Remote, "deny", reason)
		http.Error(w, err.Error(), status)
		return
	}
	if created {
		auditLog.RecordPublication("exposed", scope.AuditName(), entry.Local, entry.Remote, "allow", "")
	}
	if !session {
		w.WriteHeader(http.StatusOK)
		return
	}
	defer func() {
		released, _ := table.ReleaseScope(scope)
		for _, releasedEntry := range released {
			auditLog.RecordPublication("released", scope.AuditName(), releasedEntry.Local, releasedEntry.Remote, "allow", "")
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		return
	}
	flusher.Flush()
	<-r.Context().Done()
}

func unexpose(w http.ResponseWriter, r *http.Request, table *Table, policy Policy, auditLog *audit.Logger) {
	var request types.UnexposeRequest
	if err := decodeRequest(r, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	normalized, _, err := policy.ValidateUnexpose(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entry, err := table.Unexpose(normalized)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	auditLog.RecordPublication("released", entry.Scope.AuditName(), entry.Local, entry.Remote, "allow", "")
	w.WriteHeader(http.StatusOK)
}

func decodeRequest(r *http.Request, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	if err := decoder.Decode(destination); err != nil {
		_ = r.Body.Close()
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		_ = r.Body.Close()
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return fmt.Errorf("decode trailing request body: %w", err)
	}
	return r.Body.Close()
}
