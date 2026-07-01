package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/vandycknick/bentobox/net/netd/internal/gateway/hooks"
)

const (
	defaultQueueCapacity = 1024
	closeDrainTimeout    = 5 * time.Second
	redactedHeaderValue  = "<redacted>"
)

type Logger struct {
	policyHash string
	events     chan Event
	done       chan struct{}
	closer     io.Closer
	closeOnce  sync.Once
	closeMu    sync.RWMutex
	closed     atomic.Bool
	drops      atomic.Uint64
	closeErr   error
}

type Event struct {
	Version      int         `json:"version"`
	Phase        string      `json:"phase"`
	Family       string      `json:"family"`
	Timestamp    time.Time   `json:"timestamp"`
	PolicyHash   string      `json:"policy_hash,omitempty"`
	VMID         string      `json:"vm_id,omitempty"`
	NetworkID    string      `json:"network_id,omitempty"`
	FlowID       string      `json:"flow_id,omitempty"`
	ParentFlowID string      `json:"parent_flow_id,omitempty"`
	RequestID    string      `json:"request_id,omitempty"`
	Direction    string      `json:"direction,omitempty"`
	Protocol     string      `json:"protocol,omitempty"`
	IPVersion    string      `json:"ip_version,omitempty"`
	SourceIP     string      `json:"source_ip,omitempty"`
	SourcePort   uint16      `json:"source_port,omitempty"`
	DestIP       string      `json:"destination_ip,omitempty"`
	DestPort     uint16      `json:"destination_port,omitempty"`
	Policy       *Policy     `json:"policy,omitempty"`
	HTTP         *HTTP       `json:"http,omitempty"`
	Credential   *Credential `json:"credential,omitempty"`
	Tunnel       *Tunnel     `json:"tunnel,omitempty"`
	Error        *AuditError `json:"error,omitempty"`
	Verdict      string      `json:"verdict"`
	Reason       string      `json:"reason,omitempty"`
}

type Policy struct {
	EndpointKind string `json:"endpoint_kind,omitempty"`
	EndpointName string `json:"endpoint_name,omitempty"`
	RuleName     string `json:"rule_name,omitempty"`
}

type HTTP struct {
	Scheme   string        `json:"scheme,omitempty"`
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}

type HTTPRequest struct {
	Method  string              `json:"method,omitempty"`
	Host    string              `json:"host,omitempty"`
	Path    string              `json:"path,omitempty"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type HTTPResponse struct {
	Status  int                 `json:"status,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type Credential struct {
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	ErrorReason string `json:"error_reason,omitempty"`
}

type Tunnel struct {
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

type AuditError struct {
	Code string `json:"code,omitempty"`
}

func Open(path string, policyHash string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return newLogger(file, file, policyHash, defaultQueueCapacity), nil
}

func newLogger(writer io.Writer, closer io.Closer, policyHash string, capacity int) *Logger {
	if capacity < 1 {
		capacity = 1
	}
	logger := &Logger{
		policyHash: policyHash,
		events:     make(chan Event, capacity),
		done:       make(chan struct{}),
		closer:     closer,
	}
	go logger.drain(writer)
	return logger
}

func NewFlowID() (string, bool) {
	return newAuditID("ip")
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		l.closeMu.Lock()
		l.closed.Store(true)
		close(l.events)
		l.closeMu.Unlock()

		timer := time.NewTimer(closeDrainTimeout)
		defer timer.Stop()
		select {
		case <-l.done:
		case <-timer.C:
			l.closeErr = fmt.Errorf("audit close timed out after %s", closeDrainTimeout)
			slog.Warn("audit close timed out", "timeout", closeDrainTimeout.String())
		}
		if l.closer != nil {
			if err := l.closer.Close(); err != nil && l.closeErr == nil {
				l.closeErr = err
			}
		}
	})
	return l.closeErr
}

func (l *Logger) RecordFlow(flow hooks.Flow, decision hooks.RouteDecision) {
	l.RecordFlowOutcome(flow, decision, "")
}

func (l *Logger) RecordFlowOutcome(flow hooks.Flow, decision hooks.RouteDecision, reason string) {
	if l == nil {
		return
	}
	effectiveReason := auditReason(decision, reason)
	flowID := flow.FlowID
	if flowID == "" {
		var ok bool
		flowID, ok = NewFlowID()
		if !ok {
			return
		}
	}
	l.emit(Event{
		Version:    1,
		Phase:      "end",
		Family:     "ip",
		Timestamp:  time.Now().UTC(),
		PolicyHash: l.policyHash,
		VMID:       flow.VMID,
		NetworkID:  flow.NetworkID,
		FlowID:     flowID,
		Direction:  "egress",
		Protocol:   flow.Protocol,
		IPVersion:  ipVersion(flow),
		SourceIP:   ipString(flow.SourceIP),
		SourcePort: flow.SourcePort,
		DestIP:     ipString(flow.DestIP),
		DestPort:   flow.DestPort,
		Policy:     policyMetadata(decision),
		Credential: credential(decision, effectiveReason),
		Tunnel:     tunnel(decision),
		Error:      auditError(effectiveReason),
		Verdict:    verdict(decision),
		Reason:     effectiveReason,
	})
}

func (l *Logger) RecordHTTPRequest(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header) {
	l.RecordHTTPRequestOutcome(request, decision, status, responseHeader, "")
}

func (l *Logger) RecordHTTPRequestOutcome(request hooks.HTTPRequest, decision hooks.RouteDecision, status int, responseHeader http.Header, reason string) {
	if l == nil {
		return
	}
	family := httpFamily(request.EndpointKind)
	requestID, ok := newAuditID(family)
	if !ok {
		return
	}
	effectiveReason := auditReason(decision, reason)
	l.emit(Event{
		Version:      1,
		Phase:        "end",
		Family:       family,
		Timestamp:    time.Now().UTC(),
		PolicyHash:   l.policyHash,
		VMID:         request.Flow.VMID,
		NetworkID:    request.Flow.NetworkID,
		ParentFlowID: request.Flow.FlowID,
		RequestID:    requestID,
		Direction:    "egress",
		Protocol:     request.Flow.Protocol,
		IPVersion:    ipVersion(request.Flow),
		SourceIP:     ipString(request.Flow.SourceIP),
		SourcePort:   request.Flow.SourcePort,
		DestIP:       ipString(request.Flow.DestIP),
		DestPort:     request.Flow.DestPort,
		Policy:       policyMetadata(decision),
		Credential:   credential(decision, effectiveReason),
		Tunnel:       tunnel(decision),
		Error:        auditError(effectiveReason),
		HTTP: &HTTP{
			Scheme: httpScheme(request.EndpointKind),
			Request: &HTTPRequest{
				Method:  request.Method,
				Host:    request.Host,
				Path:    request.Path,
				Query:   request.Query,
				Headers: redactedHeaders(request.Header),
			},
			Response: &HTTPResponse{
				Status:  status,
				Headers: redactedHeaders(responseHeader),
			},
		},
		Verdict: verdict(decision),
		Reason:  effectiveReason,
	})
}

func (l *Logger) emit(event Event) {
	if l == nil || l.closed.Load() {
		return
	}
	l.closeMu.RLock()
	defer l.closeMu.RUnlock()
	if l.closed.Load() {
		return
	}
	select {
	case l.events <- event:
	default:
		dropped := l.drops.Add(1)
		slog.Warn("audit event dropped", "dropped", dropped, "phase", event.Phase, "family", event.Family)
	}
}

func (l *Logger) drain(writer io.Writer) {
	defer close(l.done)
	encoder := json.NewEncoder(writer)
	for event := range l.events {
		if err := encoder.Encode(event); err != nil {
			slog.Error("audit write failed", "error", err, "phase", event.Phase, "family", event.Family)
		}
	}
}

func newAuditID(family string) (string, bool) {
	id, err := uuid.NewV7()
	if err != nil {
		slog.Error("audit id generation failed", "error", err, "family", family)
		return "", false
	}
	return id.String(), true
}

func verdict(decision hooks.RouteDecision) string {
	if decision.Action == hooks.RouteDeny {
		return "deny"
	}
	return "allow"
}

func auditReason(decision hooks.RouteDecision, reason string) string {
	if reason != "" {
		return reason
	}
	if decision.Reason != "" {
		return decision.Reason
	}
	if decision.Layer == "flow" && decision.Source == "rule" {
		if decision.Action == hooks.RouteDeny {
			return "rule_deny"
		}
		return "rule_allow"
	}
	return decision.Reason
}

func httpFamily(endpointKind string) string {
	return "http"
}

func httpScheme(endpointKind string) string {
	if endpointKind == "https" {
		return "https"
	}
	return "http"
}

func policyMetadata(decision hooks.RouteDecision) *Policy {
	if decision.EndpointKind == "" && decision.EndpointName == "" && decision.RuleName == "" {
		return nil
	}
	return &Policy{
		EndpointKind: decision.EndpointKind,
		EndpointName: decision.EndpointName,
		RuleName:     decision.RuleName,
	}
}

func credential(decision hooks.RouteDecision, reason string) *Credential {
	if decision.Credential == nil && !strings.HasPrefix(reason, "credential_") {
		return nil
	}
	metadata := &Credential{}
	if decision.Credential != nil {
		metadata.Kind = decision.Credential.Kind
		metadata.Name = decision.Credential.Name
		metadata.Status = "selected"
	}
	if strings.HasPrefix(reason, "credential_") {
		if metadata.Status == "" {
			metadata.Status = "error"
		}
		metadata.ErrorReason = reason
	}
	return metadata
}

func tunnel(decision hooks.RouteDecision) *Tunnel {
	if decision.Tunnel == nil || (decision.Tunnel.Kind == "" && decision.Tunnel.Name == "") {
		return nil
	}
	return &Tunnel{Kind: decision.Tunnel.Kind, Name: decision.Tunnel.Name}
}

func auditError(reason string) *AuditError {
	switch reason {
	case "policy_error", "endpoint_error", "upstream_error", "proxy_error", "tunnel_not_connected", "tunnel_error":
		return &AuditError{Code: reason}
	default:
		return nil
	}
}

func redactedHeaders(header http.Header) map[string][]string {
	if len(header) == 0 {
		return nil
	}
	redacted := make(map[string][]string, len(header))
	for name, values := range header {
		canonicalName := http.CanonicalHeaderKey(name)
		if sensitiveHeaderName(canonicalName) {
			redactedValues := make([]string, len(values))
			for i := range redactedValues {
				redactedValues[i] = redactedHeaderValue
			}
			redacted[canonicalName] = redactedValues
			continue
		}
		redacted[canonicalName] = append([]string(nil), values...)
	}
	return redacted
}

func sensitiveHeaderName(name string) bool {
	lowerName := strings.ToLower(name)
	for _, marker := range []string{"auth", "token", "secret", "key", "password", "cookie"} {
		if strings.Contains(lowerName, marker) {
			return true
		}
	}
	return false
}

func ipString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func ipVersion(flow hooks.Flow) string {
	if version := ipVersionForIP(flow.SourceIP); version != "" {
		return version
	}
	return ipVersionForIP(flow.DestIP)
}

func ipVersionForIP(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	if ip.To16() != nil {
		return "ipv6"
	}
	return ""
}
