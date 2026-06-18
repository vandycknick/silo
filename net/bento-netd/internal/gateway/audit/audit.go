package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/nickvan/bentobox/net/bento-netd/internal/gateway/hooks"
)

type Logger struct {
	file *os.File
	mu   sync.Mutex
}

type Event struct {
	Timestamp    time.Time         `json:"timestamp"`
	Action       string            `json:"action"`
	FinalAction  hooks.RouteAction `json:"final_action"`
	Reason       string            `json:"reason,omitempty"`
	RuleName     string            `json:"rule_name,omitempty"`
	EndpointKind string            `json:"endpoint_kind,omitempty"`
	EndpointName string            `json:"endpoint_name,omitempty"`
	Layer        string            `json:"layer,omitempty"`
	Protocol     string            `json:"protocol"`
	SourceIP     string            `json:"source_ip"`
	SourcePort   uint16            `json:"source_port"`
	DestIP       string            `json:"dest_ip"`
	DestPort     uint16            `json:"dest_port"`
	HTTPMethod   string            `json:"http_method,omitempty"`
	HTTPHost     string            `json:"http_host,omitempty"`
	HTTPPath     string            `json:"http_path,omitempty"`
	VMID         string            `json:"vm_id,omitempty"`
	NetworkID    string            `json:"network_id,omitempty"`
}

func Open(path string) (*Logger, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{file: file}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) RecordFlow(flow hooks.Flow, decision hooks.RouteDecision) {
	if l == nil || l.file == nil {
		return
	}
	record := Event{
		Timestamp:    time.Now().UTC(),
		Action:       "decision",
		FinalAction:  decision.Action,
		Reason:       decision.Reason,
		RuleName:     decision.RuleName,
		EndpointKind: decision.EndpointKind,
		EndpointName: decision.EndpointName,
		Layer:        decision.Layer,
		Protocol:     flow.Protocol,
		SourceIP:     flow.SourceIP.String(),
		SourcePort:   flow.SourcePort,
		DestIP:       flow.DestIP.String(),
		DestPort:     flow.DestPort,
		VMID:         flow.VMID,
		NetworkID:    flow.NetworkID,
	}
	l.write(record)
}

func (l *Logger) RecordHTTP(request hooks.HTTPRequest, decision hooks.RouteDecision) {
	if l == nil || l.file == nil {
		return
	}
	record := Event{
		Timestamp:    time.Now().UTC(),
		Action:       "decision",
		FinalAction:  decision.Action,
		Reason:       decision.Reason,
		RuleName:     decision.RuleName,
		EndpointKind: decision.EndpointKind,
		EndpointName: decision.EndpointName,
		Layer:        decision.Layer,
		Protocol:     request.Flow.Protocol,
		SourceIP:     request.Flow.SourceIP.String(),
		SourcePort:   request.Flow.SourcePort,
		DestIP:       request.Flow.DestIP.String(),
		DestPort:     request.Flow.DestPort,
		HTTPMethod:   request.Method,
		HTTPHost:     request.Host,
		HTTPPath:     request.Path,
		VMID:         request.Flow.VMID,
		NetworkID:    request.Flow.NetworkID,
	}
	l.write(record)
}

func (l *Logger) write(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.file).Encode(event)
}
