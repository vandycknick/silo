// Package metrics records only bounded operational dimensions, never identities.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

type observation struct {
	Count   uint64
	Seconds float64
}
type Metrics struct {
	mu         sync.Mutex
	jobs       map[string]observation
	latency    map[string]observation
	handles    map[string]int
	sessions   int
	activeJobs int
}

func New() *Metrics {
	return &Metrics{jobs: map[string]observation{}, latency: map[string]observation{}, handles: map[string]int{}}
}
func (m *Metrics) Session(delta int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sessions += delta
	m.mu.Unlock()
}
func (m *Metrics) Job(delta int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.activeJobs += delta
	m.mu.Unlock()
}
func (m *Metrics) Handle(kind string, delta int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.handles[kind] += delta
	m.mu.Unlock()
}
func (m *Metrics) Operation(kind, outcome string, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch kind {
	case "create", "start", "stop", "restart", "remove", "set", "reauth":
	default:
		kind = "other"
	}
	if outcome != "succeeded" {
		outcome = "failed"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := kind + "/" + outcome
	v := m.jobs[key]
	v.Count++
	v.Seconds += elapsed.Seconds()
	m.jobs[key] = v
}
func (m *Metrics) Latency(kind string, elapsed time.Duration, success bool) {
	if m == nil || kind != "whois" && kind != "enrollment" {
		return
	}
	outcome := "failed"
	if success {
		outcome = "succeeded"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := kind + "/" + outcome
	v := m.latency[key]
	v.Count++
	v.Seconds += elapsed.Seconds()
	m.latency[key] = v
}
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "taild_active_sessions %d\ntaild_active_operations %d\n", m.sessions, m.activeJobs)
	keys := make([]string, 0, len(m.jobs))
	for k := range m.jobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		var kind, outcome string
		for j, c := range key {
			if c == '/' {
				kind, outcome = key[:j], key[j+1:]
				break
			}
		}
		v := m.jobs[key]
		fmt.Fprintf(w, "taild_operations_total{kind=%q,outcome=%q} %d\ntaild_operation_duration_seconds_sum{kind=%q,outcome=%q} %g\ntaild_operation_duration_seconds_count{kind=%q,outcome=%q} %d\n", kind, outcome, v.Count, kind, outcome, v.Seconds, kind, outcome, v.Count)
	}
	for _, kind := range []string{"whois", "enrollment"} {
		for _, outcome := range []string{"succeeded", "failed"} {
			v := m.latency[kind+"/"+outcome]
			fmt.Fprintf(w, "taild_%s_duration_seconds_sum{outcome=%q} %g\ntaild_%s_duration_seconds_count{outcome=%q} %d\n", kind, outcome, v.Seconds, kind, outcome, v.Count)
		}
	}
	for _, kind := range []string{"runtime", "machine", "exec", "logs", "node_lease"} {
		fmt.Fprintf(w, "taild_native_handles{kind=%q,scope=\"daemon_owned\"} %d\n", kind, m.handles[kind])
	}
}
