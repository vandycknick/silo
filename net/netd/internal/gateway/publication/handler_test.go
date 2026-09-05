package publication

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/vandycknick/silo/net/netd/internal/gateway/audit"
)

func TestHandlerAcceptsPodmanShapeAndReportsConflicts(t *testing.T) {
	table := NewTable(newRecordingForwarder())
	server := httptest.NewServer(Handler(table, Policy{Bind: BindAny, GuestIP: netip.MustParseAddr("192.168.127.2")}, nil))
	t.Cleanup(server.Close)

	response := postJSON(t, server.URL+"/services/forwarder/expose", `{"local":":8080","remote":":80","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusOK, "")

	response = postJSON(t, server.URL+"/services/forwarder/expose", `{"local":":8080","remote":":80","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusOK, "")
	response = postJSON(t, server.URL+"/services/forwarder/expose", `{"local":":8080","remote":":81","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusConflict, "already published")

	response, err := http.Get(server.URL + "/services/forwarder/all")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var entries []Entry
	if err := json.NewDecoder(response.Body).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Local != "0.0.0.0:8080" || entries[0].Remote != "192.168.127.2:80" {
		t.Fatalf("unexpected publications: %#v", entries)
	}

	response = postJSON(t, server.URL+"/services/forwarder/unexpose", `{"local":":8080","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusOK, "")
}

func TestHandlerEnforcesBindAndProtocolPolicy(t *testing.T) {
	table := NewTable(newRecordingForwarder())
	server := httptest.NewServer(Handler(table, Policy{Bind: BindLoopback, GuestIP: netip.MustParseAddr("192.168.127.2")}, nil))
	t.Cleanup(server.Close)

	response := postJSON(t, server.URL+"/services/forwarder/expose", `{"local":":8080","remote":":80","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusForbidden, "bind policy")
	response = postJSON(t, server.URL+"/services/forwarder/expose", `{"local":"127.0.0.1:8080","remote":":80","protocol":"udp"}`)
	assertResponse(t, response, http.StatusBadRequest, "protocol")
	response = postJSON(t, server.URL+"/services/forwarder/expose", `{"local":"127.0.0.1:8080","remote":"192.168.127.3:80","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusBadRequest, "guest IP")

	if len(table.All()) != 0 {
		t.Fatalf("denied requests reached the publication table: %#v", table.All())
	}
}

func TestHandlerReturnsBindFailureText(t *testing.T) {
	forwarder := newRecordingForwarder()
	forwarder.exposeErr = errors.New("listen tcp 127.0.0.1:8080: address already in use")
	table := NewTable(forwarder)
	server := httptest.NewServer(Handler(table, Policy{Bind: BindAny, GuestIP: netip.MustParseAddr("192.168.127.2")}, nil))
	t.Cleanup(server.Close)

	response := postJSON(t, server.URL+"/services/forwarder/expose", `{"local":"127.0.0.1:8080","remote":":80","protocol":"tcp"}`)
	assertResponse(t, response, http.StatusInternalServerError, "address already in use")
	if len(table.All()) != 0 {
		t.Fatalf("failed bind entered the publication table: %#v", table.All())
	}
}

func TestSessionRouteFlushesAndReleasesOnDisconnectWithAudit(t *testing.T) {
	var auditOutput bytes.Buffer
	auditLog := audit.New(&auditOutput, "sha256:test")
	table := NewTable(newRecordingForwarder())
	server := httptest.NewServer(Handler(table, Policy{Bind: BindAny, GuestIP: netip.MustParseAddr("192.168.127.2")}, auditLog))
	t.Cleanup(server.Close)

	denied := postJSON(t, server.URL+"/services/forwarder/expose", `{"local":":9000","remote":":90","protocol":"udp"}`)
	assertResponse(t, denied, http.StatusBadRequest, "protocol")

	request, err := http.NewRequest(http.MethodPost, server.URL+"/services/forwarder/expose/session", strings.NewReader(`{"local":"127.0.0.1:8081","remote":":81","protocol":"tcp"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" {
		_ = response.Body.Close()
		t.Fatalf("unexpected session response: %s, content type %q", response.Status, response.Header.Get("Content-Type"))
	}
	line, err := bufio.NewReader(response.Body).ReadBytes('\n')
	if err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	var entry Entry
	if err := json.Unmarshal(line, &entry); err != nil {
		_ = response.Body.Close()
		t.Fatalf("decode first session chunk: %v", err)
	}
	if entry.Local != "127.0.0.1:8081" || entry.Remote != "192.168.127.2:81" {
		_ = response.Body.Close()
		t.Fatalf("unexpected session publication: %#v", entry)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return len(table.All()) == 0 })
	server.Close()

	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	var events []audit.Event
	for _, line := range bytes.Split(bytes.TrimSpace(auditOutput.Bytes()), []byte("\n")) {
		var event audit.Event
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if len(events) != 3 {
		t.Fatalf("audit events = %#v, want denied, exposed, and released", events)
	}
	if events[0].Phase != "denied" || events[0].Reason != "protocol" || events[0].Publication.Scope != "attachment" {
		t.Fatalf("unexpected denied audit event: %#v", events[0])
	}
	if events[1].Phase != "exposed" || events[1].Publication.Scope != "session" {
		t.Fatalf("unexpected exposed audit event: %#v", events[1])
	}
	if events[2].Phase != "released" || events[2].Publication.Local != "127.0.0.1:8081" {
		t.Fatalf("unexpected released audit event: %#v", events[2])
	}
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	response, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertResponse(t *testing.T, response *http.Response, wantStatus int, wantBody string) {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body %q", response.StatusCode, wantStatus, body)
	}
	if !bytes.Contains(body, []byte(wantBody)) {
		t.Fatalf("body = %q, want text %q", body, wantBody)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

type recordingForwarder struct {
	mu        sync.Mutex
	entries   map[string]types.ExposeRequest
	exposeErr error
}

func newRecordingForwarder() *recordingForwarder {
	return &recordingForwarder{entries: make(map[string]types.ExposeRequest)}
}

func (f *recordingForwarder) Expose(protocol types.TransportProtocol, local, remote string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.exposeErr != nil {
		return f.exposeErr
	}
	f.entries[publicationKey(protocol, local)] = request(local, remote, protocol)
	return nil
}

func (f *recordingForwarder) Unexpose(protocol types.TransportProtocol, local string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, publicationKey(protocol, local))
	return nil
}
