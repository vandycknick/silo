package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntelligenceUsesRegistryAndFeedAgeWithoutCrossRequestObservation(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	server := newFeedServer(t, now)
	defer server.Close()

	intelligence := newTestIntelligence(t, server, now)
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err != nil {
		t.Fatal(err)
	}
	registryReleased := now.Add(-2 * time.Hour)
	facts := intelligence.Facts(EcosystemNPM, "download", "fresh", "1.0.0", &registryReleased)
	if !facts.AgeKnown || facts.AgeHours != 2 || facts.AgeSource != "registry" {
		t.Fatalf("registry facts = %#v", facts)
	}

	facts = intelligence.Facts(EcosystemNPM, "download", "fresh", "1.0.0", nil)
	if facts.AgeKnown || facts.AgeSource != "" {
		t.Fatalf("unobserved direct-download facts = %#v", facts)
	}

	facts = intelligence.Facts(EcosystemNPM, "download", "feed-only", "2.0.0", nil)
	if facts.AgeHours != 48 || facts.AgeSource != "feed" {
		t.Fatalf("feed facts = %#v", facts)
	}
}

func TestIntelligenceRejectsNonBaseFeedURLs(t *testing.T) {
	for _, feed := range []string{
		"http://feeds.example.test",
		"https://user@feeds.example.test",
		"https://feeds.example.test/base?token=secret",
		"https://feeds.example.test/base#fragment",
		"https://feeds.example.test:0",
	} {
		if _, err := NewIntelligence(feed, nil, DefaultCatalog()); err == nil {
			t.Errorf("NewIntelligence(%q) succeeded", feed)
		}
	}
}

func TestIntelligenceMatchesMalwareAndNormalizesPyPINames(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	server := newFeedServer(t, now)
	defer server.Close()

	intelligence := newTestIntelligence(t, server, now)
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err != nil {
		t.Fatal(err)
	}
	if err := intelligence.Refresh(context.Background(), EcosystemPyPI); err != nil {
		t.Fatal(err)
	}
	facts := intelligence.Facts(EcosystemNPM, "download", "bad", "9.0.0", nil)
	if !facts.MalwareDataAvailable || !facts.Malware || facts.MalwareReason != "MALWARE" {
		t.Fatalf("npm malware facts = %#v", facts)
	}

	facts = intelligence.Facts(EcosystemPyPI, "download", "Foo_Bar", "1.0", nil)
	if facts.Name != "foo-bar" || !facts.Malware || facts.MalwareReason != "MALWARE" {
		t.Fatalf("PyPI malware facts = %#v", facts)
	}
}

func TestIntelligenceReportsUnavailableFeedsWithoutInventingEvidence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	intelligence := newTestIntelligence(t, server, time.Now())
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err == nil {
		t.Fatal("expected unavailable feed refresh to fail")
	}
	facts := intelligence.Facts(EcosystemNPM, "download", "unknown", "1.0.0", nil)
	if facts.MalwareDataAvailable || facts.Malware || facts.AgeKnown || facts.AgeSource != "" {
		t.Fatalf("unavailable facts = %#v", facts)
	}
}

func TestIntelligenceRetainsLastSuccessfulSnapshotAfterRefreshFailure(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	failing := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if failing {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/base/malware_predictions.json":
			_, _ = fmt.Fprint(writer, `[{"package_name":"bad","version":"1.0.0","reason":"MALWARE"}]`)
		case "/base/releases/npm.json":
			_, _ = fmt.Fprint(writer, `[]`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	intelligence := newTestIntelligence(t, server, now)
	currentTime := now
	intelligence.now = func() time.Time { return currentTime }
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err != nil {
		t.Fatal(err)
	}
	failing = true
	currentTime = currentTime.Add(feedRefreshInterval)
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err == nil {
		t.Fatal("expected failed refresh")
	}
	facts := intelligence.Facts(EcosystemNPM, "download", "bad", "1.0.0", nil)
	if !facts.MalwareDataAvailable || !facts.Malware {
		t.Fatalf("stale malware snapshot was not retained: %#v", facts)
	}
}

func TestIntelligenceFactsDoesNotRefreshFeeds(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	intelligence := newTestIntelligence(t, server, time.Now())
	_ = intelligence.Facts(EcosystemNPM, "download", "example", "1.0.0", nil)
	if requests != 0 {
		t.Fatalf("Facts performed %d feed requests", requests)
	}
}

func TestIntelligenceRefreshAndFactsAreConcurrentSafe(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	server := newFeedServer(t, now)
	defer server.Close()

	intelligence := newTestIntelligence(t, server, now)
	var unixSeconds atomic.Int64
	unixSeconds.Store(now.Unix())
	intelligence.now = func() time.Time {
		return time.Unix(unixSeconds.Add(int64(feedRefreshInterval/time.Second)+1), 0)
	}

	stopReaders := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_ = intelligence.Facts(EcosystemNPM, "download", "bad", "1.0.0", nil)
				}
			}
		}()
	}

	for range 100 {
		if err := intelligence.Refresh(context.Background(), EcosystemNPM); err != nil {
			close(stopReaders)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(stopReaders)
	readers.Wait()
}

func TestIntelligenceRejectsCrossOriginRedirects(t *testing.T) {
	redirected := make(chan struct{}, 1)
	destination := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirected <- struct{}{}
		_, _ = fmt.Fprint(writer, "[]")
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", destination.URL)
		writer.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	intelligence := newTestIntelligence(t, source, time.Now())
	if err := intelligence.Refresh(context.Background(), EcosystemNPM); err == nil || !strings.Contains(err.Error(), "approved origin") {
		t.Fatalf("Refresh error = %v", err)
	}
	select {
	case <-redirected:
		t.Fatal("cross-origin intelligence redirect was followed")
	default:
	}
}

func newFeedServer(t *testing.T, now time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/base/malware_predictions.json":
			_, _ = fmt.Fprint(writer, `[{"package_name":"bad","version":"*","reason":"MALWARE"}]`)
		case "/base/malware_pypi.json":
			_, _ = fmt.Fprint(writer, `[{"package_name":"foo.bar","version":"1.0","reason":"MALWARE"}]`)
		case "/base/releases/npm.json":
			_, _ = fmt.Fprintf(writer, `[{"source":"npm","package_name":"feed-only","version":"2.0.0","released_on":%d}]`, now.Add(-48*time.Hour).Unix())
		case "/base/releases/pypi.json":
			_, _ = fmt.Fprint(writer, `[]`)
		default:
			http.NotFound(writer, request)
		}
	}))
}

func newTestIntelligence(t *testing.T, server *httptest.Server, now time.Time) *Intelligence {
	t.Helper()
	baseURL := strings.Replace(server.URL, "http://", "https://", 1) + "/base"
	intelligence, err := NewIntelligence(baseURL, server.Client(), DefaultCatalog())
	if err != nil {
		t.Fatalf("NewIntelligence: %v", err)
	}
	intelligence.now = func() time.Time { return now }
	return intelligence
}
