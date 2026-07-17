package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntelligenceUsesRegistryAndFeedAgeWithoutCrossRequestObservation(t *testing.T) {
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	server := newFeedServer(t, now)
	defer server.Close()

	intelligence := newTestIntelligence(t, server, now)
	registryReleased := now.Add(-2 * time.Hour)
	facts := intelligence.Facts(context.Background(), EcosystemNPM, "download", "fresh", "1.0.0", &registryReleased)
	if !facts.AgeKnown || facts.AgeHours != 2 || facts.AgeSource != "registry" {
		t.Fatalf("registry facts = %#v", facts)
	}

	facts = intelligence.Facts(context.Background(), EcosystemNPM, "download", "fresh", "1.0.0", nil)
	if facts.AgeKnown || facts.AgeSource != "" {
		t.Fatalf("unobserved direct-download facts = %#v", facts)
	}

	facts = intelligence.Facts(context.Background(), EcosystemNPM, "download", "feed-only", "2.0.0", nil)
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
	facts := intelligence.Facts(context.Background(), EcosystemNPM, "download", "bad", "9.0.0", nil)
	if !facts.MalwareDataAvailable || !facts.Malware || facts.MalwareReason != "MALWARE" {
		t.Fatalf("npm malware facts = %#v", facts)
	}

	facts = intelligence.Facts(context.Background(), EcosystemPyPI, "download", "Foo_Bar", "1.0", nil)
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
	facts := intelligence.Facts(context.Background(), EcosystemNPM, "download", "unknown", "1.0.0", nil)
	if facts.MalwareDataAvailable || facts.Malware || facts.AgeKnown || facts.AgeSource != "" {
		t.Fatalf("unavailable facts = %#v", facts)
	}
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
