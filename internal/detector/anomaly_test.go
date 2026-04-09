package detector

// White-box unit tests for the Detector.
// We are in the same package (detector) so we can call unexported methods
// directly: recentBadLogins, recentPortScans, highEventVolume, detect.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/delbrocco-a/sentinel-security-monitor/internal/events"
)

// ─── helpers ────────────────────────────────────────────────────────────────

const testIP = "10.0.0.1"
const otherIP = "10.0.0.2"

// newDetector returns a fresh Detector backed by a fresh Store.
func newDetector() (*Detector, *events.Store) {
	s := events.NewStore()
	return New(s), s
}

// inject writes an event directly into the store with a controlled timestamp,
// bypassing the HTTP layer so time-window boundary tests are deterministic.
func inject(s *events.Store, ip string, typ events.EventType, port int, age time.Duration) {
	s.DirectInject(events.Event{
		SourceIP:  ip,
		Type:      typ,
		Port:      port,
		Timestamp: time.Now().Add(-age),
	})
}

// injectN injects n identical events.
func injectN(s *events.Store, n int, ip string, typ events.EventType, port int, age time.Duration) {
	for i := 0; i < n; i++ {
		inject(s, ip, typ, port, age)
	}
}

// ─── recentBadLogins ────────────────────────────────────────────────────────

func TestRecentBadLogins_ZeroWhenEmpty(t *testing.T) {
	d, s := newDetector()
	if got := d.recentBadLogins(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestRecentBadLogins_CountsOnlyFailedLoginType(t *testing.T) {
	d, s := newDetector()
	inject(s, testIP, events.PortScan, 80, 5*time.Second)
	inject(s, testIP, events.AnomalousTraffic, 0, 5*time.Second)
	if got := d.recentBadLogins(testIP, s.ListAll()); got != 0 {
		t.Fatalf("should ignore non-FailedLogin events, got %d", got)
	}
}

func TestRecentBadLogins_CountsOnlyMatchingIP(t *testing.T) {
	d, s := newDetector()
	injectN(s, 10, otherIP, events.FailedLogin, 0, 5*time.Second)
	if got := d.recentBadLogins(testIP, s.ListAll()); got != 0 {
		t.Fatalf("should ignore events from other IPs, got %d", got)
	}
}

func TestRecentBadLogins_ExcludesEventsOutsideWindow(t *testing.T) {
	d, s := newDetector()
	// Inject events older than windowSeconds (61s > 60s window).
	injectN(s, 10, testIP, events.FailedLogin, 0, 61*time.Second)
	if got := d.recentBadLogins(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0 (all outside window), got %d", got)
	}
}

func TestRecentBadLogins_AtWindowBoundary_CountsRecent(t *testing.T) {
	d, s := newDetector()
	// 59s ago — just inside the 60s window.
	injectN(s, 3, testIP, events.FailedLogin, 0, 59*time.Second)
	if got := d.recentBadLogins(testIP, s.ListAll()); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}
}

// Threshold is 5; exactly 5 events must NOT trigger (uses > not >=).
func TestRecentBadLogins_AtThreshold_NoAnomaly(t *testing.T) {
	d, s := newDetector()
	injectN(s, failedLoginThreshold, testIP, events.FailedLogin, 0, 5*time.Second)
	if got := d.recentBadLogins(testIP, s.ListAll()); got != failedLoginThreshold {
		t.Fatalf("expected %d, got %d", failedLoginThreshold, got)
	}
	// Confirm detect() does not flag it.
	anomalies := d.detect()
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.FailedLogin {
			t.Fatal("anomaly raised at threshold — expected only above threshold")
		}
	}
}

func TestRecentBadLogins_AboveThreshold_AnomalyRaised(t *testing.T) {
	d, s := newDetector()
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)
	anomalies := d.detect()
	found := false
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.FailedLogin {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FailedLogin anomaly above threshold, none found")
	}
}

// ─── recentPortScans ────────────────────────────────────────────────────────

func TestRecentPortScans_ZeroWhenEmpty(t *testing.T) {
	d, s := newDetector()
	if got := d.recentPortScans(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestRecentPortScans_DeduplicatesByPort(t *testing.T) {
	d, s := newDetector()
	// 20 scans, all on port 80 — should count as 1 unique port.
	injectN(s, 20, testIP, events.PortScan, 80, 5*time.Second)
	if got := d.recentPortScans(testIP, s.ListAll()); got != 1 {
		t.Fatalf("expected 1 unique port, got %d", got)
	}
}

func TestRecentPortScans_CountsDistinctPorts(t *testing.T) {
	d, s := newDetector()
	for port := 1; port <= 15; port++ {
		inject(s, testIP, events.PortScan, port, 5*time.Second)
	}
	if got := d.recentPortScans(testIP, s.ListAll()); got != 15 {
		t.Fatalf("expected 15 distinct ports, got %d", got)
	}
}

func TestRecentPortScans_ExcludesOldEvents(t *testing.T) {
	d, s := newDetector()
	for port := 1; port <= 15; port++ {
		inject(s, testIP, events.PortScan, port, 61*time.Second) // outside window
	}
	if got := d.recentPortScans(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0 (all outside window), got %d", got)
	}
}

func TestRecentPortScans_AtThreshold_NoAnomaly(t *testing.T) {
	d, s := newDetector()
	for port := 1; port <= portScanThreshold; port++ {
		inject(s, testIP, events.PortScan, port, 5*time.Second)
	}
	anomalies := d.detect()
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.PortScan {
			t.Fatal("anomaly raised at threshold — expected only above threshold")
		}
	}
}

func TestRecentPortScans_AboveThreshold_AnomalyRaised(t *testing.T) {
	d, s := newDetector()
	for port := 1; port <= portScanThreshold+1; port++ {
		inject(s, testIP, events.PortScan, port, 5*time.Second)
	}
	anomalies := d.detect()
	found := false
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.PortScan {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PortScan anomaly above threshold, none found")
	}
}

// ─── highEventVolume ────────────────────────────────────────────────────────

func TestHighEventVolume_ZeroWhenEmpty(t *testing.T) {
	d, s := newDetector()
	if got := d.highEventVolume(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestHighEventVolume_CountsAllEventTypes(t *testing.T) {
	d, s := newDetector()
	inject(s, testIP, events.FailedLogin, 0, 5*time.Second)
	inject(s, testIP, events.PortScan, 80, 5*time.Second)
	inject(s, testIP, events.AnomalousTraffic, 0, 5*time.Second)
	if got := d.highEventVolume(testIP, s.ListAll()); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}
}

func TestHighEventVolume_ExcludesOtherIPs(t *testing.T) {
	d, s := newDetector()
	injectN(s, 25, otherIP, events.FailedLogin, 0, 5*time.Second)
	if got := d.highEventVolume(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestHighEventVolume_ExcludesOldEvents(t *testing.T) {
	d, s := newDetector()
	injectN(s, 25, testIP, events.FailedLogin, 0, 61*time.Second)
	if got := d.highEventVolume(testIP, s.ListAll()); got != 0 {
		t.Fatalf("expected 0 (outside window), got %d", got)
	}
}

func TestHighEventVolume_AtThreshold_NoAnomaly(t *testing.T) {
	d, s := newDetector()
	injectN(s, trafficThreshold, testIP, events.AnomalousTraffic, 0, 5*time.Second)
	anomalies := d.detect()
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.AnomalousTraffic {
			t.Fatal("anomaly raised at threshold — expected only above threshold")
		}
	}
}

func TestHighEventVolume_AboveThreshold_AnomalyRaised(t *testing.T) {
	d, s := newDetector()
	injectN(s, trafficThreshold+1, testIP, events.AnomalousTraffic, 0, 5*time.Second)
	anomalies := d.detect()
	found := false
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.AnomalousTraffic {
			found = true
		}
	}
	if !found {
		t.Fatal("expected AnomalousTraffic anomaly above threshold, none found")
	}
}

// ─── detect (multi-IP / multi-anomaly) ──────────────────────────────────────

func TestDetect_EmptyStore_ReturnsNil(t *testing.T) {
	d, _ := newDetector()
	if anomalies := d.detect(); len(anomalies) != 0 {
		t.Fatalf("expected no anomalies from empty store, got %d", len(anomalies))
	}
}

func TestDetect_NoThresholdsExceeded_ReturnsEmpty(t *testing.T) {
	d, s := newDetector()
	injectN(s, 3, testIP, events.FailedLogin, 0, 5*time.Second)
	if anomalies := d.detect(); len(anomalies) != 0 {
		t.Fatalf("expected no anomalies, got %d", len(anomalies))
	}
}

func TestDetect_MultipleIPs_IndependentlyEvaluated(t *testing.T) {
	d, s := newDetector()
	// testIP exceeds failed-login threshold; otherIP does not.
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)
	injectN(s, 2, otherIP, events.FailedLogin, 0, 5*time.Second)

	anomalies := d.detect()
	testIPFlagged, otherIPFlagged := false, false
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.FailedLogin {
			testIPFlagged = true
		}
		if a.Source == otherIP && a.Type == events.FailedLogin {
			otherIPFlagged = true
		}
	}
	if !testIPFlagged {
		t.Error("testIP should have been flagged for FailedLogin")
	}
	if otherIPFlagged {
		t.Error("otherIP should NOT have been flagged for FailedLogin")
	}
}

func TestDetect_SingleIP_MultipleAnomalyTypes(t *testing.T) {
	d, s := newDetector()
	// Exceed failed-login threshold.
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)
	// Exceed port-scan threshold (distinct ports).
	for port := 1; port <= portScanThreshold+1; port++ {
		inject(s, testIP, events.PortScan, port, 5*time.Second)
	}

	anomalies := d.detect()
	foundLogin, foundScan := false, false
	for _, a := range anomalies {
		if a.Source == testIP && a.Type == events.FailedLogin {
			foundLogin = true
		}
		if a.Source == testIP && a.Type == events.PortScan {
			foundScan = true
		}
	}
	if !foundLogin || !foundScan {
		t.Fatalf("expected both FailedLogin and PortScan anomalies; login=%v scan=%v",
			foundLogin, foundScan)
	}
}

func TestDetect_AnomalyContainsMatchingEvents(t *testing.T) {
	d, s := newDetector()
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)
	// Inject noise from another IP.
	injectN(s, 3, otherIP, events.FailedLogin, 0, 5*time.Second)

	anomalies := d.detect()
	for _, a := range anomalies {
		if a.Source == testIP {
			for _, e := range a.Events {
				if e.SourceIP != testIP {
					t.Fatalf("anomaly for %s contains event from %s", testIP, e.SourceIP)
				}
			}
		}
	}
}

func TestDetect_StaleEventsOnly_NoAnomaly(t *testing.T) {
	d, s := newDetector()
	// All events outside the 60s window.
	injectN(s, 100, testIP, events.FailedLogin, 0, 120*time.Second)
	injectN(s, 100, testIP, events.PortScan, 80, 120*time.Second)
	injectN(s, 100, testIP, events.AnomalousTraffic, 0, 120*time.Second)
	if anomalies := d.detect(); len(anomalies) != 0 {
		t.Fatalf("expected no anomalies from stale events, got %d", len(anomalies))
	}
}

// ─── Summary (HTTP handler) ──────────────────────────────────────────────────

func TestSummary_Returns200WithJSONArray(t *testing.T) {
	d, _ := newDetector()
	req := httptest.NewRequest(http.MethodGet, "/anomalies", nil)
	rr := httptest.NewRecorder()
	d.Summary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var result []Anomaly
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
}

func TestSummary_ContentTypeIsJSON(t *testing.T) {
	d, _ := newDetector()
	req := httptest.NewRequest(http.MethodGet, "/anomalies", nil)
	rr := httptest.NewRecorder()
	d.Summary(rr, req)
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

func TestSummary_ReflectsCurrentStoreState(t *testing.T) {
	d, s := newDetector()
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/anomalies", nil)
	rr := httptest.NewRecorder()
	d.Summary(rr, req)

	var result []Anomaly
	json.NewDecoder(rr.Body).Decode(&result)
	if len(result) == 0 {
		t.Fatal("expected at least one anomaly in summary response")
	}
}

// ─── matchingEvents ──────────────────────────────────────────────────────────

func TestMatchingEvents_ReturnsOnlyMatchingIP(t *testing.T) {
	allEvents := []events.Event{
		{SourceIP: testIP, Type: events.FailedLogin},
		{SourceIP: otherIP, Type: events.FailedLogin},
		{SourceIP: testIP, Type: events.PortScan},
	}
	matches := matchingEvents(testIP, allEvents)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	for _, e := range matches {
		if e.SourceIP != testIP {
			t.Fatalf("got event from wrong IP: %s", e.SourceIP)
		}
	}
}

func TestMatchingEvents_NoMatches_ReturnsNil(t *testing.T) {
	allEvents := []events.Event{
		{SourceIP: otherIP, Type: events.FailedLogin},
	}
	matches := matchingEvents(testIP, allEvents)
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}

func TestMatchingEvents_EmptySlice_ReturnsNil(t *testing.T) {
	if matches := matchingEvents(testIP, nil); len(matches) != 0 {
		t.Fatalf("expected no matches for nil input, got %d", len(matches))
	}
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

func TestDetect_ConcurrentReads_NoPanic(t *testing.T) {
	d, s := newDetector()
	injectN(s, failedLoginThreshold+1, testIP, events.FailedLogin, 0, 5*time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.detect()
		}()
	}
	wg.Wait()
}

func TestDetect_ConcurrentWritesAndDetect_NoPanic(t *testing.T) {
	d, s := newDetector()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			inject(s, testIP, events.FailedLogin, 0, 5*time.Second)
		}()
		go func() {
			defer wg.Done()
			d.detect()
		}()
	}
	wg.Wait()
}
