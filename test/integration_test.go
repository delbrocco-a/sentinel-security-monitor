package integration_test

// Integration tests spin up the real HTTP mux with real Store + Detector and
// exercise all three endpoints end-to-end over an actual TCP listener.
// No mocks. No internal package access.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/delbrocco-a/sentinel-security-monitor/internal/detector"
	"github.com/delbrocco-a/sentinel-security-monitor/internal/events"
)

// ─── server setup ────────────────────────────────────────────────────────────

type testServer struct {
	URL    string
	store  *events.Store
	client *http.Client
}

// newTestServer starts a real HTTP server on a random port and returns a
// handle to it. The caller does not need to stop it — the test process owns it.
func newTestServer(t *testing.T) *testServer {
	t.Helper()

	store := events.NewStore()
	det := detector.New(store)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", store.Ingest)
	mux.HandleFunc("GET /events", store.List)
	mux.HandleFunc("GET /anomalies", det.Summary)

	ln, err := net.Listen("tcp", "127.0.0.1:0") // OS picks a free port
	if err != nil {
		t.Fatalf("could not bind listener: %v", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // background goroutine

	t.Cleanup(func() { srv.Close() })

	return &testServer{
		URL:    "http://" + ln.Addr().String(),
		store:  store,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func (ts *testServer) postEvent(t *testing.T, body string) *http.Response {
	t.Helper()
	resp, err := ts.client.Post(
		ts.URL+"/events",
		"application/json",
		bytes.NewBufferString(body),
	)
	if err != nil {
		t.Fatalf("POST /events: %v", err)
	}
	return resp
}

func (ts *testServer) getEvents(t *testing.T) *http.Response {
	t.Helper()
	resp, err := ts.client.Get(ts.URL + "/events")
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	return resp
}

func (ts *testServer) getAnomalies(t *testing.T) *http.Response {
	t.Helper()
	resp, err := ts.client.Get(ts.URL + "/anomalies")
	if err != nil {
		t.Fatalf("GET /anomalies: %v", err)
	}
	return resp
}

func decodeEvents(t *testing.T, resp *http.Response) []events.Event {
	t.Helper()
	defer resp.Body.Close()
	var result []events.Event
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	return result
}

type anomaly struct {
	Source string            `json:"Source"`
	Type   events.EventType  `json:"Type"`
}

func decodeAnomalies(t *testing.T, resp *http.Response) []anomaly {
	t.Helper()
	defer resp.Body.Close()
	var result []anomaly
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode anomalies: %v", err)
	}
	return result
}

// injectDirect writes events directly into the store with controlled timestamps
// so time-window tests work without sleeping.
func (ts *testServer) injectDirect(ip string, typ events.EventType, port int, age time.Duration) {
	ts.store.DirectInject(events.Event{
		SourceIP:  ip,
		Type:      typ,
		Port:      port,
		Timestamp: time.Now().Add(-age),
	})
}

// ─── POST /events ─────────────────────────────────────────────────────────────

func TestIntegration_PostEvent_HappyPath(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4","username":"alice"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestIntegration_PostEvent_ResponseBodyIsEvent(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{"type":"PORT_SCAN","source_ip":"10.0.0.1","port":443}`)
	defer resp.Body.Close()
	var e events.Event
	json.NewDecoder(resp.Body).Decode(&e)
	if e.ID == 0 {
		t.Fatal("expected non-zero ID in response body")
	}
	if e.SourceIP != "10.0.0.1" {
		t.Fatalf("expected source_ip=10.0.0.1, got %q", e.SourceIP)
	}
}

func TestIntegration_PostEvent_MissingSourceIP_Returns400(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{"type":"FAILED_LOGIN"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIntegration_PostEvent_MissingType_Returns400(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{"source_ip":"1.2.3.4"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIntegration_PostEvent_MalformedJSON_Returns400(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{bad json`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIntegration_PostEvent_EmptyBody_Returns400(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, ``)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestIntegration_PostEvent_ContentTypeHeader(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

func TestIntegration_PostEvent_MethodNotAllowed_GET(t *testing.T) {
	ts := newTestServer(t)
	resp, err := ts.client.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// GET /events is registered; this should succeed (200), not 405.
	// We post nothing so we get an empty array — the important thing is no 405.
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatal("GET /events should be valid — only POST /events must be posted to")
	}
}

// ─── GET /events ──────────────────────────────────────────────────────────────

func TestIntegration_GetEvents_EmptyStore(t *testing.T) {
	ts := newTestServer(t)
	evts := decodeEvents(t, ts.getEvents(t))
	if len(evts) != 0 {
		t.Fatalf("expected empty array, got %d events", len(evts))
	}
}

func TestIntegration_GetEvents_ReflectsPostedEvents(t *testing.T) {
	ts := newTestServer(t)
	ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`).Body.Close()
	ts.postEvent(t, `{"type":"PORT_SCAN","source_ip":"10.0.0.1","port":22}`).Body.Close()

	evts := decodeEvents(t, ts.getEvents(t))
	if len(evts) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evts))
	}
}

func TestIntegration_GetEvents_IDsAreSequential(t *testing.T) {
	ts := newTestServer(t)
	for i := 0; i < 5; i++ {
		ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`).Body.Close()
	}
	evts := decodeEvents(t, ts.getEvents(t))
	for i, e := range evts {
		if e.ID != i+1 {
			t.Fatalf("event[%d].ID = %d, expected %d", i, e.ID, i+1)
		}
	}
}

func TestIntegration_GetEvents_ContentTypeHeader(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.getEvents(t)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

// ─── GET /anomalies ──────────────────────────────────────────────────────────

func TestIntegration_GetAnomalies_EmptyStore(t *testing.T) {
	ts := newTestServer(t)
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	if len(anomalies) != 0 {
		t.Fatalf("expected no anomalies from empty store, got %d", len(anomalies))
	}
}

func TestIntegration_GetAnomalies_BelowThreshold_NoAnomalies(t *testing.T) {
	ts := newTestServer(t)
	for i := 0; i < 3; i++ {
		ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`).Body.Close()
	}
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	if len(anomalies) != 0 {
		t.Fatalf("expected no anomalies, got %d", len(anomalies))
	}
}

func TestIntegration_GetAnomalies_FailedLoginBreachDetected(t *testing.T) {
	ts := newTestServer(t)
	// 6 events — one above the threshold of 5.
	for i := 0; i < 6; i++ {
		ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`).Body.Close()
	}
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	found := false
	for _, a := range anomalies {
		if a.Source == "1.2.3.4" && a.Type == events.FailedLogin {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FailedLogin anomaly for 1.2.3.4")
	}
}

func TestIntegration_GetAnomalies_PortScanBreachDetected(t *testing.T) {
	ts := newTestServer(t)
	// 11 distinct ports — one above the threshold of 10.
	for port := 1; port <= 11; port++ {
		body := fmt.Sprintf(`{"type":"PORT_SCAN","source_ip":"10.0.0.5","port":%d}`, port)
		ts.postEvent(t, body).Body.Close()
	}
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	found := false
	for _, a := range anomalies {
		if a.Source == "10.0.0.5" && a.Type == events.PortScan {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PortScan anomaly for 10.0.0.5")
	}
}

func TestIntegration_GetAnomalies_MultipleIPsIndependent(t *testing.T) {
	ts := newTestServer(t)
	// IP A exceeds threshold; IP B does not.
	for i := 0; i < 6; i++ {
		ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"192.168.1.1"}`).Body.Close()
	}
	for i := 0; i < 2; i++ {
		ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"192.168.1.2"}`).Body.Close()
	}
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	ipAFlagged, ipBFlagged := false, false
	for _, a := range anomalies {
		if a.Source == "192.168.1.1" {
			ipAFlagged = true
		}
		if a.Source == "192.168.1.2" {
			ipBFlagged = true
		}
	}
	if !ipAFlagged {
		t.Error("expected anomaly for 192.168.1.1")
	}
	if ipBFlagged {
		t.Error("did not expect anomaly for 192.168.1.2")
	}
}

func TestIntegration_GetAnomalies_StaleEvents_NoAnomaly(t *testing.T) {
	ts := newTestServer(t)
	// Inject events outside the 60-second window directly into the store.
	for i := 0; i < 10; i++ {
		ts.injectDirect("1.2.3.4", events.FailedLogin, 0, 120*time.Second)
	}
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	for _, a := range anomalies {
		if a.Source == "1.2.3.4" && a.Type == events.FailedLogin {
			t.Fatal("stale events outside window should not trigger anomaly")
		}
	}
}

func TestIntegration_GetAnomalies_ContentTypeHeader(t *testing.T) {
	ts := newTestServer(t)
	resp := ts.getAnomalies(t)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

// ─── End-to-end lifecycle ────────────────────────────────────────────────────

func TestIntegration_FullLifecycle_PostThenListThenDetect(t *testing.T) {
	ts := newTestServer(t)

	// Post 6 failed logins from the same IP.
	for i := 0; i < 6; i++ {
		resp := ts.postEvent(t, `{"type":"FAILED_LOGIN","source_ip":"172.16.0.1","username":"eve"}`)
		if resp.StatusCode != http.StatusCreated {
			resp.Body.Close()
			t.Fatalf("post %d: expected 201, got %d", i+1, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Verify the events appear in GET /events.
	evts := decodeEvents(t, ts.getEvents(t))
	if len(evts) != 6 {
		t.Fatalf("expected 6 events in store, got %d", len(evts))
	}

	// Verify the anomaly surfaces in GET /anomalies.
	anomalies := decodeAnomalies(t, ts.getAnomalies(t))
	found := false
	for _, a := range anomalies {
		if a.Source == "172.16.0.1" && a.Type == events.FailedLogin {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FailedLogin anomaly for 172.16.0.1 after full lifecycle")
	}
}

func TestIntegration_AnomaliesDisappearAfterWindowExpires(t *testing.T) {
	ts := newTestServer(t)

	// Inject 6 events that are just inside the window.
	for i := 0; i < 6; i++ {
		ts.injectDirect("5.5.5.5", events.FailedLogin, 0, 5*time.Second)
	}
	// Should trigger anomaly.
	anomaliesBefore := decodeAnomalies(t, ts.getAnomalies(t))
	foundBefore := false
	for _, a := range anomaliesBefore {
		if a.Source == "5.5.5.5" && a.Type == events.FailedLogin {
			foundBefore = true
		}
	}
	if !foundBefore {
		t.Fatal("expected anomaly while events are within window")
	}

	// Now simulate the window having passed by injecting the same events
	// with an old timestamp into a fresh server.
	ts2 := newTestServer(t)
	for i := 0; i < 6; i++ {
		ts2.injectDirect("5.5.5.5", events.FailedLogin, 0, 65*time.Second) // outside window
	}
	anomaliesAfter := decodeAnomalies(t, ts2.getAnomalies(t))
	for _, a := range anomaliesAfter {
		if a.Source == "5.5.5.5" && a.Type == events.FailedLogin {
			t.Fatal("anomaly should not appear after window has expired")
		}
	}
}
