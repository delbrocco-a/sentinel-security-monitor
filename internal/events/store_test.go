package events

// White-box unit tests for the Store.
// We are in the same package (events) so we can access unexported fields.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────────────────

func newStore() *Store { return NewStore() }

// injectEvent bypasses the HTTP layer and adds an event with a caller-supplied
// timestamp directly into the store, so time-window tests are deterministic.
func injectEvent(s *Store, e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.ID = s.nextID
	s.nextID++
	s.Events = append(s.Events, e)
}

func postEvent(t *testing.T, s *Store, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/events",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Ingest(rr, req)
	return rr
}

// ─── NewStore ───────────────────────────────────────────────────────────────

func TestNewStore_InitialisedEmpty(t *testing.T) {
	s := newStore()
	if len(s.Events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(s.Events))
	}
}

func TestNewStore_NextIDStartsAtOne(t *testing.T) {
	s := newStore()
	if s.nextID != 1 {
		t.Fatalf("expected nextID=1, got %d", s.nextID)
	}
}

// ─── append (via Ingest) ────────────────────────────────────────────────────

func TestIngest_ValidEvent_Returns201(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
}

func TestIngest_ValidEvent_AssignsID(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	var e Event
	if err := json.NewDecoder(rr.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	if e.ID != 1 {
		t.Fatalf("expected ID=1, got %d", e.ID)
	}
}

func TestIngest_ValidEvent_SetsTimestamp(t *testing.T) {
	before := time.Now()
	s := newStore()
	postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	after := time.Now()
	ts := s.Events[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Fatalf("timestamp %v not in expected range [%v, %v]", ts, before, after)
	}
}

func TestIngest_IDsIncrementMonotonically(t *testing.T) {
	s := newStore()
	for i := 1; i <= 5; i++ {
		postEvent(t, s, `{"type":"PORT_SCAN","source_ip":"10.0.0.1","port":80}`)
		if s.Events[i-1].ID != i {
			t.Fatalf("event %d: expected ID=%d, got %d", i, i, s.Events[i-1].ID)
		}
	}
}

func TestIngest_MalformedJSON_Returns400(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{not valid json`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestIngest_EmptyBody_Returns400(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, ``)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestIngest_MissingSourceIP_Returns400(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{"type":"FAILED_LOGIN"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestIngest_MissingType_Returns400(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{"source_ip":"1.2.3.4"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestIngest_BothFieldsMissing_Returns400(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestIngest_UnknownEventType_Accepted(t *testing.T) {
	// The store does not validate EventType values — that is the detector's concern.
	s := newStore()
	rr := postEvent(t, s, `{"type":"MYSTERY","source_ip":"1.2.3.4"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for unknown type, got %d", rr.Code)
	}
}

func TestIngest_OptionalFieldsPreserved(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s,
		`{"type":"PORT_SCAN","source_ip":"10.0.0.1","port":443,"username":"alice","data":"extra"}`)
	var e Event
	json.NewDecoder(rr.Body).Decode(&e)
	if e.Port != 443 || e.Username != "alice" || e.Data != "extra" {
		t.Fatalf("optional fields not preserved: %+v", e)
	}
}

func TestIngest_ContentTypeHeader(t *testing.T) {
	s := newStore()
	rr := postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
}

// ─── ListAll ────────────────────────────────────────────────────────────────

func TestListAll_EmptyStore(t *testing.T) {
	s := newStore()
	all := s.ListAll()
	if len(all) != 0 {
		t.Fatalf("expected empty slice, got %d items", len(all))
	}
}

func TestListAll_ReturnsCopy_NotSliceAlias(t *testing.T) {
	s := newStore()
	postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	cp := s.ListAll()
	cp[0].SourceIP = "mutated"
	if s.Events[0].SourceIP == "mutated" {
		t.Fatal("ListAll returned a live slice alias — mutations affect the store")
	}
}

func TestListAll_CountMatchesIngested(t *testing.T) {
	s := newStore()
	for i := 0; i < 10; i++ {
		postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
	}
	if len(s.ListAll()) != 10 {
		t.Fatalf("expected 10, got %d", len(s.ListAll()))
	}
}

// ─── List (HTTP handler) ─────────────────────────────────────────────────────

func TestList_Returns200WithJSONArray(t *testing.T) {
	s := newStore()
	postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rr := httptest.NewRecorder()
	s.List(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var events []Event
	if err := json.NewDecoder(rr.Body).Decode(&events); err != nil {
		t.Fatalf("response is not valid JSON array: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestList_EmptyStore_ReturnsEmptyArray(t *testing.T) {
	s := newStore()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rr := httptest.NewRecorder()
	s.List(rr, req)
	var events []Event
	json.NewDecoder(rr.Body).Decode(&events)
	if len(events) != 0 {
		t.Fatalf("expected empty array, got %d items", len(events))
	}
}

// ─── Concurrency ────────────────────────────────────────────────────────────

func TestIngest_ConcurrentWrites_NoPanic(t *testing.T) {
	s := newStore()
	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
		}()
	}
	wg.Wait()
	if len(s.Events) != goroutines {
		t.Fatalf("expected %d events after concurrent writes, got %d", goroutines, len(s.Events))
	}
}

func TestIngest_ConcurrentWritesAndReads_NoPanic(t *testing.T) {
	s := newStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			postEvent(t, s, `{"type":"FAILED_LOGIN","source_ip":"1.2.3.4"}`)
		}()
		go func() {
			defer wg.Done()
			s.ListAll()
		}()
	}
	wg.Wait()
}

func TestIngest_ConcurrentWrites_IDsUnique(t *testing.T) {
	s := newStore()
	const goroutines = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			postEvent(t, s, `{"type":"PORT_SCAN","source_ip":"10.0.0.1","port":80}`)
		}()
	}
	wg.Wait()

	seen := map[int]bool{}
	for _, e := range s.Events {
		if seen[e.ID] {
			t.Fatalf("duplicate ID %d found after concurrent writes", e.ID)
		}
		seen[e.ID] = true
	}
}
