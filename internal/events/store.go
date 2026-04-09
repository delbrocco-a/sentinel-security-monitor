package events

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)


type EventType string

const (
	FailedLogin      EventType = "FAILED_LOGIN"
	PortScan         EventType = "PORT_SCAN"
	AnomalousTraffic EventType = "ANOMALOUS_TRAFFIC"
)

type Event struct {
	ID        int       `json:"id"`
	Type      EventType `json:"type"`
	Username  string    `json:"username,omitempty"`
	SourceIP  string    `json:"source_ip"`
	Port			int       `json:"port,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Data			string    `json:"data"`
}

type Store struct {
	Events []Event
	mu     sync.RWMutex // ! RWMutex to protect concurrent access to store.
	nextID int
}

// ----------------------------------------------------------------------------

// Public, essentail Store object
func NewStore() *Store {
	return &Store{
		Events: []Event{},
		nextID: 1,
	}
}


// Public append to store
func (s *Store) Ingest(w http.ResponseWriter, r *http.Request) {
	// Ingest the new event

	var e Event

	// Catch [400] bad requests.
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Invalid event data", http.StatusBadRequest)
		return
	}
	
	if e.SourceIP == "" || e.Type == "" {
		http.Error(w, "source_ip and type are required", http.StatusBadRequest)
		return
	}

	// Add the new event to store
	created := s.append(e)

	// Set header
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(created)

	return
}


// Public list all in store
func (s *Store) List(w http.ResponseWriter, r *http.Request) {
	// Return summary of event store

	// Set data to all events in store
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.ListAll())

	return
}

// ----------------------------------------------------------------------------

// Private
func (s *Store) append(e Event) Event {
	// Add event

	// Aquire write lock.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Initialise event and admin.
	e.ID = s.nextID
	e.Timestamp = time.Now()
	
	// Update store
	s.nextID++
	s.Events = append(s.Events, e)

	return e
}


// Private
func (s *Store) ListAll() []Event {
	// Get all events in the store.

	// Aquire read lock.
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copy the events to return.
	cp := make([]Event, len(s.Events))
	copy(cp, s.Events)

	return cp
}