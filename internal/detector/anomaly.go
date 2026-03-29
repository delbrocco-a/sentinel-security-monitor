package detector

import (
	"time"
	"net/http"
	"encoding/json"
	"github.com/delbrocco-a/dwp-security-monitor/internal/events"
)

const (
	failedLoginThreshold = 5
	windowSeconds        = 60
)


type Anomaly struct {
	Source string
	Type   events.EventType
	Events []events.Event
}

type Detector struct {
	store *events.Store
}

// ----------------------------------------------------------------------------

func (d *Detector) detect() []Anomaly {
    allEvents := d.store.ListAll()
    seen := map[string]bool{}
    var anomalies []Anomaly
    for _, event := range allEvents {
			ip := event.SourceIP
			if seen[ip] { continue }
			seen[ip] = true
			if d.recentBadLogins(ip, allEvents) > failedLoginThreshold {
				anomalies = append(anomalies, Anomaly{Source: ip})
			}
    }
    return anomalies
}


func (d *Detector) recentBadLogins(ip string, allEvents []events.Event) int {
	// Count bad logins

	count := 0

	for _, event := range allEvents {

		// Sift irrelevant data
		if event.SourceIP != ip             { continue }
		if event.Type != events.FailedLogin { continue }

		// Count recent logins
		if time.Since(event.Timestamp) < time.Duration(windowSeconds)*time.Second {
			count++
		}
	}

	return count
}


// ----------------------------------------------------------------------------

func New(store *events.Store) *Detector {
	return &Detector{ store: store }
}

func (d *Detector) Summary(w http.ResponseWriter, r * http.Request) {
	// Return summary of all define anomalies detected

	// Header and json encode
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.detect())

	return
}