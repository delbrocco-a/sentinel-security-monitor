package detector

import (
	"time"
	"net/http"
	"encoding/json"
	"github.com/delbrocco-a/sentinel-security-monitor/internal/events"
)

const (
	failedLoginThreshold = 5
	portScanThreshold		 = 10
	trafficThreshold     = 20

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
// Detect anomalies based on events in the store

	allEvents := d.store.ListAll()
	seen := map[string]bool{}
	var anomalies []Anomaly

	// Iterate through all events, considering unique IPs for anomaly
	for _, event := range allEvents {

		// Skip if IP has been processed before
		ip := event.SourceIP
		if seen[ip] { continue }

		// For each unique IP, check for recent failed logins
		seen[ip] = true
		if d.recentBadLogins(ip, allEvents) > failedLoginThreshold {
			anomalies = append(
				anomalies, Anomaly{
					Source: ip,
					Events: matchingEvents(ip, allEvents),
					Type:   events.FailedLogin,
				},
			)
		}

		// For each IP, check for multiple port scanning events in time window
		if d.recentPortScans(ip, allEvents) > portScanThreshold {
			anomalies = append(
				anomalies,
				Anomaly {
					Source: ip,
					Events: matchingEvents(ip, allEvents),
					Type: events.PortScan,
				},
			)
		}

		// For each IP check for suspicious amounts of traffic from ip
		if d.highEventVolume(ip, allEvents) > trafficThreshold {
			anomalies = append(
				anomalies, 
				Anomaly {
					Source: ip,
					Events: matchingEvents(ip, allEvents),
					Type: events.AnomalousTraffic,
				},
			)
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


func (d *Detector) recentPortScans(ip string, allEvents []events.Event) int {
	// Count port scans
	
	seen := map[int]bool{}

	for _, event := range allEvents {

		// Sift to IP that we haven't seen
		if event.SourceIP != ip          { continue }
		if event.Type != events.PortScan { continue }

		// Count recent port scans
		if time.Since(event.Timestamp) < time.Duration(windowSeconds)*time.Second {
			seen[event.Port] = true
		}
	}

	return len(seen)
}


func (d *Detector) highEventVolume(ip string, allEvents []events.Event) int {
	// Detects high number of volumes processed for a user

	count := 0

	// Iterate throughout all events
	for _, event := range allEvents {

		// Sift to ip we haven't seen
		if event.SourceIP != ip { continue }

		//Count events within time window
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

func matchingEvents(ip string, allEvents []events.Event) []events.Event {
	// Return all events matching the given IP

	var matches []events.Event

	// Iterate through all events, matching those by IP.
	for _, event := range allEvents {
		if event.SourceIP == ip {
			matches = append(matches, event)
		}
	}

	return matches
}