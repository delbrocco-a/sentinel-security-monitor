
package main

import (
	"log"
	"net/http"

	"github.com/delbrocco-a/dwp-security-monitor/internal/events"
	"github.com/delbrocco-a/dwp-security-monitor/internal/detector"
)


func main() {
	// Initialise event store and anomaly detector endpoints.
	store := events.NewStore()
	det := detector.New(store)

	// Initialise multiplexer for handling HTTP requests.
	mux := initMux(store, det)

	logStartup(store, det, mux)
}


func initMux(store *events.Store, det *detector.Detector) *http.ServeMux {
	// Setup multiplexer for crud requests for events and anomalies.

	mux := http.NewServeMux()

	// Create endpoints for events POST and GET
	mux.HandleFunc("POST /events", store.Ingest)
	mux.HandleFunc("GET /events", store.List)

	// Create endpoint for anomalies GET only
	mux.HandleFunc("GET /anomalies", det.Summary)

	return mux
}


func logStartup(
	store *events.Store,
	det   *detector.Detector,
	mux   *http.ServeMux,
) {
	// Log startup information and start the server.

	log.Println("Starting DWP Security Monitor")
	log.Printf("Event store initialized with %d events", len(store.Events))
	log.Println("Starting on server :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}