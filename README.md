
# Sentinel Security Monitor

A lightweight backend security event monitoring system written in Go. Sentinel ingests security events, stores them, and performs real-time anomaly detection — flagging suspicious activity such as repeated failed logins from the same source IP within a sliding time window.

---

## Architecture

```
Client / Sensor
      |
      | POST /events
      v
+----------------+
|   Go HTTP API  |
|                |
|  Event Store   |  <---  GET /events
|  (in-memory)   |
|                |
|  Detector      |  <---  GET /anomalies
+----------------+
      |
      | (planned)
      v
+----------------+      +------------------+
|   Docker       | ---> |   AWS ECS        |
|   Container    |      |   (Fargate)      |
+----------------+      +------------------+
                                |
                         +------+------+
                         | Terraform   |
                         | (IaC)       |
                         +-------------+
```

**Current detection rule:** any source IP with more than 5 `FAILED_LOGIN` events within the last 60 seconds is flagged as anomalous.

---

## Tech Stack

| Component        | Technology                  |
|------------------|-----------------------------|
| Backend API      | Go 1.24                     |
| Containerisation | Docker (planned)            |
| Infrastructure   | Terraform + AWS ECS/Fargate (planned) |
| CI               | GitHub Actions              |

---

## Setup

### Prerequisites

- Go 1.24+

Run the setup (setup.sh) script to verify dependencies and build the project, 
and then run the server locally to ensure that it works.

```bash
chmod +x setup.sh
./setup.sh
go run main.go
```

Server likely starts on `http://localhost:8080`.

---

## API Reference

### POST /events
Ingest a new security event.

**Request body:**
```json
{
  "type": "FAILED_LOGIN",
  "source_ip": "192.168.1.1",
  "data": "optional detail"
}
```

**Event types:** `FAILED_LOGIN`, `PORT_SCAN`, `ANOMALOUS_TRAFFIC`

**Expect:** `201 Created` with the created event including assigned ID and timestamp.

---

### GET /events
Returns all ingested events.

**Expect:** `200 OK` with array of events.

---

### GET /anomalies
Returns all currently detected anomalies based on active detection rules.

**Expect:** `200 OK` with array of flagged source IPs and associated events.

---

## Known Limitations & Planned Improvements

- **Persistence:** event store is in-memory only — all data is lost on restart. Planned: PostgreSQL or DynamoDB backend.
- **Detection rules:** currently only `FAILED_LOGIN` threshold rule is implemented. Planned: port scan detection, rate-based anomaly scoring.
- **Authentication:** API endpoints are unauthenticated. Planned: API key middleware.
- **Observability:** no structured logging or metrics. Planned: structured JSON logs, Prometheus metrics endpoint.
- **Tests:** unit tests for detector logic and integration tests for API endpoints are planned.

---

## CI

GitHub Actions runs on every push:
- `go build ./...` — ensures the project compiles
- `go vet ./...` — static analysis

---

*Deployment hopefully via Docker and Terraform (AWS ECS/Fargate) is in progress.*