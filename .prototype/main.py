"""
main.py — HTTP server
"""

import json
import logging

from flask import Flask, Response, request, jsonify

from store import Store, EventType
from detector import Detector


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(csv_path: str = "events.csv") -> Flask:
  app = Flask(__name__)

  store = Store(csv_path=csv_path)
  det   = Detector(store)

  # ------------------------------------------------------------------ #
  # POST /events  — ingest a new event                                  #
  # ------------------------------------------------------------------ #
  @app.route("/events", methods=["POST"])
  def ingest_event():
    body = request.get_json(silent=True)
    if not body:
      return Response("Invalid event data", status=400)

    try:
      event_type = EventType(body.get("type", ""))
    except ValueError:
      return Response(
        f"Invalid type. Must be one of: {[e.value for e in EventType]}",
        status=400,
      )

    source_ip = body.get("source_ip", "")
    if not source_ip:
      return Response("source_ip and type are required", status=400)

    try:
      created = store.ingest(
        type      = event_type,
        source_ip = source_ip,
        data      = body.get("data", ""),
      )
    except ValueError as exc:
      return Response(str(exc), status=400)

    return Response(
      json.dumps(created.to_dict()),
      status=201,
      mimetype="application/json",
    )

  # ------------------------------------------------------------------ #
  # GET /events  — list all stored events                               #
  # ------------------------------------------------------------------ #
  @app.route("/events", methods=["GET"])
  def list_events():
    return jsonify([e.to_dict() for e in store.list_all()])

  # ------------------------------------------------------------------ #
  # GET /anomalies  — return detected anomalies                         #
  # ------------------------------------------------------------------ #
  @app.route("/anomalies", methods=["GET"])
  def get_anomalies():
    return jsonify(det.summary())

  return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

  app   = create_app()
  store = Store()   # used only for the startup log line

  logging.info("Starting Sentinel Security Monitor")
  logging.info("Event store initialised with %d events", len(store.events))
  logging.info("Starting server on :8080")

  app.run(host="0.0.0.0", port=8080)