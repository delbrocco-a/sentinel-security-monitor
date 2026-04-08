"""
test_sentinel.py — test suite for the Python port of sentinel-security-monitor

Run with:
  pytest test_sentinel.py -v
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from store import Event, EventType, Store
from detector import Anomaly, Detector, FAILED_LOGIN_THRESHOLD, WINDOW_SECONDS
from main import create_app


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def tmp_csv(tmp_path):
  """Return a path to a temporary CSV file that doesn't exist yet."""
  return str(tmp_path / "events.csv")


@pytest.fixture
def store(tmp_csv):
  """A fresh, empty Store backed by a temp CSV."""
  return Store(csv_path=tmp_csv)


@pytest.fixture
def detector(store):
  """A Detector wired to the fresh store."""
  return Detector(store)


@pytest.fixture
def app(tmp_csv):
  """Flask test client backed by a temp CSV."""
  flask_app = create_app(csv_path=tmp_csv)
  flask_app.config["TESTING"] = True
  return flask_app


@pytest.fixture
def client(app):
  return app.test_client()


# ===========================================================================
# Store — unit tests
# ===========================================================================

class TestStoreIngest:

  def test_ingest_returns_event_with_id(self, store):
    e = store.ingest(EventType.FAILED_LOGIN, "1.2.3.4")
    assert e.id == 1
    assert e.source_ip == "1.2.3.4"
    assert e.type == EventType.FAILED_LOGIN

  def test_ingest_auto_increments_id(self, store):
    e1 = store.ingest(EventType.FAILED_LOGIN, "1.1.1.1")
    e2 = store.ingest(EventType.PORT_SCAN,    "2.2.2.2")
    assert e1.id == 1
    assert e2.id == 2

  def test_ingest_sets_timestamp(self, store):
    before = datetime.now()
    e = store.ingest(EventType.FAILED_LOGIN, "1.2.3.4")
    after = datetime.now()
    assert before <= e.timestamp <= after

  def test_ingest_accepts_explicit_timestamp(self, store):
    ts = datetime(2024, 1, 1, 12, 0, 0)
    e = store.ingest(EventType.FAILED_LOGIN, "1.2.3.4", timestamp=ts)
    assert e.timestamp == ts

  def test_ingest_stores_optional_data(self, store):
    e = store.ingest(EventType.PORT_SCAN, "5.5.5.5", data="port 22")
    assert e.data == "port 22"

  def test_ingest_missing_source_ip_raises(self, store):
    with pytest.raises(ValueError, match="source_ip"):
      store.ingest(EventType.FAILED_LOGIN, "")

  def test_ingest_missing_type_raises(self, store):
    with pytest.raises((ValueError, AttributeError)):
      store.ingest(None, "1.2.3.4")  # type: ignore


class TestStoreListAll:

  def test_list_all_empty_initially(self, store):
    assert store.list_all() == []

  def test_list_all_returns_all_ingested(self, store):
    store.ingest(EventType.FAILED_LOGIN,      "1.1.1.1")
    store.ingest(EventType.PORT_SCAN,         "2.2.2.2")
    store.ingest(EventType.ANOMALOUS_TRAFFIC, "3.3.3.3")
    assert len(store.list_all()) == 3

  def test_list_all_returns_copy_not_reference(self, store):
    store.ingest(EventType.FAILED_LOGIN, "1.1.1.1")
    result = store.list_all()
    result.clear()
    assert len(store.list_all()) == 1


class TestStorePersistence:

  def test_events_survive_reload(self, tmp_csv):
    s1 = Store(csv_path=tmp_csv)
    s1.ingest(EventType.FAILED_LOGIN, "10.0.0.1", data="attempt")
    s1.ingest(EventType.PORT_SCAN,    "10.0.0.2")

    s2 = Store(csv_path=tmp_csv)
    assert len(s2.list_all()) == 2
    assert s2.list_all()[0].source_ip == "10.0.0.1"
    assert s2.list_all()[1].type      == EventType.PORT_SCAN

  def test_id_counter_continues_after_reload(self, tmp_csv):
    s1 = Store(csv_path=tmp_csv)
    s1.ingest(EventType.FAILED_LOGIN, "10.0.0.1")
    s1.ingest(EventType.FAILED_LOGIN, "10.0.0.2")

    s2 = Store(csv_path=tmp_csv)
    new_event = s2.ingest(EventType.PORT_SCAN, "10.0.0.3")
    assert new_event.id == 3

  def test_csv_created_on_first_write(self, tmp_csv):
    s = Store(csv_path=tmp_csv)
    assert not Path(tmp_csv).exists()   # no file yet
    s.ingest(EventType.FAILED_LOGIN, "1.2.3.4")
    assert Path(tmp_csv).exists()       # now it exists

  def test_malformed_csv_rows_are_skipped(self, tmp_csv):
    Path(tmp_csv).write_text(
      "id,type,source_ip,timestamp,data\n"
      "NOT_AN_INT,FAILED_LOGIN,1.2.3.4,2024-01-01T00:00:00,\n"
      "1,FAILED_LOGIN,1.2.3.4,2024-01-01T00:00:00,good row\n"
    )
    s = Store(csv_path=tmp_csv)
    assert len(s.list_all()) == 1
    assert s.list_all()[0].data == "good row"


# ===========================================================================
# Detector — unit tests
# ===========================================================================

class TestDetectorRecentBadLogins:

  def test_no_events_returns_zero(self, detector, store):
    assert detector._recent_bad_logins("1.2.3.4", []) == 0

  def test_counts_only_failed_logins_for_ip(self, store, detector):
    store.ingest(EventType.FAILED_LOGIN, "1.2.3.4")
    store.ingest(EventType.PORT_SCAN,    "1.2.3.4")  # different type
    store.ingest(EventType.FAILED_LOGIN, "9.9.9.9")  # different IP
    events = store.list_all()
    assert detector._recent_bad_logins("1.2.3.4", events) == 1

  def test_ignores_events_outside_window(self, store, detector):
    old_ts = datetime.now() - timedelta(seconds=WINDOW_SECONDS + 10)
    store.ingest(EventType.FAILED_LOGIN, "1.2.3.4", timestamp=old_ts)
    events = store.list_all()
    assert detector._recent_bad_logins("1.2.3.4", events) == 0

  def test_counts_events_inside_window(self, store, detector):
    for _ in range(3):
      store.ingest(EventType.FAILED_LOGIN, "1.2.3.4")
    events = store.list_all()
    assert detector._recent_bad_logins("1.2.3.4", events) == 3


class TestDetectorDetect:

  def _flood(self, store, ip: str, count: int) -> None:
    """Ingest *count* recent failed logins from *ip*."""
    for _ in range(count):
      store.ingest(EventType.FAILED_LOGIN, ip)

  def test_no_anomaly_below_threshold(self, store, detector):
    self._flood(store, "1.2.3.4", FAILED_LOGIN_THRESHOLD)
    assert detector.detect() == []

  def test_anomaly_above_threshold(self, store, detector):
    self._flood(store, "1.2.3.4", FAILED_LOGIN_THRESHOLD + 1)
    anomalies = detector.detect()
    assert len(anomalies) == 1
    assert anomalies[0].source == "1.2.3.4"

  def test_multiple_ips_detected_independently(self, store, detector):
    self._flood(store, "1.1.1.1", FAILED_LOGIN_THRESHOLD + 1)
    self._flood(store, "2.2.2.2", FAILED_LOGIN_THRESHOLD + 1)
    self._flood(store, "3.3.3.3", 1)  # under threshold — no anomaly
    anomalies = detector.detect()
    sources = {a.source for a in anomalies}
    assert sources == {"1.1.1.1", "2.2.2.2"}

  def test_anomaly_not_raised_for_old_events(self, store, detector):
    old_ts = datetime.now() - timedelta(seconds=WINDOW_SECONDS + 10)
    for _ in range(FAILED_LOGIN_THRESHOLD + 1):
      store.ingest(EventType.FAILED_LOGIN, "1.2.3.4", timestamp=old_ts)
    assert detector.detect() == []

  def test_anomaly_includes_matching_events(self, store, detector):
    self._flood(store, "5.5.5.5", FAILED_LOGIN_THRESHOLD + 2)
    anomalies = detector.detect()
    assert len(anomalies[0].events) == FAILED_LOGIN_THRESHOLD + 2

  def test_no_duplicate_anomalies_per_ip(self, store, detector):
    self._flood(store, "6.6.6.6", FAILED_LOGIN_THRESHOLD + 3)
    anomalies = detector.detect()
    sources = [a.source for a in anomalies]
    assert sources.count("6.6.6.6") == 1


# ===========================================================================
# HTTP API — integration tests
# ===========================================================================

class TestPostEvents:

  def test_post_valid_event_returns_201(self, client):
    resp = client.post(
      "/events",
      json={"type": "FAILED_LOGIN", "source_ip": "1.2.3.4"},
    )
    assert resp.status_code == 201

  def test_post_returns_event_with_id(self, client):
    resp = client.post(
      "/events",
      json={"type": "PORT_SCAN", "source_ip": "10.0.0.1"},
    )
    body = resp.get_json()
    assert body["id"] == 1
    assert body["source_ip"] == "10.0.0.1"
    assert body["type"] == "PORT_SCAN"

  def test_post_missing_source_ip_returns_400(self, client):
    resp = client.post("/events", json={"type": "FAILED_LOGIN"})
    assert resp.status_code == 400

  def test_post_missing_type_returns_400(self, client):
    resp = client.post("/events", json={"source_ip": "1.2.3.4"})
    assert resp.status_code == 400

  def test_post_invalid_type_returns_400(self, client):
    resp = client.post(
      "/events",
      json={"type": "NOT_A_TYPE", "source_ip": "1.2.3.4"},
    )
    assert resp.status_code == 400

  def test_post_non_json_body_returns_400(self, client):
    resp = client.post(
      "/events",
      data="not json",
      content_type="text/plain",
    )
    assert resp.status_code == 400

  def test_post_increments_ids(self, client):
    ids = []
    for _ in range(3):
      r = client.post(
        "/events",
        json={"type": "FAILED_LOGIN", "source_ip": "1.1.1.1"},
      )
      ids.append(r.get_json()["id"])
    assert ids == [1, 2, 3]


class TestGetEvents:

  def test_get_events_empty(self, client):
    resp = client.get("/events")
    assert resp.status_code == 200
    assert resp.get_json() == []

  def test_get_events_after_ingest(self, client):
    client.post("/events", json={"type": "PORT_SCAN", "source_ip": "1.1.1.1"})
    client.post("/events", json={"type": "FAILED_LOGIN", "source_ip": "2.2.2.2"})
    resp = client.get("/events")
    assert resp.status_code == 200
    assert len(resp.get_json()) == 2

  def test_get_events_content_type_json(self, client):
    resp = client.get("/events")
    assert "application/json" in resp.content_type


class TestGetAnomalies:

  def _flood(self, client, ip: str, count: int) -> None:
    for _ in range(count):
      client.post("/events", json={"type": "FAILED_LOGIN", "source_ip": ip})

  def test_no_anomalies_initially(self, client):
    resp = client.get("/anomalies")
    assert resp.status_code == 200
    assert resp.get_json() == []

  def test_anomaly_detected_after_threshold(self, client):
    self._flood(client, "9.9.9.9", FAILED_LOGIN_THRESHOLD + 1)
    resp = client.get("/anomalies")
    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body) == 1
    assert body[0]["source"] == "9.9.9.9"

  def test_no_anomaly_at_exact_threshold(self, client):
    self._flood(client, "8.8.8.8", FAILED_LOGIN_THRESHOLD)
    resp = client.get("/anomalies")
    assert resp.get_json() == []

  def test_anomaly_response_shape(self, client):
    self._flood(client, "7.7.7.7", FAILED_LOGIN_THRESHOLD + 1)
    body = client.get("/anomalies").get_json()
    anomaly = body[0]
    assert "source" in anomaly
    assert "type"   in anomaly
    assert "events" in anomaly
    assert isinstance(anomaly["events"], list)

  def test_anomaly_content_type_json(self, client):
    resp = client.get("/anomalies")
    assert "application/json" in resp.content_type