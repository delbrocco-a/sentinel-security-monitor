"""
detector.py — anomaly detector, mirroring anomaly.go
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from store import Event, EventType, Store


# ---------------------------------------------------------------------------
# Constants  (mirror anomaly.go)
# ---------------------------------------------------------------------------

FAILED_LOGIN_THRESHOLD = 5
WINDOW_SECONDS         = 60


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
  source: str
  type:   EventType
  events: list[Event] = field(default_factory=list)

  def to_dict(self) -> dict:
    return {
      "source": self.source,
      "type":   self.type.value,
      "events": [e.to_dict() for e in self.events],
    }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
  """
  Scans the event store for known attack patterns.

  Currently detects: brute-force failed logins.
  """

  def __init__(self, store: Store) -> None:
    self._store = store

  # ------------------------------------------------------------------
  # Public API (mirrors detector.go exported methods)
  # ------------------------------------------------------------------

  def detect(self) -> list[Anomaly]:
    """Return all anomalies found across every distinct source IP."""
    all_events = self._store.list_all()
    seen: set[str] = set()
    anomalies: list[Anomaly] = []

    for event in all_events:
      ip = event.source_ip
      if ip in seen:
        continue
      seen.add(ip)

      bad_logins = self._recent_bad_logins(ip, all_events)
      if bad_logins > FAILED_LOGIN_THRESHOLD:
        matching = [
          e for e in all_events
          if e.source_ip == ip
          and e.type == EventType.FAILED_LOGIN
          and (datetime.now() - e.timestamp) < timedelta(seconds=WINDOW_SECONDS)
        ]
        anomalies.append(
          Anomaly(
            source = ip,
            type   = EventType.FAILED_LOGIN,
            events = matching,
          )
        )

    return anomalies

  def summary(self) -> list[dict]:
    """Return anomalies serialised to plain dicts (ready for JSON)."""
    return [a.to_dict() for a in self.detect()]

  # ------------------------------------------------------------------
  # Private helpers
  # ------------------------------------------------------------------

  def _recent_bad_logins(self, ip: str, all_events: list[Event]) -> int:
    """Count failed logins for *ip* within the rolling time window."""
    cutoff = datetime.now() - timedelta(seconds=WINDOW_SECONDS)
    return sum(
      1
      for e in all_events
      if e.source_ip == ip
      and e.type     == EventType.FAILED_LOGIN
      and e.timestamp >= cutoff
    )