"""
store.py — CSV-backed event store, mirroring store.go
"""

import csv
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class EventType(str, Enum):
		FAILED_LOGIN      = "FAILED_LOGIN"
		PORT_SCAN         = "PORT_SCAN"
		ANOMALOUS_TRAFFIC = "ANOMALOUS_TRAFFIC"


@dataclass
class Event:
		id:        int
		type:      EventType
		source_ip: str
		timestamp: datetime
		data:      str = ""

		# Convenience: build from a raw CSV row dict
		@classmethod
		def from_row(cls, row: dict) -> "Event":
				return cls(
						id        = int(row["id"]),
						type      = EventType(row["type"]),
						source_ip = row["source_ip"],
						timestamp = datetime.fromisoformat(row["timestamp"]),
						data      = row.get("data", ""),
				)

		def to_row(self) -> dict:
				return {
						"id":        self.id,
						"type":      self.type.value,
						"source_ip": self.source_ip,
						"timestamp": self.timestamp.isoformat(),
						"data":      self.data,
				}

		def to_dict(self) -> dict:
				return {
						"id":        self.id,
						"type":      self.type.value,
						"source_ip": self.source_ip,
						"timestamp": self.timestamp.isoformat(),
						"data":      self.data,
				}


CSV_FIELDS = ["id", "type", "source_ip", "timestamp", "data"]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class Store:
		"""
		Thread-safe event store backed by a CSV file.

		On construction the CSV is read (or created if absent).
		Every write is flushed to disk immediately so the file is always
		consistent with in-memory state.
		"""

		def __init__(self, csv_path: str = "events.csv") -> None:
				self._path   = Path(csv_path)
				self._lock   = threading.RLock()
				self._events: list[Event] = []
				self._next_id: int = 1
				self._load()

		# ------------------------------------------------------------------
		# Public API (mirrors store.go exported methods)
		# ------------------------------------------------------------------

		@property
		def events(self) -> list[Event]:
				"""Return a snapshot of all events (thread-safe copy)."""
				with self._lock:
						return list(self._events)

		def ingest(
				self,
				type: EventType,
				source_ip: str,
				data: str = "",
				timestamp: Optional[datetime] = None,
		) -> Event:
				"""
				Validate and store a new event.

				Raises ValueError for missing required fields.
				"""
				if not source_ip:
						raise ValueError("source_ip is required")
				if not type:
						raise ValueError("type is required")

				with self._lock:
						event = Event(
								id        = self._next_id,
								type      = type,
								source_ip = source_ip,
								timestamp = timestamp or datetime.now(),
								data      = data,
						)
						self._events.append(event)
						self._next_id += 1
						self._flush()
						return event

		def list_all(self) -> list[Event]:
				"""Return a thread-safe snapshot of every stored event."""
				with self._lock:
						return list(self._events)

		# ------------------------------------------------------------------
		# CSV persistence (private)
		# ------------------------------------------------------------------

		def _load(self) -> None:
				"""Read events from CSV on disk (if the file exists)."""
				if not self._path.exists():
						return

				with self._path.open(newline="") as fh:
						reader = csv.DictReader(fh)
						for row in reader:
								try:
										event = Event.from_row(row)
										self._events.append(event)
										if event.id >= self._next_id:
												self._next_id = event.id + 1
								except (ValueError, KeyError):
										# Skip malformed rows rather than crashing
										continue

		def _flush(self) -> None:
				"""Rewrite the entire CSV from in-memory state (call under lock)."""
				with self._path.open("w", newline="") as fh:
						writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
						writer.writeheader()
						writer.writerows(e.to_row() for e in self._events)