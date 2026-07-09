#!/usr/bin/env python3
"""Time-series history store for periodic network checks.

Each completed detection (scheduled or manual) is distilled into one compact
record and appended to a JSONL file. The frontend reads a bounded time window
back out to draw trend lines, so we keep only the fields a chart needs — the
full per-hop trace payload is deliberately NOT stored here.

Design goals:
- Zero third-party dependencies; stdlib + Python 3.9 compatible.
- Thread-safe: the scheduler thread appends while HTTP handlers read.
- Never raise to the caller. A corrupt line is skipped, a missing file reads
  as empty, and a failed write is swallowed after logging — history is
  best-effort telemetry, never load-bearing for a live check.
- Bounded on disk: records past the retention window are pruned on write.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import tempfile
import threading
from typing import Any, Dict, List, Optional

# History lives under tools/data/ (one dir up from the package). Kept out of the
# package tree so it is obviously runtime state, not shipped code.
_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"
DEFAULT_HISTORY_PATH = _DATA_DIR / "netcheck_history.jsonl"

# How long a record is retained before it is pruned. Seven days of 10-minute
# samples is ~1000 records — small enough to read fully on demand.
RETENTION_SECONDS = 7 * 24 * 3600

# Hard cap on records returned to a client, so an unexpectedly large file can
# never blow up a response or the browser. Newest records win.
MAX_RETURN_RECORDS = 5000


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse_ts(ts: str) -> Optional[dt.datetime]:
    """Parse an ISO-8601 timestamp back to an aware datetime, or None.

    ``fromisoformat`` on Python 3.9 does not accept a trailing ``Z``; our own
    timestamps use ``+00:00`` so this normally succeeds, but we normalize ``Z``
    defensively in case an externally-edited record slips in.
    """
    if not ts:
        return None
    try:
        parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def summarize_result(result: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Distill a full engine result into one compact history record.

    Only the per-target scalars a trend chart needs are kept; raw samples and
    traceroute hops are dropped. ``source`` is ``"auto"`` for the scheduler or
    ``"manual"`` for a user-triggered run.
    """
    targets = []
    for target in result.get("targets", []):
        targets.append(
            {
                "name": target.get("name"),
                "url": target.get("url"),
                "ok": bool(target.get("ok")),
                "total_median": target.get("total_median"),
                "total_p95": target.get("total_p95"),
                "failure_rate": target.get("failure_rate"),
                "speed_median": target.get("speed_median"),
            }
        )
    return {
        "ts": result.get("generated_at") or _utc_now().replace(microsecond=0).isoformat(),
        "source": source,
        "verdict": result.get("verdict"),
        "elapsed_sec": result.get("elapsed_sec"),
        "targets": targets,
    }


class HistoryStore:
    """Append-only JSONL store of compact check records.

    A single process-wide lock serializes writes (the scheduler thread) against
    the prune-on-write, while reads take the same lock only briefly to snapshot
    the file. The file is small enough that reading it whole per request is fine.
    """

    def __init__(
        self,
        path: pathlib.Path = DEFAULT_HISTORY_PATH,
        retention_seconds: int = RETENTION_SECONDS,
    ) -> None:
        self._path = pathlib.Path(path)
        self._retention = retention_seconds
        self._lock = threading.Lock()

    @property
    def path(self) -> pathlib.Path:
        return self._path

    def append(self, record: Dict[str, Any]) -> None:
        """Append one record, then prune anything past the retention window.

        Best-effort: any I/O error is swallowed so a telemetry write can never
        break a live detection.
        """
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                self._prune_locked()
            except OSError:
                # History is best-effort; never propagate a disk error upward.
                pass

    def load(
        self,
        since_seconds: Optional[int] = None,
        limit: int = MAX_RETURN_RECORDS,
    ) -> List[Dict[str, Any]]:
        """Read records newest-last, optionally within a trailing time window.

        ``since_seconds`` keeps only records newer than ``now - since_seconds``.
        ``limit`` caps the count, keeping the most recent. A missing file or a
        corrupt line reads as empty / skipped rather than raising.
        """
        with self._lock:
            lines = self._read_lines_locked()

        cutoff: Optional[dt.datetime] = None
        if since_seconds is not None and since_seconds > 0:
            cutoff = _utc_now() - dt.timedelta(seconds=since_seconds)

        records: List[Dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue  # skip a corrupt/partial line, keep the rest
            if not isinstance(record, dict):
                continue
            if cutoff is not None:
                parsed = _parse_ts(str(record.get("ts", "")))
                if parsed is None or parsed < cutoff:
                    continue
            records.append(record)

        if limit and len(records) > limit:
            records = records[-limit:]
        return records

    def _read_lines_locked(self) -> List[str]:
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                return handle.readlines()
        except FileNotFoundError:
            return []
        except OSError:
            return []

    def _prune_locked(self) -> None:
        """Drop records older than the retention window by rewriting the file.

        Called under ``self._lock`` right after an append. Writes to a temp file
        in the same directory and atomically replaces the original so a crash
        mid-prune can't corrupt history. A parse of the cutoff failing leaves the
        file untouched.
        """
        cutoff = _utc_now() - dt.timedelta(seconds=self._retention)
        kept: List[str] = []
        dropped = 0
        for line in self._read_lines_locked():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
                parsed = _parse_ts(str(record.get("ts", "")))
            except ValueError:
                # Keep unparseable lines rather than silently discarding data.
                kept.append(stripped)
                continue
            if parsed is None or parsed >= cutoff:
                kept.append(stripped)
            else:
                dropped += 1

        if dropped == 0:
            return  # nothing aged out; avoid a needless rewrite

        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".netcheck_hist_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for stripped in kept:
                    handle.write(stripped + "\n")
            os.replace(tmp_name, self._path)
        except OSError:
            # Prune is opportunistic; if the rewrite fails, leave the original.
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
