#!/usr/bin/env python3
"""Background scheduler that runs a network check on a fixed interval.

A single daemon thread sleeps for the configured interval, runs one detection,
distills it into a history record, and repeats. The sleep is interruptible so
the interval can be changed, the loop paused/resumed, or a run forced "now"
without waiting out the current cycle.

Design goals:
- Zero third-party dependencies; stdlib + Python 3.9 compatible.
- Dependency-injected: the caller supplies the check function and the history
  store, so the scheduler knows nothing about the engine and stays testable.
- Never raise out of the loop. A failing check is recorded as an error on the
  status and the loop keeps going — a scheduler that dies silently is worse
  than one that logs and retries.
- Observable: ``status()`` returns a JSON-serializable snapshot (enabled,
  interval, last/next run, last error, run counter) for the UI.
"""

from __future__ import annotations

import datetime as dt
import threading
import traceback
from typing import Any, Callable, Dict, Optional

# Interval bounds. Ten minutes is the default cadence; we refuse anything below
# one minute so a misconfiguration can't turn the scheduler into a curl storm,
# and cap it at a day so "next run" stays meaningful.
DEFAULT_INTERVAL_SECONDS = 600
MIN_INTERVAL_SECONDS = 60
MAX_INTERVAL_SECONDS = 24 * 3600


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(moment: Optional[dt.datetime]) -> Optional[str]:
    return moment.replace(microsecond=0).isoformat() if moment else None


def clamp_interval(seconds: Any) -> int:
    """Coerce a client-supplied interval into the allowed range.

    Non-numeric input falls back to the default rather than raising, since this
    feeds an API knob and a bad value should degrade, not 500.
    """
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_SECONDS
    return max(MIN_INTERVAL_SECONDS, min(MAX_INTERVAL_SECONDS, value))


class CheckScheduler:
    """Runs ``run_fn`` every ``interval_seconds`` on a background thread.

    ``run_fn`` returns a full engine result dict; ``record_fn`` persists one
    (result, source) pair. Both are injected so this class has no engine or
    storage imports and can be unit-tested with fakes.

    Thread model: one daemon worker owns the loop. All shared state is guarded
    by ``_lock``; the worker blocks on ``_wake`` (an Event) for its interval so
    config changes and shutdown take effect immediately instead of after a full
    sleep.
    """

    def __init__(
        self,
        run_fn: Callable[[], Dict[str, Any]],
        record_fn: Callable[[Dict[str, Any], str], None],
        interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self._run_fn = run_fn
        self._record_fn = record_fn

        self._lock = threading.Lock()
        self._wake = threading.Event()  # set to interrupt the interval sleep
        self._stop = threading.Event()  # set to end the loop for good
        self._thread: Optional[threading.Thread] = None

        # All fields below are guarded by ``_lock``.
        self._interval = clamp_interval(interval_seconds)
        self._enabled = bool(enabled)
        self._force = False  # a one-shot "run now" request
        self._running = False  # a check is executing right now
        self._last_run_at: Optional[dt.datetime] = None
        self._last_ok_at: Optional[dt.datetime] = None
        self._last_error: Optional[str] = None
        self._run_count = 0

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Launch the worker thread (idempotent)."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, name="netcheck-scheduler", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to exit and join the worker (best-effort)."""
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)

    # ------------------------------------------------------------------ control
    def set_enabled(self, enabled: bool) -> None:
        """Pause or resume periodic runs without stopping the thread."""
        with self._lock:
            self._enabled = bool(enabled)
        self._wake.set()  # re-evaluate the schedule immediately

    def set_interval(self, seconds: int) -> int:
        """Change the cadence; returns the clamped value actually applied."""
        clamped = clamp_interval(seconds)
        with self._lock:
            self._interval = clamped
        self._wake.set()  # recompute the next-run time against the new interval
        return clamped

    def trigger_now(self) -> None:
        """Request one immediate run, regardless of the enabled flag."""
        with self._lock:
            self._force = True
        self._wake.set()

    def status(self) -> Dict[str, Any]:
        """A JSON-serializable snapshot of the scheduler state for the UI."""
        with self._lock:
            next_run = self._compute_next_run_locked()
            return {
                "enabled": self._enabled,
                "interval_seconds": self._interval,
                "running": self._running,
                "last_run_at": _iso(self._last_run_at),
                "last_ok_at": _iso(self._last_ok_at),
                "last_error": self._last_error,
                "run_count": self._run_count,
                "next_run_at": _iso(next_run),
                "server_time": _iso(_utc_now()),
            }

    # --------------------------------------------------------------------- loop
    def _compute_next_run_locked(self) -> Optional[dt.datetime]:
        """Best-effort estimate of the next run time (None when paused).

        Based on the last run plus the interval; if we've never run, the next
        run is one interval out from now. Purely informational for the UI.
        """
        if not self._enabled:
            return None
        base = self._last_run_at or _utc_now()
        return base + dt.timedelta(seconds=self._interval)

    def _loop(self) -> None:
        """Worker body: sleep, decide, run, record, repeat until stopped."""
        while not self._stop.is_set():
            with self._lock:
                enabled = self._enabled
                interval = self._interval

            # Paused: wait to be woken by a config change / shutdown rather than
            # busy-spinning. A long timeout bounds the wait even if no event fires.
            if not enabled:
                self._wait(min(interval, 60))
                if self._consume_force():
                    self._run_once("manual")
                continue

            # Enabled: sleep for the interval, but wake early on any signal.
            interrupted = self._wait(interval)
            if self._stop.is_set():
                break

            forced = self._consume_force()
            # A bare wake with neither a force nor an elapsed interval means a
            # config change (e.g. interval edit) — loop to recompute, don't run.
            if interrupted and not forced:
                continue

            with self._lock:
                still_enabled = self._enabled
            if still_enabled or forced:
                self._run_once("auto" if not forced else "manual")

    def _wait(self, seconds: float) -> bool:
        """Sleep up to ``seconds``, returning True if woken early by a signal."""
        self._wake.clear()
        woke = self._wake.wait(timeout=max(0.0, seconds))
        return woke

    def _consume_force(self) -> bool:
        """Atomically read-and-clear the one-shot force flag."""
        with self._lock:
            forced = self._force
            self._force = False
        return forced

    def _run_once(self, source: str) -> None:
        """Run one check and record it. Never raises; errors land on status."""
        with self._lock:
            self._running = True
        started = _utc_now()
        try:
            result = self._run_fn()
            self._record_fn(result, source)
            with self._lock:
                self._last_ok_at = _utc_now()
                self._last_error = None
        except Exception:  # noqa: BLE001 - keep the loop alive across any failure
            with self._lock:
                self._last_error = traceback.format_exc(limit=3).strip()
        finally:
            with self._lock:
                self._running = False
                self._last_run_at = started
                self._run_count += 1
