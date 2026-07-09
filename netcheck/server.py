#!/usr/bin/env python3
"""Local web service for one-shot network detection.

Serves a single-page frontend and a JSON API that runs the detection engine.
The blocking curl/traceroute work is dispatched to a worker thread so it never
stalls the asyncio event loop, and only one detection runs at a time.

Security posture:
- Binds to 127.0.0.1 by default (local-only, no auth needed). The bind host
  is logged on startup so an operator can see the exposure.
- The client may name targets by URL, but every URL is validated server-side
  (http/https only, no embedded credentials) before curl sees it, and any
  traceroute IP is one the engine resolved itself — never a client-supplied
  host. The API otherwise accepts only a small set of bounded numeric knobs.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import pathlib
import queue
import threading
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .engine import (
    DEFAULT_TARGETS,
    EngineConfig,
    TargetError,
    build_targets,
    run_check,
    stream_check,
    stream_trace_one,
)
from .history import HistoryStore, summarize_result
from .scheduler import (
    DEFAULT_INTERVAL_SECONDS,
    MAX_INTERVAL_SECONDS,
    MIN_INTERVAL_SECONDS,
    CheckScheduler,
    clamp_interval,
)

STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"

# Periodic detection config. The scheduler runs a lightweight sweep (curl phase
# timings only — no traceroute, no geo lookups) so a 10-minute cadence stays
# cheap and never trips ip-api's rate limit. A single history store is shared
# between the scheduler thread and the read-only HTTP handlers.
history = HistoryStore()

# The cadence check the scheduler runs: measure every default target a couple of
# times, but skip the expensive traceroute/geo phases the interactive UI uses.
_SCHEDULED_CONFIG = EngineConfig(
    samples_per_target=2,
    trace_targets=0,
    online_geo=False,
)


def _run_scheduled_check() -> Dict[str, Any]:
    """Run one periodic detection over the built-in default targets."""
    return run_check(_SCHEDULED_CONFIG, list(DEFAULT_TARGETS))


def _record_history(result: Dict[str, Any], source: str) -> None:
    """Persist one detection result as a compact history record."""
    history.append(summarize_result(result, source))


scheduler = CheckScheduler(
    run_fn=_run_scheduled_check,
    record_fn=_record_history,
    interval_seconds=DEFAULT_INTERVAL_SECONDS,
    enabled=True,
)


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Start the periodic scheduler with the app and stop it on shutdown."""
    scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()


app = FastAPI(
    title="NetCheck",
    description="一键网络延迟检测与慢因分析",
    version="1.0",
    lifespan=_lifespan,
)

# Concurrency model:
# - Batch detection (``/api/check`` and ``/api/check/stream``) is a heavy sweep
#   over every target, so only one runs at a time — a second request gets 429.
# - On-demand single-target traceroute (``/api/trace/stream``) is meant to fire
#   WHILE a batch is still running, the instant the user clicks a site card, so
#   it must NOT share the batch lock. Instead it runs on its own bounded pool:
#   several traces may run concurrently (with each other and with a batch), but
#   a semaphore caps how many, so a burst of clicks can't overwhelm the box or
#   trip ip-api's rate limit.
_batch_lock = asyncio.Lock()

# Max simultaneous on-demand traces. Bounded because each spawns a traceroute
# subprocess plus geo lookups; enough for a user clicking through several cards.
MAX_CONCURRENT_TRACES = 4
_trace_semaphore = asyncio.Semaphore(MAX_CONCURRENT_TRACES)

# Common SSE response headers: disable caching and any proxy buffering so
# frames reach the browser the instant they are produced.
_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


class TargetSpec(BaseModel):
    """One client-supplied target. Validated server-side in ``build_targets``;
    curl only ever receives the URL, never a host the engine didn't vet."""

    name: str = ""
    url: str = ""


class CheckOptions(BaseModel):
    """Client-tunable knobs for a batch check. All bounded to keep a run cheap
    and safe."""

    samples_per_target: int = Field(default=3, ge=1, le=6)
    trace_targets: int = Field(default=0, ge=0, le=3)
    trace_hops: int = Field(default=15, ge=5, le=30)
    online_geo: bool = True
    # None / empty -> engine falls back to the built-in default target list.
    targets: Optional[List[TargetSpec]] = None

    def to_engine_config(self) -> EngineConfig:
        return EngineConfig(
            samples_per_target=self.samples_per_target,
            trace_targets=self.trace_targets,
            trace_hops=self.trace_hops,
            online_geo=self.online_geo,
        )

    def resolve_targets(self):
        """Validate client targets into ``nm.Target`` objects.

        Raises ``TargetError`` (surfaced as HTTP 400 by the caller) on the
        first invalid entry so the user gets a precise, actionable message.
        Passing no targets falls back to the built-in defaults.
        """
        raw = None
        if self.targets:
            raw = [{"name": t.name, "url": t.url} for t in self.targets]
        return build_targets(raw)


class TraceOneOptions(BaseModel):
    """Request body for tracing a single, on-demand target.

    ``name``/``url`` identify one site to traceroute. The URL is validated the
    same way as batch targets, so traceroute only ever runs against an IP the
    engine resolves itself — never a client-supplied host.
    """

    name: str = ""
    url: str = ""
    trace_hops: int = Field(default=15, ge=5, le=30)
    online_geo: bool = True

    def to_engine_config(self) -> EngineConfig:
        return EngineConfig(trace_hops=self.trace_hops, online_geo=self.online_geo)

    def resolve_target(self):
        """Validate into a single ``nm.Target`` (raises ``TargetError``)."""
        return build_targets([{"name": self.name, "url": self.url}])[0]


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(str(INDEX_FILE))


@app.get("/api/health")
async def health() -> Dict[str, Any]:
    return {"ok": True}


@app.post("/api/check")
async def check(options: Optional[CheckOptions] = None) -> JSONResponse:
    """Run one full detection and return the structured result (non-streaming)."""
    opts = options or CheckOptions()
    config = opts.to_engine_config()
    try:
        targets = opts.resolve_targets()
    except TargetError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    if _batch_lock.locked():
        return JSONResponse(
            status_code=429,
            content={"error": "已有整体检测正在进行，请稍候再试"},
        )

    async with _batch_lock:
        loop = asyncio.get_running_loop()
        # run_check is fully blocking (subprocess + network); keep it off the
        # event loop so /api/health and the page stay responsive during a run.
        result = await loop.run_in_executor(
            None, functools.partial(run_check, config, targets)
        )

    # A manual run feeds the same trend history as the scheduled ones, so the
    # chart reflects on-demand checks too. Best-effort; never fails the response.
    _record_history(result, "manual")

    return JSONResponse(content=result)


# --------------------------------------------------------------------------- #
# Server-Sent Events plumbing
# --------------------------------------------------------------------------- #

# Sentinel placed on the queue by the producer thread once the generator is
# exhausted (cleanly or via error), so the async consumer knows to stop.
_STREAM_DONE = object()


def _sse_pack(event: Dict[str, Any]) -> str:
    """Format one engine event as a Server-Sent Events frame.

    The event's own ``event`` field doubles as the SSE event name, so the
    browser can dispatch with ``addEventListener(name, ...)``.
    """
    name = str(event.get("event", "message"))
    payload = json.dumps(event, ensure_ascii=False)
    return f"event: {name}\ndata: {payload}\n\n"


async def _sse_bridge(make_stream, request: Request):
    """Bridge a blocking event generator to an async SSE stream.

    ``make_stream`` is a zero-arg callable returning a generator of event dicts
    (e.g. ``stream_check`` or ``stream_trace_one``). It runs subprocesses and
    synchronous network I/O, so it must live on a worker thread. A bounded
    thread-safe queue hands events to the event loop; the loop drains it without
    ever blocking. If the client disconnects, we signal the producer so it stops
    after its current step.
    """
    loop = asyncio.get_running_loop()
    events: "queue.Queue[Any]" = queue.Queue(maxsize=64)
    cancel = threading.Event()

    def produce() -> None:
        try:
            for event in make_stream():
                if cancel.is_set():
                    break
                # Block if the consumer is behind; keeps memory bounded. A short
                # timeout lets us notice cancellation even when the queue is full.
                while not cancel.is_set():
                    try:
                        events.put(event, timeout=0.5)
                        break
                    except queue.Full:
                        continue
        except Exception as exc:  # noqa: BLE001 - surface as a stream error, never crash the thread
            try:
                events.put({"event": "error", "message": f"检测异常：{exc}"}, timeout=1)
            except queue.Full:
                pass
        finally:
            events.put(_STREAM_DONE)

    producer = loop.run_in_executor(None, produce)

    try:
        while True:
            if await request.is_disconnected():
                cancel.set()
                break
            try:
                item = await loop.run_in_executor(None, events.get, True, 0.5)
            except queue.Empty:
                # Comment frame doubles as a keep-alive so proxies don't idle-close.
                yield ": keep-alive\n\n"
                continue
            if item is _STREAM_DONE:
                break
            yield _sse_pack(item)
    finally:
        cancel.set()
        # Drain any backlog so the producer's blocking put() can return and the
        # worker thread exits instead of leaking.
        while True:
            try:
                if events.get_nowait() is _STREAM_DONE:
                    break
            except queue.Empty:
                break
        await producer


def _stream_response(make_stream, request: Request, gate) -> StreamingResponse:
    """Wrap a blocking event generator as an SSE ``StreamingResponse``.

    ``gate`` is an async context manager (a lock or semaphore) held for the
    whole stream: the batch lock serializes full sweeps, while the trace
    semaphore lets several on-demand traces run at once alongside a batch.
    """

    async def event_source():
        async with gate:
            async for frame in _sse_bridge(make_stream, request):
                yield frame

    return StreamingResponse(
        event_source(), media_type="text/event-stream", headers=_SSE_HEADERS
    )


def _recording_stream(config: EngineConfig, targets):
    """Wrap ``stream_check`` so a completed streamed run also lands in history.

    The stream emits per-target results as they finish; we relay every event
    untouched while accumulating the scalars a history record needs. Only once
    the ``done`` event passes do we reconstruct a compact result and persist it,
    so a client that disconnects mid-sweep leaves no partial record behind.
    """
    collected: List[Dict[str, Any]] = []
    generated_at: Optional[str] = None
    verdict: Optional[str] = None
    elapsed_sec: Optional[float] = None
    completed = False

    try:
        for event in stream_check(config, targets):
            name = event.get("event")
            if name == "start":
                generated_at = event.get("generated_at")
            elif name == "target":
                collected.append(event.get("data") or {})
            elif name == "verdict":
                verdict = event.get("verdict")
            elif name == "done":
                elapsed_sec = event.get("elapsed_sec")
                completed = True
            yield event
    finally:
        # Record only a run that actually reached ``done``; a disconnect or
        # error mid-sweep should not pollute the trend chart with a half result.
        if completed:
            result = {
                "generated_at": generated_at,
                "verdict": verdict,
                "elapsed_sec": elapsed_sec,
                "targets": collected,
            }
            _record_history(result, "manual")


@app.post("/api/check/stream")
async def check_stream(
    request: Request, options: Optional[CheckOptions] = None
) -> StreamingResponse:
    """Stream a batch detection as Server-Sent Events.

    Each site result is pushed the moment its curl samples finish, so the UI
    fills in live rather than after one long blocking request. Returns 400 on
    an invalid target and 429 if a detection is already running.
    """
    opts = options or CheckOptions()
    config = opts.to_engine_config()
    try:
        targets = opts.resolve_targets()
    except TargetError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    if _batch_lock.locked():
        return JSONResponse(
            status_code=429, content={"error": "已有整体检测正在进行，请稍候再试"}
        )

    return _stream_response(lambda: _recording_stream(config, targets), request, _batch_lock)


@app.post("/api/trace/stream")
async def trace_stream(
    request: Request, options: TraceOneOptions
) -> StreamingResponse:
    """Traceroute one target on demand, streaming hops as Server-Sent Events.

    Used when the user expands a site card to inspect its own route. Each hop
    and its geolocation are pushed as discovered. Returns 400 on an invalid URL
    and 429 if another detection is already running.
    """
    config = options.to_engine_config()
    try:
        target = options.resolve_target()
    except TargetError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    # Intentionally does NOT check the batch lock: an on-demand trace is meant
    # to run alongside a batch sweep. It only backs off if too many traces are
    # already in flight, so a burst of clicks can't exhaust the box or ip-api.
    if _trace_semaphore.locked():
        return JSONResponse(
            status_code=429,
            content={"error": f"同时进行的路由追踪已达上限（{MAX_CONCURRENT_TRACES} 个），请稍候"},
        )

    return _stream_response(
        lambda: stream_trace_one(target, config), request, _trace_semaphore
    )


# --------------------------------------------------------------------------- #
# Trend history + scheduler control
# --------------------------------------------------------------------------- #

# Bounds for the history query window, mirroring the retention policy so a client
# can never ask for more than we keep. Defaults to the last 6 hours.
DEFAULT_HISTORY_WINDOW_SECONDS = 6 * 3600
MAX_HISTORY_WINDOW_SECONDS = 7 * 24 * 3600


@app.get("/api/history")
async def get_history(since_seconds: int = DEFAULT_HISTORY_WINDOW_SECONDS) -> JSONResponse:
    """Return compact check records within a trailing time window for charting.

    ``since_seconds`` selects the look-back window (clamped to the retention
    period). Records come back oldest-first so the frontend can plot them
    directly. Reading is off-loaded to a thread since it touches the disk.
    """
    window = max(60, min(MAX_HISTORY_WINDOW_SECONDS, since_seconds))
    loop = asyncio.get_running_loop()
    records = await loop.run_in_executor(
        None, functools.partial(history.load, since_seconds=window)
    )
    return JSONResponse(
        content={
            "since_seconds": window,
            "count": len(records),
            "records": records,
        }
    )


class SchedulerConfig(BaseModel):
    """Client-tunable scheduler knobs. Both optional so a request can toggle the
    enabled flag and change the interval independently."""

    enabled: Optional[bool] = None
    interval_seconds: Optional[int] = Field(
        default=None, ge=MIN_INTERVAL_SECONDS, le=MAX_INTERVAL_SECONDS
    )


@app.get("/api/scheduler")
async def get_scheduler() -> JSONResponse:
    """Return the periodic scheduler's current status snapshot."""
    return JSONResponse(content=scheduler.status())


@app.post("/api/scheduler")
async def update_scheduler(config: Optional[SchedulerConfig] = None) -> JSONResponse:
    """Enable/disable periodic checks or change the interval, then return status.

    A partial body is honored: fields left unset keep their current value. The
    interval is clamped server-side as a second line of defence beyond the
    pydantic bounds.
    """
    cfg = config or SchedulerConfig()
    if cfg.interval_seconds is not None:
        scheduler.set_interval(clamp_interval(cfg.interval_seconds))
    if cfg.enabled is not None:
        scheduler.set_enabled(cfg.enabled)
    return JSONResponse(content=scheduler.status())


@app.post("/api/scheduler/run")
async def run_scheduler_now() -> JSONResponse:
    """Force one immediate periodic check without waiting for the next cycle."""
    scheduler.trigger_now()
    return JSONResponse(content=scheduler.status())


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="NetCheck local web service")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1, local-only)"
    )
    parser.add_argument(
        "--port", type=int, default=8777, help="Bind port (default: 8777)"
    )
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"⚠️  绑定到 {args.host}，服务将对外可访问且没有鉴权，请仅在可信网络中使用。"
        )
    else:
        print(f"NetCheck 仅监听本机 {args.host}:{args.port}，无需鉴权。")
    print(f"打开浏览器访问  http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
