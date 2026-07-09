#!/usr/bin/env python3
"""One-shot network detection engine.

Runs curl phase timings and traceroute against a fixed set of targets, then
diagnoses where the slowness is and attaches IP geolocation to every hop.

Design goals:
- Compatible with the system Python 3.9 interpreter (no ``datetime.UTC``).
- Reuses the battle-tested pure functions from ``network_monitor`` for
  curl-metric parsing, phase math, diagnosis and traceroute parsing, so the
  logic stays in one place.
- Never runs a shell; every external command is an argv list built from
  server-controlled targets or IPs parsed out of traceroute output. The
  engine never accepts an arbitrary host from the client.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import pathlib
import shutil
import statistics
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Reuse the pure helpers from the existing monitor module. It lives one
# directory up, so make sure the parent is importable.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import network_monitor as nm  # noqa: E402

from .geoip import GeoInfo, GeoResolver, classify_ip  # noqa: E402


# Fixed target list. Names are stable identifiers used by the frontend; URLs
# are the only thing curl ever receives, so the client cannot inject a host.
DEFAULT_TARGETS: List[nm.Target] = [
    nm.Target("百度", "https://www.baidu.com"),
    nm.Target("阿里云", "https://www.aliyun.com"),
    nm.Target("腾讯云", "https://cloud.tencent.com"),
    nm.Target("码云 Gitee", "https://gitee.com"),
    nm.Target("GitHub", "https://github.com"),
    nm.Target("微软", "https://www.microsoft.com"),
]

# Guardrails for client-supplied targets. curl receives the URL verbatim, so
# these bounds keep a run cheap and prevent the endpoint from being turned into
# a request proxy against arbitrary internal services.
MAX_TARGETS = 12
MAX_NAME_LEN = 40
MAX_URL_LEN = 300
ALLOWED_SCHEMES = ("http", "https")


class TargetError(ValueError):
    """Raised when a client-supplied target fails validation."""


def _clean_target_name(name: str, fallback_host: str) -> str:
    """Normalize a display name; fall back to the host when empty.

    Control characters are stripped because the name is echoed into the UI and
    used to build DOM ids on the client.
    """
    cleaned = "".join(ch for ch in (name or "") if ch.isprintable()).strip()
    cleaned = cleaned[:MAX_NAME_LEN].strip()
    return cleaned or fallback_host[:MAX_NAME_LEN] or "target"


def _validate_target_url(url: str) -> str:
    """Validate a single URL and return its normalized form.

    Only plain http/https URLs to a real hostname are accepted. Embedded
    credentials are rejected so a run can't smuggle auth to an internal host.
    """
    url = (url or "").strip()
    if not url:
        raise TargetError("URL 不能为空")
    if len(url) > MAX_URL_LEN:
        raise TargetError("URL 过长")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise TargetError(f"仅支持 http/https：{url!r}")
    if parsed.username or parsed.password:
        raise TargetError("URL 不能包含用户名/密码")
    if not parsed.hostname:
        raise TargetError(f"URL 缺少主机名：{url!r}")
    # Reject control/whitespace chars that could break the argv or the UI.
    if any(ch.isspace() for ch in url):
        raise TargetError("URL 不能包含空白字符")
    return url


def build_targets(raw: Optional[List[Dict[str, str]]]) -> List[nm.Target]:
    """Turn a client target list into validated ``nm.Target`` objects.

    ``raw`` is a list of ``{"name": ..., "url": ...}`` dicts. Passing ``None``
    or an empty list yields the built-in defaults. Raises ``TargetError`` on the
    first invalid entry so the caller can report a precise message.
    """
    if not raw:
        return list(DEFAULT_TARGETS)
    if len(raw) > MAX_TARGETS:
        raise TargetError(f"目标数量超过上限（最多 {MAX_TARGETS} 个）")

    targets: List[nm.Target] = []
    seen_urls = set()
    for entry in raw:
        url = _validate_target_url(str(entry.get("url", "")))
        if url in seen_urls:
            continue  # silently drop exact duplicates
        seen_urls.add(url)
        host = urllib.parse.urlsplit(url).hostname or url
        name = _clean_target_name(str(entry.get("name", "")), host)
        targets.append(nm.Target(name=name, url=url))
    if not targets:
        raise TargetError("没有有效的目标站点")
    return targets


# Chinese labels for the dominant-delay phase, shown in the UI.
PHASE_LABELS_ZH = {
    "dns": "DNS 解析",
    "tcp": "TCP 连接 / 路由链路",
    "tls": "TLS 握手 / 代理 / 丢包",
    "server": "服务端首字节响应",
    "download": "内容下载 / 带宽",
}

# A hop whose median latency is at/above this is treated as "slow".
SLOW_HOP_MS = 100.0


def utc_iso() -> str:
    """3.9-compatible UTC timestamp (the monitor module uses ``dt.UTC``)."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


# ``network_monitor.utc_iso`` uses ``datetime.UTC`` which only exists on
# Python 3.11+. run_curl() calls it on every sample, so on the system 3.9
# interpreter it would raise AttributeError. Override the module attribute
# with our 3.9-safe implementation; nm functions resolve it at call time.
nm.utc_iso = utc_iso


@dataclass(frozen=True)
class EngineConfig:
    samples_per_target: int = 3
    curl_timeout: float = 15.0
    trace_hops: int = 15
    trace_targets: int = 1  # how many slowest targets get a traceroute
    ipv4_only: bool = True
    use_rtk: bool = False
    online_geo: bool = True
    geo_timeout: float = 6.0


def _tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def measure_target(target: nm.Target, config: EngineConfig) -> Dict[str, Any]:
    """Run curl ``samples_per_target`` times and summarize one target."""
    samples: List[Dict[str, Any]] = []
    for _ in range(max(1, config.samples_per_target)):
        sample = nm.run_curl(
            target,
            timeout=config.curl_timeout,
            ipv4=config.ipv4_only,
            use_rtk=config.use_rtk,
        )
        samples.append(sample)

    summary = nm.summarize_target(samples)
    diagnosis_en = nm.diagnose(summary)

    phase_medians = {
        key: (summary["phase_stats"][key]["median"] or 0.0)
        for key in ("dns", "tcp", "tls", "server", "download")
    }
    worst_phase = None
    if any(phase_medians.values()):
        worst_phase = max(phase_medians, key=lambda k: phase_medians[k])

    return {
        "name": target.name,
        "url": target.url,
        "ok": summary["ok_count"] > 0,
        "samples": summary["count"],
        "failures": summary["failure_count"],
        "failure_rate": summary["failure_rate"],
        "total_median": summary["total_median"],
        "total_p95": summary["total_p95"],
        "speed_median": summary["speed_median"],
        "last_ip": summary["last_ip"],
        "phases": {key: summary["phase_stats"][key]["median"] for key in
                   ("dns", "tcp", "tls", "server", "download", "total")},
        "worst_phase": worst_phase,
        "worst_phase_label": PHASE_LABELS_ZH.get(worst_phase or "", None),
        "diagnosis_en": diagnosis_en,
        "diagnosis": _diagnosis_zh(summary, worst_phase),
        "raw_samples": samples,
    }


def _diagnosis_zh(summary: Dict[str, Any], worst_phase: Optional[str]) -> str:
    """Human-friendly Chinese diagnosis derived from the same signals as
    ``network_monitor.diagnose``."""
    if summary["count"] == 0:
        return "没有采样数据"
    if summary["failure_rate"] >= 0.2:
        return "失败率偏高，先排查 DNS / 链路 / 防火墙，再看延迟"
    total_median = summary["total_median"] or 0.0
    worst_value = 0.0
    if worst_phase:
        worst_value = summary["phase_stats"][worst_phase]["median"] or 0.0
    if worst_value < 0.2 and total_median < 0.8:
        return "当前采样下访问正常"
    label = PHASE_LABELS_ZH.get(worst_phase or "", worst_phase or "未知")
    return f"主要耗时集中在：{label}"


def _hop_median_ms(hop: Dict[str, Any]) -> Optional[float]:
    latencies = hop.get("latencies_ms") or []
    return statistics.median(latencies) if latencies else None


# traceroute is run with this many probes per hop, so a hop with fewer timed
# replies had that many probes time out. Kept in sync with the ``-q`` flag.
PROBES_PER_HOP = 3


def _hop_view(hop: Dict[str, Any], is_dest: bool = False) -> Dict[str, Any]:
    """Per-hop view including each probe's latency, so the UI can show the
    round-by-round detail behind the single median figure.

    Important distinction: a ``*`` (no reply) at an *intermediate* hop is
    almost never packet loss. Routers generate the ICMP "TTL exceeded" reply on
    a low-priority control path and commonly rate-limit or suppress it entirely
    while still forwarding traffic normally. So a silent middle hop is reported
    as a neutral "no reply", NOT as loss. Only the *destination* hop failing to
    answer is a meaningful (still soft) signal, since that endpoint is what we
    actually care about reaching — and even then many hosts drop ICMP by policy.
    """
    latencies = list(hop.get("latencies_ms") or [])
    median = statistics.median(latencies) if latencies else None
    responded = len(latencies)
    silent = max(0, PROBES_PER_HOP - responded)

    # ``responded == 0`` -> fully silent; ``0 < responded < sent`` -> partial.
    if responded == 0:
        status = "silent"
    elif silent > 0:
        status = "partial"
    else:
        status = "ok"

    # Loss is only asserted at the destination. Intermediate silence is
    # explicitly neutral (loss_pct is None so the UI shows "—" not "0%").
    loss_pct = round(silent / PROBES_PER_HOP * 100) if (is_dest and PROBES_PER_HOP) else None

    return {
        "hop": hop["hop"],
        "ip": hop.get("ip"),
        "median_ms": median,
        "min_ms": min(latencies) if latencies else None,
        "max_ms": max(latencies) if latencies else None,
        "probes_ms": latencies,
        "probes_sent": PROBES_PER_HOP,
        "responded": responded,
        "silent": silent,
        "is_dest": is_dest,
        "status": status,  # "ok" | "partial" | "silent"
        "loss_pct": loss_pct,  # meaningful only at destination; else None
        "slow": bool(median is not None and median >= SLOW_HOP_MS),
        "raw": hop.get("raw"),
    }


def run_traceroute(ip: str, config: EngineConfig) -> str:
    """Run traceroute to a single IP. Returns raw stdout (or an error line)."""
    # Validate the IP defensively: we only ever traceroute addresses we parsed
    # out of curl/traceroute ourselves, never a client-supplied host.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"invalid ip: {ip!r}"
    cmd = nm.tool_cmd("traceroute", config.use_rtk) + [
        "-n",  # numeric, skip reverse DNS for speed
        "-m", str(config.trace_hops),
        "-q", str(PROBES_PER_HOP),
        "-w", "1",
        ip,
    ]
    return nm.run_command(cmd, timeout=max(15.0, config.trace_hops + 5))


def build_trace_report(
    target: Dict[str, Any],
    resolver: GeoResolver,
    config: EngineConfig,
) -> Optional[Dict[str, Any]]:
    """Traceroute the target's last IP and annotate every hop with geo info."""
    ip = target.get("last_ip")
    if not ip:
        return None

    trace_output = run_traceroute(ip, config)
    hops = nm.parse_trace_hops(trace_output)
    key_nodes = nm.trace_key_nodes(trace_output)
    analysis_en = nm.analyze_trace(trace_output)

    # Collect every hop IP plus the destination for a single batched geo query.
    hop_ips = [hop["ip"] for hop in hops if hop.get("ip")]
    geo_map = resolver.resolve_many([ip, *hop_ips])

    annotated_hops = []
    for hop in hops:
        hop_ip = hop.get("ip")
        geo = geo_map.get(hop_ip) if hop_ip else None
        view = _hop_view(hop, is_dest=(hop_ip == ip))
        view["geo"] = _geo_dict(geo) if geo else None
        annotated_hops.append(view)

    # Identify the key node roles and enrich them with geo + latency.
    key_node_view = []
    for node in key_nodes:
        node_ip = node.get("ip")
        geo = geo_map.get(node_ip) if node_ip else None
        key_node_view.append({
            "role": _role_zh(node["role"]),
            "role_en": node["role"],
            "hop": node["hop"],
            "ip": node_ip,
            "median_ms": _hop_median_ms(node),
            "geo": _geo_dict(geo) if geo else None,
        })

    return {
        "target": target["name"],
        "dest_ip": ip,
        "dest_geo": _geo_dict(geo_map.get(ip)) if geo_map.get(ip) else None,
        "analysis_en": analysis_en,
        "analysis": _trace_analysis_zh(annotated_hops),
        "hops": annotated_hops,
        "key_nodes": key_node_view,
        "raw": trace_output,
    }


def _role_zh(role_en: str) -> str:
    return {
        "private gateway": "内网网关",
        "first public hop": "首个公网节点",
        "highest visible latency": "延迟最高节点",
        "sustained latency candidate": "持续高延迟起点",
        "last visible hop": "最后可见节点",
    }.get(role_en, role_en)


def _trace_analysis_zh(annotated_hops: List[Dict[str, Any]]) -> str:
    """Locate where the path starts being consistently slow, in Chinese.

    Note on ``*`` hops: intermediate silence is treated as ICMP rate-limiting,
    not loss (see ``_hop_view``). We only flag "疑似丢包" when the destination
    hop itself fails to answer, and even then hedge, since many endpoints drop
    ICMP by policy.
    """
    responsive = [h for h in annotated_hops if h["ip"] and h["median_ms"] is not None]

    # Did we actually reach the destination? The destination hop is the one
    # flagged is_dest by the caller (its IP equals the resolved target IP).
    dest_hop = next((h for h in annotated_hops if h.get("is_dest")), None)
    reached = bool(dest_hop and dest_hop.get("median_ms") is not None)

    # Caveat appended when the tail of the path is silent, so the user doesn't
    # read trailing "*" as packet loss.
    tail_note = ""
    if not reached:
        tail_note = (
            "；注意：末段节点未回应 traceroute 探测，这通常是目标或沿途路由器"
            "按策略限速/屏蔽 ICMP，并不等于你的流量在丢包"
        )

    if not responsive:
        return "沿途节点均未回应探测（多为路由器限速 ICMP），无法据此定位慢点" + tail_note

    # Find the first hop that is slow AND stays slow for the rest of the path.
    for idx, hop in enumerate(responsive):
        if not hop["slow"]:
            continue
        later = responsive[idx + 1:]
        if len(later) >= 2 and all(h["median_ms"] >= SLOW_HOP_MS * 0.8 for h in later):
            place = ""
            geo = hop.get("geo")
            if geo and geo.get("location") not in (None, "归属地未知"):
                place = f"（{geo['location']} / {geo.get('carrier') or '未知运营商'}）"
            return (
                f"链路在第 {hop['hop']} 跳 {hop['ip']}{place} 起延迟明显升高，"
                f"约 {hop['median_ms']:.0f}ms，且之后持续偏高，慢点很可能在此处或其上游"
                + tail_note
            )

    worst = max(responsive, key=lambda h: h["median_ms"])
    if worst["median_ms"] >= SLOW_HOP_MS:
        geo = worst.get("geo")
        place = f"（{geo['location']}）" if geo and geo.get("location") else ""
        return (
            f"未发现持续性突增，但第 {worst['hop']} 跳 {worst['ip']}{place} "
            f"延迟最高（约 {worst['median_ms']:.0f}ms），可能为瞬时抖动"
            + tail_note
        )
    return "路由沿途延迟平稳，未发现明显慢点" + tail_note


def _geo_dict(geo: GeoInfo) -> Dict[str, Any]:
    return {
        "ip": geo.ip,
        "scope": geo.scope,
        "location": geo.location_label(),
        "carrier": geo.carrier_label(),
        "asn": geo.asn,
        "source": geo.source,
        "note": geo.note,
    }


def _overall_verdict(targets: List[Dict[str, Any]]) -> str:
    """A one-line summary across all targets for the top of the report."""
    ok_targets = [t for t in targets if t["ok"]]
    if not ok_targets:
        return "所有目标均无法访问，请检查本机网络连接"
    slow = [t for t in ok_targets if (t["total_median"] or 0.0) >= 1.0]
    failed = [t for t in targets if not t["ok"]]
    parts = []
    if failed:
        parts.append(f"{len(failed)} 个目标访问失败（{'、'.join(t['name'] for t in failed)}）")
    if slow:
        parts.append(f"{len(slow)} 个目标偏慢（{'、'.join(t['name'] for t in slow)}）")
    if not parts:
        return "整体网络状况良好，常用站点访问正常"
    return "；".join(parts)


def run_check(
    config: Optional[EngineConfig] = None,
    targets_spec: Optional[List[nm.Target]] = None,
) -> Dict[str, Any]:
    """Full one-shot detection: measure all targets, then traceroute the
    slowest ones and attach geolocation. This is the single entry point the
    web server calls. ``targets_spec`` overrides the built-in target list."""
    config = config or EngineConfig()
    target_list = targets_spec or list(DEFAULT_TARGETS)
    started = time.time()

    if not _tool_available("curl"):
        return {
            "generated_at": utc_iso(),
            "error": "本机未找到 curl，无法进行检测",
            "targets": [],
            "traces": [],
        }

    # Measure targets concurrently: each curl run is blocking I/O.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(target_list)) as pool:
        targets = list(pool.map(lambda t: measure_target(t, config), target_list))

    resolver = GeoResolver(timeout=config.geo_timeout, online=config.online_geo)

    # Attach geolocation for each target's destination IP up front.
    dest_ips = [t["last_ip"] for t in targets if t.get("last_ip")]
    dest_geo = resolver.resolve_many(dest_ips) if dest_ips else {}
    for t in targets:
        ip = t.get("last_ip")
        t["geo"] = _geo_dict(dest_geo[ip]) if ip and ip in dest_geo else None

    # Pick the slowest reachable targets for traceroute (traceroute is the
    # expensive part, so we bound how many we run).
    traceable = sorted(
        (t for t in targets if t.get("last_ip") and _tool_available("traceroute")),
        key=lambda t: (t["total_p95"] if t["total_p95"] is not None else -1),
        reverse=True,
    )
    traces = []
    for t in traceable[: max(0, config.trace_targets)]:
        report = build_trace_report(t, resolver, config)
        if report:
            traces.append(report)

    return {
        "generated_at": utc_iso(),
        "elapsed_sec": round(time.time() - started, 1),
        "verdict": _overall_verdict(targets),
        "targets": targets,
        "traces": traces,
        "geo_online": config.online_geo,
    }


# --------------------------------------------------------------------------- #
# Streaming API
#
# ``stream_check`` yields event dicts as work completes so the web layer can
# push them to the browser over Server-Sent Events. Each site result appears
# as soon as its curl samples finish, and each traceroute hop — plus that
# hop's geolocation — is emitted the moment it is discovered, giving the UI a
# live, node-by-node view instead of one blocking payload at the end.
# --------------------------------------------------------------------------- #


def stream_traceroute(ip: str, config: EngineConfig):
    """Run traceroute and yield each parsed hop as its line is printed.

    Uses ``Popen`` with line buffering so hops surface in real time. ``rtk`` is
    intentionally bypassed here (it buffers/rewrites output, which would defeat
    streaming); the engine defaults to ``use_rtk=False`` anyway.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return
    if not _tool_available("traceroute"):
        return

    cmd = ["traceroute", "-n", "-m", str(config.trace_hops),
           "-q", str(PROBES_PER_HOP), "-w", "1", ip]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except OSError:
        return

    deadline = time.time() + max(20.0, config.trace_hops + 8)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            for hop in nm.parse_trace_hops(line):
                yield hop
            if time.time() > deadline:
                break
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def _stream_trace_target(target: Dict[str, Any], resolver: GeoResolver, config: EngineConfig):
    """Yield trace_start -> (hop, hop_geo)* -> trace_end for one target."""
    ip = target.get("last_ip")
    if not ip:
        return

    dest_geo = resolver.resolve(ip)  # usually a cache hit from the target phase
    yield {
        "event": "trace_start",
        "target": target["name"],
        "dest_ip": ip,
        "dest_geo": _geo_dict(dest_geo),
    }

    collected: List[Dict[str, Any]] = []
    for hop in stream_traceroute(ip, config):
        collected.append(hop)
        hop_ip = hop.get("ip")
        hop_view = _hop_view(hop, is_dest=(hop_ip == ip))
        yield {"event": "hop", "target": target["name"], "data": hop_view}

        # Resolve this node's geolocation immediately so the row fills in live.
        if hop_ip:
            geo = resolver.resolve(hop_ip)
            yield {
                "event": "hop_geo",
                "target": target["name"],
                "hop": hop["hop"],
                "ip": hop_ip,
                "geo": _geo_dict(geo),
            }

    # Build the end-of-trace summary from everything we saw. Reconstruct the
    # raw text from hop lines so we can reuse the vetted key-node picker.
    raw_output = "\n".join(h.get("raw") or "" for h in collected)
    key_nodes = nm.trace_key_nodes(raw_output)
    hop_ips = [h["ip"] for h in collected if h.get("ip")]
    geo_map = resolver.resolve_many(hop_ips) if hop_ips else {}

    annotated = []
    for hop in collected:
        hop_ip = hop.get("ip")
        view = _hop_view(hop, is_dest=(hop_ip == ip))
        view["geo"] = _geo_dict(geo_map[hop_ip]) if hop_ip and hop_ip in geo_map else None
        annotated.append(view)

    key_node_view = []
    for node in key_nodes:
        node_ip = node.get("ip")
        geo = geo_map.get(node_ip) if node_ip else None
        key_node_view.append({
            "role": _role_zh(node["role"]),
            "role_en": node["role"],
            "hop": node["hop"],
            "ip": node_ip,
            "median_ms": _hop_median_ms(node),
            "geo": _geo_dict(geo) if geo else None,
        })

    yield {
        "event": "trace_end",
        "target": target["name"],
        "analysis": _trace_analysis_zh(annotated),
        "key_nodes": key_node_view,
        "hops": annotated,
        "raw": raw_output,
    }


def stream_check(
    config: Optional[EngineConfig] = None,
    targets: Optional[List[nm.Target]] = None,
):
    """Full detection as a stream of events (see module note above)."""
    config = config or EngineConfig()
    target_list = targets if targets else list(DEFAULT_TARGETS)
    started = time.time()

    yield {
        "event": "start",
        "generated_at": utc_iso(),
        "geo_online": config.online_geo,
        "target_names": [t.name for t in target_list],
    }

    if not _tool_available("curl"):
        yield {"event": "error", "message": "本机未找到 curl，无法进行检测"}
        return

    resolver = GeoResolver(timeout=config.geo_timeout, online=config.online_geo)
    targets_done: List[Dict[str, Any]] = []

    # Measure targets concurrently; emit each the instant its samples finish.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(target_list)) as pool:
        future_to_target = {
            pool.submit(measure_target, t, config): t for t in target_list
        }
        for future in concurrent.futures.as_completed(future_to_target):
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - never let one target kill the stream
                bad = future_to_target[future]
                result = {
                    "name": bad.name, "url": bad.url, "ok": False,
                    "samples": 0, "failures": 0, "failure_rate": 1.0,
                    "total_median": None, "total_p95": None, "speed_median": None,
                    "last_ip": None, "phases": {}, "worst_phase": None,
                    "diagnosis": f"检测出错：{exc}", "geo": None,
                }
            ip = result.get("last_ip")
            result["geo"] = _geo_dict(resolver.resolve(ip)) if ip else None
            targets_done.append(result)
            yield {"event": "target", "data": result}

    yield {"event": "verdict", "verdict": _overall_verdict(targets_done)}

    # Traceroute the slowest reachable targets, streaming hops as they arrive.
    traceable = sorted(
        (t for t in targets_done if t.get("last_ip") and _tool_available("traceroute")),
        key=lambda t: (t["total_p95"] if t["total_p95"] is not None else -1),
        reverse=True,
    )
    for t in traceable[: max(0, config.trace_targets)]:
        yield from _stream_trace_target(t, resolver, config)

    yield {"event": "done", "elapsed_sec": round(time.time() - started, 1)}


# --------------------------------------------------------------------------- #
# On-demand single-target traceroute
#
# ``stream_trace_one`` powers the "expand a site to see its route" interaction:
# the browser asks for one specific target, we resolve its IP with a quick curl
# and then stream that target's hops exactly like the batch path does. Reusing
# ``_stream_trace_target`` keeps the event shape identical to ``stream_check``.
# --------------------------------------------------------------------------- #


def stream_trace_one(target: nm.Target, config: Optional[EngineConfig] = None):
    """Resolve one target's IP, then stream its traceroute hops.

    Emits the same trace_start -> (hop, hop_geo)* -> trace_end events as the
    batch flow, bracketed by its own ``done``. ``target`` is already validated
    by ``build_targets``; the IP handed to traceroute is one we resolve here,
    never a client-supplied host.
    """
    config = config or EngineConfig()
    started = time.time()

    if not _tool_available("traceroute"):
        yield {"event": "error", "message": "本机未找到 traceroute，无法追踪路由"}
        return
    if not _tool_available("curl"):
        yield {"event": "error", "message": "本机未找到 curl，无法解析目标地址"}
        return

    # One curl sample is enough just to learn the destination IP.
    probe = measure_target(target, EngineConfig(
        samples_per_target=1,
        curl_timeout=config.curl_timeout,
        ipv4_only=config.ipv4_only,
        use_rtk=config.use_rtk,
    ))
    ip = probe.get("last_ip")
    if not ip:
        yield {
            "event": "error",
            "message": f"无法解析「{target.name}」的地址，可能是域名解析失败或站点不可达",
        }
        return

    resolver = GeoResolver(timeout=config.geo_timeout, online=config.online_geo)
    trace_target = {"name": target.name, "url": target.url, "last_ip": ip}
    yield from _stream_trace_target(trace_target, resolver, config)
    yield {"event": "done", "elapsed_sec": round(time.time() - started, 1)}
