#!/usr/bin/env python3
"""Periodic network monitor with curl timing metrics and markdown reports."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import math
import pathlib
import shutil
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable


DEFAULT_TARGETS = [
    "baidu=https://www.baidu.com",
    "aliyun=https://www.aliyun.com",
    "tencent=https://cloud.tencent.com",
    "gitee=https://gitee.com",
    "mi-204=http://connect.rom.miui.com/generate_204",
]

CURL_FIELDS = [
    "http_code",
    "remote_ip",
    "time_namelookup",
    "time_connect",
    "time_appconnect",
    "time_starttransfer",
    "time_total",
    "speed_download",
    "size_download",
]


@dataclass(frozen=True)
class Target:
    name: str
    url: str


def utc_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def parse_targets(raw_targets: Iterable[str]) -> list[Target]:
    targets: list[Target] = []
    for raw in raw_targets:
        if "=" in raw:
            name, url = raw.split("=", 1)
        else:
            url = raw
            name = raw.removeprefix("https://").removeprefix("http://").split("/", 1)[0]
        name = name.strip()
        url = url.strip()
        if not name or not url:
            raise ValueError(f"invalid target: {raw!r}")
        targets.append(Target(name=name, url=url))
    return targets


def parse_curl_metrics(stdout: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line.startswith("METRIC "):
            continue
        key, value = line.removeprefix("METRIC ").split("=", 1)
        metrics[key] = value
    return metrics


def to_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def to_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def build_curl_writeout() -> str:
    return "".join(f"METRIC {field}=%{{{field}}}\\n" for field in CURL_FIELDS)


def tool_cmd(tool: str, use_rtk: bool) -> list[str]:
    if use_rtk and shutil.which("rtk"):
        return ["rtk", tool]
    return [tool]


def run_curl(target: Target, timeout: float, ipv4: bool, use_rtk: bool) -> dict[str, Any]:
    cmd = tool_cmd("curl", use_rtk) + [
        "--max-time",
        str(timeout),
        "-o",
        "/dev/null",
        "-sS",
        "-w",
        build_curl_writeout(),
    ]
    if ipv4:
        cmd.append("-4")
    cmd.append(target.url)

    started = time.time()
    record: dict[str, Any] = {
        "timestamp": utc_iso(),
        "epoch": started,
        "target": target.name,
        "url": target.url,
        "ok": False,
    }

    try:
        completed = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout + 5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        record.update({"return_code": None, "error": f"curl subprocess timeout: {exc}"})
        return record

    metrics = parse_curl_metrics(completed.stdout)
    http_code = to_int(metrics.get("http_code"))
    total = to_float(metrics.get("time_total"))
    record.update(
        {
            "return_code": completed.returncode,
            "http_code": http_code,
            "remote_ip": metrics.get("remote_ip") or None,
            "dns": to_float(metrics.get("time_namelookup")),
            "connect": to_float(metrics.get("time_connect")),
            "tls": to_float(metrics.get("time_appconnect")),
            "first_byte": to_float(metrics.get("time_starttransfer")),
            "total": total,
            "speed_download": to_float(metrics.get("speed_download")),
            "size_download": to_float(metrics.get("size_download")),
        }
    )
    record["ok"] = completed.returncode == 0 and bool(http_code) and http_code < 500
    if completed.returncode != 0:
        record["error"] = completed.stderr.strip() or f"curl exited {completed.returncode}"
    return record


def phase_durations(sample: dict[str, Any]) -> dict[str, float]:
    dns = float(sample.get("dns") or 0.0)
    connect = float(sample.get("connect") or 0.0)
    tls_abs = float(sample.get("tls") or 0.0)
    first = float(sample.get("first_byte") or 0.0)
    total = float(sample.get("total") or 0.0)
    handshake_end = tls_abs if tls_abs > 0 else connect
    return {
        "dns": max(dns, 0.0),
        "tcp": max(connect - dns, 0.0),
        "tls": max(tls_abs - connect, 0.0) if tls_abs > 0 else 0.0,
        "server": max(first - handshake_end, 0.0),
        "download": max(total - first, 0.0),
        "total": max(total, 0.0),
    }


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    rank = (len(ordered) - 1) * pct
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def fmt_seconds(value: float | None) -> str:
    if value is None:
        return "-"
    if value < 1:
        return f"{value * 1000:.0f}ms"
    return f"{value:.2f}s"


def fmt_rate(value: float | None) -> str:
    if value is None:
        return "-"
    if value < 1024:
        return f"{value:.0f} B/s"
    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB/s"
    return f"{value / (1024 * 1024):.1f} MB/s"


def summarize_target(samples: list[dict[str, Any]]) -> dict[str, Any]:
    ok_samples = [sample for sample in samples if sample.get("ok")]
    phases = [phase_durations(sample) for sample in ok_samples]
    totals = [phase["total"] for phase in phases if phase["total"] > 0]
    speeds = [
        float(sample["speed_download"])
        for sample in ok_samples
        if isinstance(sample.get("speed_download"), (int, float))
    ]
    phase_keys = ["dns", "tcp", "tls", "server", "download", "total"]
    phase_stats = {}
    for key in phase_keys:
        values = [phase[key] for phase in phases]
        phase_stats[key] = {
            "median": statistics.median(values) if values else None,
            "p95": percentile(values, 0.95),
        }
    return {
        "count": len(samples),
        "ok_count": len(ok_samples),
        "failure_count": len(samples) - len(ok_samples),
        "failure_rate": (len(samples) - len(ok_samples)) / len(samples) if samples else 0.0,
        "total_median": statistics.median(totals) if totals else None,
        "total_p95": percentile(totals, 0.95),
        "speed_median": statistics.median(speeds) if speeds else None,
        "phase_stats": phase_stats,
        "last_ip": next((sample.get("remote_ip") for sample in reversed(ok_samples) if sample.get("remote_ip")), None),
    }


def diagnose(summary: dict[str, Any]) -> str:
    if summary["count"] == 0:
        return "no samples"
    if summary["failure_rate"] >= 0.2:
        return "high failure rate; inspect DNS/path/firewall before latency"

    phase_stats = summary["phase_stats"]
    medians = {
        key: value["median"] or 0.0
        for key, value in phase_stats.items()
        if key != "total"
    }
    if not medians:
        return "no successful timing samples"
    worst_phase, worst_value = max(medians.items(), key=lambda item: item[1])
    if worst_value < 0.2 and (summary["total_median"] or 0.0) < 0.8:
        return "healthy in current samples"
    labels = {
        "dns": "DNS resolution",
        "tcp": "TCP connect / route path",
        "tls": "TLS handshake / proxy / packet loss",
        "server": "server response before first byte",
        "download": "body download / throughput",
    }
    return f"dominant delay: {labels.get(worst_phase, worst_phase)}"


def load_samples(path: pathlib.Path) -> list[dict[str, Any]]:
    samples = []
    if not path.exists():
        return samples
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record_type") == "trace":
            continue
        samples.append(record)
    return samples


def load_trace_sections(path: pathlib.Path) -> list[str]:
    sections: list[str] = []
    if not path.exists():
        return sections
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("record_type") == "trace":
            sections.extend(record.get("sections") or [])
    return sections


def run_command(cmd: list[str], timeout: float) -> str:
    try:
        completed = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"$ {' '.join(cmd)}\nERROR: {exc}"
    output = completed.stdout.strip() or completed.stderr.strip()
    return f"$ {' '.join(cmd)}\n{output}".rstrip()


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def parse_trace_hops(trace_output: str) -> list[dict[str, Any]]:
    hops = []
    for line in trace_output.splitlines():
        stripped = line.strip()
        if not stripped or not stripped[0].isdigit():
            continue
        parts = stripped.split()
        try:
            hop_no = int(parts[0])
        except ValueError:
            continue
        ip = None
        for part in parts[1:]:
            candidate = part.strip("()")
            try:
                ipaddress.ip_address(candidate)
                ip = candidate
                break
            except ValueError:
                continue
        latencies = []
        for index, part in enumerate(parts):
            if part == "ms" and index > 0:
                value = to_float(parts[index - 1])
                if value is not None:
                    latencies.append(value)
        hops.append({"hop": hop_no, "ip": ip, "latencies_ms": latencies, "raw": stripped})
    return hops


def parse_route_gateway(route_output: str) -> str | None:
    for line in route_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            return stripped.split(":", 1)[1].strip() or None
    return None


def median_latency_ms(hop: dict[str, Any]) -> float | None:
    latencies = hop.get("latencies_ms") or []
    return statistics.median(latencies) if latencies else None


def find_sustained_latency_start(visible_hops: list[dict[str, Any]]) -> dict[str, Any] | None:
    high_hops = [
        hop
        for hop in visible_hops
        if (median_latency_ms(hop) or 0.0) >= 100
    ]
    for hop in high_hops:
        later = [item for item in visible_hops if item["hop"] > hop["hop"]]
        if len(later) >= 2 and all((median_latency_ms(item) or 0.0) >= 80 for item in later):
            return hop
    return None


def trace_key_nodes(trace_output: str) -> list[dict[str, Any]]:
    hops = parse_trace_hops(trace_output)
    visible = [hop for hop in hops if hop["ip"] and hop["latencies_ms"]]
    if not visible:
        return []

    nodes: list[dict[str, Any]] = []
    private_hops = [hop for hop in visible if is_private_ip(hop["ip"])]
    for hop in private_hops:
        nodes.append({"role": "private gateway", **hop})

    first_public = next((hop for hop in visible if not is_private_ip(hop["ip"])), None)
    if first_public:
        nodes.append({"role": "first public hop", **first_public})

    highest = max(visible, key=lambda hop: median_latency_ms(hop) or -1)
    if (median_latency_ms(highest) or 0.0) >= 80:
        nodes.append({"role": "highest visible latency", **highest})

    sustained = find_sustained_latency_start(visible)
    if sustained:
        nodes.append({"role": "sustained latency candidate", **sustained})

    last_visible = visible[-1]
    nodes.append({"role": "last visible hop", **last_visible})

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for node in nodes:
        key = (node["role"], node["hop"], node["ip"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(node)
    return deduped


def render_key_nodes_table(trace_output: str) -> str:
    nodes = trace_key_nodes(trace_output)
    if not nodes:
        return "No responsive key nodes."
    lines = [
        "| Role | Hop | IP | Median latency |",
        "| --- | ---: | --- | ---: |",
    ]
    for node in nodes:
        lines.append(
            "| {role} | {hop} | {ip} | {latency} |".format(
                role=node["role"],
                hop=node["hop"],
                ip=node["ip"],
                latency=fmt_seconds((median_latency_ms(node) or 0.0) / 1000),
            )
        )
    return "\n".join(lines)


def analyze_trace(trace_output: str) -> str:
    hops = parse_trace_hops(trace_output)
    visible = [hop for hop in hops if hop["ip"] and hop["latencies_ms"]]
    if not visible:
        return "no responsive hops; trace is not enough to locate a node"

    private_hops = [hop for hop in visible if is_private_ip(hop["ip"])]
    sustained = find_sustained_latency_start(visible)

    notes = []
    if private_hops:
        notes.append(
            "private gateway path: "
            + " -> ".join(f"{hop['hop']}:{hop['ip']}" for hop in private_hops)
        )
    if sustained:
        notes.append(f"candidate sustained latency starts near hop {sustained['hop']} ({sustained['ip']})")
    else:
        notes.append("no sustained latency jump in responsive hops")
    return "; ".join(notes)


def render_report(samples: list[dict[str, Any]], trace_sections: list[str]) -> str:
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        by_target[str(sample.get("target", "unknown"))].append(sample)

    generated_at = utc_iso()
    lines = [
        "# Network Monitor Report",
        "",
        f"- Generated: `{generated_at}`",
        f"- Samples: `{len(samples)}`",
        "",
        "## Summary",
        "",
        "| Target | Samples | Failures | Median total | P95 total | Median speed | Last IP | Diagnosis |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]

    summaries: dict[str, dict[str, Any]] = {}
    for target_name in sorted(by_target):
        summary = summarize_target(by_target[target_name])
        summaries[target_name] = summary
        lines.append(
            "| {name} | {count} | {failures} | {median} | {p95} | {speed} | {ip} | {diag} |".format(
                name=target_name,
                count=summary["count"],
                failures=summary["failure_count"],
                median=fmt_seconds(summary["total_median"]),
                p95=fmt_seconds(summary["total_p95"]),
                speed=fmt_rate(summary["speed_median"]),
                ip=summary["last_ip"] or "-",
                diag=diagnose(summary),
            )
        )

    lines.extend(["", "## Phase Breakdown", ""])
    for target_name in sorted(summaries):
        lines.extend([f"### {target_name}", ""])
        lines.append("| Phase | Median | P95 |")
        lines.append("| --- | ---: | ---: |")
        for phase in ["dns", "tcp", "tls", "server", "download", "total"]:
            stats = summaries[target_name]["phase_stats"][phase]
            lines.append(
                f"| {phase} | {fmt_seconds(stats['median'])} | {fmt_seconds(stats['p95'])} |"
            )
        lines.append("")

    if trace_sections:
        lines.extend(["## Route / Trace Evidence", ""])
        for section in trace_sections:
            lines.append(section)
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_jsonl(path: pathlib.Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_trace_snapshot(path: pathlib.Path, sections: list[str]) -> None:
    if not sections:
        return
    write_jsonl(
        path,
        {
            "record_type": "trace",
            "timestamp": utc_iso(),
            "sections": sections,
        },
    )


def collect_trace_sections(samples: list[dict[str, Any]], trace: bool, hops: int, use_rtk: bool) -> list[str]:
    if not trace:
        return []
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        by_target[str(sample.get("target", "unknown"))].append(sample)
    summaries = {name: summarize_target(items) for name, items in by_target.items()}
    ranked = sorted(
        summaries.items(),
        key=lambda item: item[1]["total_p95"] if item[1]["total_p95"] is not None else -1,
        reverse=True,
    )
    sections = []
    for target_name, summary in ranked[:2]:
        ip = summary.get("last_ip")
        if not ip:
            continue
        route = run_command(tool_cmd("route", use_rtk) + ["-n", "get", str(ip)], timeout=5)
        gateway = parse_route_gateway(route)
        gateway_trace = ""
        if gateway:
            gateway_trace = run_command(
                tool_cmd("traceroute", use_rtk) + ["-m", "5", "-q", "3", "-w", "1", gateway],
                timeout=10,
            )
        trace_output = run_command(
            tool_cmd("traceroute", use_rtk) + ["-m", str(hops), "-q", "1", "-w", "1", str(ip)],
            timeout=max(10, hops + 5),
        )
        gateway_lines = []
        if gateway:
            gateway_lines = [
                f"- Gateway: `{gateway}`",
                f"- Gateway trace analysis: {analyze_trace(gateway_trace)}",
                "",
                "#### Gateway trace",
                "",
                "```text",
                gateway_trace,
                "```",
                "",
            ]
        sections.append(
            "\n".join(
                [
                    f"### {target_name} ({ip})",
                    "",
                    f"- Trace analysis: {analyze_trace(trace_output)}",
                    "",
                    "#### Path key nodes",
                    "",
                    render_key_nodes_table(trace_output),
                    "",
                    *gateway_lines,
                    "#### Route and target trace",
                    "",
                    "```text",
                    route,
                    "",
                    trace_output,
                    "```",
                ]
            )
        )
    return sections


def monitor(args: argparse.Namespace) -> int:
    targets = parse_targets(args.target or DEFAULT_TARGETS)
    use_rtk = not args.no_rtk
    output = pathlib.Path(args.output)
    report = pathlib.Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)

    if args.report_only:
        samples = load_samples(output)
        trace_sections = load_trace_sections(output)
        trace_sections.extend(collect_trace_sections(samples, trace=not args.no_trace, hops=args.trace_hops, use_rtk=use_rtk))
        report.write_text(render_report(samples, trace_sections), encoding="utf-8")
        print(f"loaded samples: {len(samples)}")
        print(f"wrote report: {report}")
        return 0

    stop_at = time.time() + args.duration if args.duration else None
    print(f"writing samples to {output}")
    print(f"report will be written to {report}")
    print("press Ctrl-C to stop and generate the report")
    if args.no_trace:
        print("route/traceroute collection is disabled")
    elif args.trace_every:
        print(f"route/traceroute snapshot will run every {args.trace_every} round(s)")
    else:
        print("route/traceroute will run only when the final report is generated")

    round_count = 0
    try:
        while True:
            round_started = time.time()
            for target in targets:
                sample = run_curl(target, timeout=args.timeout, ipv4=not args.ipv6, use_rtk=use_rtk)
                write_jsonl(output, sample)
                total = fmt_seconds(sample.get("total") if isinstance(sample.get("total"), float) else None)
                status = "ok" if sample.get("ok") else "fail"
                print(f"{sample['timestamp']} {target.name} {status} total={total} ip={sample.get('remote_ip') or '-'}")
            round_count += 1
            if not args.no_trace and args.trace_every and round_count % args.trace_every == 0:
                print("collecting route/traceroute snapshot...")
                snapshot_sections = collect_trace_sections(
                    load_samples(output),
                    trace=True,
                    hops=args.trace_hops,
                    use_rtk=use_rtk,
                )
                write_trace_snapshot(output, snapshot_sections)
                if snapshot_sections:
                    print(f"stored {len(snapshot_sections)} trace section(s)")
                else:
                    print("no trace snapshot stored; no successful remote_ip samples yet")
            if stop_at and time.time() >= stop_at:
                break
            sleep_for = max(0.0, args.interval - (time.time() - round_started))
            if stop_at:
                sleep_for = min(sleep_for, max(0.0, stop_at - time.time()))
            if sleep_for <= 0:
                continue
            time.sleep(sleep_for)
    except KeyboardInterrupt:
        print("\nreceived Ctrl-C; generating report")

    samples = load_samples(output)
    trace_sections = load_trace_sections(output)
    trace_sections.extend(collect_trace_sections(samples, trace=not args.no_trace, hops=args.trace_hops, use_rtk=use_rtk))
    report.write_text(render_report(samples, trace_sections), encoding="utf-8")
    print(f"wrote report: {report}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Monitor network timing and generate a markdown report.")
    parser.add_argument("--target", action="append", help="Target as name=url. Repeatable.")
    parser.add_argument("--interval", type=float, default=60.0, help="Seconds between rounds.")
    parser.add_argument("--duration", type=float, default=300.0, help="Total monitor duration in seconds. Use 0 for until Ctrl-C.")
    parser.add_argument("--timeout", type=float, default=20.0, help="curl max-time per target.")
    parser.add_argument("--output", default="network-samples.jsonl", help="JSONL sample output path.")
    parser.add_argument("--report", default="network-report.md", help="Markdown report output path.")
    parser.add_argument("--report-only", action="store_true", help="Generate a report from an existing JSONL file without monitoring.")
    parser.add_argument("--ipv6", action="store_true", help="Do not force IPv4.")
    parser.add_argument("--no-rtk", action="store_true", help="Call curl/route/traceroute directly instead of through rtk.")
    parser.add_argument("--no-trace", action="store_true", help="Skip route/traceroute evidence in the final report.")
    parser.add_argument("--trace-every", type=int, default=1, help="Collect route/traceroute snapshots every N rounds. Use 0 for final report only.")
    parser.add_argument("--trace-hops", type=int, default=15, help="Max traceroute hops for the final report.")
    args = parser.parse_args(argv)
    if args.duration == 0:
        args.duration = None
    if args.interval <= 0:
        parser.error("--interval must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.trace_every < 0:
        parser.error("--trace-every must be zero or positive")
    return monitor(args)


if __name__ == "__main__":
    raise SystemExit(main())
