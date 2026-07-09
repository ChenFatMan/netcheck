#!/usr/bin/env python3
"""IP geolocation lookup: online (ip-api batch) first, offline fallback.

Design goals:
- Zero third-party dependencies (uses urllib from the stdlib).
- Compatible with the system Python 3.9 interpreter.
- Never raise to the caller: any network/parse failure degrades to an
  "unknown" record so the detection flow keeps working offline.
- Cache results per-process to avoid re-querying the same hop IP.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


# Baidu Qifu IP-portrait endpoint (primary). Single-IP GET, Chinese fields,
# richer scene info (IDC/机房/宽带…) but no ASN. It is an unofficial endpoint
# guarded by a Referer check, so a browser-like Referer + UA are required or it
# answers 403. Treated as best-effort: any failure falls back to ip-api.
BAIDU_GEO_URL = "https://qifu.baidu.com/api/v1/ip-portrait/brief-info?ip="

# The endpoint 403s without a Referer from its own origin; a UA is also sent so
# it looks like a normal XHR from the site.
BAIDU_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Referer": "https://qifu.baidu.com/",
    "Accept": "application/json, text/plain, */*",
}

# How many Baidu single-IP lookups to run at once (one route can have ~15 hops;
# serial lookups would stall the stream). Bounded so a burst can't hammer the
# endpoint or exhaust threads.
BAIDU_MAX_CONCURRENCY = 6

# ip-api free endpoint: batch, no API key, HTTP only, rate-limited to
# ~45 requests/minute per source IP. Used as the fallback provider. We request
# Chinese localized fields.
IP_API_BATCH_URL = "http://ip-api.com/batch?lang=zh-CN"

# Fields requested from ip-api. Keep this stable so parsing is predictable.
IP_API_FIELDS = "status,message,query,country,regionName,city,isp,org,as"

# Bound the batch size to stay well under the endpoint's 100-item limit.
MAX_BATCH_SIZE = 100

DEFAULT_TIMEOUT = 6.0

# Geo provider strategies.
PROVIDER_AUTO = "auto"  # Baidu first, ip-api for whatever Baidu couldn't resolve
PROVIDER_BAIDU = "baidu"  # Baidu only
PROVIDER_IPAPI = "ipapi"  # ip-api only


@dataclass(frozen=True)
class GeoInfo:
    """Normalized geolocation record for a single IP address."""

    ip: str
    scope: str  # "public" | "private" | "reserved" | "invalid"
    ok: bool = False
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    source: str = "unknown"  # "online" | "offline" | "cache" | "local"
    note: Optional[str] = None

    def location_label(self) -> str:
        """Human-friendly location string, e.g. '中国 北京市 北京'."""
        parts = [part for part in (self.country, self.region, self.city) if part]
        # Collapse duplicate adjacent parts (region == city happens for
        # municipalities like 北京 / 上海).
        deduped: List[str] = []
        for part in parts:
            if not deduped or deduped[-1] != part:
                deduped.append(part)
        if deduped:
            return " ".join(deduped)
        if self.scope == "private":
            return "内网地址"
        if self.scope == "reserved":
            return "保留地址"
        return "归属地未知"

    def carrier_label(self) -> str:
        """Best-effort ISP/operator label."""
        return self.isp or self.org or "-"


def classify_ip(ip: str) -> str:
    """Classify an IP into public/private/reserved/invalid."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_private or addr.is_link_local:
        return "private"
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return "reserved"
    return "public"


def _local_geo(ip: str, scope: str) -> GeoInfo:
    """Build a record for IPs we resolve locally without any network call."""
    notes = {
        "private": "内网/局域网地址，无公网归属地",
        "reserved": "保留或特殊用途地址",
        "invalid": "非法 IP",
    }
    return GeoInfo(ip=ip, scope=scope, ok=False, source="local", note=notes.get(scope))


def _parse_batch_item(item: Dict[str, object], ip: str, scope: str) -> GeoInfo:
    """Turn one ip-api batch response element into a GeoInfo record."""
    status = str(item.get("status") or "")
    if status != "success":
        message = item.get("message")
        return GeoInfo(
            ip=ip,
            scope=scope,
            ok=False,
            source="online",
            note=str(message) if message else "在线查询无结果",
        )

    def _clean(key: str) -> Optional[str]:
        value = item.get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    return GeoInfo(
        ip=ip,
        scope=scope,
        ok=True,
        country=_clean("country"),
        region=_clean("regionName"),
        city=_clean("city"),
        isp=_clean("isp"),
        org=_clean("org"),
        asn=_clean("as"),
        source="online",
    )


def _parse_baidu_item(item: Dict[str, object], ip: str, scope: str) -> GeoInfo:
    """Turn Baidu's ``data`` object into a GeoInfo record.

    Baidu returns country/province/city/isp plus a ``scene`` tag (IDC / 宽带 /
    机房…) but no ASN. The scene is folded into ``note`` since it is useful
    context (a hop in an IDC vs a broadband access network) without a column of
    its own. An empty/None field is normalized to None.
    """

    def _clean(key: str) -> Optional[str]:
        value = item.get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    country = _clean("country")
    province = _clean("province")
    city = _clean("city")
    isp = _clean("isp")
    company = _clean("company")
    scene = _clean("scene")

    # Nothing usable came back — treat as an unresolved online result so the
    # caller can fall back to ip-api.
    if not any((country, province, city, isp)):
        return GeoInfo(ip=ip, scope=scope, ok=False, source="online", note="百度无结果")

    return GeoInfo(
        ip=ip,
        scope=scope,
        ok=True,
        country=country,
        region=province,
        city=city,
        isp=isp,
        org=company,
        asn=None,  # Baidu does not expose ASN
        source="online",
        note=f"场景：{scene}" if scene else None,
    )


def _query_baidu_one(ip: str, timeout: float) -> GeoInfo:
    """Look up one public IP via Baidu. Never raises: any failure yields an
    unresolved (ok=False) record so the caller can fall back to ip-api."""
    url = BAIDU_GEO_URL + urllib.parse.quote(ip, safe="")
    request = urllib.request.Request(url, headers=BAIDU_HEADERS, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
        payload = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return GeoInfo(ip=ip, scope="public", ok=False, source="offline",
                       note=f"百度查询失败：{exc}")

    if not isinstance(payload, dict) or payload.get("code") != 200:
        message = payload.get("message") if isinstance(payload, dict) else "响应异常"
        return GeoInfo(ip=ip, scope="public", ok=False, source="online",
                       note=f"百度查询无结果：{message}")

    data = payload.get("data")
    if not isinstance(data, dict):
        return GeoInfo(ip=ip, scope="public", ok=False, source="online",
                       note="百度响应缺少 data")
    return _parse_baidu_item(data, ip, "public")


@dataclass
class GeoResolver:
    """Resolves IPs to geolocation with an in-memory cache.

    Public IPs are resolved online: Baidu first (concurrent single-IP lookups),
    then ip-api (batched) for whatever Baidu couldn't resolve. Private/reserved/
    invalid IPs never hit the network. Any failure falls back to an 'unknown'
    public record so callers always get a GeoInfo for every requested IP.
    """

    timeout: float = DEFAULT_TIMEOUT
    online: bool = True
    provider: str = PROVIDER_AUTO  # see PROVIDER_* constants
    _cache: Dict[str, GeoInfo] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def resolve_many(self, ips: Iterable[str]) -> Dict[str, GeoInfo]:
        """Resolve a collection of IPs, returning a map keyed by IP string."""
        # Deduplicate while preserving determinism.
        unique_ips: List[str] = []
        seen = set()
        for ip in ips:
            if ip and ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        result: Dict[str, GeoInfo] = {}
        to_query: List[str] = []

        for ip in unique_ips:
            scope = classify_ip(ip)
            if scope != "public":
                result[ip] = _local_geo(ip, scope)
                continue
            with self._lock:
                cached = self._cache.get(ip)
            if cached is not None:
                # Return cached info but mark the delivery source as cache.
                result[ip] = GeoInfo(
                    **{**cached.__dict__, "source": "cache"}
                ) if cached.source != "cache" else cached
            elif self.online:
                to_query.append(ip)
            else:
                result[ip] = self._offline_unknown(ip, scope)

        if to_query:
            fetched = self._query_online(to_query)
            for ip in to_query:
                info = fetched.get(ip) or self._offline_unknown(ip, "public")
                if info.ok:
                    with self._lock:
                        self._cache[ip] = info
                result[ip] = info

        return result

    def resolve(self, ip: str) -> GeoInfo:
        """Resolve a single IP."""
        return self.resolve_many([ip])[ip]

    def _offline_unknown(self, ip: str, scope: str) -> GeoInfo:
        return GeoInfo(
            ip=ip,
            scope=scope,
            ok=False,
            source="offline",
            note="离线或在线查询不可用",
        )

    def _query_online(self, ips: List[str]) -> Dict[str, GeoInfo]:
        """Resolve public IPs online per the configured provider strategy.

        ``auto`` (default): try Baidu first (concurrent single-IP lookups), then
        send only the IPs Baidu couldn't resolve to ip-api's batch endpoint.
        This keeps Baidu's richer Chinese labels as the primary source while
        ip-api backstops its gaps and rate limits.
        """
        if self.provider == PROVIDER_IPAPI:
            return self._query_ipapi(ips)
        if self.provider == PROVIDER_BAIDU:
            return self._query_baidu(ips)

        # AUTO: Baidu first, ip-api for the remainder.
        results = self._query_baidu(ips)
        unresolved = [ip for ip in ips if not results.get(ip, GeoInfo(ip, "public")).ok]
        if unresolved:
            for ip, info in self._query_ipapi(unresolved).items():
                # Only overwrite with an ip-api hit; keep Baidu's note otherwise.
                if info.ok or not results.get(ip):
                    results[ip] = info
        return results

    def _query_baidu(self, ips: List[str]) -> Dict[str, GeoInfo]:
        """Look up IPs via Baidu concurrently (one GET each). Never raises."""
        results: Dict[str, GeoInfo] = {}
        if not ips:
            return results
        workers = min(BAIDU_MAX_CONCURRENCY, len(ips))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_ip = {
                pool.submit(_query_baidu_one, ip, self.timeout): ip for ip in ips
            }
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                except Exception as exc:  # noqa: BLE001 - degrade, never crash
                    results[ip] = GeoInfo(
                        ip=ip, scope="public", ok=False, source="offline",
                        note=f"百度查询异常：{exc}",
                    )
        return results

    def _query_ipapi(self, ips: List[str]) -> Dict[str, GeoInfo]:
        """Query ip-api in batches. Failures degrade to offline-unknown."""
        results: Dict[str, GeoInfo] = {}
        for start in range(0, len(ips), MAX_BATCH_SIZE):
            chunk = ips[start : start + MAX_BATCH_SIZE]
            chunk_result = self._query_batch(chunk)
            results.update(chunk_result)
        return results

    def _query_batch(self, chunk: List[str]) -> Dict[str, GeoInfo]:
        payload = [{"query": ip, "fields": IP_API_FIELDS} for ip in chunk]
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            IP_API_BATCH_URL,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
            items = json.loads(raw)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            # Whole-batch failure: mark everything offline-unknown.
            return {ip: self._batch_error(ip, exc) for ip in chunk}

        if not isinstance(items, list):
            return {ip: self._batch_error(ip, "unexpected response shape") for ip in chunk}

        parsed: Dict[str, GeoInfo] = {}
        for ip, item in zip(chunk, items):
            if isinstance(item, dict):
                # ip-api echoes the query back; trust our own ordering as the key.
                parsed[ip] = _parse_batch_item(item, ip, "public")
            else:
                parsed[ip] = self._batch_error(ip, "malformed batch element")
        return parsed

    def _batch_error(self, ip: str, exc: object) -> GeoInfo:
        return GeoInfo(
            ip=ip,
            scope="public",
            ok=False,
            source="offline",
            note=f"在线查询失败：{exc}",
        )
