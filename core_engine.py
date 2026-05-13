#!/usr/bin/env python3
"""
Crimson Core Engine v2.0
Authorized adversary-emulation web/service scanner.
USE ONLY against targets covered by a signed, written Rules of
Engagement (RoE). The --roe-confirmed flag is REQUIRED at every
invocation and its value is logged to the audit trail.
What this engine does:
  - Resolves IPv4 and IPv6 targets.
  - Scans TCP ports (async-connect default, optional SYN with Scapy).
  - Detects services via lightweight protocol probes.
  - Auto-detects HTTP vs HTTPS regardless of port.
  - Passive WAF/header fingerprinting.
  - Checks a fixed list of sensitive web paths.
  - Queries NVD CVEs with caching and bounded concurrency.
  - Multi-egress routing: direct, Tor-only, or Tor+dedicated proxies.
  - Adaptive pacing with jitter and ban-aware backoff.
  - Multi-signal ban detection (status, body pattern, RST rate,
    response-time anomalies, response-size anomalies).
  - Optional JA3/TLS fingerprint spoofing via curl_cffi.
  - Decoy traffic injection from passive recon + fallback list.
  - Checkpoint/resume.
  - Dual audit log (text + JSONL).
  - Executive-summary Markdown report.
Hukuki uyarı:
Bu araç YALNIZCA yazılı izninizin olduğu sistemlere karşı kullanılabilir.
İzinsiz tarama TCK 243-244 kapsamında suçtur.
"""
from __future__ import annotations
import argparse
import asyncio
import csv
import ctypes
import dataclasses
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import statistics
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from importlib.util import find_spec
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
# --------------------------------------------------------------------------
# Optional dependencies — gracefully degraded
# --------------------------------------------------------------------------
try:
    import aiohttp
except ImportError as exc:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_IMPORT_ERROR = exc
else:
    AIOHTTP_IMPORT_ERROR = None
try:
    import httpx
except ImportError as exc:
    httpx = None  # type: ignore[assignment]
    HTTPX_IMPORT_ERROR = exc
else:
    HTTPX_IMPORT_ERROR = None
try:
    from aiohttp_socks import ProxyConnector
except ImportError as exc:
    ProxyConnector = None  # type: ignore[assignment]
    AIOHTTP_SOCKS_IMPORT_ERROR = exc
else:
    AIOHTTP_SOCKS_IMPORT_ERROR = None
try:
    from asyncio_throttle import Throttler
except ImportError as exc:
    Throttler = None  # type: ignore[assignment]
    THROTTLE_IMPORT_ERROR = exc
else:
    THROTTLE_IMPORT_ERROR = None
try:
    import yaml as _yaml  # type: ignore[import]
except ImportError:
    _yaml = None  # type: ignore[assignment]
try:
    from curl_cffi.requests import AsyncSession as _CurlCffiAsyncSession  # type: ignore[import]
    CURL_CFFI_AVAILABLE = True
except ImportError:
    _CurlCffiAsyncSession = None  # type: ignore[assignment]
    CURL_CFFI_AVAILABLE = False
try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLACK_EX = RESET_ALL = BRIGHT = ""
    Fore = Style = _NoColor()  # type: ignore[assignment]
    def colorama_init(*_args, **_kwargs):
        return None
# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
APP_NAME = "Crimson"
APP_VERSION = "2.0.0"
REPORT_PREFIX = "crimson"
LOG_FILE_TEXT = "crimson_audit.log"
LOG_FILE_JSONL = "crimson_audit.jsonl"
LOG_MAX_BYTES = 2_000_000
LOG_BACKUP_COUNT = 5
DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_BANNER_TIMEOUT = 3.0
DEFAULT_PORT_CONCURRENCY = 500
DEFAULT_SERVICE_CONCURRENCY = 50
DEFAULT_UDP_TIMEOUT = 2.0
MAX_HTTP_READ_BYTES = 8192
MAX_BANNER_READ_BYTES = 1024
MIN_PRINTABLE_RATIO = 0.7
TCP_SYN_ACK_FLAGS = 0x12
MAX_CVE_DESCRIPTION_LENGTH = 500
MAX_CVE_RESULTS_PER_QUERY = 3
NVD_FREE_RATE_LIMIT = 90
NVD_API_KEY_RATE_LIMIT = 2000
NVD_RATE_PERIOD_SECONDS = 300
UDP_SCAN_PORTS = (53, 161, 1900)
DEFAULT_WEB_REQUEST_DELAY = 3.0
DEFAULT_WEB_SENSITIVE_DELAY = 5.0
DEFAULT_WEB_MAX_GLOBAL_RATE = 20
DEFAULT_WEB_STOP_STATUSES = frozenset({403, 429, 503})
DEFAULT_TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_TOR_CONTROL_HOST = "127.0.0.1"
DEFAULT_TOR_CONTROL_PORT = 9051
DEFAULT_TOR_NEW_IDENTITY_WAIT = 10.0
HTTP_PROXY_SCHEMES = frozenset({"http", "https"})
SOCKS_PROXY_SCHEMES = frozenset({"socks4", "socks4a", "socks5", "socks5h"})
SUPPORTED_PROXY_SCHEMES = HTTP_PROXY_SCHEMES | SOCKS_PROXY_SCHEMES
DEFAULT_BAN_COOLDOWN_SECONDS = 900
DEFAULT_BAN_SOFT_THRESHOLD = 3
DEFAULT_BAN_COOLDOWN_MULTIPLIER = 2.0
DEFAULT_BAN_COOLDOWN_MAX = 7200
JITTER_LOW = 0.7
JITTER_HIGH = 1.5
PACING_BASELINE_WINDOW = 10
PACING_SLOWDOWN_THRESHOLD = 1.5
DEFAULT_DECOY_RATE = 0.0
DECOY_FALLBACK_PATHS = (
    "/", "/hakkimizda", "/iletisim", "/duyurular", "/haberler",
    "/etkinlikler", "/belediye-meclisi", "/baskan", "/hizmetler", "/robots.txt",
)
RECON_MAX_LINKS = 30
RECON_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
)
BLOCK_BODY_PATTERNS = (
    r"\bcaptcha\b",
    r"\baccess denied\b",
    r"\brequest blocked\b",
    r"\bblocked by\b",
    r"\bweb application firewall\b",
    r"\bcloudflare ray id\b",
    r"\bincapsula\b",
    r"\bsucuri\b",
    r"\bakamai bot manager\b",
)
_BLOCK_BODY_RE = re.compile("|".join(BLOCK_BODY_PATTERNS), re.IGNORECASE)
SENSITIVE_ENDPOINT_KEYWORDS = (
    "login", "signin", "auth", "oauth", "account", "payment",
    "checkout", "pay", "form", "contact", "admin",
)
SENSITIVE_PATHS = (
    "/.env", "/.git/config", "/.git/HEAD", "/robots.txt",
    "/server-status", "/server-info", "/admin", "/wp-config.php",
    "/config.php", "/.htpasswd", "/api/swagger.json",
    "/actuator/health", "/.DS_Store", "/phpinfo.php",
)
GENERIC_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
)
# curl_cffi fingerprint profile names
FINGERPRINT_PROFILES = {
    "chrome120": "chrome120",
    "chrome119": "chrome119",
    "firefox120": "firefox120",
    "safari17": "safari17_0",
}
WEB_PORT_HINTS = frozenset({
    80, 81, 82, 83, 84, 85, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8180, 8181, 8443, 8834, 9000, 9090,
    9443, 10000,
})
TLS_PORT_HINTS = frozenset({
    443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 995, 8443, 8834, 9443,
})
UDP_PROBES: dict[int, bytes] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
}
UDP_SERVICE_HINTS = {53: "dns", 161: "snmp", 1900: "ssdp"}
LOW_CONFIDENCE_PORT_HINTS: dict[int, tuple[str, str]] = {
    9929: ("nping-echo", "Nping Echo service (port heuristic)"),
    31337: ("elite", "Port-based heuristic on 31337/tcp"),
}
CPE_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "open ssh": ("openbsd", "openssh"),
    "microsoft-iis": ("microsoft", "iis"),
    "microsoft iis": ("microsoft", "iis"),
    "iis": ("microsoft", "iis"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
}
DEFAULT_STATE_DIR = "~/.crimson/state"
ROE_REF_PATTERN = re.compile(r"^[A-Za-z0-9._\-:/]{4,128}$")
# Curated top ports — duplicates removed via set()
_RAW_TOP_PORTS = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
    37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163,
    179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 395, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
    464, 465, 475, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544,
    545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648,
    666, 667, 668, 683, 687, 691, 700, 705, 709, 711, 714, 720, 722, 726,
    727, 730, 731, 740, 749, 765, 783, 787, 800, 801, 808, 843, 873, 880,
    888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    999, 1000, 1024, 1025, 1080, 1110, 1234, 1311, 1433, 1434, 1521,
    1604, 1701, 1720, 1723, 1755, 1812, 1900, 2000, 2049, 2082, 2083,
    2086, 2087, 2095, 2096, 2222, 2375, 2376, 2483, 2484, 2638, 3128,
    3260, 3268, 3269, 3306, 3389, 3478, 3690, 3724, 4040, 4369, 4443,
    4444, 4500, 4567, 4789, 4848, 5000, 5001, 5005, 5060, 5061, 5222,
    5269, 5353, 5432, 5555, 5601, 5631, 5666, 5672, 5800, 5900, 5984,
    5985, 5986, 6000, 6379, 6443, 6660, 6661, 6662, 6663, 6664, 6665,
    6666, 6667, 6668, 6669, 6697, 7000, 7001, 7002, 7077, 7474, 7547,
    7777, 8000, 8001, 8008, 8009, 8010, 8025, 8080, 8081, 8086, 8088,
    8089, 8090, 8125, 8161, 8181, 8333, 8443, 8500, 8530, 8531, 8649,
    8834, 8880, 8888, 9000, 9001, 9042, 9043, 9080, 9090, 9091, 9092,
    9100, 9200, 9300, 9418, 9443, 9999, 10000, 10001, 10250, 10255,
    11211, 15672, 16379, 25565, 27017, 27018, 27019, 28015, 31337,
    32400, 32768, 49152, 50000, 50070, 54321, 60000, 61613, 61614,
]
TOP_PORTS = sorted(set(_RAW_TOP_PORTS))
# --------------------------------------------------------------------------
# Audit logging — text + JSONL
# --------------------------------------------------------------------------
_JSONL_LOCK = threading.Lock()
_JSONL_PATH: Path | None = None
def setup_logging(output_dir: Path | str = ".") -> None:
    """Configure text logger and bind JSONL path. Idempotent."""
    global _JSONL_PATH
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    text_path = (out / LOG_FILE_TEXT).resolve()
    jsonl_path = (out / LOG_FILE_JSONL).resolve()
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if getattr(handler, "baseFilename", None) == str(text_path):
            _JSONL_PATH = jsonl_path
            return
    handler = RotatingFileHandler(
        str(text_path),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s"))
    logger.addHandler(handler)
    _JSONL_PATH = jsonl_path
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
def audit_event(event: str, **fields: Any) -> None:
    """Write a structured JSONL audit event. Never crashes the scan."""
    if _JSONL_PATH is None:
        logging.info("AUDIT %s %s", event, fields)
        return
    record = {"ts": _utc_now_iso(), "event": event, **fields}
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    try:
        with _JSONL_LOCK:
            with _JSONL_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line)
    except OSError as exc:
        logging.warning("audit_event failed: %s", exc)
class TimingScope:
    __slots__ = ("_started", "elapsed_ms")
    def __init__(self) -> None:
        self._started = 0.0
        self.elapsed_ms = 0.0
    def __enter__(self) -> "TimingScope":
        self._started = time.monotonic()
        return self
    def __exit__(self, *_exc) -> None:
        self.elapsed_ms = (time.monotonic() - self._started) * 1000.0
# --------------------------------------------------------------------------
# Dataclasses
# --------------------------------------------------------------------------
@dataclass(slots=True)
class Target:
    original: str
    address: str
    family: int = socket.AF_INET
@dataclass(slots=True)
class WebFinding:
    path: str
    status: int
    size: int
    content_type: str = ""
@dataclass(slots=True)
class WebResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    proxy: str | None = None
    egress_id: str | None = None
    latency_ms: float = 0.0
@dataclass(slots=True)
class WebBlockEvent:
    url: str
    status: int
    reason: str
    proxy: str | None = None
    egress_id: str | None = None
@dataclass(slots=True)
class ServiceResult:
    port: int
    state: str = "open"
    service: str = "unknown"
    version: str = "unknown"
    transport: str = "tcp"
    tls: bool = False
    http_status: int | None = None
    title: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    waf: str | None = None
    sensitive_paths: list[WebFinding] = field(default_factory=list)
    cves: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    os_hint: str | None = None
# --------------------------------------------------------------------------
# State (checkpoint/resume)
# --------------------------------------------------------------------------
def target_hash(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
def default_state_path(target: str) -> Path:
    base = Path(os.path.expanduser(DEFAULT_STATE_DIR))
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{target_hash(target)}.json"
@dataclass(slots=True)
class ScanState:
    target: str
    target_hash: str
    started_at: float
    last_updated_at: float
    completed_ports: list[int] = field(default_factory=list)
    completed_paths: list[str] = field(default_factory=list)
    discovered_decoy_paths: list[str] = field(default_factory=list)
    egress_cooldowns: dict[str, float] = field(default_factory=dict)
    roe_ref: str | None = None
    version: int = 1
    @classmethod
    def new(cls, target: str, roe_ref: str | None = None) -> "ScanState":
        now = time.time()
        return cls(
            target=target,
            target_hash=target_hash(target),
            started_at=now,
            last_updated_at=now,
            roe_ref=roe_ref,
        )
    def mark_port_done(self, port: int) -> None:
        if port not in self.completed_ports:
            self.completed_ports.append(port)
        self.last_updated_at = time.time()
    def mark_path_done(self, path: str) -> None:
        if path not in self.completed_paths:
            self.completed_paths.append(path)
        self.last_updated_at = time.time()
    def add_decoy_paths(self, paths: list[str]) -> None:
        for path in paths:
            if path not in self.discovered_decoy_paths:
                self.discovered_decoy_paths.append(path)
        self.last_updated_at = time.time()
def save_state(state: ScanState, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(state)
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".crimson_state_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        logging.warning("save_state failed: %s", exc)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
def load_state(path: Path) -> ScanState | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("load_state failed: %s", exc)
        return None
    return ScanState(
        target=payload.get("target", ""),
        target_hash=payload.get("target_hash", ""),
        started_at=payload.get("started_at", time.time()),
        last_updated_at=payload.get("last_updated_at", time.time()),
        completed_ports=list(payload.get("completed_ports", [])),
        completed_paths=list(payload.get("completed_paths", [])),
        discovered_decoy_paths=list(payload.get("discovered_decoy_paths", [])),
        egress_cooldowns=dict(payload.get("egress_cooldowns", {})),
        roe_ref=payload.get("roe_ref"),
        version=int(payload.get("version", 1)),
    )
# --------------------------------------------------------------------------
# Egress: Tor + dedicated proxy pool with routing policy
# --------------------------------------------------------------------------
def redact_proxy_url(proxy_url: str | None) -> str | None:
    if not proxy_url:
        return proxy_url
    parsed = urlsplit(proxy_url)
    if parsed.username is None and parsed.password is None:
        return proxy_url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme, f"<credentials>@{host}", parsed.path, parsed.query, parsed.fragment)
    )
def is_sensitive_url(url: str) -> bool:
    parsed = urlsplit(url)
    haystack = f"{parsed.path}?{parsed.query}".lower()
    return any(keyword in haystack for keyword in SENSITIVE_ENDPOINT_KEYWORDS)
def parse_status_codes(value: str | None) -> set[int]:
    if value is None:
        return set(DEFAULT_WEB_STOP_STATUSES)
    statuses: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            status = int(part)
        except ValueError as exc:
            raise SystemExit(f"Invalid HTTP status code: {part!r}") from exc
        if status < 100 or status > 599:
            raise SystemExit(f"Invalid HTTP status code: {status}")
        statuses.add(status)
    return statuses
class TorControlClient:
    """Speaks the Tor control protocol over a local socket."""
    def __init__(
        self,
        host: str = DEFAULT_TOR_CONTROL_HOST,
        port: int = DEFAULT_TOR_CONTROL_PORT,
        password: str | None = None,
        cookie_file: str | None = None,
        new_identity_wait: float = DEFAULT_TOR_NEW_IDENTITY_WAIT,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.cookie_file = cookie_file
        self.new_identity_wait = max(0.0, new_identity_wait)
    @staticmethod
    def _quoted(value: str) -> str:
        return json.dumps(value)
    def _auth_command(self) -> str:
        if self.password is not None:
            return f"AUTHENTICATE {self._quoted(self.password)}"
        if self.cookie_file:
            path = Path(self.cookie_file)
            allowed_prefixes = (
                "/var/run/tor", "/var/lib/tor", "/run/tor", str(Path.home())
            )
            resolved = str(path.resolve())
            if not any(resolved.startswith(prefix) for prefix in allowed_prefixes):
                raise RuntimeError(
                    f"Refusing to read Tor cookie outside permitted directories: {resolved}"
                )
            if not path.exists():
                raise RuntimeError(f"Tor cookie file not found: {path}")
            return f"AUTHENTICATE {path.read_bytes().hex()}"
        return "AUTHENTICATE"
    @staticmethod
    def _read_response(reader) -> list[str]:
        lines: list[str] = []
        while True:
            raw_line = reader.readline()
            if not raw_line:
                raise RuntimeError("Tor control connection closed unexpectedly")
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                return lines
    @staticmethod
    def _ensure_ok(lines: list[str], command: str) -> None:
        if not lines or not lines[-1].startswith("250 "):
            detail = lines[-1] if lines else "no response"
            raise RuntimeError(f"Tor control command failed during {command}: {detail}")
    def signal_new_identity(self) -> None:
        try:
            with socket.create_connection((self.host, self.port), timeout=8.0) as sock:
                reader = sock.makefile("rb")
                for command in (self._auth_command(), "SIGNAL NEWNYM", "QUIT"):
                    sock.sendall((command + "\r\n").encode("utf-8"))
                    lines = self._read_response(reader)
                    if command != "QUIT":
                        self._ensure_ok(lines, command)
        except (OSError, RuntimeError) as exc:
            audit_event("tor_newnym_failed", error=str(exc))
            logging.warning("SIGNAL NEWNYM failed: %s", exc)
            return
        audit_event("tor_newnym_ok", wait_seconds=self.new_identity_wait)
        if self.new_identity_wait:
            time.sleep(self.new_identity_wait)
class EgressKind(str, Enum):
    DIRECT = "direct"
    TOR = "tor"
    PROXY = "proxy"
class EgressMode(str, Enum):
    DIRECT = "direct"
    TOR_ONLY = "tor_only"
    MULTI_EGRESS = "multi_egress"
@dataclass(slots=True)
class EgressNode:
    id: str
    kind: EgressKind
    url: str | None
    role: str = "general"
    consecutive_failures: int = 0
    cooldown_until: float = 0.0
    last_used: float = 0.0
    total_requests: int = 0
    total_failures: int = 0
    def is_available(self, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        return self.cooldown_until <= now
def _validate_proxy_url(proxy_url: str) -> str:
    parsed = urlsplit(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES:
        allowed = ", ".join(sorted(SUPPORTED_PROXY_SCHEMES))
        raise SystemExit(
            f"Unsupported proxy scheme '{parsed.scheme}' in {proxy_url!r}. Allowed: {allowed}"
        )
    if not parsed.hostname:
        raise SystemExit(f"Proxy URL must include a host: {proxy_url!r}")
    return proxy_url
class EgressPool:
    """Selects egress nodes per request and manages cooldowns."""
    def __init__(
        self,
        nodes: list[EgressNode],
        mode: EgressMode,
        tor_control: TorControlClient | None = None,
        cooldown_seconds: float = DEFAULT_BAN_COOLDOWN_SECONDS,
        cooldown_multiplier: float = DEFAULT_BAN_COOLDOWN_MULTIPLIER,
        cooldown_max: float = DEFAULT_BAN_COOLDOWN_MAX,
    ) -> None:
        if not nodes:
            raise ValueError("EgressPool requires at least one node")
        self.nodes = nodes
        self.mode = mode
        self.tor_control = tor_control
        self.cooldown_seconds = cooldown_seconds
        self.cooldown_multiplier = cooldown_multiplier
        self.cooldown_max = cooldown_max
        self._rr_cursor = 0
        audit_event(
            "egress_pool_init",
            mode=mode.value,
            node_count=len(nodes),
            nodes=[{"id": n.id, "kind": n.kind.value, "role": n.role} for n in nodes],
        )
    def select(self, url: str) -> EgressNode | None:
        now = time.monotonic()
        candidates = self._candidates_for(url)
        available = [n for n in candidates if n.is_available(now)]
        if not available:
            return None
        if self.mode == EgressMode.MULTI_EGRESS:
            available.sort(key=lambda n: n.last_used)
            picked = available[0]
        else:
            self._rr_cursor = (self._rr_cursor + 1) % max(len(available), 1)
            picked = available[self._rr_cursor % len(available)]
        picked.last_used = now
        picked.total_requests += 1
        return picked
    def _candidates_for(self, url: str) -> list[EgressNode]:
        if self.mode == EgressMode.DIRECT:
            return [n for n in self.nodes if n.kind == EgressKind.DIRECT]
        if self.mode == EgressMode.TOR_ONLY:
            return [n for n in self.nodes if n.kind == EgressKind.TOR]
        if is_sensitive_url(url):
            tor_nodes = [n for n in self.nodes if n.kind == EgressKind.TOR]
            if tor_nodes:
                return tor_nodes
        return [n for n in self.nodes if n.kind in (EgressKind.PROXY, EgressKind.TOR)]
    def mark_failure(self, node: EgressNode, reason: str) -> None:
        node.consecutive_failures += 1
        node.total_failures += 1
        audit_event(
            "egress_failure",
            egress_id=node.id,
            reason=reason,
            consecutive=node.consecutive_failures,
        )
    def mark_success(self, node: EgressNode) -> None:
        node.consecutive_failures = 0
    def mark_banned(self, node: EgressNode, reason: str) -> None:
        base = self.cooldown_seconds * (
            self.cooldown_multiplier ** max(0, node.consecutive_failures - 1)
        )
        cooldown = min(base, self.cooldown_max)
        node.cooldown_until = time.monotonic() + cooldown
        audit_event(
            "egress_banned",
            egress_id=node.id,
            kind=node.kind.value,
            reason=reason,
            cooldown_seconds=cooldown,
        )
        if node.kind == EgressKind.TOR and self.tor_control is not None:
            self.tor_control.signal_new_identity()
            node.cooldown_until = time.monotonic() + min(cooldown / 2, 300.0)
    def has_available(self) -> bool:
        now = time.monotonic()
        return any(n.is_available(now) for n in self.nodes)
    def summary(self) -> dict:
        return {
            "mode": self.mode.value,
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind.value,
                    "role": n.role,
                    "total_requests": n.total_requests,
                    "total_failures": n.total_failures,
                    "in_cooldown": not n.is_available(),
                }
                for n in self.nodes
            ],
        }
def build_pool_direct() -> EgressPool:
    direct = EgressNode(id="direct", kind=EgressKind.DIRECT, url=None, role="general")
    return EgressPool([direct], mode=EgressMode.DIRECT)
def build_pool_tor_only(
    socks_url: str = DEFAULT_TOR_SOCKS_PROXY,
    tor_control: TorControlClient | None = None,
) -> EgressPool:
    _validate_proxy_url(socks_url)
    tor = EgressNode(id="tor-default", kind=EgressKind.TOR, url=socks_url, role="general")
    return EgressPool([tor], mode=EgressMode.TOR_ONLY, tor_control=tor_control)
def build_pool_from_yaml(yaml_path: str, tor_control: TorControlClient | None = None) -> EgressPool:
    if _yaml is None:
        raise SystemExit("PyYAML required for --egress-config. Install: pip install pyyaml")
    path = Path(yaml_path)
    if not path.exists():
        raise SystemExit(f"Egress config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}
    mode_str = str(data.get("mode", "multi_egress")).lower()
    try:
        mode = EgressMode(mode_str)
    except ValueError as exc:
        raise SystemExit(f"Invalid egress mode in YAML: {mode_str}") from exc
    nodes: list[EgressNode] = []
    tor_cfg = data.get("tor") or {}
    if tor_cfg.get("enabled"):
        socks_url = tor_cfg.get("socks_url", DEFAULT_TOR_SOCKS_PROXY)
        _validate_proxy_url(socks_url)
        nodes.append(
            EgressNode(id="tor-default", kind=EgressKind.TOR, url=socks_url, role="sensitive")
        )
    for entry in data.get("proxies") or []:
        url = entry.get("url")
        if not url:
            continue
        _validate_proxy_url(url)
        nodes.append(
            EgressNode(
                id=str(entry.get("id") or url),
                kind=EgressKind.PROXY,
                url=url,
                role=str(entry.get("role", "recon")),
            )
        )
    if not nodes:
        raise SystemExit("Egress config produced zero nodes")
    if mode == EgressMode.MULTI_EGRESS and not any(n.kind == EgressKind.PROXY for n in nodes):
        logging.warning("multi_egress mode but no proxies — falling back to tor_only")
        mode = EgressMode.TOR_ONLY
    return EgressPool(nodes, mode=mode, tor_control=tor_control)
def _maybe_tor_control(args) -> TorControlClient | None:
    return TorControlClient(
        host=getattr(args, "tor_control_host", DEFAULT_TOR_CONTROL_HOST),
        port=getattr(args, "tor_control_port", DEFAULT_TOR_CONTROL_PORT),
        password=getattr(args, "tor_control_password", None),
        cookie_file=getattr(args, "tor_control_cookie", None),
        new_identity_wait=getattr(args, "tor_new_identity_wait", DEFAULT_TOR_NEW_IDENTITY_WAIT),
    )
def build_egress_from_args(args) -> EgressPool:
    if getattr(args, "egress_config", None):
        return build_pool_from_yaml(args.egress_config, tor_control=_maybe_tor_control(args))
    if getattr(args, "web_tor", False):
        return build_pool_tor_only(tor_control=_maybe_tor_control(args))
    return build_pool_direct()
# --------------------------------------------------------------------------
# Ban signal analyzer
# --------------------------------------------------------------------------
class BanSignalAnalyzer:
    """Multi-signal ban detection. Aggregates soft signals until threshold."""
    def __init__(
        self,
        stop_statuses: set[int],
        soft_threshold: int = DEFAULT_BAN_SOFT_THRESHOLD,
        window: int = 20,
    ) -> None:
        self.stop_statuses = stop_statuses
        self.soft_threshold = soft_threshold
        self.window = window
        # Per-node rolling stats: list of (status, latency_ms, size, ts)
        self._stats: dict[str, deque] = {}
        self._soft_count: dict[str, int] = {}
    def _bucket(self, egress_id: str) -> deque:
        if egress_id not in self._stats:
            self._stats[egress_id] = deque(maxlen=self.window)
        return self._stats[egress_id]
    def record(self, egress_id: str, status: int, latency_ms: float, size: int) -> None:
        self._bucket(egress_id).append((status, latency_ms, size, time.monotonic()))
    def evaluate(
        self,
        egress_id: str,
        status: int,
        body: bytes,
        latency_ms: float,
    ) -> tuple[bool, str | None]:
        """
        Return (is_banned, reason). is_banned=True means cooldown the node.
        """
        # Hard signal: explicit block status
        if status in self.stop_statuses:
            self._soft_count[egress_id] = 0
            return True, f"hard:http_{status}"
        # Body pattern signal (regex with word boundaries — no false matches on
        # the literal substring 'waf' appearing in document content)
        text_sample = body[:4096].decode("utf-8", errors="ignore")
        match = _BLOCK_BODY_RE.search(text_sample)
        if match:
            self._soft_count[egress_id] = 0
            return True, f"hard:body_pattern:{match.group(0)[:32]}"
        # Soft signals (require accumulation)
        soft_reasons: list[str] = []
        bucket = self._bucket(egress_id)
        if len(bucket) >= 5:
            recent_latencies = [item[1] for item in bucket if item[1] > 0]
            if recent_latencies:
                baseline = statistics.median(recent_latencies)
                if baseline > 0 and latency_ms > baseline * PACING_SLOWDOWN_THRESHOLD:
                    soft_reasons.append("soft:latency_spike")
            sizes = [item[2] for item in bucket if item[2] > 0]
            if len(sizes) >= 5:
                median_size = statistics.median(sizes)
                if median_size > 100 and size < median_size * 0.3:
                    soft_reasons.append("soft:size_dropoff")
        for reason in soft_reasons:
            self._soft_count[egress_id] = self._soft_count.get(egress_id, 0) + 1
            audit_event("ban_soft_signal", egress_id=egress_id, reason=reason,
                        count=self._soft_count[egress_id])
        if self._soft_count.get(egress_id, 0) >= self.soft_threshold:
            self._soft_count[egress_id] = 0
            return True, "soft:threshold_exceeded"
        return False, None
    def record_error(self, egress_id: str, error_kind: str) -> tuple[bool, str | None]:
        """Network-level failures (RST, TLS handshake fail) — accumulate."""
        self._soft_count[egress_id] = self._soft_count.get(egress_id, 0) + 1
        audit_event(
            "ban_soft_signal",
            egress_id=egress_id,
            reason=f"soft:{error_kind}",
            count=self._soft_count[egress_id],
        )
        if self._soft_count[egress_id] >= self.soft_threshold:
            self._soft_count[egress_id] = 0
            return True, f"soft:network_errors:{error_kind}"
        return False, None
# --------------------------------------------------------------------------
# Adaptive pacing — jitter + adaptive slowdown
# --------------------------------------------------------------------------
class AdaptivePacer:
    """Per-target jittered delay with adaptive slowdown on degradation."""
    def __init__(self, base_delay: float, sensitive_delay: float, max_global_rate: int) -> None:
        self.base_delay = max(0.0, base_delay)
        self.sensitive_delay = max(self.base_delay, sensitive_delay)
        self.max_global_rate = max(1, max_global_rate)
        self._lock = asyncio.Lock()
        self._last_request = 0.0
        self._latency_history: deque = deque(maxlen=PACING_BASELINE_WINDOW)
        self._slowdown_factor = 1.0
    def record_latency(self, latency_ms: float) -> None:
        self._latency_history.append(latency_ms)
    def _adjust_slowdown(self) -> None:
        if len(self._latency_history) < 5:
            return
        median = statistics.median(self._latency_history)
        recent = list(self._latency_history)[-3:]
        avg_recent = sum(recent) / len(recent)
        if median > 0 and avg_recent > median * PACING_SLOWDOWN_THRESHOLD:
            self._slowdown_factor = min(4.0, self._slowdown_factor * 1.5)
            audit_event("pacer_slowdown", factor=self._slowdown_factor)
        else:
            # Decay back toward 1.0
            if self._slowdown_factor > 1.0:
                self._slowdown_factor = max(1.0, self._slowdown_factor * 0.9)
    async def wait(self, url: str) -> None:
        async with self._lock:
            self._adjust_slowdown()
            global_floor = 60.0 / self.max_global_rate
            endpoint_delay = self.sensitive_delay if is_sensitive_url(url) else self.base_delay
            jitter = random.uniform(JITTER_LOW, JITTER_HIGH)
            required = max(global_floor, endpoint_delay) * jitter * self._slowdown_factor
            elapsed = time.monotonic() - self._last_request
            wait_time = required - elapsed
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_request = time.monotonic()
# --------------------------------------------------------------------------
# Decoy traffic injector
# --------------------------------------------------------------------------
class DecoyInjector:
    """Decides whether to enqueue a decoy request before a sensitive one."""
    def __init__(self, rate: float, paths: list[str]) -> None:
        self.rate = max(0.0, min(1.0, rate))
        self.paths = paths or list(DECOY_FALLBACK_PATHS)
    def should_inject(self) -> bool:
        if not self.paths or self.rate <= 0.0:
            return False
        return random.random() < self.rate
    def pick(self) -> str:
        return random.choice(self.paths)
# --------------------------------------------------------------------------
# Passive recon — discover real paths for decoy pool
# --------------------------------------------------------------------------
async def passive_recon(target_url: str, timeout: float = 5.0) -> list[str]:
    """Fetch robots.txt + sitemap.xml + homepage; extract internal paths."""
    if aiohttp is None:
        return []
    discovered: set[str] = set()
    headers = {"User-Agent": RECON_USER_AGENT}
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    parsed = urlsplit(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidate_urls = [
        f"{base}/robots.txt",
        f"{base}/sitemap.xml",
        f"{base}/",
    ]
    async with aiohttp.ClientSession(timeout=client_timeout, headers=headers) as session:
        for url in candidate_urls:
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    if resp.status != 200:
                        continue
                    body = await resp.read()
                    text = body.decode("utf-8", errors="ignore")
                    if url.endswith("robots.txt"):
                        for line in text.splitlines():
                            line = line.strip()
                            if line.lower().startswith(("allow:", "disallow:")):
                                _, _, path = line.partition(":")
                                path = path.strip()
                                if path and path.startswith("/") and path != "/":
                                    discovered.add(path)
                    elif url.endswith("sitemap.xml"):
                        for match in re.finditer(r"<loc>([^<]+)</loc>", text):
                            loc = match.group(1).strip()
                            loc_parsed = urlsplit(loc)
                            if loc_parsed.netloc == parsed.netloc and loc_parsed.path:
                                discovered.add(loc_parsed.path)
                    else:
                        for match in re.finditer(
                            r'href=["\'](/[^"\'#?\s]+)', text, re.IGNORECASE
                        ):
                            href = match.group(1)
                            if not href.startswith("//"):
                                discovered.add(href)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
    paths = sorted(discovered)[:RECON_MAX_LINKS]
    audit_event("passive_recon_done", target=target_url, paths_found=len(paths))
    return paths
# --------------------------------------------------------------------------
# Web request controller — aiohttp + optional curl_cffi backend
# --------------------------------------------------------------------------
class WebRequestController:
    """
    Routes web requests through the egress pool. Applies adaptive pacing,
    ban detection, optional fingerprint spoofing, and decoy injection.
    """
    def __init__(
        self,
        egress: EgressPool,
        pacer: AdaptivePacer,
        ban_analyzer: BanSignalAnalyzer,
        decoy: DecoyInjector,
        max_retries: int = 0,
        user_agent: str | None = None,
        fingerprint: str | None = None,
        state: ScanState | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.egress = egress
        self.pacer = pacer
        self.ban_analyzer = ban_analyzer
        self.decoy = decoy
        self.max_retries = max(0, max_retries)
        self.user_agent = user_agent
        self.fingerprint = fingerprint if (fingerprint and CURL_CFFI_AVAILABLE) else None
        self.state = state
        self.state_path = state_path
        self.block_events: list[WebBlockEvent] = []
        self._blocked_targets: set[tuple[str, str]] = set()
        self._curl_session = None
        if fingerprint and not CURL_CFFI_AVAILABLE:
            logging.warning(
                "--fingerprint requested but curl_cffi not installed; falling back to aiohttp"
            )
    @property
    def uses_proxy(self) -> bool:
        return self.egress.mode != EgressMode.DIRECT
    @staticmethod
    def _target_key(url: str) -> tuple[str, str]:
        parsed = urlsplit(url)
        return parsed.netloc.lower(), parsed.path or "/"
    def is_blocked(self, url: str) -> bool:
        return self._target_key(url) in self._blocked_targets
    def _build_headers(self) -> dict[str, str]:
        ua = self.user_agent or random.choice(GENERIC_USER_AGENTS)
        # Chrome-like header ordering (Python dicts preserve insertion order)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
    async def _persist_state_if_any(self) -> None:
        if self.state is None or self.state_path is None:
            return
        try:
            save_state(self.state, self.state_path)
        except Exception as exc:
            logging.warning("state persistence failed: %s", exc)
    async def request(
        self,
        session,  # aiohttp.ClientSession
        url: str,
        timeout,
        ssl_policy,
        allow_redirects: bool = False,
        is_decoy: bool = False,
    ) -> WebResponse | None:
        if self.is_blocked(url):
            audit_event("skip_blocked", url=url)
            return None
        # Maybe inject a decoy before this real request (don't recurse on decoys themselves)
        if not is_decoy and self.decoy.should_inject():
            decoy_path = self.decoy.pick()
            parsed = urlsplit(url)
            decoy_url = f"{parsed.scheme}://{parsed.netloc}{decoy_path}"
            await self.request(session, decoy_url, timeout, ssl_policy, allow_redirects, is_decoy=True)
        for attempt in range(self.max_retries + 1):
            node = self.egress.select(url)
            if node is None:
                audit_event("no_egress_available", url=url)
                logging.warning("All egress nodes in cooldown — pausing 30s")
                await asyncio.sleep(30.0)
                continue
            await self.pacer.wait(url)
            headers = self._build_headers()
            timer = TimingScope()
            try:
                with timer:
                    response = await self._send_request(
                        session=session,
                        url=url,
                        timeout=timeout,
                        ssl_policy=ssl_policy,
                        node=node,
                        headers=headers,
                        allow_redirects=allow_redirects,
                    )
                response.latency_ms = timer.elapsed_ms
                response.egress_id = node.id
            except Exception as exc:
                self.egress.mark_failure(node, f"transport:{type(exc).__name__}")
                banned, reason = self.ban_analyzer.record_error(node.id, type(exc).__name__)
                if banned and reason is not None:
                    self.egress.mark_banned(node, reason)
                audit_event(
                    "http_error",
                    url=url,
                    egress_id=node.id,
                    error=str(exc)[:200],
                )
                if attempt >= self.max_retries:
                    return None
                await asyncio.sleep(min(30.0, max(1.0, self.pacer.base_delay) * (2 ** attempt)))
                continue
            self.pacer.record_latency(response.latency_ms)
            self.ban_analyzer.record(node.id, response.status, response.latency_ms, len(response.body))
            audit_event(
                "http_request",
                url=url,
                status=response.status,
                egress_id=node.id,
                latency_ms=round(response.latency_ms, 2),
                size=len(response.body),
                decoy=is_decoy,
            )
            banned, reason = self.ban_analyzer.evaluate(
                node.id, response.status, response.body, response.latency_ms
            )
            if banned and reason is not None:
                self.egress.mark_banned(node, reason)
                self._blocked_targets.add(self._target_key(url))
                event = WebBlockEvent(
                    url=url,
                    status=response.status,
                    reason=reason,
                    proxy=redact_proxy_url(node.url),
                    egress_id=node.id,
                )
                self.block_events.append(event)
                if self.state is not None:
                    self.state.egress_cooldowns[node.id] = time.time()
                    await self._persist_state_if_any()
                if is_decoy:
                    return None
                # Retry on next iteration with a different egress
                continue
            self.egress.mark_success(node)
            return response
        return None
    async def _send_request(
        self,
        session,
        url: str,
        timeout,
        ssl_policy,
        node: EgressNode,
        headers: dict[str, str],
        allow_redirects: bool,
    ) -> WebResponse:
        # curl_cffi path: full JA3/TLS fingerprint spoofing
        if self.fingerprint:
            return await self._send_via_curl_cffi(url, node, headers, timeout, allow_redirects)
        # SOCKS proxy via aiohttp_socks (new connector per request — pooling
        # would help perf but breaks per-node cooldown semantics)
        if node.url and urlsplit(node.url).scheme.lower() in SOCKS_PROXY_SCHEMES:
            if ProxyConnector is None:
                raise RuntimeError("aiohttp_socks not installed")
            connector = ProxyConnector.from_url(node.url)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as proxy_session:
                async with proxy_session.get(
                    url,
                    timeout=timeout,
                    ssl=ssl_policy,
                    allow_redirects=allow_redirects,
                    headers=headers,
                ) as response:
                    body = await response.read()
                    return WebResponse(
                        url=url,
                        status=response.status,
                        headers=dict(response.headers),
                        body=body,
                        proxy=redact_proxy_url(node.url),
                    )
        # HTTP proxy via aiohttp native
        proxy_arg = node.url if node.kind == EgressKind.PROXY else None
        async with session.get(
            url,
            timeout=timeout,
            ssl=ssl_policy,
            allow_redirects=allow_redirects,
            headers=headers,
            proxy=proxy_arg,
        ) as response:
            body = await response.read()
            return WebResponse(
                url=url,
                status=response.status,
                headers=dict(response.headers),
                body=body,
                proxy=redact_proxy_url(node.url),
            )
    async def _send_via_curl_cffi(
        self,
        url: str,
        node: EgressNode,
        headers: dict[str, str],
        timeout,
        allow_redirects: bool,
    ) -> WebResponse:
        if _CurlCffiAsyncSession is None:
            raise RuntimeError("curl_cffi not available")
        impersonate = FINGERPRINT_PROFILES.get(self.fingerprint, "chrome120")
        proxies = None
        if node.url:
            proxies = {"http": node.url, "https": node.url}
        total_timeout = getattr(timeout, "total", None) or 10.0
        async with _CurlCffiAsyncSession(impersonate=impersonate) as cs:
            r = await cs.get(
                url,
                headers=headers,
                proxies=proxies,
                allow_redirects=allow_redirects,
                timeout=total_timeout,
                verify=False,
            )
            body = r.content if isinstance(r.content, bytes) else (r.content or b"")
            return WebResponse(
                url=url,
                status=r.status_code,
                headers=dict(r.headers),
                body=body,
                proxy=redact_proxy_url(node.url),
            )
    def report_metadata(self) -> dict:
        return {
            "egress": self.egress.summary(),
            "blocked_targets": [asdict(event) for event in self.block_events],
            "fingerprint_profile": self.fingerprint,
            "decoy_rate": self.decoy.rate,
        }
# --------------------------------------------------------------------------
# Scapy loader, banner formatting, target resolution, helpers
# --------------------------------------------------------------------------
def load_scapy():
    try:
        from scapy.all import IP, IPv6, TCP, conf, sr, sr1
    except ImportError as exc:
        raise RuntimeError("Scapy required for --syn. Install: pip install scapy") from exc
    return IP, IPv6, TCP, conf, sr, sr1
def scapy_is_available() -> bool:
    return find_spec("scapy") is not None
def has_elevated_privileges() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except Exception:
        return False
def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False
def resolve_target(value: str) -> Target:
    if looks_like_ip(value):
        addr = ipaddress.ip_address(value)
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        return Target(original=value, address=str(addr), family=family)
    try:
        info = socket.getaddrinfo(value, None)
    except socket.gaierror as exc:
        raise SystemExit(f"Cannot resolve target {value!r}: {exc}") from exc
    if not info:
        raise SystemExit(f"No address records for {value!r}")
    family, _, _, _, sockaddr = info[0]
    return Target(original=value, address=sockaddr[0], family=family)
def parse_ports(args: argparse.Namespace) -> list[int]:
    if getattr(args, "top_ports", False):
        return TOP_PORTS
    if getattr(args, "ports", None):
        ports: set[int] = set()
        for chunk in args.ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start_s, end_s = chunk.split("-", 1)
                try:
                    start, end = int(start_s), int(end_s)
                except ValueError as exc:
                    raise SystemExit(f"Invalid port range: {chunk!r}") from exc
                if start < 1 or end > 65535 or start > end:
                    raise SystemExit(f"Invalid port range: {chunk!r}")
                ports.update(range(start, end + 1))
            else:
                try:
                    port = int(chunk)
                except ValueError as exc:
                    raise SystemExit(f"Invalid port: {chunk!r}") from exc
                if port < 1 or port > 65535:
                    raise SystemExit(f"Port out of range: {port}")
                ports.add(port)
        return sorted(ports)
    start = max(1, min(65535, int(args.start)))
    end = max(start, min(65535, int(args.end)))
    return list(range(start, end + 1))
def format_banner_bytes(data: bytes, max_text: int = 120, max_hex: int = 40) -> str:
    if not data:
        return "open, no banner"
    printable = bytes(b for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = len(printable) / max(len(data), 1)
    if ratio >= MIN_PRINTABLE_RATIO:
        text = data.decode("utf-8", errors="ignore").strip()
        text = re.sub(r"\s+", " ", text)
        if len(text) > max_text:
            text = text[: max_text - 3] + "..."
        return text or "open, no banner"
    hex_repr = data[:max_hex].hex()
    return f"<Binary Data: {hex_repr}>"
def estimate_os_from_ttl(ttl: int, window: int, options: list) -> str:
    mss = 0
    wscale = 0
    for opt in options:
        if not isinstance(opt, tuple) or not opt:
            continue
        name = opt[0]
        value = opt[1] if len(opt) > 1 else None
        if name == "MSS" and isinstance(value, int):
            mss = value
        elif name == "WScale" and isinstance(value, int):
            wscale = value
    option_names = [item[0] for item in options if isinstance(item, tuple) and item]
    compact = [n for n in option_names if n != "EOL"]
    linux_order = ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"]
    windows_order = ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"]
    def has_order(expected: list[str]) -> bool:
        cursor = 0
        for name in compact:
            if cursor < len(expected) and name == expected[cursor]:
                cursor += 1
        return cursor == len(expected)
    if ttl <= 64:
        if has_order(linux_order):
            return "Linux-like (high)"
        if window == 65535 and wscale in {4, 5, 6}:
            return "macOS/FreeBSD-like (medium)"
        if mss == 1460 and wscale in {7, 8}:
            return "Linux-like (medium)"
        return "Unix-like (low)"
    if ttl <= 128:
        if has_order(windows_order):
            return "Windows-like (high)"
        if window in {8192, 16384, 64240, 65535}:
            return "Windows-like (medium)"
        return "Windows or embedded device (low)"
    if ttl <= 255:
        if window == 4128:
            return "Cisco IOS-like (medium)"
        return "network device or Unix-like (low)"
    return "unknown"
# --------------------------------------------------------------------------
# Scanners (TCP connect, SYN, UDP)
# --------------------------------------------------------------------------
class AsyncConnectScanner:
    def __init__(self, target: Target, concurrency: int, timeout: float) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
    async def _scan_one(self, port: int, semaphore: asyncio.Semaphore) -> int | None:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target.address, port),
                    timeout=self.timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except (OSError, asyncio.TimeoutError):
                return None
    async def scan(self, ports: list[int]) -> list[int]:
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._scan_one(port, semaphore) for port in ports]
        open_ports: list[int] = []
        started = time.monotonic()
        print_stage(
            "Port Scan",
            f"Mode: async-connect | Timeout: {self.timeout:.2f}s | Concurrency: {self.concurrency}",
        )
        for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
            result = await task
            if result is not None:
                open_ports.append(result)
            if idx % 200 == 0 or idx == len(tasks):
                sys.stdout.write(Fore.CYAN + "\r" + render_progress("Scanning ports", idx, len(tasks)))
                sys.stdout.flush()
        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)
class _UdpProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
    def datagram_received(self, data: bytes, _addr) -> None:
        if not self.response.done():
            self.response.set_result(data)
    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)
class UdpScanner:
    def __init__(self, target: Target, timeout: float = DEFAULT_UDP_TIMEOUT) -> None:
        self.target = target
        self.timeout = timeout
    async def _probe(self, port: int) -> ServiceResult | None:
        loop = asyncio.get_running_loop()
        transport = None
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                _UdpProbeProtocol,
                remote_addr=(self.target.address, port),
                family=self.target.family,
            )
            transport.sendto(UDP_PROBES[port])
            raw = await asyncio.wait_for(protocol.response, timeout=self.timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            if transport is not None:
                transport.close()
        service = UDP_SERVICE_HINTS.get(port, "udp")
        return ServiceResult(
            port=port,
            service=service,
            version=format_banner_bytes(raw, max_text=80, max_hex=20),
            transport="udp",
            tls=False,
        )
    async def scan(self) -> dict[int, ServiceResult]:
        print_stage(
            "UDP Scan",
            f"Ports: {', '.join(str(p) for p in UDP_SCAN_PORTS)} | Timeout: {self.timeout:.2f}s",
        )
        results = await asyncio.gather(
            *(self._probe(port) for port in UDP_SCAN_PORTS), return_exceptions=True
        )
        open_udp: dict[int, ServiceResult] = {}
        for item in results:
            if isinstance(item, ServiceResult):
                open_udp[item.port] = item
        print(Fore.GREEN + f"UDP responders found: {len(open_udp)}")
        return open_udp
class SynScanner:
    def __init__(self, target: Target, timeout: float, retry: int, batch_size: int) -> None:
        self.IP, self.IPv6, self.TCP, self.conf, self.sr, self.sr1 = load_scapy()
        self.target = target
        self.timeout = timeout
        self.retry = retry
        self.batch_size = batch_size
        self.os_hints: dict[int, str] = {}
    def _layer(self):
        return (
            self.IPv6(dst=self.target.address)
            if self.target.family == socket.AF_INET6
            else self.IP(dst=self.target.address)
        )
    def _scan_batch(self, ports: list[int]) -> list[int]:
        open_ports: list[int] = []
        pending = list(ports)
        ip_layer = self._layer()
        for _attempt in range(self.retry + 1):
            if not pending:
                break
            try:
                sport = random.randint(1024, 65535)
                packets = ip_layer / self.TCP(sport=sport, dport=pending, flags="S")
                answered, unanswered = self.sr(packets, timeout=self.timeout, verbose=0)
                for _sent, received in answered:
                    if not received.haslayer(self.TCP):
                        continue
                    tcp = received.getlayer(self.TCP)
                    if int(tcp.flags) != TCP_SYN_ACK_FLAGS:
                        continue
                    port = int(tcp.sport)
                    open_ports.append(port)
                    ttl = 0
                    if received.haslayer(self.IP):
                        ttl = int(received[self.IP].ttl)
                    elif received.haslayer(self.IPv6):
                        ttl = int(received[self.IPv6].hlim)
                    self.os_hints[port] = estimate_os_from_ttl(
                        ttl, int(tcp.window), list(tcp.options)
                    )
                    # Proper RST: ack = received.seq + 1, seq = received.ack
                    rst = ip_layer / self.TCP(
                        sport=sport,
                        dport=port,
                        flags="R",
                        seq=int(tcp.ack),
                        ack=int(tcp.seq) + 1,
                    )
                    self.sr1(rst, timeout=0.2, verbose=0)
                pending = [int(pkt.dport) for pkt in unanswered if pkt.haslayer(self.TCP)]
            except Exception as exc:
                logging.warning("SYN batch error on %s: %s", self.target.address, exc)
                break
        return open_ports
    def scan(self, ports: list[int]) -> list[int]:
        try:
            self.conf.verb = 0
            self.conf.use_pcap = True
        except Exception:
            pass
        started = time.monotonic()
        open_ports: set[int] = set()
        batches = [ports[i : i + self.batch_size] for i in range(0, len(ports), self.batch_size)]
        print_stage(
            "Port Scan",
            f"Mode: syn-stealth | Timeout: {self.timeout:.2f}s | "
            f"Retry: {self.retry} | Batch size: {self.batch_size}",
        )
        for idx, batch in enumerate(batches, start=1):
            open_ports.update(self._scan_batch(batch))
            sys.stdout.write(Fore.CYAN + "\r" + render_progress("Scanning batches", idx, len(batches)))
            sys.stdout.flush()
        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)
# --------------------------------------------------------------------------
# CVE lookup
# --------------------------------------------------------------------------
class CveLookup:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    def __init__(self, enabled: bool, concurrency: int = 3) -> None:
        self.enabled = enabled
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache: dict[str, list[dict[str, str]]] = {}
        self._api_key = os.getenv("NVD_API_KEY")
        self._client = None
        if Throttler is not None:
            rate = NVD_API_KEY_RATE_LIMIT if self._api_key else NVD_FREE_RATE_LIMIT
            self.throttler = Throttler(rate_limit=rate, period=NVD_RATE_PERIOD_SECONDS)
        else:
            self.throttler = None
    def _api_headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        return {"apiKey": self._api_key}
    def _http_client(self):
        if self._client is None and httpx is not None:
            self._client = httpx.AsyncClient(timeout=8)
        return self._client
    async def aclose(self) -> None:
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None
    @staticmethod
    def _query_from_version(service: str, version: str) -> str | None:
        if version.lower() in {"unknown", "filtered", "no response", "open, no banner", "open, probe failed"}:
            return None
        if version.startswith("<Binary Data:"):
            return None
        parsed = CveLookup._extract_cpe_parts(service, version)
        if parsed is None:
            return None
        vendor, product, product_version = parsed
        return f"cpe:2.3:a:{vendor}:{product}:{product_version}:*:*:*:*:*:*:*"
    @staticmethod
    def _extract_cpe_parts(service: str, version: str) -> tuple[str, str, str] | None:
        cleaned = re.sub(r"[\r\n].*", "", version).strip()
        cleaned = re.sub(r"\([^)]*\)", "", cleaned)
        cleaned = re.sub(r"[,;]+", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if not cleaned or cleaned.startswith("<Binary Data:"):
            return None
        candidates = [
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)/(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>OpenSSH)[-_](?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)\s+(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
        ]
        product_name = ""
        product_version = ""
        for pattern in candidates:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                product_name = re.sub(r"\s+", " ", match.group("product")).strip()
                product_version = match.group("version").strip()
                break
        if not product_name or not product_version:
            return None
        normalized = product_name.lower().replace("_", " ").replace("/", " ").strip()
        mapped = CPE_PRODUCT_MAP.get(normalized)
        if mapped is None and service in {"http", "https"}:
            first_token = normalized.split()[0] if normalized.split() else ""
            mapped = CPE_PRODUCT_MAP.get(first_token)
        if mapped is None:
            return None
        vendor, product = mapped
        return vendor, product, product_version
    async def query(self, service: str, version: str, session=None) -> list[dict[str, str]]:
        if not self.enabled or httpx is None:
            return []
        virtual_match = self._query_from_version(service, version)
        if not virtual_match:
            return []
        if virtual_match in self.cache:
            return self.cache[virtual_match]
        params = {"virtualMatchString": virtual_match, "resultsPerPage": MAX_CVE_RESULTS_PER_QUERY}
        client = self._http_client()
        if client is None:
            return []
        async with self.semaphore:
            try:
                if self.throttler is not None:
                    async with self.throttler:
                        response = await client.get(self.NVD_API, params=params, headers=self._api_headers())
                else:
                    response = await client.get(self.NVD_API, params=params, headers=self._api_headers())
                if response.status_code != 200:
                    self.cache[virtual_match] = []
                    return []
                payload = response.json()
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError):
                self.cache[virtual_match] = []
                return []
        findings = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions") or []
            description = descriptions[0].get("value", "N/A") if descriptions else "N/A"
            metrics = cve.get("metrics", {})
            severity = "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "unknown")
                    break
            findings.append({
                "id": cve.get("id", "unknown"),
                "severity": severity,
                "description": description[:MAX_CVE_DESCRIPTION_LENGTH],
            })
        self.cache[virtual_match] = findings
        return findings
# --------------------------------------------------------------------------
# Service detector
# --------------------------------------------------------------------------
class ServiceDetector:
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare"],
        "aws_waf": ["x-amzn-requestid", "x-amzn-waf"],
        "akamai": ["akamai", "akamai-ghost"],
        "f5_bigip": ["bigip", "x-wa-info"],
        "sucuri": ["x-sucuri-id", "sucuri"],
        "imperva": ["incap_ses", "visid_incap"],
        "modsecurity": ["mod_security", "modsecurity", "owasp"],
        "reblaze": ["x-reblaze-protection"],
        "stackpath": ["x-sp-url", "x-sp-edge"],
        "azion": ["x-azion-", "server: azion"],
    }
    ACTIVE_PROBES = {
        "tls_client_hello": b"\x16\x03\x01\x00\x41\x01\x00\x00\x3D\x03\x03",
        "rdp_routing_token": b"\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00",
        "smbv2_negotiate": b"\x00\x00\x00\x54\xFE\x53\x4D\x42\x40\x00\x00\x00\x00\x00\x00\x00",
    }
    def __init__(
        self,
        target: Target,
        concurrency: int,
        timeout: float,
        check_sensitive_paths: bool,
        cve_lookup: CveLookup,
        web_controller: WebRequestController | None = None,
        web_only: bool = False,
    ) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.check_sensitive_paths = check_sensitive_paths
        self.cve_lookup = cve_lookup
        self.web_controller = web_controller
        self.web_only = web_only
    def _host_header(self, port: int) -> str:
        if ":" in self.target.original and not self.target.original.startswith("["):
            host = f"[{self.target.original}]"
        else:
            host = self.target.original
        if port in {80, 443}:
            return host
        return f"{host}:{port}"
    def _http_request_bytes(self, port: int, path: str = "/") -> bytes:
        ua = (self.web_controller.user_agent if self.web_controller and self.web_controller.user_agent
              else random.choice(GENERIC_USER_AGENTS))
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self._host_header(port)}\r\n"
            f"User-Agent: {ua}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
    def _http_url(self, port: int, tls: bool, path: str = "/") -> str:
        scheme = "https" if tls else "http"
        host = self.target.original
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 443 if tls else 80
        netloc = host if port == default_port else f"{host}:{port}"
        return f"{scheme}://{netloc}{path}"
    @staticmethod
    def _parse_headers(raw_response: str) -> tuple[int | None, dict[str, str], str | None]:
        head, _, body = raw_response.partition("\r\n\r\n")
        lines = head.splitlines()
        status = None
        headers: dict[str, str] = {}
        if lines:
            match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
            if match:
                status = int(match.group(1))
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None
        return status, headers, title
    @staticmethod
    def _extract_title(body: bytes) -> str | None:
        text = body.decode("utf-8", errors="ignore")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None
    def _result_from_web_response(self, port: int, tls: bool, response: WebResponse) -> ServiceResult:
        headers = {k.lower(): v for k, v in response.headers.items()}
        server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
        scheme = "https" if tls else "http"
        notes = []
        if self.web_controller:
            for event in self.web_controller.block_events:
                if event.url == response.url:
                    notes.append(f"Web block observed: {event.reason}")
                    break
        if response.egress_id:
            notes.append(f"egress={response.egress_id}")
        return ServiceResult(
            port=port,
            service=scheme,
            version=server,
            tls=tls,
            http_status=response.status,
            title=self._extract_title(response.body),
            headers=headers,
            waf=self._detect_waf(headers),
            notes=notes,
        )
    @classmethod
    def _detect_waf(cls, headers: dict[str, str]) -> str | None:
        pairs = [f"{k}: {v}" for k, v in headers.items()]
        haystack = "\n".join([*headers.keys(), *headers.values(), *pairs]).lower()
        for name, signatures in cls.WAF_SIGNATURES.items():
            if any(sig in haystack for sig in signatures):
                return name
        return None
    async def _open_plain(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(self.target.address, port), timeout=self.timeout
        )
    async def _open_tls(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context()
        target_is_ip = looks_like_ip(self.target.original)
        server_hostname = None if target_is_ip else self.target.original
        if target_is_ip:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return await asyncio.wait_for(
            asyncio.open_connection(
                self.target.address, port, ssl=context, server_hostname=server_hostname
            ),
            timeout=self.timeout,
        )
    def _request_ssl_policy(self):
        return False if looks_like_ip(self.target.original) else None
    @staticmethod
    def _port_hint_result(port: int, prior: ServiceResult) -> ServiceResult | None:
        hint = LOW_CONFIDENCE_PORT_HINTS.get(port)
        if hint is None:
            return None
        service, version = hint
        notes = list(prior.notes)
        if prior.version and prior.version not in {"unknown", "open, no banner", "open, probe failed"}:
            notes.append(f"Original banner: {trim_text(prior.version, 80)}")
        notes.append("Service name assigned by port heuristic")
        return dataclasses.replace(prior, service=service, version=version, notes=notes)
    async def _read_greeting(self, reader: asyncio.StreamReader) -> bytes:
        try:
            return await asyncio.wait_for(reader.read(MAX_BANNER_READ_BYTES), timeout=min(1.2, self.timeout))
        except asyncio.TimeoutError:
            return b""
    async def _first_successful_http_probe(self, port: int, session) -> ServiceResult | None:
        tls_order = [True, False] if port in TLS_PORT_HINTS else [False, True]
        for tls in tls_order:
            result = await self._probe_http_via_session(port, tls=tls, session=session)
            if result is not None:
                return result
        return None
    async def _probe_http_via_session(self, port: int, tls: bool, session, path: str = "/") -> ServiceResult | None:
        if self.web_controller is None or aiohttp is None:
            return None
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        url = self._http_url(port, tls=tls, path=path)
        response = await self.web_controller.request(
            session=session,
            url=url,
            timeout=timeout,
            ssl_policy=self._request_ssl_policy(),
            allow_redirects=False,
        )
        if response is None:
            return None
        return self._result_from_web_response(port, tls, response)
    async def _probe_http(self, port: int, tls: bool, reader=None, writer=None) -> ServiceResult | None:
        close_writer = False
        try:
            if reader is None or writer is None:
                reader, writer = await (self._open_tls(port) if tls else self._open_plain(port))
                close_writer = True
            writer.write(self._http_request_bytes(port))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(MAX_HTTP_READ_BYTES), timeout=self.timeout)
            text = raw.decode("utf-8", errors="ignore")
            if not text.startswith("HTTP/"):
                return None
            status, headers, title = self._parse_headers(text)
            server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
            scheme = "https" if tls else "http"
            notes = []
            if tls and looks_like_ip(self.target.original):
                notes.append("TLS verification disabled (IP target)")
            return ServiceResult(
                port=port, service=scheme, version=server, tls=tls,
                http_status=status, title=title, headers=headers,
                waf=self._detect_waf(headers), notes=notes,
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return None
        finally:
            if close_writer and writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    async def _probe_known_greeting(self, port: int) -> ServiceResult:
        reader = writer = None
        try:
            reader, writer = await self._open_plain(port)
            greeting = await self._read_greeting(reader)
            text = format_banner_bytes(greeting)
            if text.startswith("SSH-"):
                match = re.match(r"(SSH-[\d.]+-\S+)", text)
                version = match.group(1) if match else text.splitlines()[0]
                return ServiceResult(port=port, service="ssh", version=version)
            if text.startswith("220") and re.search(r"(ftp|filezilla|vsftpd|proftpd)", text, re.IGNORECASE):
                return ServiceResult(port=port, service="ftp", version=text.splitlines()[0])
            if text.startswith("220") and re.search(r"(smtp|mail|postfix|exim|sendmail)", text, re.IGNORECASE):
                return ServiceResult(port=port, service="smtp", version=text.splitlines()[0])
            if text.startswith("+OK"):
                service = "pop3" if port in {110, 995} else "imap/pop"
                return ServiceResult(port=port, service=service, version=text.splitlines()[0])
            if b"mysql_native_password" in greeting:
                printable = "".join(chr(b) for b in greeting if 32 <= b <= 126)
                match = re.search(r"(\d+\.\d+\.\d+[\w.-]*)", printable)
                version = f"MySQL {match.group(1)}" if match else "MySQL-compatible server"
                return ServiceResult(port=port, service="mysql", version=version)
            if self.web_controller is None or not self.web_controller.uses_proxy:
                http = await self._probe_http(port, tls=False, reader=reader, writer=writer)
                if http:
                    writer = None
                    return http
            if greeting:
                return ServiceResult(port=port, service="unknown", version=text)
            return ServiceResult(port=port, service="unknown", version="open, no banner")
        except (OSError, asyncio.TimeoutError):
            return ServiceResult(port=port, service="unknown", version="open, probe failed")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    async def _probe_active_payloads(self, port: int) -> ServiceResult | None:
        for probe_name, payload in self.ACTIVE_PROBES.items():
            reader = writer = None
            try:
                reader, writer = await self._open_plain(port)
                writer.write(payload)
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(MAX_BANNER_READ_BYTES), timeout=min(1.5, self.timeout))
                if not raw:
                    continue
                if raw.startswith((b"\x15\x03", b"\x16\x03")):
                    return ServiceResult(port=port, service="tls", version="TLS/SSL service", tls=True)
                if b"\x03\x00\x00" in raw[:8]:
                    return ServiceResult(port=port, service="rdp", version="Microsoft Remote Desktop")
                if b"\xFE\x53\x4D\x42" in raw or b"\xFF\x53\x4D\x42" in raw:
                    return ServiceResult(port=port, service="smb", version="Microsoft SMB service")
                version = f"{probe_name}: {format_banner_bytes(raw, max_text=72, max_hex=20)}"
                return ServiceResult(port=port, service="proprietary", version=version)
            except (OSError, asyncio.TimeoutError):
                continue
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
        return None
    async def _check_sensitive_paths(self, result: ServiceResult, session) -> list[WebFinding]:
        if not self.check_sensitive_paths or result.service not in {"http", "https"}:
            return []
        if self.web_controller is None or aiohttp is None:
            return []
        scheme = result.service
        host = self.target.original
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host if result.port in {80, 443} else f"{host}:{result.port}"
        base_url = f"{scheme}://{netloc}"
        findings: list[WebFinding] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async def fetch_path(path: str) -> WebFinding | None:
            response = await self.web_controller.request(
                session=session,
                url=base_url + path,
                timeout=timeout,
                ssl_policy=self._request_ssl_policy(),
                allow_redirects=False,
            )
            if response is None:
                return None
            if response.status == 200:
                return WebFinding(
                    path=path,
                    status=response.status,
                    size=len(response.body),
                    content_type=response.headers.get("content-type", ""),
                )
            return None
        path_results = await asyncio.gather(
            *(fetch_path(path) for path in SENSITIVE_PATHS),
            return_exceptions=True,
        )
        for item in path_results:
            if isinstance(item, WebFinding):
                findings.append(item)
        return findings
    async def detect_one(self, port: int, semaphore: asyncio.Semaphore, session) -> ServiceResult:
        async with semaphore:
            result: ServiceResult | None = None
            result = await self._first_successful_http_probe(port, session)
            if self.web_only:
                if result is None:
                    return ServiceResult(
                        port=port,
                        service="unknown",
                        version="web probe failed",
                        notes=["Web-only mode skipped direct TCP fallback probes"],
                    )
                result.sensitive_paths = await self._check_sensitive_paths(result, session)
                result.cves = await self.cve_lookup.query(result.service, result.version, session)
                return result
            if result is None:
                result = await self._probe_known_greeting(port)
            if result.service == "unknown" and port in WEB_PORT_HINTS:
                fallback = await self._probe_http_via_session(port, tls=False, session=session)
                if fallback is not None:
                    result = fallback
            if result.service == "unknown" and port not in TLS_PORT_HINTS:
                tls_result = await self._probe_http_via_session(port, tls=True, session=session)
                if tls_result is not None:
                    result = tls_result
            if result.service == "unknown" and (
                result.version in {"open, no banner", "open, probe failed"}
                or result.version.startswith("<Binary Data:")
            ):
                active_result = await self._probe_active_payloads(port)
                if active_result is not None:
                    if active_result.service in {"tls", "rdp", "smb"}:
                        result = active_result
                    elif result.version in {"open, no banner", "open, probe failed"}:
                        result = active_result
            if result.service == "unknown":
                hinted = self._port_hint_result(port, result)
                if hinted is not None:
                    result = hinted
            result.sensitive_paths = await self._check_sensitive_paths(result, session)
            result.cves = await self.cve_lookup.query(result.service, result.version, session)
            return result
    async def detect(self, ports: list[int]) -> dict[int, ServiceResult]:
        semaphore = asyncio.Semaphore(self.concurrency)
        if aiohttp is None:
            raise SystemExit("aiohttp required for service detection")
        connector = aiohttp.TCPConnector(ssl=self._request_ssl_policy(), limit=max(self.concurrency, 20))
        timeout = aiohttp.ClientTimeout(total=max(self.timeout, 5.0))
        collected: dict[int, ServiceResult] = {}
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.detect_one(port, semaphore, session) for port in ports]
            print_stage(
                "Service Detection",
                f"Timeout: {self.timeout:.2f}s | Concurrency: {self.concurrency} | Targets: {len(ports)} open ports",
            )
            for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
                result = await task
                collected[result.port] = result
                if idx % 10 == 0 or idx == len(tasks):
                    sys.stdout.write(Fore.CYAN + "\r" + render_progress("Fingerprinting", idx, len(tasks)))
                    sys.stdout.flush()
        print()
        return collected
# --------------------------------------------------------------------------
# Diff engine
# --------------------------------------------------------------------------
class DiffEngine:
    @staticmethod
    def compare(old_report_path: str, current: dict[int, ServiceResult], base_dir: str | Path = ".") -> list[str]:
        base_path = Path(base_dir).resolve()
        path = Path(old_report_path)
        if not path.is_absolute():
            path = base_path / path
        path = path.resolve()
        try:
            path.relative_to(base_path)
        except ValueError:
            return [f"Rejected compare path outside output directory: {path}"]
        if path.suffix.lower() != ".json":
            return [f"Rejected compare path with non-JSON extension: {path}"]
        if not path.exists():
            return [f"Previous report not found: {path}"]
        with path.open("r", encoding="utf-8") as handle:
            old_report = json.load(handle)
        old_ports = {int(item["port"]): item for item in old_report.get("ports", [])}
        messages: list[str] = []
        for port, result in current.items():
            old = old_ports.get(port)
            if old is None:
                messages.append(f"New open port: {port}/{result.transport} ({result.service} {result.version})")
                continue
            if result.version != old.get("version"):
                messages.append(f"Version changed on port {port}: {old.get('version')} -> {result.version}")
        for old_port in sorted(set(old_ports) - set(current)):
            messages.append(f"Previously open port is no longer open: {old_port}")
        return messages
# --------------------------------------------------------------------------
# UI helpers
# --------------------------------------------------------------------------
def print_banner() -> None:
    print(
        Fore.RED + Style.BRIGHT
        + r"""
  ____ ____  ___ __  __ ____   ___  _   _
 / ___|  _ \|_ _|  \/  / ___| / _ \| \ | |
| |   | |_) || || |\/| \___ \| | | |  \| |
| |___|  _ < | || |  | |___) | |_| | |\  |
 \____|_| \_\___|_|  |_|____/ \___/|_| \_|
"""
        + Style.RESET_ALL
    )
    print(Fore.LIGHTBLACK_EX + "  " + "-" * 70)
    print(Fore.WHITE + Style.BRIGHT + f"  Crimson Core v{APP_VERSION} | Authorized Adversary-Emulation Scanner")
    print(Fore.RED + "  Multi-egress | ban-aware | adaptive pacing | audit logged")
    print(Fore.LIGHTBLACK_EX + "  " + "-" * 70 + "\n")
def print_stage(title: str, detail: str = "") -> None:
    line = "=" * 78
    print(Fore.CYAN + line)
    print(Fore.WHITE + Style.BRIGHT + f"[ {title} ]")
    if detail:
        print(Fore.LIGHTBLACK_EX + detail)
    print(Fore.CYAN + line)
def render_progress(prefix: str, done: int, total: int, width: int = 28) -> str:
    total = max(total, 1)
    ratio = min(max(done / total, 0.0), 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(ratio * 100)
    return f"{prefix} [{bar}] {percent:>3}% ({done}/{total})"
def trim_text(value: str | None, width: int) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."
def result_color(result: ServiceResult) -> str:
    if result.service in {"http", "https"}:
        return Fore.GREEN
    if result.service in {"ssh", "smtp", "ftp", "mysql", "pop3", "imap/pop"}:
        return Fore.CYAN
    if result.cves or result.sensitive_paths:
        return Fore.YELLOW
    return Fore.WHITE
# --------------------------------------------------------------------------
# Markdown executive report
# --------------------------------------------------------------------------
def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev.upper(), 4)
def _max_severity(results: dict[int, ServiceResult]) -> str:
    severities = []
    for result in results.values():
        for cve in result.cves:
            severities.append(cve.get("severity", "unknown"))
    if not severities:
        return "LOW" if any(r.sensitive_paths for r in results.values()) else "INFO"
    severities.sort(key=_severity_rank)
    return severities[0].upper()
def write_executive_report(
    target: Target,
    results: dict[int, ServiceResult],
    roe_ref: str | None,
    scan_mode: str,
    web_policy: dict,
    raw_report_path: Path,
    output_path: Path,
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_cves = sum(len(r.cves) for r in results.values())
    total_sensitive = sum(len(r.sensitive_paths) for r in results.values())
    open_count = len(results)
    max_sev = _max_severity(results)
    risk_label = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Informational",
    }.get(max_sev, "Unknown")
    lines: list[str] = []
    lines.append(f"# Crimson Scan Report — {target.original}")
    lines.append("")
    lines.append(f"- **Scan time (UTC):** {timestamp}")
    lines.append(f"- **Target:** `{target.original}` (`{target.address}`)")
    lines.append(f"- **RoE reference:** `{roe_ref or 'N/A'}`")
    lines.append(f"- **Scan mode:** {scan_mode}")
    lines.append(f"- **Egress mode:** {web_policy.get('egress', {}).get('mode', 'direct')}")
    lines.append(f"- **Tool:** {APP_NAME} v{APP_VERSION}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"Scan identified **{open_count}** open service(s), "
        f"**{total_cves}** potential CVE match(es), "
        f"**{total_sensitive}** sensitive path exposure(s). "
        f"Overall risk: **{risk_label}**."
    )
    lines.append("")
    if max_sev in {"CRITICAL", "HIGH"}:
        lines.append("**Recommendation:** Immediate remediation required for findings flagged Critical/High. ")
        lines.append("See Findings section. Patch within 72 hours.")
    elif max_sev == "MEDIUM":
        lines.append("**Recommendation:** Address findings within the next planned patch cycle.")
    else:
        lines.append("**Recommendation:** Monitor and address as part of normal hardening.")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("Authorized scan executed against the in-scope hosts under the referenced RoE. ")
    lines.append("Techniques applied:")
    lines.append("")
    lines.append("- Port discovery (async-connect / SYN as configured)")
    lines.append("- Service fingerprinting via banner grabbing and protocol probes")
    lines.append("- Passive WAF/header analysis")
    lines.append("- Sensitive path enumeration (limited list)")
    lines.append("- NVD CVE correlation by detected version")
    lines.append("- Multi-egress traffic with ban-aware backoff and adaptive pacing")
    lines.append("")
    lines.append("Excluded by RoE: active exploitation, DoS, exfiltration, social engineering.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not any(r.cves or r.sensitive_paths for r in results.values()):
        lines.append("_No CVE matches or sensitive-path exposures identified._")
        lines.append("")
    else:
        for port in sorted(results):
            result = results[port]
            if not (result.cves or result.sensitive_paths):
                continue
            lines.append(f"### Port {port}/{result.transport} — {result.service}")
            lines.append("")
            lines.append(f"- **Version:** `{result.version}`")
            if result.title:
                lines.append(f"- **Title:** {trim_text(result.title, 80)}")
            if result.waf:
                lines.append(f"- **WAF detected:** {result.waf}")
            if result.sensitive_paths:
                lines.append("- **Sensitive paths exposed:**")
                for finding in result.sensitive_paths:
                    lines.append(f"    - `{finding.path}` (status={finding.status}, size={finding.size})")
            if result.cves:
                lines.append("- **Potential CVEs:**")
                for cve in result.cves:
                    lines.append(f"    - `{cve.get('id')}` ({cve.get('severity', 'unknown')}): "
                                 f"{trim_text(cve.get('description', ''), 200)}")
            lines.append("")
            lines.append("**Remediation:** Upgrade to a patched release, restrict exposure where possible, ")
            lines.append("monitor logs for exploitation attempts. Verify with vendor advisories.")
            lines.append("")
    lines.append("## Egress & Behavioral Log Summary")
    lines.append("")
    egress = web_policy.get("egress", {})
    nodes = egress.get("nodes", [])
    lines.append(f"- **Egress mode:** {egress.get('mode')}")
    lines.append(f"- **Total egress nodes:** {len(nodes)}")
    total_reqs = sum(n.get("total_requests", 0) for n in nodes)
    total_fails = sum(n.get("total_failures", 0) for n in nodes)
    lines.append(f"- **Total requests:** {total_reqs} (failures: {total_fails})")
    blocked = web_policy.get("blocked_targets", [])
    lines.append(f"- **Block events:** {len(blocked)}")
    if blocked:
        for ev in blocked[:10]:
            lines.append(f"    - `{ev.get('url')}` — {ev.get('reason')} (egress={ev.get('egress_id')})")
    lines.append("")
    lines.append("## Appendix")
    lines.append("")
    lines.append(f"- **Raw JSON report:** `{raw_report_path}`")
    lines.append(f"- **Audit log (text):** `{LOG_FILE_TEXT}`")
    lines.append(f"- **Audit log (JSONL):** `{LOG_FILE_JSONL}`")
    lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
# --------------------------------------------------------------------------
# BlueScanner — orchestrator
# --------------------------------------------------------------------------
class BlueScanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.target = resolve_target(args.target)
        self.ports = parse_ports(args)
        self.scan_mode = self._select_scan_mode()
        self.state_path = self._resolve_state_path()
        self.state = self._load_or_init_state()
        egress = build_egress_from_args(args)
        decoy_paths = self._build_decoy_paths()
        pacer = AdaptivePacer(
            base_delay=args.web_request_delay,
            sensitive_delay=args.web_sensitive_delay,
            max_global_rate=args.web_max_global_rate,
        )
        ban = BanSignalAnalyzer(
            stop_statuses=parse_status_codes(args.web_stop_statuses),
            soft_threshold=args.ban_soft_threshold,
        )
        decoy = DecoyInjector(rate=args.decoy_rate, paths=decoy_paths)
        self.web_controller = WebRequestController(
            egress=egress,
            pacer=pacer,
            ban_analyzer=ban,
            decoy=decoy,
            max_retries=args.web_max_retries,
            user_agent=args.user_agent,
            fingerprint=args.fingerprint,
            state=self.state,
            state_path=self.state_path,
        )
    def _resolve_state_path(self) -> Path:
        if self.args.state_file:
            return Path(self.args.state_file).expanduser().resolve()
        return default_state_path(self.target.original)
    def _load_or_init_state(self) -> ScanState:
        if self.args.resume:
            existing = load_state(self.state_path)
            if existing is not None:
                audit_event("state_resumed", state_path=str(self.state_path),
                            completed_ports=len(existing.completed_ports))
                return existing
            logging.info("No prior state found at %s — starting fresh", self.state_path)
        state = ScanState.new(self.target.original, roe_ref=self.args.roe_confirmed)
        save_state(state, self.state_path)
        return state
    def _build_decoy_paths(self) -> list[str]:
        if self.state.discovered_decoy_paths:
            return list(self.state.discovered_decoy_paths)
        return list(DECOY_FALLBACK_PATHS)
    def _select_scan_mode(self) -> str:
        if self.args.web_only:
            return "web-only"
        if self.args.syn:
            return "syn"
        return "connect"  # SYN no longer auto-selected; must be explicit
    async def _maybe_recon_decoys(self) -> None:
        """If state has no recon paths, run passive recon now."""
        if self.args.no_recon:
            return
        if self.state.discovered_decoy_paths:
            return
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target.original}/"
            paths = await passive_recon(url, timeout=5.0)
            if paths:
                self.state.add_decoy_paths(paths)
                save_state(self.state, self.state_path)
                # Rebuild decoy injector with new paths
                self.web_controller.decoy = DecoyInjector(rate=self.args.decoy_rate, paths=paths)
                break
    async def run(self) -> int:
        print_banner()
        print_stage(
            "Session",
            f"Target: {self.target.original} ({self.target.address}) | "
            f"Ports: {len(self.ports)} | Mode: {self.scan_mode} | "
            f"RoE: {self.args.roe_confirmed}",
        )
        logging.info("Scan started for %s (%s)", self.target.original, self.target.address)
        audit_event(
            "scan_started",
            target=self.target.original,
            address=self.target.address,
            scan_mode=self.scan_mode,
            ports=len(self.ports),
            roe_ref=self.args.roe_confirmed,
        )
        if self.web_controller.uses_proxy:
            print_stage(
                "Egress Policy",
                f"Mode: {self.web_controller.egress.mode.value} | "
                f"Nodes: {len(self.web_controller.egress.nodes)} | "
                f"Pacer base: {self.web_controller.pacer.base_delay:.1f}s | "
                f"Sensitive: {self.web_controller.pacer.sensitive_delay:.1f}s | "
                f"Global cap: {self.web_controller.pacer.max_global_rate} req/min | "
                f"Decoy rate: {self.web_controller.decoy.rate:.2f}",
            )
        await self._maybe_recon_decoys()
        if self.scan_mode == "web-only":
            open_ports = self.ports
            os_hints: dict[int, str] = {}
        elif self.scan_mode == "syn":
            open_ports = await asyncio.get_event_loop().run_in_executor(None, self._run_syn_scan)
            os_hints = getattr(self, "_syn_os_hints", {})
        else:
            scanner = AsyncConnectScanner(
                self.target,
                concurrency=self.args.port_concurrency,
                timeout=self.args.timeout,
            )
            open_ports = await scanner.scan(self.ports)
            os_hints = {}
        if not open_ports and not self.args.udp:
            print(Fore.YELLOW + "No open TCP ports found.")
            audit_event("scan_no_open_ports")
            return 0
        results: dict[int, ServiceResult] = {}
        cve_lookup = CveLookup(enabled=not self.args.no_cve)
        try:
            detector = ServiceDetector(
                self.target,
                concurrency=self.args.service_concurrency,
                timeout=self.args.banner_timeout,
                check_sensitive_paths=not self.args.no_web_checks,
                cve_lookup=cve_lookup,
                web_controller=self.web_controller,
                web_only=self.args.web_only,
            )
            if open_ports:
                results = await detector.detect(open_ports)
        finally:
            await cve_lookup.aclose()
        for port, hint in os_hints.items():
            if port in results:
                results[port].os_hint = hint
        if self.args.udp:
            udp_results = await UdpScanner(self.target, timeout=self.args.udp_timeout).scan()
            for port, udp_result in udp_results.items():
                if port in results:
                    results[port].notes.append(f"UDP {udp_result.service}: {udp_result.version}")
                    continue
                results[port] = udp_result
        if not results:
            print(Fore.YELLOW + "No open TCP ports or UDP responders found.")
            return 0
        self._print_results(results)
        self._print_web_blocks()
        if self.args.compare:
            self._print_diff(DiffEngine.compare(self.args.compare, results, self.args.output_dir))
        report_path = self._write_report(results)
        print(Fore.CYAN + f"\nRaw report saved: {report_path}")
        # Executive markdown report (always written alongside)
        exec_path = report_path.with_suffix(".executive.md")
        write_executive_report(
            target=self.target,
            results=results,
            roe_ref=self.args.roe_confirmed,
            scan_mode=self.scan_mode,
            web_policy=self.web_controller.report_metadata(),
            raw_report_path=report_path,
            output_path=exec_path,
        )
        print(Fore.CYAN + f"Executive report: {exec_path}")
        audit_event("scan_finished", target=self.target.original, open_services=len(results))
        logging.info("Scan finished for %s", self.target.address)
        # Save final state
        for port in results:
            self.state.mark_port_done(port)
        save_state(self.state, self.state_path)
        return 0
    def _run_syn_scan(self) -> list[int]:
        try:
            scanner = SynScanner(
                self.target,
                timeout=self.args.timeout,
                retry=self.args.retry,
                batch_size=self.args.batch_size,
            )
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        ports = scanner.scan(self.ports)
        self._syn_os_hints = scanner.os_hints
        return ports
    @staticmethod
    def _print_diff(messages: list[str]) -> None:
        if not messages:
            return
        print_stage("Diff Report")
        for message in messages:
            print(Fore.MAGENTA + f"  - {message}")
    @staticmethod
    def _print_results(results: dict[int, ServiceResult]) -> None:
        print_stage("Results", f"Open services discovered: {len(results)}")
        print(Fore.CYAN + "-" * 120)
        print(
            Fore.WHITE + Style.BRIGHT
            + f"{'PORT':<8} {'SERVICE':<10} {'TLS':<5} {'OS HINT':<22} {'VERSION':<34} {'FINDINGS'}"
        )
        print(Fore.CYAN + "-" * 120)
        total_cves = 0
        total_sensitive = 0
        web_services = 0
        for port in sorted(results):
            result = results[port]
            findings = []
            if result.waf:
                findings.append(f"WAF={result.waf}")
            if result.sensitive_paths:
                findings.append(f"files={len(result.sensitive_paths)}")
            if result.cves:
                findings.append(f"cves={len(result.cves)}")
            if result.os_hint:
                findings.append(f"os={result.os_hint}")
            if result.http_status is not None:
                findings.append(f"http={result.http_status}")
            if result.title:
                findings.append(f"title={trim_text(result.title, 22)}")
            total_cves += len(result.cves)
            total_sensitive += len(result.sensitive_paths)
            if result.service in {"http", "https"}:
                web_services += 1
            color = result_color(result)
            print(
                color
                + f"{port:<8} {result.service:<10} {str(result.tls):<5} "
                + f"{trim_text(result.os_hint or '-', 22):<22} "
                + f"{trim_text(result.version, 34):<34} "
                + trim_text(", ".join(findings) or "-", 38)
            )
        print(Fore.CYAN + "-" * 120)
        print(
            Fore.WHITE + Style.BRIGHT
            + f"Summary: {len(results)} open port(s) | {web_services} web service(s) | "
            + f"{total_sensitive} sensitive path hit(s) | {total_cves} CVE match(es)"
        )
        print(Fore.CYAN + "=" * 120)
    def _print_web_blocks(self) -> None:
        if not self.web_controller.block_events:
            return
        print_stage("Web Blocks", f"Blocked host/path targets observed: {len(self.web_controller.block_events)}")
        for event in self.web_controller.block_events:
            print(
                Fore.YELLOW
                + f"  - {event.status} {event.url} | {event.reason} | egress={event.egress_id}"
            )
    def _write_report(self, results: dict[int, ServiceResult]) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target.address)
        output_dir = Path(self.args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        extension = {"json": "json", "csv": "csv", "markdown": "md"}[self.args.format]
        report_path = output_dir / f"{REPORT_PREFIX}_{safe_target}_{timestamp}.{extension}"
        payload = {
            "scanner": APP_NAME,
            "version": APP_VERSION,
            "target": asdict(self.target),
            "timestamp_utc": timestamp,
            "scan_mode": self.scan_mode,
            "roe_ref": self.args.roe_confirmed,
            "web_policy": self.web_controller.report_metadata(),
            "ports": [self._serialize_result(results[port]) for port in sorted(results)],
        }
        if self.args.format == "json":
            with report_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        elif self.args.format == "csv":
            with report_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["port", "service", "version", "cves"])
                writer.writeheader()
                for result in (results[port] for port in sorted(results)):
                    writer.writerow({
                        "port": result.port,
                        "service": result.service,
                        "version": result.version,
                        "cves": ",".join(cve.get("id", "") for cve in result.cves),
                    })
        else:
            with report_path.open("w", encoding="utf-8") as handle:
                handle.write("| Port | Service | Version | CVEs |\n")
                handle.write("| --- | --- | --- | --- |\n")
                for result in (results[port] for port in sorted(results)):
                    cves = ", ".join(cve.get("id", "") for cve in result.cves) or "-"
                    handle.write(
                        f"| {result.port}/{result.transport} | {result.service} | "
                        f"{result.version.replace('|', '/')} | {cves} |\n"
                    )
        return report_path
    @staticmethod
    def _serialize_result(result: ServiceResult) -> dict:
        return asdict(result)
# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} — authorized adversary-emulation scanner. "
                    "Use ONLY with a signed RoE.",
    )
    # Required RoE attestation
    parser.add_argument(
        "--roe-confirmed",
        required=True,
        help="Mandatory: signed RoE reference (e.g. 'RoE-2026-BLD-001'). "
             "Logged to audit trail.",
    )
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port for range scans")
    parser.add_argument("-e", "--end", type=int, default=65535, help="End port for range scans")
    parser.add_argument("-p", "--ports", help="Comma-separated ports/ranges, e.g.: 22,80,443,8000-8100")
    parser.add_argument("--top-ports", action="store_true", help="Use the built-in curated top ports list")
    parser.add_argument("--syn", action="store_true", help="Use privileged SYN scanning via Scapy (explicit)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--banner-timeout", type=float, default=DEFAULT_BANNER_TIMEOUT)
    parser.add_argument("--retry", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--port-concurrency", type=int, default=DEFAULT_PORT_CONCURRENCY)
    parser.add_argument("--service-concurrency", type=int, default=DEFAULT_SERVICE_CONCURRENCY)
    parser.add_argument("--no-cve", action="store_true")
    parser.add_argument("--no-web-checks", action="store_true")
    parser.add_argument("--no-recon", action="store_true",
                        help="Skip passive recon for decoy path discovery")
    parser.add_argument("--compare", help="Compare against a previous JSON report")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT)
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument("--web-only", action="store_true",
                        help="Skip TCP/UDP discovery, treat selected ports as HTTP(S) targets")
    # Egress: --web-tor and --egress-config are mutually exclusive
    parser.add_argument("--web-tor", action="store_true",
                        help=f"Route web requests through local Tor SOCKS at {DEFAULT_TOR_SOCKS_PROXY}")
    parser.add_argument("--egress-config",
                        help="Path to YAML egress config (multi_egress mode)")
    # Tor control
    parser.add_argument("--tor-new-identity", action="store_true",
                        help="Request a fresh Tor circuit before scan starts")
    parser.add_argument("--tor-control-host", default=DEFAULT_TOR_CONTROL_HOST)
    parser.add_argument("--tor-control-port", type=int, default=DEFAULT_TOR_CONTROL_PORT)
    parser.add_argument("--tor-control-password")
    parser.add_argument("--tor-control-cookie")
    parser.add_argument("--tor-new-identity-wait", type=float, default=DEFAULT_TOR_NEW_IDENTITY_WAIT)
    # Legacy single-proxy (kept for backwards compatibility)
    parser.add_argument("--web-proxy", help="DEPRECATED: use --egress-config")
    parser.add_argument("--web-proxy-file", help="DEPRECATED: use --egress-config")
    # Pacing
    parser.add_argument("--web-request-delay", type=float, default=DEFAULT_WEB_REQUEST_DELAY)
    parser.add_argument("--web-sensitive-delay", type=float, default=DEFAULT_WEB_SENSITIVE_DELAY)
    parser.add_argument("--web-max-global-rate", type=int, default=DEFAULT_WEB_MAX_GLOBAL_RATE)
    parser.add_argument("--web-max-retries", type=int, default=0)
    parser.add_argument("--web-stop-statuses", default="403,429,503")
    # Ban detection
    parser.add_argument("--ban-soft-threshold", type=int, default=DEFAULT_BAN_SOFT_THRESHOLD,
                        help="Number of soft signals before egress cooldown")
    parser.add_argument("--ban-cooldown", type=float, default=DEFAULT_BAN_COOLDOWN_SECONDS,
                        help="Base cooldown seconds for banned egress nodes")
    # Optional browser/request realism controls; disabled by default.
    parser.add_argument("--user-agent", help="Fixed User-Agent string")
    parser.add_argument("--fingerprint", choices=tuple(FINGERPRINT_PROFILES),
                        help="TLS fingerprint profile via curl_cffi (optional dep)")
    parser.add_argument("--decoy-rate", type=float, default=DEFAULT_DECOY_RATE,
                        help="Probability of injecting a decoy request (0.0-1.0)")
    # State / resume
    parser.add_argument("--state-file", help="Custom state file path "
                                             "(default: ~/.crimson/state/<hash>.json)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from prior state if available")
    return parser
def validate_args(args: argparse.Namespace) -> None:
    # RoE format
    if not ROE_REF_PATTERN.match(args.roe_confirmed or ""):
        raise SystemExit(
            "--roe-confirmed must be a non-empty token of 4–128 chars "
            "(letters, digits, ._-:/)."
        )
    # Egress mutex
    if args.web_tor and args.egress_config:
        raise SystemExit("--web-tor cannot be combined with --egress-config")
    if args.web_tor and (args.web_proxy or args.web_proxy_file):
        raise SystemExit("--web-tor cannot be combined with --web-proxy or --web-proxy-file")
    if args.egress_config and (args.web_proxy or args.web_proxy_file):
        raise SystemExit("--egress-config cannot be combined with legacy --web-proxy(-file)")
    # Tor flag implications
    if args.web_tor and not args.web_only:
        raise SystemExit("--web-tor requires --web-only (direct TCP discovery would leak your IP)")
    if args.tor_new_identity and not args.web_only:
        raise SystemExit("--tor-new-identity requires --web-only")
    if args.tor_new_identity and not args.web_tor and not (args.web_proxy or "").startswith("socks5"):
        raise SystemExit("--tor-new-identity requires --web-tor or a local Tor SOCKS --web-proxy")
    # Mode combinations
    if args.web_only and args.syn:
        raise SystemExit("--web-only cannot be combined with --syn")
    if args.web_only and args.udp:
        raise SystemExit("--web-only cannot be combined with --udp")
    # SYN privilege check
    if args.syn and not has_elevated_privileges():
        raise SystemExit("--syn requires elevated privileges (run as root / Administrator)")
    # Decoy rate range
    if not 0.0 <= args.decoy_rate <= 1.0:
        raise SystemExit("--decoy-rate must be between 0.0 and 1.0")
def write_roe_attestation(args: argparse.Namespace) -> None:
    """Record RoE attestation as the first audit event."""
    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"
    audit_event(
        "roe_attestation",
        operator=operator,
        roe_ref=args.roe_confirmed,
        host=socket.gethostname(),
        cli=" ".join(sys.argv),
        version=APP_VERSION,
    )
# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv: Iterable[str] | None = None) -> int:
    colorama_init(autoreset=True)
    args = build_parser().parse_args(argv)
    validate_args(args)
    setup_logging(args.output_dir)
    write_roe_attestation(args)
    if AIOHTTP_IMPORT_ERROR is not None:
        raise SystemExit(
            f"Missing dependency: {AIOHTTP_IMPORT_ERROR}. "
            "Install with: pip install -r requirements.txt"
        )
    if HTTPX_IMPORT_ERROR is not None and not args.no_cve:
        raise SystemExit(
            f"Missing dependency for CVE lookup: {HTTPX_IMPORT_ERROR}. "
            "Install with: pip install httpx, or pass --no-cve."
        )
    if THROTTLE_IMPORT_ERROR is not None and not args.no_cve:
        logging.warning("asyncio_throttle not installed; CVE rate limiting disabled")
    if args.web_tor and AIOHTTP_SOCKS_IMPORT_ERROR is not None:
        raise SystemExit(
            "aiohttp_socks required for --web-tor. Install: pip install aiohttp-socks"
        )
    if args.fingerprint and not CURL_CFFI_AVAILABLE:
        logging.warning("--fingerprint requested but curl_cffi missing — falling back to aiohttp")
    if args.tor_new_identity:
        print(Fore.CYAN + "Requesting new Tor identity before scan...")
        TorControlClient(
            host=args.tor_control_host,
            port=args.tor_control_port,
            password=args.tor_control_password,
            cookie_file=args.tor_control_cookie,
            new_identity_wait=args.tor_new_identity_wait,
        ).signal_new_identity()
    try:
        return asyncio.run(BlueScanner(args).run())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        audit_event("scan_interrupted")
        return 130
if __name__ == "__main__":
    raise SystemExit(main())
