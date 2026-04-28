#!/usr/bin/env python3
"""
BlueScanner Core Engine

Authorized security testing scanner for academic and blue-team use.

What this engine does:
  - Resolves IPv4 and IPv6 targets.
  - Scans TCP ports with a reliable async connect scanner by default.
  - Optionally performs a privileged SYN scan when Scapy and permissions exist.
  - Detects common services with lightweight protocol probes.
  - Handles HTTP and HTTPS automatically instead of relying only on fixed ports.
  - Performs passive WAF/header fingerprinting.
  - Checks a small list of sensitive web paths on confirmed web services.
  - Queries NVD CVEs with caching and bounded concurrency.
  - Writes a structured JSON report.

Use only on systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import aiohttp
except ImportError as exc:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_IMPORT_ERROR = exc
else:
    AIOHTTP_IMPORT_ERROR = None

try:
    from colorama import Fore, Style, init
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLACK_EX = RESET_ALL = BRIGHT = ""

    Fore = Style = _NoColor()

    def init(*_args, **_kwargs):
        return None

APP_NAME = "BlueScanner"
REPORT_PREFIX = "bluescan"
DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_BANNER_TIMEOUT = 3.0
DEFAULT_PORT_CONCURRENCY = 500
DEFAULT_SERVICE_CONCURRENCY = 50

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/robots.txt",
    "/server-status",
    "/server-info",
    "/admin",
    "/wp-config.php",
    "/config.php",
    "/.htpasswd",
    "/api/swagger.json",
    "/actuator/health",
    "/.DS_Store",
    "/phpinfo.php",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

TOP_PORTS = [
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
    999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035,
    1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046,
    1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057,
    1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068,
    1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079,
    1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1096, 1097, 1098, 1099, 1100, 1104, 1106,
    1107, 1108, 1110, 1111, 1112, 1114, 1117, 1119, 1122, 1124, 1131,
    1137, 1138, 1141, 1145, 1148, 1151, 1152, 1163, 1164, 1165, 1166,
    1169, 1175, 1183, 1186, 1199, 1201, 1218, 1233, 1234, 1247, 1248,
    1259, 1271, 1272, 1287, 1296, 1310, 1311, 1352, 1417, 1433, 1434,
    1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556,
    1580, 1600, 1666, 1687, 1700, 1717, 1718, 1720, 1723, 1755, 1761,
    1782, 1783, 1801, 1812, 1862, 1863, 1864, 1875, 1900, 1935, 1947,
    1984, 1993, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
    2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034,
    2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
    2065, 2068, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126,
    2135, 2144, 2160, 2161, 2179, 2190, 2191, 2222, 2251, 2260, 2301,
    2323, 2381, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2601,
    2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718,
    2725, 2809, 2869, 2875, 2909, 2967, 2998, 3000, 3001, 3003, 3005,
    3006, 3011, 3017, 3030, 3031, 3052, 3061, 3071, 3077, 31038, 3128,
    31337, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 32768, 32769, 32770,
    32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32781, 32782, 32783, 32784, 32785, 3300, 3301, 3304, 3306, 3307, 3322,
    3323, 3324, 3325, 3333, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493,
    3495, 3517, 3527, 3546, 3551, 3659, 3689, 3690, 3703, 3737, 3766, 3784,
    3800, 3801, 3808, 3809, 3814, 3820, 3826, 3827, 3828, 3849, 3851, 3852,
    3853, 3863, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3916, 3918, 3920,
    3944, 3945, 3963, 3971, 3981, 3986, 3995, 3998, 4000, 4001, 4002, 4003,
    4004, 4005, 4006, 4040, 4045, 4111, 4125, 4126, 4129, 4164, 4165, 4200,
    4224, 4242, 4252, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550,
    4555, 4567, 4658, 4662, 4750, 4827, 4848, 4899, 4900, 49152, 49153,
    49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 4998, 49999, 5000, 5001, 5002, 5003, 5004,
    5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5081, 5087, 5100,
    5101, 5102, 51103, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269,
    5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550,
    5555, 5560, 5566, 5631, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802,
    5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902,
    5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5938, 5950, 5952,
    5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002,
    6003, 6004, 6005, 6006, 6007, 6009, 6025, 6051, 6059, 6060, 6100, 6101,
    6106, 6112, 6123, 6129, 6156, 6346, 6389, 64623, 64680, 65000, 6502,
    6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669,
    6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000,
    7001, 7002, 7004, 7007, 7019, 7024, 7025, 7070, 7100, 7103, 7106, 7200,
    7201, 7272, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 765, 7676, 7741,
    7744, 7777, 7778, 7800, 7878, 7911, 7913, 7920, 7921, 7937, 7938, 7999,
    8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8019, 8021, 8022, 8031,
    8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8093, 8097, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
    8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600,
    8649, 8651, 8652, 8654, 8686, 8701, 8765, 8800, 8873, 8888, 8899, 8994,
    9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081,
    9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9191, 9200, 9207,
    9220, 9290, 9415, 9418, 9443, 9444, 9485, 9500, 9502, 9503, 9535, 9575,
    9593, 9594, 9595, 9618, 9666, 981, 9876, 9877, 9878, 9898, 9900, 9917,
    9929, 9943, 9944, 9968, 9988, 9998, 9999, 10000, 10001, 10002, 10003,
    10004, 10009, 10010, 10012, 10024, 10025, 10082, 10160, 10180, 10215,
    10243, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13724, 13782, 13783,
    14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
    16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877,
    17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801,
    19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502,
    24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356,
    27715, 28201, 30000, 30718, 33354, 33899, 3404, 34571, 34572, 34573,
    35500, 38292, 40000, 40193, 40911, 41511, 42510, 44176, 44442, 44443,
    44501, 45100, 48080, 50000, 50001, 50002, 50003, 50006, 50300, 50389,
    50500, 50636, 50800, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
    55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 5962,
    60020, 60443, 61532, 61900, 62078, 63331, 6481, 65129, 65389,
]

WEB_PORT_HINTS = {
    80, 81, 82, 83, 84, 85, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8180, 8181, 8443, 8834, 9000, 9090,
    9443, 10000,
}

TLS_PORT_HINTS = {
    443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 995, 8443, 8834, 9443,
}


def load_scapy():
    try:
        from scapy.all import IP, IPv6, TCP, conf, sr, sr1
    except ImportError as exc:
        raise RuntimeError("Scapy is required for --syn scans. Install it with: pip install scapy") from exc
    return IP, IPv6, TCP, conf, sr, sr1


@dataclass(slots=True)
class Target:
    original: str
    address: str
    family: int


@dataclass(slots=True)
class WebFinding:
    path: str
    status: int
    size: int
    content_type: str = ""


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


def setup_logging() -> None:
    logging.basicConfig(
        filename="bluescanner_audit.log",
        level=logging.INFO,
        format="%(asctime)s - [%(levelname)s] - %(message)s",
    )


def print_banner() -> None:
    print(
        Fore.CYAN
        + Style.BRIGHT
        + r"""
  ____  _            ____                                 
 | __ )| |_   _  ___/ ___|  ___ __ _ _ __  _ __   ___ _ __
 |  _ \| | | | |/ _ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |_) | | |_| |  __/___) | (_| (_| | | | | | | |  __/ |   
 |____/|_|\__,_|\___|____/ \___\__,_|_| |_|_| |_|\___|_|   
"""
        + Style.RESET_ALL
    )
    print(Fore.WHITE + Style.BRIGHT + "  Core Engine | Async + SYN + Service Intel")
    print(Fore.RED + "  Authorized testing only.\n")


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


def resolve_target(host: str) -> Target:
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SystemExit(f"Could not resolve target '{host}': {exc}") from exc

    preferred = sorted(records, key=lambda item: 0 if item[0] == socket.AF_INET else 1)[0]
    family = preferred[0]
    address = preferred[4][0]
    return Target(original=host, address=address, family=family)


def parse_ports(args: argparse.Namespace) -> list[int]:
    if args.ports:
        ports = set()
        for part in args.ports.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                if start > end:
                    raise SystemExit(f"Invalid port range: {part}")
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    elif args.top_ports:
        ports = set(TOP_PORTS)
    else:
        ports = set(range(args.start, args.end + 1))

    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise SystemExit(f"Invalid TCP port(s): {sorted(invalid)[:10]}")
    return sorted(ports)


def estimate_os_from_ttl(ttl: int, window: int, options: list[tuple]) -> str:
    if ttl <= 0:
        return "unknown"

    option_map = {key: value for key, value in options if isinstance(key, str)}
    mss = option_map.get("MSS")
    wscale = option_map.get("WScale")

    if ttl <= 64:
        if window == 65535 and wscale in {4, 5, 6}:
            return "macOS/FreeBSD-like"
        if mss == 1460 and wscale in {7, 8}:
            return "Linux-like"
        return "Unix-like"
    if ttl <= 128:
        if window in {8192, 16384, 64240, 65535}:
            return "Windows-like"
        return "Windows or embedded device"
    if ttl <= 255:
        if window == 4128:
            return "Cisco IOS-like"
        return "network device or Unix-like"
    return "unknown"


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
                await writer.wait_closed()
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


class SynScanner:
    def __init__(self, target: Target, timeout: float, retry: int, batch_size: int) -> None:
        self.IP, self.IPv6, self.TCP, self.conf, self.sr, self.sr1 = load_scapy()
        self.target = target
        self.timeout = timeout
        self.retry = retry
        self.batch_size = batch_size
        self.os_hints: dict[int, str] = {}

    def _layer(self):
        return self.IPv6(dst=self.target.address) if self.target.family == socket.AF_INET6 else self.IP(dst=self.target.address)

    def _scan_batch(self, ports: list[int]) -> list[int]:
        open_ports: list[int] = []
        pending = list(ports)
        ip_layer = self._layer()

        for _attempt in range(self.retry + 1):
            if not pending:
                break

            sport = random.randint(1024, 65535)
            packets = ip_layer / self.TCP(sport=sport, dport=pending, flags="S")
            answered, unanswered = self.sr(packets, timeout=self.timeout, verbose=0)

            for _sent, received in answered:
                if not received.haslayer(self.TCP):
                    continue
                tcp = received.getlayer(self.TCP)
                if int(tcp.flags) != 0x12:
                    continue

                port = int(tcp.sport)
                open_ports.append(port)

                ttl = 0
                if received.haslayer(self.IP):
                    ttl = int(received[self.IP].ttl)
                elif received.haslayer(self.IPv6):
                    ttl = int(received[self.IPv6].hlim)
                self.os_hints[port] = estimate_os_from_ttl(ttl, int(tcp.window), list(tcp.options))

                rst = ip_layer / self.TCP(sport=sport, dport=port, flags="R", seq=int(tcp.ack))
                self.sr1(rst, timeout=0.2, verbose=0)

            pending = [int(packet.dport) for packet in unanswered if packet.haslayer(self.TCP)]

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
            f"Mode: syn-stealth | Timeout: {self.timeout:.2f}s | Retry: {self.retry} | Batch size: {self.batch_size}",
        )

        for idx, batch in enumerate(batches, start=1):
            open_ports.update(self._scan_batch(batch))
            sys.stdout.write(Fore.CYAN + "\r" + render_progress("Scanning batches", idx, len(batches)))
            sys.stdout.flush()

        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)


class CveLookup:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, enabled: bool, concurrency: int = 3) -> None:
        self.enabled = enabled
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache: dict[str, list[dict[str, str]]] = {}

    @staticmethod
    def _query_from_version(service: str, version: str) -> str | None:
        if version.lower() in {"unknown", "filtered", "no response"}:
            return None
        cleaned = re.sub(r"\s+", " ", version).strip()
        cleaned = re.sub(r"[\r\n].*", "", cleaned)
        cleaned = cleaned[:80]
        if len(cleaned) < 4:
            return None
        if service == "http" and cleaned.lower().startswith("http/"):
            return None
        return cleaned

    async def query(self, service: str, version: str, session: aiohttp.ClientSession) -> list[dict[str, str]]:
        if not self.enabled:
            return []

        keyword = self._query_from_version(service, version)
        if not keyword:
            return []
        if keyword in self.cache:
            return self.cache[keyword]

        params = {"keywordSearch": keyword, "resultsPerPage": 3}
        headers = {}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        async with self.semaphore:
            try:
                async with session.get(self.NVD_API, params=params, headers=headers, timeout=8) as response:
                    if response.status != 200:
                        self.cache[keyword] = []
                        return []
                    payload = await response.json()
            except (aiohttp.ClientError, asyncio.TimeoutError):
                self.cache[keyword] = []
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
            findings.append(
                {
                    "id": cve.get("id", "unknown"),
                    "severity": severity,
                    "description": description[:160],
                }
            )

        self.cache[keyword] = findings
        return findings


class ServiceDetector:
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare"],
        "aws_waf": ["x-amzn-requestid", "x-amzn-waf"],
        "akamai": ["akamai", "akamai-ghost"],
        "f5_bigip": ["bigip", "x-wa-info"],
        "sucuri": ["x-sucuri-id", "sucuri"],
        "imperva": ["incap_ses", "visid_incap"],
    }

    def __init__(
        self,
        target: Target,
        concurrency: int,
        timeout: float,
        check_sensitive_paths: bool,
        cve_lookup: CveLookup,
    ) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.check_sensitive_paths = check_sensitive_paths
        self.cve_lookup = cve_lookup

    def _host_header(self, port: int) -> str:
        if ":" in self.target.original and not self.target.original.startswith("["):
            host = f"[{self.target.original}]"
        else:
            host = self.target.original
        if port in {80, 443}:
            return host
        return f"{host}:{port}"

    def _http_request(self, port: int, path: str = "/") -> bytes:
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self._host_header(port)}\r\n"
            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")

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

    @classmethod
    def _detect_waf(cls, headers: dict[str, str]) -> str | None:
        haystack = "\n".join([*headers.keys(), *headers.values()]).lower()
        for name, signatures in cls.WAF_SIGNATURES.items():
            if any(signature in haystack for signature in signatures):
                return name
        return None

    async def _open_plain(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(asyncio.open_connection(self.target.address, port), timeout=self.timeout)

    async def _open_tls(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server_hostname = self.target.original if not self._looks_like_ip(self.target.original) else None
        return await asyncio.wait_for(
            asyncio.open_connection(self.target.address, port, ssl=context, server_hostname=server_hostname),
            timeout=self.timeout,
        )

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    async def _read_greeting(self, reader: asyncio.StreamReader) -> bytes:
        try:
            return await asyncio.wait_for(reader.read(1024), timeout=min(1.2, self.timeout))
        except asyncio.TimeoutError:
            return b""

    async def _probe_http(
        self,
        port: int,
        tls: bool,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> ServiceResult | None:
        close_writer = False
        try:
            if reader is None or writer is None:
                reader, writer = await (self._open_tls(port) if tls else self._open_plain(port))
                close_writer = True

            writer.write(self._http_request(port))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(8192), timeout=self.timeout)
            text = raw.decode("utf-8", errors="ignore")
            if not text.startswith("HTTP/"):
                return None

            status, headers, title = self._parse_headers(text)
            server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
            scheme = "https" if tls else "http"
            return ServiceResult(
                port=port,
                service=scheme,
                version=server,
                tls=tls,
                http_status=status,
                title=title,
                headers=headers,
                waf=self._detect_waf(headers),
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
            text = greeting.decode("utf-8", errors="ignore").strip()

            if text.startswith("SSH-"):
                return ServiceResult(port=port, service="ssh", version=text.splitlines()[0])
            if text.startswith("220") and re.search(r"(ftp|filezilla|vsftpd|proftpd)", text, re.IGNORECASE):
                return ServiceResult(port=port, service="ftp", version=text.splitlines()[0])
            if text.startswith("220") and re.search(r"(smtp|mail|postfix|exim|sendmail)", text, re.IGNORECASE):
                return ServiceResult(port=port, service="smtp", version=text.splitlines()[0])
            if text.startswith("+OK"):
                service = "pop3" if port in {110, 995} else "imap/pop"
                return ServiceResult(port=port, service=service, version=text.splitlines()[0])
            if b"mysql_native_password" in greeting:
                printable = "".join(chr(byte) for byte in greeting if 32 <= byte <= 126)
                match = re.search(r"(\d+\.\d+\.\d+[\w.-]*)", printable)
                version = f"MySQL {match.group(1)}" if match else "MySQL-compatible server"
                return ServiceResult(port=port, service="mysql", version=version)

            http = await self._probe_http(port, tls=False, reader=reader, writer=writer)
            if http:
                writer = None
                return http

            if text:
                return ServiceResult(port=port, service="unknown", version=text[:120])
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

    async def _check_sensitive_paths(
        self,
        result: ServiceResult,
        session: aiohttp.ClientSession,
    ) -> list[WebFinding]:
        if not self.check_sensitive_paths or result.service not in {"http", "https"}:
            return []

        scheme = result.service
        host = self.target.original
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host if result.port in {80, 443} else f"{host}:{result.port}"
        base_url = f"{scheme}://{netloc}"

        findings: list[WebFinding] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        for path in SENSITIVE_PATHS:
            try:
                async with session.get(
                    base_url + path,
                    timeout=timeout,
                    ssl=False,
                    allow_redirects=False,
                    headers={"User-Agent": random.choice(USER_AGENTS)},
                ) as response:
                    body = await response.read()
                    if response.status == 200:
                        findings.append(
                            WebFinding(
                                path=path,
                                status=response.status,
                                size=len(body),
                                content_type=response.headers.get("content-type", ""),
                            )
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        return findings

    async def detect_one(
        self,
        port: int,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> ServiceResult:
        async with semaphore:
            result: ServiceResult | None = None

            if port in TLS_PORT_HINTS:
                result = await self._probe_http(port, tls=True)
            if result is None:
                result = await self._probe_known_greeting(port)
            if result.service == "unknown" and port in WEB_PORT_HINTS:
                result = await self._probe_http(port, tls=False) or result
            if result.service == "unknown" and port not in TLS_PORT_HINTS:
                tls_result = await self._probe_http(port, tls=True)
                if tls_result is not None:
                    result = tls_result

            result.sensitive_paths = await self._check_sensitive_paths(result, session)
            result.cves = await self.cve_lookup.query(result.service, result.version, session)
            return result

    async def detect(self, ports: list[int]) -> dict[int, ServiceResult]:
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=max(self.concurrency, 20))
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


class DiffEngine:
    @staticmethod
    def compare(old_report_path: str, current_results: dict[int, ServiceResult]) -> list[str]:
        path = Path(old_report_path)
        if not path.exists():
            return [f"Previous report not found: {path}"]

        with path.open("r", encoding="utf-8") as handle:
            old_report = json.load(handle)

        old_ports = {int(item["port"]): item for item in old_report.get("ports", [])}
        messages: list[str] = []

        for port, result in current_results.items():
            old = old_ports.get(port)
            if old is None:
                messages.append(f"New open port: {port}/{result.transport} ({result.service} {result.version})")
                continue
            if result.version != old.get("version"):
                messages.append(f"Version changed on port {port}: {old.get('version')} -> {result.version}")

        for old_port in sorted(set(old_ports) - set(current_results)):
            messages.append(f"Previously open port is no longer open: {old_port}")

        return messages


class BlueScanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.target = resolve_target(args.target)
        self.ports = parse_ports(args)

    async def run(self) -> int:
        print_banner()
        print_stage(
            "Session",
            (
                f"Target: {self.target.original} ({self.target.address}) | "
                f"Ports selected: {len(self.ports)} | "
                f"Scan mode: {'SYN' if self.args.syn else 'Connect'}"
            ),
        )
        logging.info("Scan started for %s (%s)", self.target.original, self.target.address)

        if self.args.syn:
            open_ports = self._run_syn_scan()
            os_hints = getattr(self, "_syn_os_hints", {})
        else:
            scanner = AsyncConnectScanner(
                self.target,
                concurrency=self.args.port_concurrency,
                timeout=self.args.timeout,
            )
            open_ports = await scanner.scan(self.ports)
            os_hints = {}

        if not open_ports:
            print(Fore.YELLOW + "No open TCP ports found.")
            return 0

        cve_lookup = CveLookup(enabled=not self.args.no_cve)
        detector = ServiceDetector(
            self.target,
            concurrency=self.args.service_concurrency,
            timeout=self.args.banner_timeout,
            check_sensitive_paths=not self.args.no_web_checks,
            cve_lookup=cve_lookup,
        )

        results = await detector.detect(open_ports)
        for port, hint in os_hints.items():
            if port in results:
                results[port].os_hint = hint

        self._print_results(results)
        if self.args.compare:
            self._print_diff(DiffEngine.compare(self.args.compare, results))

        report_path = self._write_report(results)
        print(Fore.CYAN + f"\nJSON report saved: {report_path}")
        logging.info("Scan finished for %s", self.target.address)
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
            Fore.WHITE
            + Style.BRIGHT
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
            Fore.WHITE
            + Style.BRIGHT
            + (
                f"Summary: {len(results)} open port(s) | "
                f"{web_services} web service(s) | "
                f"{total_sensitive} sensitive path hit(s) | "
                f"{total_cves} CVE match(es)"
            )
        )
        print(Fore.CYAN + "=" * 120)

    def _write_report(self, results: dict[int, ServiceResult]) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target.address)
        output_dir = Path(self.args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / f"{REPORT_PREFIX}_{safe_target}_{timestamp}.json"

        payload = {
            "scanner": APP_NAME,
            "target": asdict(self.target),
            "timestamp_utc": timestamp,
            "scan_mode": "syn" if self.args.syn else "connect",
            "ports": [self._serialize_result(results[port]) for port in sorted(results)],
        }

        with report_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

        return report_path

    @staticmethod
    def _serialize_result(result: ServiceResult) -> dict:
        data = asdict(result)
        data["sensitive_paths"] = [asdict(item) for item in result.sensitive_paths]
        return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BlueScanner Core Engine")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port for range scans")
    parser.add_argument("-e", "--end", type=int, default=65535, help="End port for range scans")
    parser.add_argument("-p", "--ports", help="Comma-separated ports and ranges, for example: 22,80,443,8000-8100")
    parser.add_argument("--top-ports", action="store_true", help="Scan the built-in top TCP ports list")
    parser.add_argument("--syn", action="store_true", help="Use privileged SYN scanning through Scapy")
    parser.add_argument("--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT, help="TCP connect/SYN timeout")
    parser.add_argument("--banner-timeout", type=float, default=DEFAULT_BANNER_TIMEOUT, help="Service probe timeout")
    parser.add_argument("--retry", type=int, default=1, help="Retries for SYN scan batches")
    parser.add_argument("--batch-size", type=int, default=512, help="SYN scan batch size")
    parser.add_argument("--port-concurrency", type=int, default=DEFAULT_PORT_CONCURRENCY, help="Concurrent TCP port checks")
    parser.add_argument("--service-concurrency", type=int, default=DEFAULT_SERVICE_CONCURRENCY, help="Concurrent service probes")
    parser.add_argument("--no-cve", action="store_true", help="Disable NVD CVE lookup")
    parser.add_argument("--no-web-checks", action="store_true", help="Disable sensitive web path checks")
    parser.add_argument("--compare", help="Compare against a previous JSON report")
    parser.add_argument("--output-dir", default=".", help="Directory where JSON reports are written")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    init(autoreset=True)
    setup_logging()
    args = build_parser().parse_args(argv)

    if AIOHTTP_IMPORT_ERROR is not None:
        raise SystemExit(
            f"Missing dependency: {AIOHTTP_IMPORT_ERROR}. "
            "Install dependencies with: pip install aiohttp colorama"
        )

    try:
        return asyncio.run(BlueScanner(args).run())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
