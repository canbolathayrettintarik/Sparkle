#!/usr/bin/env python3
"""
BlueScanner v2.1 - Enterprise Blue Team Vulnerability Analysis Tool
Features: SYN Stealth, Jitter, TLS Analysis, Security Headers, Diffing, Async CVE Checker,
          Persistent Logging, Passive OS Fingerprinting (TTL), Sensitive File Hunter,
          SecOps Webhook (Slack / Discord / Teams).
"""

import sys
import os
import socket
import argparse
import re
import asyncio
import ssl
import json
import time
import logging
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Required 3rd party libraries:
#   pip install scapy colorama aiohttp
from scapy.all import IP, TCP, sr, sr1, conf, RandShort
from colorama import init, Fore, Style

# ─── SETUP & CONFIGURATION ───────────────────────────────────────────────
init(autoreset=True)
conf.verb = 0
try:
    conf.use_pcap = True
except Exception:
    pass

# Enterprise Logging Infrastructure
logging.basicConfig(
    filename='bluescanner_audit.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8834, 27017
]

# Sensitive paths to probe during HTTP analysis (File Hunter)
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
    "/actuator/env",
    "/actuator/health",
    "/.DS_Store",
    "/phpinfo.php",
]

# ─── ASCII BANNER ────────────────────────────────────────────────────────
def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ██████╗ ██╗     ██╗   ██╗███████╗
  ██╔══██╗██║     ██║   ██║██╔════╝
  ██████╔╝██║     ██║   ██║█████╗  
  ██╔══██╗██║     ██║   ██║██╔══╝  
  ██████╔╝███████╗╚██████╔╝███████╗
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
  ██████╗  ██████╗ █████╗ ███╗  ██╗
  ██╔════╝ ██╔════╝██╔══██╗████╗ ██║
  ╚█████╗  ██║     ███████║██╔██╗██║
   ╚═══██╗ ██║     ██╔══██║██║╚████║
  ██████╔╝ ╚██████╗██║  ██║██║ ╚███║
  ╚═════╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
""" + Style.RESET_ALL)
    print(Fore.WHITE + Style.BRIGHT + " " * 12 + "v2.1 Enterprise Edition | Blue Team Intelligence Engine")
    print(Fore.RED + Style.BRIGHT + " " * 22 + "Coded by Emre | Autonomous Security\n")


# ─── MODULE 1: SYN SCANNER + PASSIVE OS FINGERPRINTING (TTL) ─────────────
class SynScanner:
    """
    Stealth SYN scanner with integrated passive OS fingerprinting.

    OS Fingerprinting Concept
    ─────────────────────────
    Modern TCP/IP stacks use predictable default TTL values:
      • Windows      → 128
      • Linux / BSD  → 64
      • Solaris      → 255
      • Cisco IOS    → 255
    Because each router hop decrements TTL by 1, we cannot compare the raw
    received TTL directly to these defaults.  Instead we round UP to the
    nearest known default:  received_ttl=62 → nearest=64 → Linux.
    This gives a probabilistic fingerprint — accurate enough for an initial
    triage without sending a single extra packet.

    The result is stored in self.port_info and later merged into the JSON report.
    """

    # (lower_bound, upper_bound_inclusive, OS label)
    TTL_MAP = [
        (1,   64,  "Linux / Unix / macOS"),
        (65,  128, "Windows"),
        (129, 255, "Cisco / Solaris / Network Device"),
    ]

    def __init__(self, target_ip, chunk_size=500, timeout=1.2, retry=1, workers=4):
        self.target_ip = target_ip
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.retry = retry
        self.workers = workers
        self.open_ports = []
        # port_info stores {port: {"os_guess": str, "ttl": int}}
        self.port_info: dict[int, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _guess_os(ttl: int) -> str:
        """Map a received TTL value to a probable OS label."""
        if ttl <= 0:
            return "Unknown"
        for low, high, label in SynScanner.TTL_MAP:
            if low <= ttl <= high:
                return label
        return "Unknown"

    def _sweep_chunk(self, ports: list[int]):
        pending = list(ports)
        for attempt in range(self.retry + 1):
            if not pending:
                break
            pkts = IP(dst=self.target_ip) / TCP(
                sport=RandShort(), dport=pending, flags="S"
            )
            ans, unans = sr(pkts, timeout=self.timeout, verbose=0)

            for _, rcv in ans:
                if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:  # SYN/ACK
                    port = rcv.sport

                    # ── Passive OS Fingerprinting via TTL ──────────────────
                    received_ttl: int = rcv.ttl if hasattr(rcv, 'ttl') else 0
                    os_guess = self._guess_os(received_ttl)
                    # ──────────────────────────────────────────────────────

                    # Stealth: RST — do not complete the 3-way handshake
                    rst = IP(dst=self.target_ip) / TCP(
                        sport=RandShort(), dport=port, flags="R"
                    )
                    sr1(rst, timeout=0.2, verbose=0)

                    with self._lock:
                        if port not in self.open_ports:
                            self.open_ports.append(port)
                            self.port_info[port] = {
                                "ttl": received_ttl,
                                "os_guess": os_guess,
                            }

            pending = [p.dport for p in unans]

    def run(self, ports: list[int]) -> list[int]:
        chunks = [ports[i: i + self.chunk_size] for i in range(0, len(ports), self.chunk_size)]
        total = len(chunks)
        done = 0
        logging.info(f"SYN Scan Started: Target={self.target_ip}, Port Count={len(ports)}")
        print(Fore.YELLOW + f"[>] SYN Stealth Sweep: {len(ports)} ports | {self.workers} workers")

        start = time.time()
        with ThreadPoolExecutor(max_workers=self.workers) as exe:
            futures = {exe.submit(self._sweep_chunk, c): c for c in chunks}
            for _ in as_completed(futures):
                done += 1
                sys.stdout.write(
                    Fore.CYAN + f"\r  [+] Scan Progress: {done}/{total} chunks completed."
                )
                sys.stdout.flush()

        print(
            Fore.GREEN + Style.BRIGHT
            + f"\n[+] SYN scan finished: {len(self.open_ports)} open ports | {time.time() - start:.1f}s"
        )
        self.open_ports.sort()

        # Print OS fingerprinting summary
        if self.port_info:
            os_labels = {v["os_guess"] for v in self.port_info.values() if v["os_guess"] != "Unknown"}
            if os_labels:
                label_str = " / ".join(sorted(os_labels))
                print(
                    Fore.MAGENTA + Style.BRIGHT
                    + f"[OS] Passive Fingerprint → Probable OS: {label_str} (via TTL analysis)"
                )

        return self.open_ports


# ─── MODULE 2: THREAT INTELLIGENCE (Async CVE Analysis) ──────────────────
class ThreatIntelligence:
    @staticmethod
    async def check_cve(service: str, version: str) -> list:
        """Asynchronous NVD CVE Query Simulation"""
        if version in ["Filtered (Timeout)", "RST (IPS Blocked)", "Closed/Error", "Unknown Service"] or not version:
            return []

        await asyncio.sleep(0.3)

        cve_findings = []
        ver_lower = version.lower()
        if "nginx 1.18" in ver_lower or "nginx/1.18" in ver_lower:
            cve_findings.append({
                "cve": "CVE-2021-23017",
                "severity": "HIGH",
                "remediation": "Update Nginx to version 1.20+"
            })
        elif "openssh 8.2" in ver_lower:
            cve_findings.append({
                "cve": "CVE-2020-15778",
                "severity": "MEDIUM",
                "remediation": "Use sftp instead of scp."
            })
        elif "apache/2.4.49" in ver_lower:
            cve_findings.append({
                "cve": "CVE-2021-41773",
                "severity": "CRITICAL",
                "remediation": "Path Traversal vulnerability. Emergency patch required!"
            })

        return cve_findings


# ─── MODULE 3: VULNERABILITY & CONFIGURATION (BANNER, TLS, FILE HUNTER) ──
class BannerGrabber:
    """
    Layer-7 analyser: banner grabbing, TLS cert inspection, HTTP security
    headers, and sensitive file discovery.

    Sensitive File Hunter Concept
    ─────────────────────────────
    Since we're already opening an HTTP connection, we send additional
    lightweight GET requests to well-known sensitive paths.  A 200 OK
    response indicates the resource is publicly accessible and is flagged
    as a "Critical File Exposed" finding.  Requests use the same jitter
    and User-Agent spoofing already in place to stay under WAF radar.
    """

    SSL_PORTS  = {443, 8443, 8834, 993, 995, 636}
    HTTP_PORTS = {80, 443, 8080, 8443, 8834, 3000}

    def __init__(self, target_ip: str, timeout: float = 2.5, concurrency: int = 50):
        self.target_ip  = target_ip
        self.timeout    = timeout
        self.semaphore  = asyncio.Semaphore(concurrency)
        self.results: dict = {}

    # ── Helper: build a minimal HTTP request string ───────────────────────
    def _http_request(self, path: str = "/") -> bytes:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Connection: close\r\n\r\n"
        )
        return req.encode()

    def _analyze_http_headers(self, banner: str) -> list:
        findings = []
        if "HTTP/" in banner:
            if "Strict-Transport-Security" not in banner:
                findings.append({
                    "type": "Config",
                    "issue": "Missing HSTS",
                    "remediation": "Add HSTS header to web server configuration."
                })
            if "X-Frame-Options" not in banner:
                findings.append({
                    "type": "Config",
                    "issue": "Missing X-Frame-Options",
                    "remediation": "Add header to prevent Clickjacking."
                })
        return findings

    def _analyze_ssl_cert(self, cert: dict) -> dict:
        if not cert or 'notAfter' not in cert:
            return {"status": "Certificate Not Retrieved", "risk": "INFO"}
        try:
            expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            days_left   = (expire_date - datetime.utcnow()).days
            if days_left < 0:
                return {"status": f"Expired ({abs(days_left)} days ago)", "days_left": days_left, "risk": "HIGH"}
            elif days_left <= 30:
                return {"status": f"Critical Expiry ({days_left} days left)", "days_left": days_left, "risk": "HIGH"}
            else:
                return {"status": f"Valid ({days_left} days left)", "days_left": days_left, "risk": "LOW"}
        except Exception:
            return {"status": "Unreadable Date", "risk": "INFO"}

    # ── NEW: Sensitive File Hunter ────────────────────────────────────────
    async def _hunt_sensitive_files(
        self, port: int, use_ssl: bool
    ) -> list[dict]:
        """
        Probes a list of well-known sensitive paths on an HTTP(S) port.
        Returns a list of finding dicts for any path that returns HTTP 200.
        """
        exposed = []
        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

        for path in SENSITIVE_PATHS:
            try:
                # Light jitter — don't hammer WAF rate limits
                await asyncio.sleep(random.uniform(0.05, 0.25))

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port, ssl=ssl_ctx),
                    timeout=self.timeout,
                )
                writer.write(self._http_request(path))
                await writer.drain()

                raw    = await asyncio.wait_for(reader.read(512), timeout=self.timeout)
                banner = raw.decode("utf-8", errors="ignore")

                # Only flag genuine 200 OK (not redirects or errors)
                if banner.startswith("HTTP/") and " 200 " in banner.split("\r\n")[0]:
                    logging.warning(f"Sensitive file exposed: {self.target_ip}:{port}{path}")
                    exposed.append({
                        "type": "Critical File Exposed",
                        "issue": f"Accessible path: {path}",
                        "remediation": f"Restrict access to {path} via server configuration or firewall rules.",
                    })

                writer.close()
                await writer.wait_closed()

            except Exception:
                # Silently skip — path not reachable / filtered
                pass

        return exposed

    # ── Core per-port grab ────────────────────────────────────────────────
    async def _grab(self, port: int):
        async with self.semaphore:
            # Jitter — bypass IPS / WAF rate limits
            await asyncio.sleep(random.uniform(0.2, 0.8))

            use_ssl = port in self.SSL_PORTS
            ssl_ctx = ssl.create_default_context() if use_ssl else None
            if ssl_ctx:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode    = ssl.CERT_NONE

            cert_analysis = {"status": "None", "risk": "INFO"}
            sec_findings: list = []
            cve_findings: list = []

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port, ssl=ssl_ctx),
                    timeout=self.timeout,
                )

                if use_ssl:
                    ssl_obj = writer.get_extra_info('ssl_object')
                    if ssl_obj:
                        cert_analysis = self._analyze_ssl_cert(ssl_obj.getpeercert())

                if port in self.HTTP_PORTS:
                    writer.write(self._http_request("/"))
                    await writer.drain()

                raw    = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                banner = raw.decode("utf-8", errors="ignore").strip()

                sec_findings = self._analyze_http_headers(banner)

                server_match = re.search(r"Server:\s*(.*)", banner, re.IGNORECASE)
                version = (
                    server_match.group(1).strip()
                    if server_match
                    else banner.split('\n')[0].strip()[:50]
                )
                version = version.replace('\r', '').replace('\n', '').strip()
                version = version if version else "Unknown Service"

                cve_findings = await ThreatIntelligence.check_cve(
                    "HTTP/HTTPS" if port in self.HTTP_PORTS else "Unknown", version
                )

                writer.close()
                await writer.wait_closed()

                # ── Sensitive File Hunter (HTTP ports only) ────────────────
                file_findings: list = []
                if port in self.HTTP_PORTS:
                    file_findings = await self._hunt_sensitive_files(port, use_ssl)
                    if file_findings:
                        print(
                            Fore.RED + Style.BRIGHT
                            + f"\n  [🔥] Port {port}: {len(file_findings)} sensitive file(s) exposed!"
                        )

                self.results[port] = {
                    "service":       "HTTP/HTTPS" if port in self.HTTP_PORTS else "Network Service",
                    "version":       version,
                    "ssl":           use_ssl,
                    "cert_analysis": cert_analysis,
                    "sec_headers":   sec_findings,
                    "file_hunter":   file_findings,
                    "cve":           cve_findings,
                }

            except asyncio.TimeoutError:
                logging.warning(f"Port {port} Timeout (Drop/WAF)")
                self.results[port] = {
                    "service": "Unknown", "version": "Filtered (Timeout)",
                    "ssl": use_ssl, "cert_analysis": cert_analysis,
                    "sec_headers": [], "file_hunter": [], "cve": [],
                }
            except ConnectionResetError:
                logging.warning(f"Port {port} Connection Reset (IPS Block)")
                self.results[port] = {
                    "service": "Unknown", "version": "RST (IPS Blocked)",
                    "ssl": use_ssl, "cert_analysis": cert_analysis,
                    "sec_headers": [], "file_hunter": [], "cve": [],
                }
            except Exception:
                self.results[port] = {
                    "service": "Unknown", "version": "Closed/Error",
                    "ssl": use_ssl, "cert_analysis": cert_analysis,
                    "sec_headers": [], "file_hunter": [], "cve": [],
                }

    async def run(self, ports: list[int]) -> dict:
        print(Fore.YELLOW + "\n[>] Deep Analysis & Vulnerability Scan Started (Jitter + File Hunter Active)...")
        tasks = [self._grab(p) for p in ports]
        await asyncio.gather(*tasks)
        return self.results


# ─── MODULE 4: DIFFING ENGINE + SECOPS WEBHOOK ───────────────────────────
class DiffEngine:
    """
    Compares a previous JSON scan report against the current results and
    reports newly opened ports and service version changes.

    SecOps Webhook Concept
    ──────────────────────
    SOC teams don't stare at terminals 24/7.  Whenever an anomaly is
    detected we fire a webhook to a Slack / Discord / Teams channel.  All
    three platforms accept the same simple JSON payload:

        POST <webhook_url>
        Content-Type: application/json
        {"text": "<alert message>"}

    We use aiohttp for non-blocking delivery.  The webhook URL is read
    from --webhook CLI arg or the WEBHOOK_URL environment variable.
    If neither is set the notification step is silently skipped.
    """

    @staticmethod
    async def _send_webhook(webhook_url: str, message: str):
        """Fire-and-forget async webhook delivery (Slack/Discord/Teams compatible)."""
        try:
            import aiohttp  # imported here so the rest of the tool works without aiohttp
            payload = {"text": message}
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status not in (200, 204):
                        logging.warning(f"Webhook delivery failed: HTTP {resp.status}")
                    else:
                        logging.info(f"Webhook delivered: {message[:80]}")
        except ImportError:
            logging.warning("aiohttp not installed — webhook skipped. pip install aiohttp")
        except Exception as exc:
            logging.warning(f"Webhook error: {exc}")

    @classmethod
    def compare(cls, old_report_path: str, current_ports: dict, webhook_url: str | None = None):
        """
        Diff two scan reports.  Fires a webhook for every anomaly when a
        webhook_url is provided (or WEBHOOK_URL env var is set).
        """
        resolved_webhook = webhook_url or os.environ.get("WEBHOOK_URL")

        try:
            with open(old_report_path, 'r') as f:
                old_data = json.load(f)

            print(Fore.RED + Style.BRIGHT + "\n[!] --- SOC ANOMALY (DIFF) REPORT ---")
            old_ports = {p['port']: p for p in old_data.get('ports', [])}
            anomalies = False
            webhook_tasks = []

            for port, data in current_ports.items():
                if port not in old_ports:
                    msg = (
                        f"🚨 BlueScanner ALERT | New Port Detected on Network! "
                        f"Target: {old_data.get('target','?')} | "
                        f"Port: {port} ({data['version']})"
                    )
                    print(Fore.RED + Style.BRIGHT + f"[🚨] {msg}")
                    logging.critical(msg)
                    anomalies = True
                    if resolved_webhook:
                        webhook_tasks.append(msg)
                else:
                    old_version = old_ports[port]['service']['version']
                    if data['version'] != old_version:
                        msg = (
                            f"🚨 BlueScanner ALERT | Service Version Changed! "
                            f"Target: {old_data.get('target','?')} | "
                            f"Port: {port} | {old_version} → {data['version']}"
                        )
                        print(Fore.MAGENTA + Style.BRIGHT + f"[🚨] {msg}")
                        logging.warning(msg)
                        anomalies = True
                        if resolved_webhook:
                            webhook_tasks.append(msg)

            for old_p in old_ports:
                if old_p not in current_ports:
                    print(Fore.GREEN + f"[✓] INFO: Port {old_p} Closed or Filtered.")

            if not anomalies:
                print(Fore.GREEN + "[+] System stable. No new attack surface detected.")
            print(Fore.RED + Style.BRIGHT + "-------------------------------------\n")

            # ── Deliver webhooks (run a temporary event loop for async calls) ──
            if webhook_tasks and resolved_webhook:
                print(Fore.YELLOW + f"[>] Sending {len(webhook_tasks)} SecOps webhook alert(s)...")

                async def _fire_all():
                    await asyncio.gather(*[
                        cls._send_webhook(resolved_webhook, m) for m in webhook_tasks
                    ])

                asyncio.run(_fire_all())
                print(Fore.GREEN + f"[+] Webhook alerts sent to SOC channel.")

        except FileNotFoundError:
            print(Fore.RED + f"[-] ERROR: Comparison file '{old_report_path}' not found.")


# ─── MAIN ORCHESTRATOR & CLI ─────────────────────────────────────────────
class BlueScanner:
    def __init__(self, args):
        self.args      = args
        self.target_ip = socket.gethostbyname(args.target)
        self.syn       = SynScanner(
            self.target_ip,
            chunk_size=args.chunk,
            timeout=1.5,
            workers=args.workers,
        )
        self.grabber = BannerGrabber(self.target_ip, concurrency=args.concurrency)

    def run(self):
        logging.info(f"=== New Scan Session: {self.target_ip} ===")
        if self.args.ports:
            ports = [int(p.strip()) for p in self.args.ports.split(",")]
        elif self.args.top_ports:
            ports = TOP_PORTS
        else:
            ports = list(range(self.args.start, self.args.end + 1))

        print(
            Fore.WHITE + Style.BRIGHT
            + f"\n[*] Enterprise Target: {self.target_ip} | Total Ports to Scan: {len(ports)}"
        )

        # ── Stage 1: SYN Scan + Passive OS Fingerprinting ─────────────────
        open_ports = self.syn.run(ports)
        if not open_ports:
            print(Fore.RED + "[-] No open ports found or WAF/IPS dropped all packets.")
            logging.warning("Scan completed: No open ports.")
            return

        # ── Stage 2: Deep Analysis (Banner + TLS + File Hunter) ───────────
        results = asyncio.run(self.grabber.run(open_ports))

        # ── Stage 3: Diffing + Webhook Alerts ─────────────────────────────
        if self.args.compare:
            DiffEngine.compare(
                self.args.compare,
                results,
                webhook_url=getattr(self.args, 'webhook', None),
            )

        # ── Stage 4: Terminal Output ───────────────────────────────────────
        print(Fore.CYAN + Style.BRIGHT + "\n" + "═" * 95)
        print(
            Fore.WHITE + Style.BRIGHT
            + f"  {'PORT':<6} {'OS GUESS':<22} {'VERSION':<22} {'SECURITY FINDINGS'}"
        )
        print(Fore.CYAN + "─" * 95)

        for port, info in results.items():
            sec_flags = []
            if info['ssl'] and info['cert_analysis']['risk'] == 'HIGH':
                sec_flags.append(f"SSL: {info['cert_analysis']['status']}")
            if info['sec_headers']:
                sec_flags.append(f"{len(info['sec_headers'])} Config Errors")
            if info.get('file_hunter'):
                sec_flags.append(f"{len(info['file_hunter'])} File(s) Exposed")
            if info['cve']:
                sec_flags.append(f"{len(info['cve'])} CVE Found")

            sec_str = ", ".join(sec_flags)[:35] if sec_flags else "Clean"
            color   = Fore.RED if sec_flags else Fore.GREEN

            # Pull OS guess from SynScanner port_info
            os_guess = self.syn.port_info.get(port, {}).get("os_guess", "Unknown")

            print(
                color  + f"  {port:<6} "
                + Fore.MAGENTA + f"{os_guess[:20]:<22} "
                + Fore.YELLOW  + f"{info['version'][:20]:<22} "
                + color        + f"{sec_str}"
            )

        print(Fore.CYAN + "═" * 95)

        # ── Stage 5: SIEM-Ready JSON Export (with OS fingerprint + file hunter) ──
        ts       = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"bluescan_{self.target_ip.replace('.', '_')}_{ts}.json"

        json_data = {"target": self.target_ip, "scan_time": ts, "ports": []}
        for port, info in results.items():
            port_meta = self.syn.port_info.get(port, {"ttl": 0, "os_guess": "Unknown"})
            json_data["ports"].append({
                "port":     port,
                "os_fingerprint": {
                    "ttl":      port_meta["ttl"],
                    "os_guess": port_meta["os_guess"],
                },
                "service":  {"name": info['service'], "version": info['version']},
                "security": {
                    "ssl_enabled":              info['ssl'],
                    "ssl_analysis":             info['cert_analysis'],
                    "configuration_findings":   info['sec_headers'],
                    "sensitive_files_exposed":  info.get('file_hunter', []),
                    "threat_intelligence":      info['cve'],
                },
            })

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4)
        print(Fore.CYAN + Style.BRIGHT + f"\n[✓] Enterprise Report (JSON) Saved: {filename}")
        logging.info(f"Scan finished. Report: {filename}")


# ─── ENTRYPOINT ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Blue Team Config & Vulnerability Scanner Enterprise Edition"
    )
    p.add_argument("target",           help="Target IP or Domain")
    p.add_argument("-s", "--start",    type=int, default=1,     help="Start Port")
    p.add_argument("-e", "--end",      type=int, default=65535, help="End Port")
    p.add_argument("--top-ports",      action="store_true",     help="Scan only top common ports")
    p.add_argument("-p", "--ports",    type=str,                help="Custom port list (e.g., 22,80,443)")
    p.add_argument("--compare",        type=str,                help="Old JSON report for anomaly (Diff) comparison")
    p.add_argument("--webhook",        type=str,                help="Slack/Discord/Teams webhook URL for SOC alerts")
    p.add_argument("--chunk",          type=int, default=500,   help="Network layer packet chunk size")
    p.add_argument("--workers",        type=int, default=4,     help="Network layer CPU thread count")
    p.add_argument("--concurrency",    type=int, default=50,    help="Application layer concurrent connection limit")

    args = p.parse_args()

    print_banner()

    scanner = BlueScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan cancelled by user.")
        logging.warning("User cancelled the scan (KeyboardInterrupt).")
        sys.exit(0)
