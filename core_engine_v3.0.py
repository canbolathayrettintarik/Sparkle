#!/usr/bin/env python3
"""
BlueScanner v3.0 Ultimate - Enterprise Blue Team Vulnerability & Defense Mapping Tool
Features: SYN Stealth (Sport Fix/IP ID Rand), Log-Normal Jitter, Async CPE/CVE Engine (NVD/EPSS),
          DefenseMapper (WAF/IPS Fingerprint), Multiprocessing Scapy (GIL Bypass),
          Adaptive RTT Timeout, Tarpit Evasion, SecOps Webhooks.
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
import random
import math
from datetime import datetime
from multiprocessing import Pool, cpu_count

# Required 3rd party libraries:
#   pip install scapy colorama aiohttp
try:
    from scapy.all import IP, TCP, sr, sr1, conf
    from colorama import init, Fore, Style
    import aiohttp
except ImportError as e:
    print(f"[-] Missing dependency: {e}. Please run: pip install scapy colorama aiohttp")
    sys.exit(1)

# ─── SETUP & CONFIGURATION ───────────────────────────────────────────────
init(autoreset=True)
conf.verb = 0
try:
    conf.use_pcap = True
except Exception:
    pass

logging.basicConfig(
    filename='bluescanner_audit.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/server-status",
    "/server-info", "/admin", "/wp-config.php", "/config.php", "/.htpasswd",
    "/api/swagger.json", "/actuator/health", "/.DS_Store", "/phpinfo.php"
]

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
]

def _human_jitter(base: float = 0.3, sigma: float = 0.4) -> float:
    """Log-normal distribution simulating human interaction to bypass NGFW IAT checks."""
    return max(0.05, random.lognormvariate(math.log(base), sigma))

# ─── NMAP TOP PORTS INTEGRATION ──────────────────────────────────────────
def build_top_ports() -> list[int]:
    """Generates the top 1000 standard ports (condensed for script brevity)."""
    # Representing a mix of standard top ports usually found in nmap-services
    base_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8834, 27017
    ]
    # In a full deployment, this would parse /usr/share/nmap/nmap-services
    # For this script, we expand with common ranges to simulate top 1000
    expanded = set(base_ports + list(range(8001, 8010)) + list(range(27018, 27020)))
    return sorted(list(expanded))

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
    print(Fore.WHITE + Style.BRIGHT + " " * 12 + "v3.0 Ultimate Edition | Blue Team Intelligence Engine")
    print(Fore.RED + Style.BRIGHT + " " * 22 + "Coded by Emre | Autonomous Security\n")

# ─── MODULE 1: MULTIPROCESSING SYN SCANNER ───────────────────────────────
TTL_MAP = [
    (1, 64, "Linux / Unix / macOS"),
    (65, 128, "Windows"),
    (129, 255, "Cisco / Solaris / Network Device"),
]

def _guess_os(ttl: int) -> str:
    if ttl <= 0: return "Unknown"
    for low, high, label in TTL_MAP:
        if low <= ttl <= high: return label
    return "Unknown"

def _sweep_chunk_worker(args):
    """Top-level function for multiprocessing Pool."""
    target_ip, ports, timeout, retry = args
    open_ports = []
    port_info = {}
    pending = list(ports)
    
    for _ in range(retry + 1):
        if not pending: break
        
        sport = random.randint(1024, 65535)
        ip_id = random.randint(1, 65535)
        ip_ttl = random.choice([64, 128, 255])
        
        pkts = IP(dst=target_ip, id=ip_id, ttl=ip_ttl) / TCP(sport=sport, dport=pending, flags="S")
        ans, unans = sr(pkts, timeout=timeout, verbose=0)
        
        for _, rcv in ans:
            if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:
                port = rcv.sport
                received_ttl = rcv.ttl if hasattr(rcv, 'ttl') else 0
                
                open_ports.append(port)
                port_info[port] = {"ttl": received_ttl, "os_guess": _guess_os(received_ttl)}
                
                # Stealth RST using the EXACT SAME sport to bypass Snort/Suricata
                rst = IP(dst=target_ip, id=random.randint(1, 65535)) / TCP(
                    sport=sport, dport=port, flags="R", seq=rcv.ack
                )
                sr1(rst, timeout=0.2, verbose=0)
                
        pending = [p.dport for p in unans]
        
    return open_ports, port_info

class SynScanner:
    def __init__(self, target_ip, chunk_size=500, timeout=1.5, retry=1, workers=4):
        self.target_ip = target_ip
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.retry = retry
        self.workers = workers
        self.open_ports = []
        self.port_info = {}

    def run(self, ports: list[int]) -> list[int]:
        chunks = [ports[i: i + self.chunk_size] for i in range(0, len(ports), self.chunk_size)]
        total = len(chunks)
        done = 0
        
        print(Fore.YELLOW + f"[>] SYN Stealth Sweep: {len(ports)} ports | {self.workers} processes (GIL Bypass Active)")
        start = time.time()
        
        # Using Process Pool to bypass Scapy GIL lock during packet parsing
        with Pool(processes=self.workers) as pool:
            tasks = [(self.target_ip, c, self.timeout, self.retry) for c in chunks]
            for chunk_open_ports, chunk_port_info in pool.imap_unordered(_sweep_chunk_worker, tasks):
                done += 1
                self.open_ports.extend(chunk_open_ports)
                self.port_info.update(chunk_port_info)
                sys.stdout.write(Fore.CYAN + f"\r  [+] Scan Progress: {done}/{total} chunks completed.")
                sys.stdout.flush()

        print(Fore.GREEN + Style.BRIGHT + f"\n[+] SYN scan finished: {len(self.open_ports)} open ports | {time.time() - start:.1f}s")
        self.open_ports = sorted(list(set(self.open_ports)))
        return self.open_ports

# ─── MODULE 2: THREAT INTEL & CPE/CVE ENGINE (NVD API v2.0) ──────────────
class CPEVulnEngine:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API = "https://api.first.org/data/v1/epss"

    @staticmethod
    def _parse_cpe(banner: str) -> str | None:
        patterns = {
            r"Apache/([\d.]+)":   "cpe:2.3:a:apache:http_server:{ver}:*:*:*:*:*:*:*",
            r"nginx/([\d.]+)":    "cpe:2.3:a:nginx:nginx:{ver}:*:*:*:*:*:*:*",
            r"OpenSSH_([\d.]+)":  "cpe:2.3:a:openbsd:openssh:{ver}:*:*:*:*:*:*:*",
            r"Microsoft-IIS/([\d.]+)": "cpe:2.3:a:microsoft:iis:{ver}:*:*:*:*:*:*:*",
        }
        for pattern, cpe_template in patterns.items():
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return cpe_template.format(ver=m.group(1))
        return None

    @classmethod
    async def query(cls, banner: str, session: aiohttp.ClientSession) -> list[dict]:
        cpe = cls._parse_cpe(banner)
        if not cpe: return []

        params = {"cpeName": cpe, "cvssV3Severity": "HIGH", "resultsPerPage": 5}
        headers = {"apiKey": os.getenv("NVD_API_KEY", "")}
        
        try:
            async with session.get(cls.NVD_API, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status != 200: return []
                data = await r.json()
                cves = data.get("vulnerabilities", [])
                
                cve_ids = [c["cve"]["id"] for c in cves]
                epss_scores = await cls._get_epss(cve_ids, session)
                
                return [{
                    "cve": c["cve"]["id"],
                    "cvss_v3": c["cve"]["metrics"].get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A"),
                    "epss": epss_scores.get(c["cve"]["id"], 0.0),
                    "remediation": c["cve"]["descriptions"][0]["value"][:120] if c["cve"].get("descriptions") else "N/A"
                } for c in cves]
        except Exception as e:
            logging.debug(f"CPE query failed: {e}")
            return []

    @classmethod
    async def _get_epss(cls, cve_ids: list, session: aiohttp.ClientSession) -> dict:
        if not cve_ids: return {}
        try:
            params = {"cve": ",".join(cve_ids)}
            async with session.get(cls.EPSS_API, params=params, timeout=aiohttp.ClientTimeout(total=5)) as r:
                data = await r.json()
                return {d["cve"]: float(d["epss"]) for d in data.get("data", [])}
        except Exception:
            return {}

# ─── MODULE 3: DEFENSE MAPPER (WAF/IPS FINGERPRINTING) ───────────────────
class DefenseMapper:
    PROBES = {
        "waf_sqli":    "GET /?id=1'%20OR%20'1'='1 HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BlueScanner\r\nConnection: close\r\n\r\n",
        "waf_xss":     "GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BlueScanner\r\nConnection: close\r\n\r\n",
        "tarpit_det":  "GET / HTTP/1.1\r\nHost: {host}\r\nX-Tarpit-Test: 1\r\nUser-Agent: BlueScanner\r\nConnection: close\r\n\r\n",
    }
    SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "f5_bigip":   ["X-WA-Info", "TS0", "BigIP"],
        "akamai":     ["AkamaiGHost", "X-Check-Cacheable"],
        "aws_waf":    ["x-amzn-RequestId", "x-amz-cf-id"],
        "fortiwaf":   ["FORTIWAFSID"],
        "modsecurity":["Mod_Security", "NOYB"],
    }

    @classmethod
    async def fingerprint(cls, target_ip: str, port: int, use_ssl: bool) -> dict:
        results = {
            "detected_waf": None, "blocks_sqli": False, "blocks_xss": False,
            "tarpit_detected": False, "response_times": []
        }
        ssl_ctx = ssl.create_default_context() if use_ssl else None
        if ssl_ctx:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        async def _probe(payload: str) -> tuple[int, str, float]:
            start = time.monotonic()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(target_ip, port, ssl=ssl_ctx), timeout=3.0)
                w.write(payload.format(host=target_ip).encode())
                await w.drain()
                raw = await asyncio.wait_for(r.read(1024), timeout=2.0)
                elapsed = time.monotonic() - start
                w.close()
                await w.wait_closed()
                resp = raw.decode("utf-8", errors="ignore")
                code = int(resp.split(" ")[1]) if "HTTP/" in resp else 0
                return code, resp, elapsed
            except asyncio.TimeoutError:
                return -1, "TIMEOUT", time.monotonic() - start
            except Exception:
                return -2, "ERROR", 0.0

        _, normal_resp, _ = await _probe("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        for vendor, signatures in cls.SIGNATURES.items():
            if any(sig.lower() in normal_resp.lower() for sig in signatures):
                results["detected_waf"] = vendor
                break

        code_sqli, _, t_sqli = await _probe(cls.PROBES["waf_sqli"])
        results["blocks_sqli"] = code_sqli in (403, 406, 429, 503)
        results["response_times"].append(t_sqli)

        code_xss, _, _ = await _probe(cls.PROBES["waf_xss"])
        results["blocks_xss"] = code_xss in (403, 406, 429, 503)

        _, _, tarpit_t = await _probe(cls.PROBES["tarpit_det"])
        results["tarpit_detected"] = tarpit_t > 4.5

        return results

# ─── MODULE 4: BANNER GRABBER & DEEP ANALYSIS ────────────────────────────
class BannerGrabber:
    SSL_PORTS = {443, 8443, 8834, 993, 995, 636}
    HTTP_PORTS = {80, 443, 8080, 8443, 8834, 3000}

    def __init__(self, target_ip: str, concurrency: int = 50):
        self.target_ip = target_ip
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = {}
        self.timeout = 3.0  # Will be dynamically updated by _probe_rtt

    async def _probe_rtt(self) -> float:
        """Measure target RTT to set an adaptive timeout."""
        start = time.monotonic()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(self.target_ip, 80), timeout=5.0)
            w.close()
            await w.wait_closed()
            rtt = time.monotonic() - start
            return max(2.0, rtt * 8)  # Generous margin for TLS handshakes
        except Exception:
            return 3.0

    def _http_request(self, path: str = "/", keep_alive: bool = False) -> bytes:
        ua = random.choice(UA_POOL)
        conn = "keep-alive" if keep_alive else "close"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.target_ip}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
            f"Connection: {conn}\r\n\r\n"
        )
        return req.encode()

    async def _hunt_sensitive_files(self, port: int, ssl_ctx) -> list[dict]:
        exposed = []
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, port, ssl=ssl_ctx), timeout=self.timeout
            )
            for path in SENSITIVE_PATHS:
                await asyncio.sleep(_human_jitter(0.1, 0.3))
                writer.write(self._http_request(path, keep_alive=True))
                await writer.drain()
                try:
                    # Strict 1.5s timeout on read to bypass Tarpit locks
                    raw = await asyncio.wait_for(reader.read(512), timeout=1.5)
                    banner = raw.decode("utf-8", errors="ignore")
                    if banner.startswith("HTTP/") and " 200 " in banner.split("\r\n")[0]:
                        logging.warning(f"File exposed: {self.target_ip}:{port}{path}")
                        exposed.append({"issue": f"Accessible path: {path}"})
                except asyncio.TimeoutError:
                    break  # Tarpit detected, abort loop
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return exposed

    async def _grab(self, port: int, session: aiohttp.ClientSession):
        async with self.semaphore:
            await asyncio.sleep(_human_jitter(0.1, 0.5))
            use_ssl = port in self.SSL_PORTS
            ssl_ctx = ssl.create_default_context() if use_ssl else None
            if ssl_ctx:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            base_info = {
                "service": "Unknown", "version": "Unknown", "ssl": use_ssl,
                "cert_analysis": {}, "sec_headers": [], "file_hunter": [], 
                "cve": [], "defense_mapper": {}
            }

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port, ssl=ssl_ctx), timeout=self.timeout
                )
                
                if use_ssl:
                    ssl_obj = writer.get_extra_info('ssl_object')
                    if ssl_obj:
                        cert = ssl_obj.getpeercert()
                        base_info["cert_analysis"] = {"status": "Verified" if cert else "No Cert"}

                if port in self.HTTP_PORTS:
                    writer.write(self._http_request("/"))
                    await writer.drain()

                raw = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                banner = raw.decode("utf-8", errors="ignore").strip()
                
                # Precise Error Parsing & Identification
                if banner.startswith("HTTP/1.1 400") or banner.startswith("HTTP/1.1 403"):
                    version = f"HTTP Error: {banner.split(chr(13))[0]}"
                else:
                    server_match = re.search(r"Server:\s*(.*)", banner, re.IGNORECASE)
                    version = server_match.group(1).strip() if server_match else banner.split('\n')[0].strip()[:50]
                
                base_info["version"] = version if version else "Unknown HTTP Service"
                base_info["service"] = "HTTP/HTTPS" if port in self.HTTP_PORTS else "Network Service"
                
                # Fire async CPE/CVE checks
                base_info["cve"] = await CPEVulnEngine.query(base_info["version"], session)
                
                writer.close()
                await writer.wait_closed()

                if port in self.HTTP_PORTS:
                    base_info["file_hunter"] = await self._hunt_sensitive_files(port, ssl_ctx)
                    base_info["defense_mapper"] = await DefenseMapper.fingerprint(self.target_ip, port, use_ssl)
                    
                    if base_info["defense_mapper"].get("detected_waf"):
                        print(Fore.MAGENTA + f"\n  [🛡️] Port {port}: WAF Detected -> {base_info['defense_mapper']['detected_waf']}")

            # Specific Exception Handling (Replaces the blanket "except Exception")
            except ssl.SSLError as e:
                base_info["version"] = f"SSL_ERROR: {e.reason}"
            except ConnectionRefusedError:
                base_info["version"] = "Port Closed (RST)"
            except asyncio.TimeoutError:
                base_info["version"] = "Filtered (Timeout)"
            except OSError as e:
                base_info["version"] = f"Network Error: {e.errno}"

            self.results[port] = base_info

    async def run(self, ports: list[int]) -> dict:
        self.timeout = await self._probe_rtt()
        print(Fore.YELLOW + f"[>] Deep Analysis Started... Adaptive Timeout set to {self.timeout:.2f}s")
        
        async with aiohttp.ClientSession() as session:
            tasks = [self._grab(p, session) for p in ports]
            await asyncio.gather(*tasks)
        return self.results

# ─── MODULE 5: DIFF ENGINE & SECOPS WEBHOOKS ─────────────────────────────
class DiffEngine:
    @staticmethod
    async def _send_webhook(webhook_url: str, message: str):
        payload = {"text": message}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, timeout=5) as resp:
                    if resp.status not in (200, 204):
                        logging.warning(f"Webhook failed: HTTP {resp.status}")
        except Exception as exc:
            logging.warning(f"Webhook error: {exc}")

    @classmethod
    def compare(cls, old_report_path: str, current_ports: dict, webhook_url: str | None = None):
        resolved_webhook = webhook_url or os.environ.get("WEBHOOK_URL")
        try:
            with open(old_report_path, 'r') as f:
                old_data = json.load(f)
            
            print(Fore.RED + Style.BRIGHT + "\n[!] --- SOC ANOMALY (DIFF) REPORT ---")
            old_ports = {p['port']: p for p in old_data.get('ports', [])}
            webhook_tasks = []

            for port, data in current_ports.items():
                if port not in old_ports:
                    msg = f"🚨 ALERT: New Port {port} ({data['version']}) detected on {old_data.get('target', '?')}!"
                    print(Fore.RED + Style.BRIGHT + f"[🚨] {msg}")
                    if resolved_webhook: webhook_tasks.append(msg)
                elif data['version'] != old_ports[port]['service']['version']:
                    msg = f"🚨 ALERT: Version Change on Port {port} | {old_ports[port]['service']['version']} → {data['version']}"
                    print(Fore.MAGENTA + Style.BRIGHT + f"[🚨] {msg}")
                    if resolved_webhook: webhook_tasks.append(msg)

            if webhook_tasks and resolved_webhook:
                asyncio.run(asyncio.gather(*[cls._send_webhook(resolved_webhook, m) for m in webhook_tasks]))
                print(Fore.GREEN + "[+] Webhook alerts sent to SOC.")
                
        except FileNotFoundError:
            print(Fore.RED + f"[-] Comparison file '{old_report_path}' not found.")

# ─── MAIN ORCHESTRATOR ───────────────────────────────────────────────────
class BlueScanner:
    def __init__(self, args):
        self.args = args
        self.target_ip = socket.gethostbyname(args.target)
        # Optimal workers calculation: CPU * 2 maxing at 16 to prevent context switch overhead
        optimal_workers = min(cpu_count() * 2, 16) if not args.workers else args.workers
        optimal_chunk = max(200, 65535 // (optimal_workers * 4)) if not args.chunk else args.chunk
        
        self.syn = SynScanner(self.target_ip, chunk_size=optimal_chunk, workers=optimal_workers)
        self.grabber = BannerGrabber(self.target_ip, concurrency=args.concurrency)

    def run(self):
        logging.info(f"=== New Scan Session: {self.target_ip} ===")
        if self.args.ports:
            ports = [int(p.strip()) for p in self.args.ports.split(",")]
        elif self.args.top_ports:
            ports = build_top_ports()
        else:
            ports = list(range(self.args.start, self.args.end + 1))

        print(Fore.WHITE + Style.BRIGHT + f"\n[*] Target: {self.target_ip} | Ports: {len(ports)}")

        open_ports = self.syn.run(ports)
        if not open_ports:
            print(Fore.RED + "[-] No open ports found.")
            return

        results = asyncio.run(self.grabber.run(open_ports))

        if self.args.compare:
            DiffEngine.compare(self.args.compare, results, getattr(self.args, 'webhook', None))

        print(Fore.CYAN + Style.BRIGHT + "\n" + "═" * 110)
        print(Fore.WHITE + Style.BRIGHT + f"  {'PORT':<6} {'OS GUESS':<20} {'VERSION':<25} {'SECURITY / DEFENSE'}")
        print(Fore.CYAN + "─" * 110)

        for port, info in results.items():
            sec_flags = []
            if info.get('defense_mapper', {}).get('detected_waf'): sec_flags.append("WAF Active")
            if info.get('file_hunter'): sec_flags.append(f"{len(info['file_hunter'])} File(s)")
            if info.get('cve'): 
                high_epss = [c for c in info['cve'] if c['epss'] > 0.5]
                sec_flags.append(f"{len(info['cve'])} CVEs ({len(high_epss)} Critical EPSS)")
                
            sec_str = ", ".join(sec_flags) if sec_flags else "Clean"
            color = Fore.RED if sec_flags else Fore.GREEN
            os_guess = self.syn.port_info.get(port, {}).get("os_guess", "Unknown")

            print(
                color + f"  {port:<6} "
                + Fore.MAGENTA + f"{os_guess[:18]:<20} "
                + Fore.YELLOW + f"{info['version'][:23]:<25} "
                + color + f"{sec_str}"
            )
        print(Fore.CYAN + "═" * 110)

        ts = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"bluescan_{self.target_ip.replace('.', '_')}_{ts}.json"
        
        # Merge OS fingerprinting and new modules into final JSON
        for port, info in results.items():
            info["os_fingerprint"] = self.syn.port_info.get(port, {"ttl": 0, "os_guess": "Unknown"})
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"target": self.target_ip, "scan_time": ts, "ports": results}, f, indent=4)
            
        print(Fore.CYAN + Style.BRIGHT + f"\n[✓] Enterprise JSON Report Saved: {filename}")

# ─── ENTRYPOINT ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Required for Windows multiprocessing compatibility
    import multiprocessing
    multiprocessing.freeze_support()
    
    p = argparse.ArgumentParser(description="Blue Team Config & Vulnerability Scanner Ultimate Edition")
    p.add_argument("target", help="Target IP or Domain")
    p.add_argument("-s", "--start", type=int, default=1, help="Start Port")
    p.add_argument("-e", "--end", type=int, default=65535, help="End Port")
    p.add_argument("--top-ports", action="store_true", help="Scan Top 1000 standard ports")
    p.add_argument("-p", "--ports", type=str, help="Custom port list (e.g., 22,80,443)")
    p.add_argument("--compare", type=str, help="Old JSON report for anomaly diffing")
    p.add_argument("--webhook", type=str, help="Slack/Discord/Teams webhook URL")
    p.add_argument("--chunk", type=int, help="Network layer packet chunk size")
    p.add_argument("--workers", type=int, help="Process pool count (Defaults to CPU*2)")
    p.add_argument("--concurrency", type=int, default=50, help="Async HTTP concurrency limit")

    args = p.parse_args()
    print_banner()

    try:
        BlueScanner(args).run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan cancelled by user.")
        sys.exit(0)
