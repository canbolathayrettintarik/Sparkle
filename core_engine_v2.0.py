#!/usr/bin/env python3
"""
BlueScanner v2.0 - Enterprise Blue Team Vulnerability Analysis Tool
Features: SYN Stealth, Jitter, TLS Analysis, Security Headers, Diffing, Async CVE Checker, Persistent Logging.
"""

import sys
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

# Required 3rd party libraries: pip install scapy colorama
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

# ─── NMAP TOP 1000 PORT PARSER ───────────────────────────────────────────
NMAP_RAW_PORTS = (
    "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,"
    "135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,"
    "406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,"
    "563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,"
    "765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,"
    "1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,"
    "1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,"
    "1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,"
    "1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,"
    "1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,"
    "1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,"
    "2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,"
    "2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,"
    "2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,"
    "2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,"
    "3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,"
    "3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,"
    "3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,"
    "3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,"
    "4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,"
    "5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,"
    "5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,"
    "5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,"
    "5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,"
    "6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,"
    "6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,"
    "7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,"
    "8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,"
    "8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,"
    "9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,"
    "9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,"
    "9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,"
    "10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,"
    "13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,"
    "16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,"
    "19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,"
    "25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,"
    "32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,"
    "44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,"
    "50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,"
    "55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,"
    "65129,65389,7001,8008"
)

def build_top_ports(raw_string):
    """Parses Nmap's comma and dash separated port syntax into a sorted integer list."""
    ports = set()
    for part in raw_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

TOP_PORTS = build_top_ports(NMAP_RAW_PORTS)

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
    print(Fore.WHITE + Style.BRIGHT + " " * 12 + "v2.0 Enterprise Edition | Blue Team Intelligence Engine")
    print(Fore.RED + Style.BRIGHT + " " * 22 + "Coded by Emre | Autonomous Security\n")

# ─── MODULE 1: SYN SCANNER (Stealth Network Layer) ───────────────────────
class SynScanner:
    def __init__(self, target_ip, chunk_size=500, timeout=1.2, retry=1, workers=4):
        self.target_ip = target_ip
        self.chunk_size = chunk_size
        self.timeout = timeout
        self.retry = retry
        self.workers = workers
        self.open_ports = []
        self._lock = threading.Lock()

    def _sweep_chunk(self, ports: list[int]):
        pending = list(ports)
        for attempt in range(self.retry + 1):
            if not pending: break
            pkts = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=pending, flags="S")
            ans, unans = sr(pkts, timeout=self.timeout, verbose=0)
            
            for _, rcv in ans:
                if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12: # SYN/ACK Received
                    port = rcv.sport
                    # Stealth: Send RST immediately, do not complete 3-way handshake
                    rst = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=port, flags="R")
                    sr1(rst, timeout=0.2, verbose=0)
                    with self._lock:
                        if port not in self.open_ports:
                            self.open_ports.append(port)
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
                sys.stdout.write(Fore.CYAN + f"\r  [+] Scan Progress: {done}/{total} chunks completed.")
                sys.stdout.flush()
        
        print(Fore.GREEN + Style.BRIGHT + f"\n[+] SYN scan finished: {len(self.open_ports)} open ports | {time.time() - start:.1f}s")
        self.open_ports.sort()
        return self.open_ports

# ─── MODULE 2: THREAT INTELLIGENCE (Async CVE Analysis) ──────────────────
class ThreatIntelligence:
    @staticmethod
    async def check_cve(service: str, version: str) -> list:
        """Asynchronous NVD CVE Query Simulation"""
        if version in ["Filtered (Timeout)", "RST (IPS Blocked)", "Closed/Error", "Unknown Service"] or not version:
            return []
        
        # Simulate network latency for API call
        await asyncio.sleep(0.3) 
        
        cve_findings = []
        ver_lower = version.lower()
        # Mocked rules for presentation/educational purposes:
        if "nginx 1.18" in ver_lower or "nginx/1.18" in ver_lower:
            cve_findings.append({"cve": "CVE-2021-23017", "severity": "HIGH", "remediation": "Update Nginx to version 1.20+"})
        elif "openssh 8.2" in ver_lower:
            cve_findings.append({"cve": "CVE-2020-15778", "severity": "MEDIUM", "remediation": "Use sftp instead of scp."})
        elif "apache/2.4.49" in ver_lower:
            cve_findings.append({"cve": "CVE-2021-41773", "severity": "CRITICAL", "remediation": "Path Traversal vulnerability. Emergency patch required!"})
            
        return cve_findings

# ─── MODULE 3: VULNERABILITY & CONFIGURATION (BANNER & TLS) ──────────────
class BannerGrabber:
    SSL_PORTS = {443, 8443, 8834, 993, 995, 636}
    HTTP_PORTS = {80, 443, 8080, 8443, 8834, 3000}

    def __init__(self, target_ip: str, timeout: float = 2.5, concurrency: int = 50):
        self.target_ip = target_ip
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = {}

    def _analyze_http_headers(self, banner: str) -> list:
        findings = []
        if "HTTP/" in banner:
            if "Strict-Transport-Security" not in banner: 
                findings.append({"type": "Config", "issue": "Missing HSTS", "remediation": "Add HSTS header to web server configuration."})
            if "X-Frame-Options" not in banner: 
                findings.append({"type": "Config", "issue": "Missing X-Frame-Options", "remediation": "Add header to prevent Clickjacking."})
        return findings

    def _analyze_ssl_cert(self, cert: dict) -> dict:
        if not cert or 'notAfter' not in cert:
            return {"status": "Certificate Not Retrieved", "risk": "INFO"}
        try:
            expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            if days_left < 0:
                return {"status": f"Expired ({abs(days_left)} days ago)", "days_left": days_left, "risk": "HIGH"}
            elif days_left <= 30:
                return {"status": f"Critical Expiry ({days_left} days left)", "days_left": days_left, "risk": "HIGH"}
            else:
                return {"status": f"Valid ({days_left} days left)", "days_left": days_left, "risk": "LOW"}
        except Exception:
            return {"status": "Unreadable Date", "risk": "INFO"}

    async def _grab(self, port: int):
        async with self.semaphore:
            # PRIVACY/STEALTH (Jitter) - Bypass IPS/WAF rate limits
            await asyncio.sleep(random.uniform(0.2, 0.8)) 
            
            use_ssl = port in self.SSL_PORTS
            ssl_ctx = ssl.create_default_context() if use_ssl else None
            if ssl_ctx:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            cert_analysis = {"status": "None", "risk": "INFO"}
            sec_findings = []
            cve_findings = []
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port, ssl=ssl_ctx),
                    timeout=self.timeout
                )

                # Blue Team: Extract Certificate
                if use_ssl:
                    ssl_obj = writer.get_extra_info('ssl_object')
                    if ssl_obj:
                        cert_analysis = self._analyze_ssl_cert(ssl_obj.getpeercert())

                # Blue Team: Security Headers and User-Agent Spoofing
                if port in self.HTTP_PORTS:
                    req = (f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n"
                           f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36\r\n"
                           f"Accept: text/html\r\nConnection: close\r\n\r\n")
                    writer.write(req.encode())
                    await writer.drain()

                raw = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                banner = raw.decode("utf-8", errors="ignore").strip()
                
                sec_findings = self._analyze_http_headers(banner)
                
                server_match = re.search(r"Server:\s*(.*)", banner, re.IGNORECASE)
                version = server_match.group(1).strip() if server_match else banner.split('\n')[0].strip()[:50]
                
                # BUG FIX: Remove \r and \n characters so it doesn't break terminal alignment
                version = version.replace('\r', '').replace('\n', '').strip()
                version = version if version else "Unknown Service"
                
                cve_findings = await ThreatIntelligence.check_cve("HTTP/HTTPS" if port in self.HTTP_PORTS else "Unknown", version)

                self.results[port] = {
                    "service": "HTTP/HTTPS" if port in self.HTTP_PORTS else "Network Service",
                    "version": version,
                    "ssl": use_ssl,
                    "cert_analysis": cert_analysis,
                    "sec_headers": sec_findings,
                    "cve": cve_findings
                }
                writer.close()
                await writer.wait_closed()

            # ERROR HANDLING: Detailed categorization for SOC Analysts
            except asyncio.TimeoutError:
                logging.warning(f"Port {port} Timeout (Drop/WAF)")
                self.results[port] = {"service": "Unknown", "version": "Filtered (Timeout)", "ssl": use_ssl, "cert_analysis": cert_analysis, "sec_headers": [], "cve": []}
            except ConnectionResetError:
                logging.warning(f"Port {port} Connection Reset (IPS Block)")
                self.results[port] = {"service": "Unknown", "version": "RST (IPS Blocked)", "ssl": use_ssl, "cert_analysis": cert_analysis, "sec_headers": [], "cve": []}
            except Exception as e:
                self.results[port] = {"service": "Unknown", "version": "Closed/Error", "ssl": use_ssl, "cert_analysis": cert_analysis, "sec_headers": [], "cve": []}

    async def run(self, ports: list[int]) -> dict:
        print(Fore.YELLOW + f"\n[>] Deep Analysis & Vulnerability Scan Started (Jitter Active)...")
        tasks = [self._grab(p) for p in ports]
        await asyncio.gather(*tasks)
        return self.results

# ─── MODULE 4: DIFFING ENGINE (Anomaly Detection) ────────────────────────
class DiffEngine:
    @staticmethod
    def compare(old_report_path: str, current_ports: dict):
        try:
            with open(old_report_path, 'r') as f:
                old_data = json.load(f)
            
            print(Fore.RED + Style.BRIGHT + "\n[!] --- SOC ANOMALY (DIFF) REPORT ---")
            old_ports = {p['port']: p for p in old_data.get('ports', [])}
            anomalies = False
            
            for port, data in current_ports.items():
                if port not in old_ports:
                    msg = f"[🚨] ALERT: New Port Detected on Network! Port {port} ({data['version']})"
                    print(Fore.RED + Style.BRIGHT + msg)
                    logging.critical(msg)
                    anomalies = True
                else:
                    old_version = old_ports[port]['service']['version']
                    if data['version'] != old_version:
                        msg = f"[🚨] ALERT: Service Version Changed! Port {port} ({old_version} -> {data['version']})"
                        print(Fore.MAGENTA + Style.BRIGHT + msg)
                        logging.warning(msg)
                        anomalies = True
            
            for old_p in old_ports:
                if old_p not in current_ports:
                    print(Fore.GREEN + f"[✓] INFO: Port {old_p} Closed or Filtered.")
            
            if not anomalies:
                print(Fore.GREEN + "[+] System stable. No new attack surface detected.")
            print(Fore.RED + Style.BRIGHT + "-------------------------------------\n")
            
        except FileNotFoundError:
            print(Fore.RED + f"[-] ERROR: Comparison file '{old_report_path}' not found.")

# ─── MAIN ORCHESTRATOR & CLI ─────────────────────────────────────────────
class BlueScanner:
    def __init__(self, args):
        self.args = args
        self.target_ip = socket.gethostbyname(args.target)
        self.syn = SynScanner(self.target_ip, chunk_size=args.chunk, timeout=1.5, workers=args.workers)
        self.grabber = BannerGrabber(self.target_ip, concurrency=args.concurrency)

    def run(self):
        logging.info(f"=== New Scan Session: {self.target_ip} ===")
        if self.args.ports:
            ports = [int(p.strip()) for p in self.args.ports.split(",")]
        elif self.args.top_ports:
            ports = TOP_PORTS
        else:
            ports = list(range(self.args.start, self.args.end + 1))

        print(Fore.WHITE + Style.BRIGHT + f"\n[*] Enterprise Target: {self.target_ip} | Total Ports to Scan: {len(ports)}")

        # Stage 1: SYN Scan
        open_ports = self.syn.run(ports)
        if not open_ports:
            print(Fore.RED + "[-] No open ports found or WAF/IPS dropped all packets.")
            logging.warning("Scan completed: No open ports.")
            return

        # Stage 2: Deep Analysis
        results = asyncio.run(self.grabber.run(open_ports))

        # Stage 3: Diffing
        if self.args.compare:
            DiffEngine.compare(self.args.compare, results)

        # Stage 4: Terminal Output
        print(Fore.CYAN + Style.BRIGHT + "\n" + "═" * 85)
        print(Fore.WHITE + Style.BRIGHT + f"  {'PORT':<6} {'SERVICE':<15} {'VERSION':<25} {'SECURITY FINDINGS'}")
        print(Fore.CYAN + "─" * 85)
        
        for port, info in results.items():
            sec_flags = []
            if info['ssl'] and info['cert_analysis']['risk'] == 'HIGH': 
                sec_flags.append(f"SSL: {info['cert_analysis']['status']}")
            if info['sec_headers']: 
                sec_flags.append(f"{len(info['sec_headers'])} Config Errors")
            if info['cve']:
                sec_flags.append(f"{len(info['cve'])} CVE Found")
                
            sec_str = ", ".join(sec_flags)[:30] if sec_flags else "Clean"
            color = Fore.RED if sec_flags else Fore.GREEN
            
            print(color + f"  {port:<6} " + 
                  Fore.WHITE + f"{info['service']:<15} " + 
                  Fore.YELLOW + f"{info['version'][:23]:<25} " + 
                  color + f"{sec_str}")
        
        print(Fore.CYAN + "═" * 85)
        
        # Stage 5: SIEM-Ready JSON Export
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"bluescan_{self.target_ip.replace('.', '_')}_{ts}.json"
        
        json_data = {"target": self.target_ip, "scan_time": ts, "ports": []}
        for port, info in results.items():
            json_data["ports"].append({
                "port": port, 
                "service": {"name": info['service'], "version": info['version']}, 
                "security": {
                    "ssl_enabled": info['ssl'], 
                    "ssl_analysis": info['cert_analysis'], 
                    "configuration_findings": info['sec_headers'],
                    "threat_intelligence": info['cve']
                }
            })
            
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4)
        print(Fore.CYAN + Style.BRIGHT + f"\n[✓] Enterprise Report (JSON) Saved: {filename}")
        logging.info(f"Scan finished. Report: {filename}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Blue Team Config & Vulnerability Scanner Enterprise Edition")
    p.add_argument("target", help="Target IP or Domain")
    p.add_argument("-s", "--start", type=int, default=1, help="Start Port")
    p.add_argument("-e", "--end", type=int, default=65535, help="End Port")
    p.add_argument("--top-ports", action="store_true", help="Scan only top common ports")
    p.add_argument("-p", "--ports", type=str, help="Custom port list (e.g., 22,80,443)")
    p.add_argument("--compare", type=str, help="Old JSON report file for anomaly (Diff) comparison")
    p.add_argument("--chunk", type=int, default=500, help="Network layer packet chunk size")
    p.add_argument("--workers", type=int, default=4, help="Network layer CPU thread count")
    p.add_argument("--concurrency", type=int, default=50, help="Application layer concurrent connection limit")
    
    args = p.parse_args()
    
    print_banner()
    
    scanner = BlueScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan cancelled by user.")
        logging.warning("User cancelled the scan (KeyboardInterrupt).")
        sys.exit(0)
