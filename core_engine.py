import sys
import socket
import argparse
import re
import asyncio
import ssl
from scapy.all import IP, TCP, sr, sr1, conf, RandShort
from colorama import init, Fore, Style

init(autoreset=True)
conf.verb = 0

class StealthScannerEngine:
    def __init__(self, target_ip: str, target_name: str, max_concurrent_connections: int = 100):
        self.target_ip = target_ip
        self.target_name = target_name
        self.open_ports = []
        self.results = {}
        # OS PROTECTION: Limit concurrent asyncio connections
        self.semaphore = asyncio.Semaphore(max_concurrent_connections)
        
        # HEURISTIC DICTIONARY: Popular ports, NVIDIA, and Nessus added
        self.COMMON_PORTS = {
            21: "FTP (Guess)", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB/CIFS",
            1433: "MSSQL (Guess)", 1521: "Oracle DB (Guess)", 
            1716: "NVIDIA Shield (Guess)", 3306: "MySQL (Guess)", 
            3389: "RDP (Guess)", 5355: "LLMNR (Guess)",
            5432: "PostgreSQL (Guess)", 5900: "VNC (Guess)", 
            6379: "Redis (Guess)", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8834: "Nessus Web UI (Guess)", # Nessus eklendi
            27017: "MongoDB (Guess)",
            47984: "NVIDIA GameStream", 47989: "NVIDIA GameStream", 
            47990: "NVIDIA GameStream", 48010: "NVIDIA GameStream"
        }

    def _syn_sweep_chunk(self, ports_chunk: list):
        """PHASE 1: Scans thousands of ports in a single batch using Scapy."""
        packets = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=ports_chunk, flags="S")
        ans, unans = sr(packets, timeout=2.0, verbose=0)
        
        for snd, rcv in ans:
            if rcv.haslayer(TCP) and rcv.getlayer(TCP).flags == 0x12:
                open_port = snd.dport
                self.open_ports.append(open_port)
                
                rst_packet = IP(dst=self.target_ip) / TCP(sport=RandShort(), dport=open_port, flags="R")
                sr1(rst_packet, timeout=0.2, verbose=0)

    async def _async_grab_banner(self, port: int):
        """BLUE TEAM PHASE 2: Protocol-Aware & HTTPS Ready Banner Grabbing"""
        async with self.semaphore:
            try:
                # SSL/TLS CHECK: 8834 (Nessus) SSL listesine eklendi!
                use_ssl = port in [443, 8443, 8834]
                ssl_context = None
                
                if use_ssl:
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port, ssl=ssl_context),
                    timeout=2.0 
                )
                
                server_speaks_first = port in [21, 22, 25, 110, 143]
                
                if not server_speaks_first:
                    # Web portlarına (Nessus dahil) tam HTTP GET atıyoruz
                    if port in [80, 443, 8080, 8443, 8834]:
                        req = (
                            f"GET / HTTP/1.1\r\n"
                            f"Host: {self.target_ip}\r\n"
                            f"User-Agent: BlueTeam-InternalScanner/1.0\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                    else:
                        req = "\r\n\r\n" 
                    
                    writer.write(req.encode('utf-8'))
                    await writer.drain()
                else:
                    await asyncio.sleep(0.5)
                
                banner_bytes = await reader.read(2048) 
                banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                
                version_details = []
                
                if banner:
                    # Web portları regex analizi (Nessus 8834 dahil edildi)
                    if port in [80, 443, 8080, 8443, 8834]:
                        match_server = re.search(r"Server:\s*(.*)", banner, re.IGNORECASE)
                        if match_server:
                            version_details.append(f"Server: {match_server.group(1).strip()}")
                            
                        match_tech = re.search(r"X-Powered-By:\s*(.*)", banner, re.IGNORECASE)
                        if match_tech:
                            version_details.append(f"Tech: {match_tech.group(1).strip()}")
                            
                        version = " | ".join(version_details) if version_details else "Unknown Web Service"
                    else:
                        version = banner.split('\n')[0].strip()
                else:
                    version = self.COMMON_PORTS.get(port, "Unknown Service (Silent)")
                
                self.results[port] = version
                print(Fore.GREEN + f"[+] Port {port:<5} OPEN  | {version}")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception:
                fallback_version = self.COMMON_PORTS.get(port, "Filtered/Unknown")
                self.results[port] = fallback_version
                print(Fore.GREEN + f"[+] Port {port:<5} OPEN  | {fallback_version}")

    def run_scan(self, start_port: int, end_port: int, chunk_size: int = 1000):
        print(Fore.CYAN + Style.BRIGHT + f"\n[*] Target Scanning  : {self.target_name} ({self.target_ip})")
        print(Fore.CYAN + f"[*] Port Range       : {start_port} - {end_port}")
        print(Fore.CYAN + f"[*] Scan Mode        : High-Speed Batch Sweep & Blue Team Recon")
        print("-" * 65)
        
        all_ports = list(range(start_port, end_port + 1))
        chunks = [all_ports[i:i + chunk_size] for i in range(0, len(all_ports), chunk_size)]
        
        print(Fore.YELLOW + f"[*] Phase 1: Initiating stealth SYN scan in {len(chunks)} blocks...\n")
        
        for idx, chunk in enumerate(chunks):
            sys.stdout.write(f"\r[>] Progress: Scanning block {idx+1}/{len(chunks)}...")
            sys.stdout.flush()
            self._syn_sweep_chunk(chunk)
            
        print(Fore.YELLOW + f"\n\n[*] Phase 1 Completed. Discovered {len(self.open_ports)} open ports.")
        print("-" * 65)
        
        if self.open_ports:
            print(Fore.YELLOW + "[*] Phase 2: Starting async service/version detection...\n")
            
            async def main_async_runner():
                tasks = [self._async_grab_banner(port) for port in self.open_ports]
                await asyncio.gather(*tasks)
                
            asyncio.run(main_async_runner())
                
        print("-" * 65)
        print(Fore.CYAN + Style.BRIGHT + f"[*] Scan Finished. Total Asset Surfaces Identified: {len(self.results)}\n")
        return self.results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=Fore.YELLOW + Style.BRIGHT + "Autonomous Network Recon Engine (Blue Team Edition)",
        epilog="Example: sudo venv/bin/python core_engine.py -t 192.168.1.68 -s 1 -e 65535"
    )
    
    parser.add_argument("-t", "--target", required=True, help="Target IP or Domain Name")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start Port (Default: 1)")
    parser.add_argument("-e", "--end", type=int, default=65535, help="End Port (Default: 65535)")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(Fore.RED + "[-] ERROR: Unresolvable IP or Domain Name!")
        sys.exit(1)
        
    engine = StealthScannerEngine(target_ip=target_ip, target_name=args.target)
    findings = engine.run_scan(args.start, args.end)
