import socket
import asyncio
import re 
from DataModels import Host, Port, Vulnerability 
from core_engine import Target, SynScanner, ServiceDetector 
from api_client import NISTClient 

class DummyCveLookup:
    async def query(self, service, version, session):
        return []

class ScannerController:
    def __init__(self, target_ip: str, target_name: str = ""):
        self.target_ip = target_ip
        self.target_name = target_name or target_ip
        self.current_host = Host(ip_address=self.target_ip, hostname=self.target_name) 

    async def _map_results_to_objects(self, raw_results: dict, syn_info: dict, gui_log_func=None):
        nist = NISTClient() 
        api_tasks = []
        temp_ports = []

        for port_num, port_data in raw_results.items():
            raw_v = port_data.version
            clean_v = re.sub(r'^(SSH-2.0-|HTTP/1.1\s|Server:\s)', '', raw_v, flags=re.IGNORECASE)
            clean_v = clean_v.split('\n')[0].strip()
            
            new_port = Port(
                number=port_num,
                protocol="TCP",
                state=port_data.state,
                service_name=port_data.service,
                service_version=clean_v
            )
            temp_ports.append(new_port)
            
            if clean_v:
                # GUI'ye anlık bilgi gönder
                if gui_log_func: gui_log_func(f"[*] Port {port_num}: {clean_v} için CVE sorgulanıyor...")
                api_tasks.append(nist.search_vulnerabilities(new_port.service_name, clean_v))
            else: 
                async def empty_task(): return []
                api_tasks.append(empty_task())

        if api_tasks:
            all_vulns_lists = await asyncio.gather(*api_tasks)
            for port, vulns in zip(temp_ports, all_vulns_lists):
                port.vulnerabilities.extend(vulns)
                self.current_host.ports.append(port)

    async def execute_scan_pipeline(self, ports: list, gui_log_func=None):
        """Ana operasyon döngüsü."""
        target_obj = Target(original=self.target_ip, address=self.target_ip, family=socket.AF_INET) 
        
        if gui_log_func: gui_log_func("[*] Port tarama başlatıldı...")
        
        scanner = SynScanner(target=target_obj, timeout=1.5, retry=1, batch_size=512)
        open_ports = scanner.scan(ports)
        
        if not open_ports:
            if gui_log_func: gui_log_func("[-] Açık port bulunamadı.")
            return self.current_host 
            
        if gui_log_func: gui_log_func(f"[+] {len(open_ports)} açık port bulundu. Servis tespiti yapılıyor...")

        detector = ServiceDetector(
            target=target_obj,
            concurrency=50,
            timeout=3.0,
            check_sensitive_paths=True,
            cve_lookup=DummyCveLookup()
        )
        
        scan_results = await detector.detect(open_ports)
        
        # 2. BURASI KRİTİK: Log fonksiyonunu buraya da paslıyoruz
        await self._map_results_to_objects(
            raw_results=scan_results, 
            syn_info=scanner.os_hints, 
            gui_log_func=gui_log_func
        )
        
        return self.current_host