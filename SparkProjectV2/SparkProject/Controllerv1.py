import socket
import asyncio
import re  # [HATA BURADAYDI] Regex kütüphanesini ekledik
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

    async def _map_results_to_objects(self, raw_results: dict, syn_info: dict):
        if not self.current_host.os_info and syn_info:
            for port_num, info in syn_info.items():
                if info and info != "unknown":
                    self.current_host.os_info = info
                    break 

        nist = NISTClient() 
        api_tasks = []
        temp_ports = []

        for port_num, port_data in raw_results.items():
            # [TEMİZLEME] NIST API'nin daha iyi sonuç bulması için versiyonu ayıklıyoruz[cite: 1, 5]
            raw_v = port_data.version
            # Başındaki SSH-2.0-, HTTP/1.1 gibi gereksiz protokol bilgilerini siliyoruz
            clean_v = re.sub(r'^(SSH-2.0-|HTTP/1.1\s|Server:\s)', '', raw_v, flags=re.IGNORECASE)
            # Sadece ilk satırı al ve boşlukları temizle
            clean_v = clean_v.split('\n')[0].strip()
            
            new_port = Port(
                number=port_num,
                protocol="TCP",
                state=port_data.state,
                service_name=port_data.service,
                service_version=clean_v
            )
            temp_ports.append(new_port)
            
            # Eğer versiyon tespit edildiyse asenkron sorguyu başlat[cite: 5]
            if clean_v:
                print(f"[*] {new_port.service_name} için zafiyet taraması zorlanıyor...")
                api_tasks.append(nist.search_vulnerabilities(new_port.service_name, clean_v))
            else: 
                # Task sırasını korumak için boş bir görev ekle
                async def empty_task(): return []
                api_tasks.append(empty_task())

        if api_tasks:
            # Tüm API sorgularını paralel olarak gerçekleştiriyoruz[cite: 1, 5]
            all_vulns_lists = await asyncio.gather(*api_tasks)
            for port, vulns in zip(temp_ports, all_vulns_lists):
                port.vulnerabilities.extend(vulns)
                self.current_host.ports.append(port)

    async def execute_scan_pipeline(self, start_port: int = 1, end_port: int = 1000):
        """Ana operasyon döngüsü."""
        target_obj = Target(original=self.target_ip, address=self.target_ip, family=socket.AF_INET) 
        
        # 1. Aşama: Port Tarama (SynScanner senkron çalışır)[cite: 2, 6]
        scanner = SynScanner(target=target_obj, timeout=1.5, retry=1, batch_size=512)
        open_ports = scanner.scan(list(range(start_port, end_port + 1)))
        
        if not open_ports:
            print("[-] Açık port bulunamadı.")
            return self.current_host 
            
        # 2. Aşama: Servis Tespiti (Detector asenkron çalışır)[cite: 2, 6]
        detector = ServiceDetector(
            target=target_obj,
            concurrency=50,
            timeout=3.0,
            check_sensitive_paths=True,
            cve_lookup=DummyCveLookup()
        )
        
        # Servis tespitini bekle[cite: 1, 2]
        scan_results = await detector.detect(open_ports)
        
        # 3. Aşama: Verileri nesneye dök ve NIST üzerinden zafiyet sorgula[cite: 1, 5]
        await self._map_results_to_objects(raw_results=scan_results, syn_info=scanner.os_hints)
        
        return self.current_host