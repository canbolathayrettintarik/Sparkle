from data_models import Host, Port, Vulnerability

 
from core_engine import StealthScannerEngine

class ScannerController:
    def __init__(self, target_ip: str, target_name: str = ""):
        self.target_ip = target_ip
        self.target_name = target_name or target_ip
        
       
        self.current_host = Host(ip_address=self.target_ip, hostname=self.target_name)

    def execute_scan_pipeline(self, start_port: int = 1, end_port: int = 1000):
        
        scanner = StealthScannerEngine(
            target_ip=self.target_ip, 
            target_name=self.target_name
        )
        raw_scan_results = scanner.run_scan(start_port, end_port)
        
        self._map_results_to_objects(raw_scan_results)
        
      
        return self.current_host

    def _map_results_to_objects(self, scan_results: dict):
        
        for port_num, banner_data in scan_results.items():
            new_port = Port(
                number=port_num,
                protocol="TCP",   
                state="open",
                service_name=self._extract_service_name(port_num),
                service_version=banner_data  
            )
            self.current_host.ports.append(new_port)

    def _extract_service_name(self, port_num: int) -> str:
         
        well_known_ports = {22: "ssh", 80: "http", 443: "https", 3306: "mysql"}
        return well_known_ports.get(port_num, "unknown")