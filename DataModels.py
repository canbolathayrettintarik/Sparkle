from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float
    severity: str  # Örn: 'High', 'Critical'
    description: str
    reference_url: Optional[str] = None

@dataclass
class Port:
    number: int
    protocol: str  # 'TCP' veya 'UDP'
    state: str     # 'open', 'filtered', vb.
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    
   
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

@dataclass
class Host:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    ports: List[Port] = field(default_factory=list)
    
    def get_critical_vulnerabilities(self) -> List[Vulnerability]:
        critical_vulns = []
        for port in self.ports:
            for vuln in port.vulnerabilities:
                if vuln.cvss_score >= 7.0:
                    critical_vulns.append(vuln)
        return critical_vulns


