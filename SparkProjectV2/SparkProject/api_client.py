import aiohttp
import asyncio
from DataModels import Vulnerability

class NISTClient:
    def __init__(self, api_key: str = None, concurrency: int = 3):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}
        self.semaphore = asyncio.Semaphore(concurrency)

    async def search_vulnerabilities(self, service_name: str, version: str):
        
        

        query = f"{service_name} {version}"
        
        params = {"keywordSearch": query, "resultsPerPage": 5}

        async with self.semaphore:
            try:
                 
                async with aiohttp.ClientSession(headers=self.headers) as session:
                    async with session.get(self.base_url, params=params, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_response(data)
                        elif response.status == 403:
                            print(f"[!] NIST API Rate Limit aşıldı ({query}). Bekleniyor...")
                            await asyncio.sleep(6)  
                        return []
            except Exception as e:
                print(f"----API error: {e}")
                return []

    def _parse_response(self, data):
        vulnerabilities = []
        vulnerabilities_list = data.get('vulnerabilities', [])

        for item in vulnerabilities_list:
            cve_data = item.get('cve', {})
             
            metrics = cve_data.get('metrics', {})
            cvss_data = {}
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            vuln = Vulnerability(
                cve_id=cve_data.get('id', 'Unknown'),
                cvss_score=float(cvss_data.get('baseScore', 0.0)),
                severity=cvss_data.get('baseSeverity', 'UNKNOWN'),
                description=cve_data.get('descriptions', [{}])[0].get('value', 'No description')
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities