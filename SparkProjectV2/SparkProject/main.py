import argparse
from Controllerv1 import ScannerController
import core_engine
import asyncio
def main():
    

    core_engine.print_banner()
    parser = argparse.ArgumentParser(description="Otonom Ağ Keşif ve Zafiyet Tarayıcı")
    parser.add_argument("target", help="Taranacak hedef IP adresi")
    args = parser.parse_args()

    print(f"[*] Hedef {args.target} için sistem başlatılıyor...")
    
     
    controller = ScannerController(target_ip=args.target)
     
    try:
        final_host_data = asyncio.run(controller.execute_scan_pipeline(start_port=1, end_port=65000))
    except KeyboardInterrupt:
        print("\n[!]Scan aborted by user.")
        return
   
    print(f"\n[+]--------------------------")
    print("=" * 60)
    print(f"Target : {final_host_data.ip_address}")
    print(f"OS: {final_host_data.os_info}")
    print("-" * 60)
    
    for port in final_host_data.ports:
        print(f"[Port {port.number}] -> Service: {port.service_name} | Version: {port.service_version}")
         
        if port.vulnerabilities:
            for vuln in port.vulnerabilities:
                print(f"    └── [VUlnarability] {vuln.cve_id} | Risk: {vuln.severity}")
        else:
            print("    └── Clean")

if __name__ == "__main__":
    main()