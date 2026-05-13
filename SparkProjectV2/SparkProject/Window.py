import customtkinter as ctk
import asyncio
import threading
import queue
from Controllerv1 import ScannerController
import core_engine
import io
import contextlib
import core_engine
class BlueScanGUI:
    def print_banner_to_gui(self):
            
            f = io.StringIO()
            
            with contextlib.redirect_stdout(f):
                core_engine.print_banner()  
            
            
            banner_text = f.getvalue()
            self.console.insert("end", banner_text + "\n")
    
    
    def __init__(self, root):
        self.root = root
        self.root.title("BlueScan v3.3 Ultimate")
        self.root.geometry("1000x700")
        ctk.set_appearance_mode("dark")
        
        
        self.update_queue = queue.Queue()
        
        self._build_ui()
        self._check_queue()

    def _build_ui(self):
         
        self.sidebar = ctk.CTkFrame(self.root, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        self.logo = ctk.CTkLabel(self.sidebar, text="BLUESCAN", font=("Urbanist", 24, "bold"), text_color="#deff9a")
        self.logo.pack(pady=20)
         
        self.scan_btn = ctk.CTkButton(self.sidebar, text="FULL SCAN (1-1000)", command=self.on_full_scan_clicked, fg_color="#1a1a1a", border_width=1, border_color="#deff9a")
        self.scan_btn.pack(pady=10, padx=20)

         
        self.top_ports_btn = ctk.CTkButton(self.sidebar, text="QUICK SCAN (TOP)", command=self.on_top_ports_clicked, fg_color="#2b2b2b", border_width=1, border_color="#55ff55")
        self.top_ports_btn.pack(pady=10, padx=20)

         
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(side="right", expand=True, fill="both", padx=10, pady=10)
        
        self.entry = ctk.CTkEntry(self.main_frame, placeholder_text="Target IP Address...", width=500)
        self.entry.pack(pady=20)
        
        self.progress = ctk.CTkProgressBar(self.main_frame, width=800)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        self.console = ctk.CTkTextbox(self.main_frame, width=850, height=450, font=("Azeret Mono", 13))
        self.console.pack(pady=10)

    def log(self, message):
         
        self.update_queue.put(("log", message))

    def _check_queue(self):
        
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                if msg_type == "log":
                    self.console.insert("end", data + "\n")
                    self.console.see("end")
                elif msg_type == "progress":
                    self.progress.set(data)
                elif msg_type == "state":
                    self.scan_btn.configure(state=data)
        except queue.Empty:
            pass
        self.root.after(100, self._check_queue)

    def on_scan_clicked(self):
        target = self.entry.get()
        if not target:
            self.log("[-] Target is missing!")
            return
        
        self.update_queue.put(("state", "disabled"))
        self.console.delete("1.0", "end")
        
         
        thread = threading.Thread(target=self.run_scanner, args=(target,))
        thread.daemon = True
        thread.start()

    def on_full_scan_clicked(self):
        """1 ile 1000 arasındaki tüm portları tarar."""
        ports = list(range(1, 1001))
        self.start_scan_process(ports)

    def on_top_ports_clicked(self):
        """Motordaki orijinal --top-ports listesini kullanarak hızlı tarama yapar."""
        try:
            # 1. Senaryo: Eğer core_engine içinde TOP_PORTS diye bir liste varsa
            if hasattr(core_engine, 'TOP_PORTS'):
                top_ports = core_engine.TOP_PORTS
            
            # 2. Senaryo: Eğer bir fonksiyon olarak tanımlandıysa (get_top_ports gibi)
            elif hasattr(core_engine, 'get_top_ports'):
                top_ports = core_engine.get_top_ports()
                
            else:
                # Eğer isim farklıysa burayı motordaki isme göre güncelle (örn: core_engine.common_ports)
                self.log("[-] Error: core_engine içinde top-ports verisi bulunamadı!")
                return

            self.log(f"[*] Quick Scan selected using engine's top {len(top_ports)} ports.")
            self.start_scan_process(top_ports)

        except Exception as e:
            self.log(f"[-] Error accessing engine ports: {str(e)}")
   
   
    def start_scan_process(self, port_list):


        """Tarama işlemini ortak bir yerden başlatır."""
        target = self.entry.get().strip()
        if not target:
            self.log("[-] Error: Target IP is missing!")
            return
        
        self.scan_btn.configure(state="disabled")
        self.top_ports_btn.configure(state="disabled")
        self.console.delete("1.0", "end")
        self.print_banner_to_gui()
        
        # Thread'e port listesini de gönderiyoruz
        thread = threading.Thread(target=self.run_scanner, args=(target, port_list))
        thread.daemon = True
        thread.start()


    def run_scanner(self, target, port_list):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        self.log(f"[*] Target: {target}")
        self.log(f"[*] Port Count: {len(port_list)} ports selected.")
        
        try:
            controller = ScannerController(target_ip=target)
            # Controller'a butondan gelen listeyi paslıyoruz
            results = loop.run_until_complete(controller.execute_scan_pipeline(port_list, gui_log_func=self.log))
            
            self.log(f"\n[+] SUCCESS: Scan finished for {results.ip_address}")
            for p in results.ports:
                vulns = len(p.vulnerabilities)
                self.log(f"-> {p.number}/TCP | {p.service_name} | {p.service_version} | [{vulns} Vulns]")

        except Exception as e:
            self.log(f"[-] Critical Error: {str(e)}")
        finally:
            self.update_queue.put(("state", "normal"))
            # Butonları tekrar aktif et
            self.root.after(0, lambda: self.scan_btn.configure(state="normal"))
            self.root.after(0, lambda: self.top_ports_btn.configure(state="normal"))
            loop.close()

 
if __name__ == "__main__":
    root = ctk.CTk()
    app = BlueScanGUI(root)
    root.mainloop()

    
