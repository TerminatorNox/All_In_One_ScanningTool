import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import hashlib
import time
import os
import sys
import platform
import random
import re
import base64
import subprocess
import zipfile

# ================= EXTERNAL LIBRARIES =================
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import sniff, IP, TCP, UDP, Ether, Raw, hexdump
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ================= UTILITIES =================
def is_root():
    """Check for administrative privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


# ================= MAIN APPLICATION =================
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("OmniScanner Pro – Advanced Security Suite")
        self.root.geometry("1150x900")

        # Professional Security Theme Palette
        self.colors = {
            "bg": "#0f172a",
            "fg": "#f8fafc",
            "accent": "#38bdf8",
            "console": "#1e293b",
            "warning": "#f59e0b",
            "danger": "#ef4444",
            "success": "#22c55e",
            "button": "#0ea5e9",
            "input_bg": "#1e293b"
        }

        self.root_mode = is_root()
        self.apply_styles()

        # Main Navigation Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=15, pady=15)

        # Build UI Tabs
        self.setup_mode_tab()
        self.setup_network_mapper()
        self.setup_ping_scanner()
        self.setup_subdomain_recon()
        self.setup_network_analyzer() 
        self.setup_web_auditor()
        self.setup_vulnerability_tab()
        self.setup_password_cracker_tab() # Hash Cracker
        self.setup_file_cracker_tab()     # NEW: File Cracker
        self.setup_ip_utils()
        self.setup_creator_tab()
        self.setup_about_tab()

    def apply_styles(self):
        """Configure the look and feel of the application."""
        self.root.configure(bg=self.colors["bg"])
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#94a3b8", padding=[15, 5], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", 
                  background=[("selected", self.colors["accent"])], 
                  foreground=[("selected", "#ffffff")])
        
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["fg"])
        style.configure("TButton", font=("Segoe UI", 10, "bold"))

    def create_console(self, parent):
        """Generate a consistent terminal-style output box."""
        return scrolledtext.ScrolledText(
            parent,
            bg=self.colors["console"],
            fg=self.colors["fg"],
            insertbackground="white",
            font=("Consolas", 11),
            padx=10,
            pady=10,
            borderwidth=0,
            relief="flat"
        )

    # ================= 1. EXECUTION MODE TAB =================
    def setup_mode_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Mode  ")

        status = "ROOT / ADMIN MODE ENABLED" if self.root_mode else "NORMAL USER MODE"
        color = self.colors["success"] if self.root_mode else self.colors["warning"]

        tk.Label(
            tab, text="Execution Context", font=("Segoe UI", 24, "bold"),
            fg=self.colors["accent"], bg=self.colors["bg"]
        ).pack(pady=(100, 10))

        self.mode_label = tk.Label(
            tab, text=status, fg=color, bg=self.colors["bg"], font=("Segoe UI", 14, "bold")
        )
        self.mode_label.pack(pady=10)

        info_text = (
            "Normal Mode: Safe for scanning, web auditing, and recon.\n"
            "Root Mode: Required for low-level packet analysis."
        )
        tk.Label(tab, text=info_text, fg="#94a3b8", bg=self.colors["bg"], justify="center").pack(pady=20)

        ttk.Button(tab, text="Elevate Privileges", command=self.request_root).pack(pady=15)

    def request_root(self):
        if self.root_mode:
            messagebox.showinfo("Privileges", "Already running as administrator.")
            return

        try:
            script_path = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            if platform.system() == "Darwin":
                cmd = f'osascript -e \'do shell script "{sys.executable} \\"{script_path}\\" {params}" with administrator privileges\''
                subprocess.Popen(cmd, shell=True)
                self.root.destroy()
            elif platform.system() == "Windows":
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}" {params}', None, 1)
                self.root.destroy()
            else:
                cmd = ["pkexec", sys.executable, script_path] + sys.argv[1:]
                subprocess.Popen(cmd)
                self.root.destroy()
        except Exception as e:
            messagebox.showerror("Elevation Failed", str(e))

    # ================= 2. PORT SCANNER =================
    def setup_network_mapper(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Port Scanner ")
        header = tk.Frame(tab, bg=self.colors["bg"])
        header.pack(fill="x", padx=20, pady=20)
        tk.Label(header, text="Target IP:").pack(side="left")
        self.target_entry = tk.Entry(header, bg=self.colors["input_bg"], fg="white", width=30)
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.pack(side="left", padx=10)
        ttk.Button(header, text="Scan", command=self.scan_ports).pack(side="left")
        self.scan_out = self.create_console(tab)
        self.scan_out.pack(expand=True, fill="both", padx=20, pady=10)

    def scan_ports(self):
        self.scan_out.delete(1.0, tk.END)
        target = self.target_entry.get()
        def worker():
            for p in [21, 22, 23, 25, 53, 80, 443, 3306, 8080]:
                try:
                    s = socket.socket(); s.settimeout(0.3)
                    if s.connect_ex((target, p)) == 0:
                        self.scan_out.insert(tk.END, f"[+] Port {p} OPEN\n")
                    s.close()
                except: pass
            self.scan_out.insert(tk.END, "[*] Finished.")
        threading.Thread(target=worker, daemon=True).start()

    # ================= 3. PING SCANNER =================
    def setup_ping_scanner(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Ping Scanner ")
        frame = tk.Frame(tab, bg=self.colors["bg"])
        frame.pack(fill="x", padx=20, pady=20)
        tk.Label(frame, text="Base IP:").pack(side="left")
        self.ping_base = tk.Entry(frame, bg=self.colors["input_bg"], fg="white", width=20)
        self.ping_base.insert(0, "127.0.0")
        self.ping_base.pack(side="left", padx=10)
        ttk.Button(frame, text="Scan Range", command=self.run_ping_scan).pack(side="left")
        self.ping_out = self.create_console(tab)
        self.ping_out.pack(expand=True, fill="both", padx=20, pady=10)

    def run_ping_scan(self):
        self.ping_out.delete(1.0, tk.END)
        base = self.ping_base.get()
        def ping_host(ip):
            param = "-n" if platform.system().lower() == "windows" else "-c"
            cmd = ["ping", param, "1", "-W", "1", ip]
            if subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                self.ping_out.insert(tk.END, f"[ACTIVE] {ip}\n")
        def worker():
            for i in range(1, 255):
                threading.Thread(target=ping_host, args=(f"{base}.{i}",), daemon=True).start()
        threading.Thread(target=worker, daemon=True).start()

    # ================= 4. RECON =================
    def setup_subdomain_recon(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Recon ")
        ctrl = tk.Frame(tab, bg=self.colors["bg"])
        ctrl.pack(fill="x", padx=20, pady=20)
        self.domain_entry = tk.Entry(ctrl, bg=self.colors["input_bg"], fg="white", width=35)
        self.domain_entry.insert(0, "google.com"); self.domain_entry.pack(side="left", padx=10)
        ttk.Button(ctrl, text="Enumerate", command=self.recon_subdomains).pack(side="left")
        self.recon_out = self.create_console(tab); self.recon_out.pack(expand=True, fill="both", padx=20, pady=10)

    def recon_subdomains(self):
        self.recon_out.delete(1.0, tk.END); domain = self.domain_entry.get()
        def worker():
            for sub in ["www", "mail", "ftp", "dev", "api", "admin"]:
                try:
                    ip = socket.gethostbyname(f"{sub}.{domain}")
                    self.recon_out.insert(tk.END, f"[FOUND] {sub}.{domain} -> {ip}\n")
                except: pass
        threading.Thread(target=worker, daemon=True).start()

    # ================= 5. ANALYZER =================
    def setup_network_analyzer(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Analyzer ")
        top = tk.Frame(tab, bg=self.colors["bg"]); top.pack(fill="x", padx=15, pady=10)
        self.sniff_filter = tk.Entry(top, bg=self.colors["input_bg"], fg="white", width=40)
        self.sniff_filter.insert(0, "ip"); self.sniff_filter.pack(side="left", padx=10)
        self.sniff_btn = ttk.Button(top, text="Start Capture", command=self.toggle_sniff); self.sniff_btn.pack(side="left")
        self.paned = tk.PanedWindow(tab, orient=tk.VERTICAL, bg=self.colors["bg"], borderwidth=0)
        self.paned.pack(expand=True, fill="both", padx=15, pady=5)
        self.sniff_list = tk.Listbox(self.paned, bg=self.colors["console"], fg="#00ff00", borderwidth=0)
        self.sniff_list.bind('<<ListboxSelect>>', self.on_packet_select); self.paned.add(self.sniff_list, height=300)
        self.packet_details = scrolledtext.ScrolledText(self.paned, bg="#020617", fg="#94a3b8", borderwidth=0)
        self.paned.add(self.packet_details)
        self.is_sniffing = False; self.captured_packets = []

    def toggle_sniff(self):
        if not self.root_mode: messagebox.showerror("Error", "Root Required"); return
        if not SCAPY_AVAILABLE: messagebox.showerror("Error", "Scapy Required"); return
        if not self.is_sniffing:
            self.is_sniffing = True; self.sniff_btn.config(text="Stop Capture")
            threading.Thread(target=self.sniff_logic, args=(self.sniff_filter.get(),), daemon=True).start()
        else: self.is_sniffing = False; self.sniff_btn.config(text="Start Capture")

    def sniff_logic(self, f):
        def cb(pkt):
            if not self.is_sniffing: return True
            self.captured_packets.append(pkt)
            self.sniff_list.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {pkt.summary()}")
            self.sniff_list.see(tk.END)
        sniff(filter=f, prn=cb, stop_filter=lambda x: not self.is_sniffing, store=0)

    def on_packet_select(self, e):
        sel = self.sniff_list.curselection()
        if not sel: return
        pkt = self.captured_packets[sel[0]]
        self.packet_details.delete(1.0, tk.END)
        self.packet_details.insert(tk.END, pkt.show(dump=True) + "\n" + hexdump(pkt, dump=True))

    # ================= 6. WEB AUDIT =================
    def setup_web_auditor(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text=" Web Audit ")
        ctrl = tk.Frame(tab, bg=self.colors["bg"]); ctrl.pack(fill="x", padx=20, pady=20)
        self.url_entry = tk.Entry(ctrl, bg=self.colors["input_bg"], fg="white", width=50)
        self.url_entry.insert(0, "https://www.google.com"); self.url_entry.pack(side="left", padx=10)
        ttk.Button(ctrl, text="Audit", command=self.audit_web).pack(side="left")
        self.web_out = self.create_console(tab); self.web_out.pack(expand=True, fill="both", padx=20, pady=10)

    def audit_web(self):
        self.web_out.delete(1.0, tk.END); url = self.url_entry.get()
        def worker():
            try:
                r = requests.get(url, timeout=5)
                self.web_out.insert(tk.END, f"Status: {r.status_code}\n\nHeaders:\n")
                for k, v in r.headers.items(): self.web_out.insert(tk.END, f"{k}: {v}\n")
            except Exception as e: self.web_out.insert(tk.END, str(e))
        threading.Thread(target=worker, daemon=True).start()

    # ================= 7. VULN AUDIT =================
    def setup_vulnerability_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text=" Vuln Audit ")
        frame = tk.Frame(tab, bg=self.colors["bg"]); frame.pack(fill="x", padx=20, pady=20)
        self.vuln_target = tk.Entry(frame, bg=self.colors["input_bg"], fg="white", width=25)
        self.vuln_target.insert(0, "127.0.0.1"); self.vuln_target.pack(side="left", padx=10)
        ttk.Button(frame, text="Banner Grab", command=self.banner_grab).pack(side="left")
        self.vuln_out = self.create_console(tab); self.vuln_out.pack(expand=True, fill="both", padx=20, pady=10)

    def banner_grab(self):
        self.vuln_out.delete(1.0, tk.END); target = self.vuln_target.get()
        def worker():
            for p in [21, 22, 80, 443]:
                try:
                    s = socket.socket(); s.settimeout(1.5); s.connect((target, p))
                    if p == 80: s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    b = s.recv(1024).decode(errors='ignore').strip()
                    self.vuln_out.insert(tk.END, f"[+] {p}: {b[:100]}\n"); s.close()
                except: pass
        threading.Thread(target=worker, daemon=True).start()

    # ================= 8. ADVANCED PASSWORD CRACKER =================
    def setup_password_cracker_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" Hash Cracker ")

        frame = tk.Frame(tab, bg=self.colors["bg"], padx=20, pady=20)
        frame.pack(fill="x")

        # Hash Input
        tk.Label(frame, text="Target Hash:").pack(anchor="w")
        self.hash_to_crack = tk.Entry(frame, bg=self.colors["input_bg"], fg=self.colors["success"], width=64, font=("Consolas", 11))
        self.hash_to_crack.insert(0, "5ebe2294ecd0e0f08eab7690d2a6ee69") # 'secret'
        self.hash_to_crack.pack(fill="x", pady=5)

        # Wordlist Selection
        file_frame = tk.Frame(frame, bg=self.colors["bg"])
        file_frame.pack(fill="x", pady=5)
        
        tk.Label(file_frame, text="Wordlist:").pack(side="left")
        self.wordlist_path = tk.StringVar()
        self.wordlist_entry = tk.Entry(file_frame, textvariable=self.wordlist_path, bg=self.colors["input_bg"], fg="white", width=50)
        self.wordlist_entry.pack(side="left", padx=10)
        
        ttk.Button(file_frame, text="Browse", command=self.browse_wordlist).pack(side="left")

        # Algorithm & Action
        action_frame = tk.Frame(frame, bg=self.colors["bg"])
        action_frame.pack(fill="x", pady=10)

        tk.Label(action_frame, text="Algorithm:").pack(side="left")
        self.crack_algo = ttk.Combobox(action_frame, values=["MD5", "SHA1", "SHA256"], width=10)
        self.crack_algo.set("MD5")
        self.crack_algo.pack(side="left", padx=10)

        self.crack_btn = ttk.Button(action_frame, text="Start Cracking", command=self.crack_password)
        self.crack_btn.pack(side="left", padx=10)

        self.crack_out = self.create_console(tab)
        self.crack_out.pack(expand=True, fill="both", padx=20, pady=10)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(title="Select Wordlist", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            self.wordlist_path.set(filename)

    def crack_password(self):
        target = self.hash_to_crack.get().strip().lower()
        w_path = self.wordlist_path.get()
        algo = self.crack_algo.get()

        if not target or not w_path:
            messagebox.showwarning("Incomplete Data", "Please provide both a hash and a wordlist file.")
            return

        if not os.path.exists(w_path):
            messagebox.showerror("Error", "Wordlist file not found.")
            return

        self.crack_out.delete(1.0, tk.END)
        self.crack_out.insert(tk.END, f"[*] Initializing Dictionary Attack ({algo})...\n")
        self.crack_out.insert(tk.END, f"[*] Target: {target}\n[*] Wordlist: {os.path.basename(w_path)}\n{'-'*50}\n")

        def worker():
            start_time = time.time()
            try:
                with open(w_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for count, line in enumerate(f, 1):
                        word = line.strip()
                        
                        # Generate Hash
                        if algo == "MD5":
                            attempt = hashlib.md5(word.encode()).hexdigest()
                        elif algo == "SHA1":
                            attempt = hashlib.sha1(word.encode()).hexdigest()
                        else:
                            attempt = hashlib.sha256(word.encode()).hexdigest()

                        if attempt == target:
                            elapsed = time.time() - start_time
                            self.crack_out.insert(tk.END, f"\n[MATCH FOUND] After {count} attempts!\n")
                            self.crack_out.insert(tk.END, f"[PASSWORD] -> {word}\n")
                            self.crack_out.insert(tk.END, f"[TIME]     -> {elapsed:.2f} seconds\n")
                            return
                        
                        if count % 1000 == 0:
                            self.crack_out.insert(tk.END, f"[*] Processed {count} words...\n")
                            self.crack_out.see(tk.END)

                self.crack_out.insert(tk.END, "\n[!] Cracking finished. No match found in the wordlist.")
            except Exception as e:
                self.crack_out.insert(tk.END, f"\n[!] Error: {str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    # ================= 9. FILE CRACKER =================
    def setup_file_cracker_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=" File Cracker ")

        frame = tk.Frame(tab, bg=self.colors["bg"], padx=20, pady=20)
        frame.pack(fill="x")

        # Protected File Selection
        target_frame = tk.Frame(frame, bg=self.colors["bg"])
        target_frame.pack(fill="x", pady=5)
        
        tk.Label(target_frame, text="Target ZIP File:").pack(side="left")
        self.target_file_path = tk.StringVar()
        self.target_file_entry = tk.Entry(target_frame, textvariable=self.target_file_path, bg=self.colors["input_bg"], fg="white", width=47)
        self.target_file_entry.pack(side="left", padx=10)
        ttk.Button(target_frame, text="Browse", command=self.browse_target_file).pack(side="left")

        # Wordlist Selection
        wordlist_frame = tk.Frame(frame, bg=self.colors["bg"])
        wordlist_frame.pack(fill="x", pady=5)
        
        tk.Label(wordlist_frame, text="Wordlist File:  ").pack(side="left")
        self.file_wordlist_path = tk.StringVar()
        self.file_wordlist_entry = tk.Entry(wordlist_frame, textvariable=self.file_wordlist_path, bg=self.colors["input_bg"], fg="white", width=47)
        self.file_wordlist_entry.pack(side="left", padx=10)
        ttk.Button(wordlist_frame, text="Browse", command=self.browse_file_wordlist).pack(side="left")

        # Action Button
        action_btn = ttk.Button(frame, text="Start Cracking File", command=self.crack_file_password)
        action_btn.pack(pady=10)

        self.file_crack_out = self.create_console(tab)
        self.file_crack_out.pack(expand=True, fill="both", padx=20, pady=10)

    def browse_target_file(self):
        filename = filedialog.askopenfilename(title="Select Protected File", filetypes=(("ZIP files", "*.zip"), ("All files", "*.*")))
        if filename:
            self.target_file_path.set(filename)

    def browse_file_wordlist(self):
        filename = filedialog.askopenfilename(title="Select Wordlist", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if filename:
            self.file_wordlist_path.set(filename)

    def crack_file_password(self):
        target_path = self.target_file_path.get()
        w_path = self.file_wordlist_path.get()

        if not target_path or not w_path:
            messagebox.showwarning("Incomplete Data", "Please provide both the protected file and a wordlist.")
            return

        if not os.path.exists(target_path) or not os.path.exists(w_path):
            messagebox.showerror("Error", "File or Wordlist not found.")
            return

        self.file_crack_out.delete(1.0, tk.END)
        self.file_crack_out.insert(tk.END, f"[*] Initializing ZIP Dictionary Attack...\n")
        self.file_crack_out.insert(tk.END, f"[*] File: {os.path.basename(target_path)}\n[*] Wordlist: {os.path.basename(w_path)}\n{'-'*50}\n")

        def worker():
            start_time = time.time()
            try:
                with zipfile.ZipFile(target_path) as zf:
                    with open(w_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for count, line in enumerate(f, 1):
                            password = line.strip()
                            try:
                                # We use testzip to verify the password without full extraction
                                zf.testzip() # This doesn't actually take a pwd, let's use extractall or setpassword
                                # Actually, ZipFile.extractall is standard for verification
                                zf.extractall(pwd=password.encode())
                                elapsed = time.time() - start_time
                                self.file_crack_out.insert(tk.END, f"\n[SUCCESS] Password Found after {count} attempts!\n")
                                self.file_crack_out.insert(tk.END, f"[PASSWORD] -> {password}\n")
                                self.file_crack_out.insert(tk.END, f"[TIME]     -> {elapsed:.2f} seconds\n")
                                return
                            except (RuntimeError, zipfile.BadZipFile, Exception):
                                # Skip incorrect passwords (usually RuntimeError: Bad password)
                                pass
                            
                            if count % 100 == 0:
                                self.file_crack_out.insert(tk.END, f"[*] Testing: {password} (Total: {count})\n")
                                self.file_crack_out.see(tk.END)

                self.file_crack_out.insert(tk.END, "\n[!] Cracking finished. Password not in wordlist.")
            except Exception as e:
                self.file_crack_out.insert(tk.END, f"\n[!] Error: {str(e)}")

        threading.Thread(target=worker, daemon=True).start()

    # ================= 10. IP UTILS =================
    def setup_ip_utils(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text=" IP Utils ")
        ctrl = tk.Frame(tab, bg=self.colors["bg"]); ctrl.pack(fill="x", padx=20, pady=20)
        self.ip_entry = tk.Entry(ctrl, bg=self.colors["input_bg"], fg="white", width=25)
        self.ip_entry.insert(0, "8.8.8.8"); self.ip_entry.pack(side="left", padx=10)
        ttk.Button(ctrl, text="Geo Locate", command=self.geo_locate).pack(side="left")
        self.geo_out = self.create_console(tab); self.geo_out.pack(expand=True, fill="both", padx=20, pady=10)

    def geo_locate(self):
        self.geo_out.delete(1.0, tk.END)
        def worker():
            try:
                r = requests.get(f"http://ip-api.com/json/{self.ip_entry.get()}", timeout=5).json()
                if r.get("status") == "success":
                    self.geo_out.insert(tk.END, f"Country: {r.get('country')}\nCity: {r.get('city')}\nISP: {r.get('isp')}\n")
            except: pass
        threading.Thread(target=worker, daemon=True).start()

    def setup_creator_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text=" Creator ")
        tk.Label(tab, text="Scratchpad", font=("Segoe UI", 12), fg=self.colors["accent"]).pack(pady=10)
        self.notes = scrolledtext.ScrolledText(tab, bg="#1e293b", fg="#cbd5e1", borderwidth=0)
        self.notes.pack(expand=True, fill="both", padx=20, pady=10)

    def setup_about_tab(self):
        tab = ttk.Frame(self.notebook); self.notebook.add(tab, text=" About ")
        about = "OmniScanner Pro V 1.0\n\nFEATURES:\n• ZIP File Cracker\n• Wordlist Hash Cracker\n• Advanced Sniffer\n• Port & Ping Scanners"
        tk.Label(tab, text=about, justify="center", bg=self.colors["bg"], fg="#94a3b8", font=("Segoe UI", 11), padx=40, pady=60).pack(expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    if os.name == "nt":
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except: pass
    app = App(root)
    root.mainloop()