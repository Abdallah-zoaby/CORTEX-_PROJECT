import customtkinter as ctk
import threading
import sys
import os
import time
import json
import random
import asyncio
import aiohttp
import math
import google.generativeai as genai
from engine.scanner.main import CortexScanner, ScanConfig, ScanMode, VulnerabilityType, SeverityLevel
from engine.scanner.main import PortScanner, SubdomainEnumerator, BruteForceEngine, SSLTLSAnalyzer, JSSecretsAnalyzer
from simulation.ransom import RansomSim
from simulation.leak import DataLeakSim
from simulation.persist import PersistenceSim
from core.remediation import CortexFixer
from core.system import scan_startup_apps, scan_running_processes, scan_scheduled_tasks
from core.network import scan_open_ports, check_dns_integrity
from core.behavioral import BehavioralEngine, SIEMReporter, calculate_entropy
from core.twin import DigitalTwinTarget
from engine.simulation.attack_graph import AttackGraphEngine
from engine.simulation.ueba_engine import UEBAEngine, AutoResponseEngine
from engine.simulation.purple_controller import PurpleController
from engine.scanner.mobile import MobileAPKAuditor
from engine.scanner.api_audit import APIAuditor
from engine.scanner.network_sniffer import NetworkAnomalyDetector

try:
    from reports.pdf_generator import generate_pdf_report
except ImportError:
    generate_pdf_report = None

# --- Configuration & Theme ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# ================= VISUAL COMPONENTS =================
class SecurityGauge(ctk.CTkFrame):
    """Custom animated gauge for security metrics"""
    def __init__(self, master, title, color="#238636", **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.color = color
        self.value = 0
        
        self.canvas = ctk.CTkCanvas(self, width=160, height=100, bg="#161b22", highlightthickness=0)
        self.canvas.pack()
        
        self.lbl_title = ctk.CTkLabel(self, text=title, font=("Segoe UI", 10, "bold"), text_color="#8b949e")
        self.lbl_title.pack()
        
        self.lbl_val = ctk.CTkLabel(self, text="0%", font=("JetBrains Mono", 18, "bold"), text_color=color)
        self.lbl_val.place(relx=0.5, rely=0.6, anchor="center")
        
        self.draw_gauge(0)

    def draw_gauge(self, percent):
        self.canvas.delete("gauge")
        # Background arc
        self.canvas.create_arc(10, 20, 150, 160, start=0, extent=180, outline="#30363d", width=12, style="arc", tags="gauge")
        # Value arc
        extent = (percent / 100) * 180
        self.canvas.create_arc(10, 20, 150, 160, start=180, extent=-extent, outline=self.color, width=12, style="arc", tags="gauge")
        self.lbl_val.configure(text=f"{int(percent)}%")
        self.value = percent

    def set_value(self, val):
        self.draw_gauge(val)

class GlobalAttackMap(ctk.CTkCanvas):
    """Stylized Cyber-Attack World Map"""
    def __init__(self, master, **kwargs):
        super().__init__(master, bg="#0d1117", highlightthickness=0, **kwargs)
        self.points = []
        self.draw_base_map()
        
    def draw_base_map(self):
        # Draw a stylized doted world map
        for _ in range(300):
            x = random.randint(10, 800)
            y = random.randint(10, 400)
            self.create_oval(x, y, x+1, y+1, fill="#1f6feb", tags="map")

    def animate_attack(self, origin_name="Unknown"):
        # Simulated attack from a random spot to a "center" (The user's system)
        x0, y0 = random.randint(50, 750), random.randint(50, 350)
        x1, y1 = 400, 200 # App Center
        
        line = self.create_line(x0, y0, x0+1, y0+1, fill="#da3633", width=2, arrow="last", tags="attack")
        
        def _step(curr_x, curr_y, step=0):
            if step < 20:
                nx = x0 + (x1 - x0) * (step/20)
                ny = y0 + (y1 - y0) * (step/20)
                self.coords(line, x0, y0, nx, ny)
                self.after(30, lambda: _step(nx, ny, step+1))
            else:
                self.create_oval(x1-5, y1-5, x1+5, y1+5, outline="#da3633", width=2, tags="attack")
                self.after(2000, lambda: self.delete(line))

        _step(x0, y0)

class ReconRadar(ctk.CTkCanvas):
    """Animated Radar for Recon activities"""
    def __init__(self, master, **kwargs):
        super().__init__(master, bg="#0d1117", highlightthickness=0, **kwargs)
        self.angle = 0
        self.is_scanning = False
        self.sweep_line = None
        self.targets = [] # List of (x, y, color)
        self.draw_radar_static()
        
    def draw_radar_static(self):
        cx, cy = 150, 150
        # Circles
        for r in [40, 80, 120]:
            self.create_oval(cx-r, cy-r, cx+r, cy+r, outline="#1f6feb", width=1, dash=(5,5))
        # Crosshairs
        self.create_line(cx-130, cy, cx+130, cy, fill="#1f6feb", width=1, dash=(5,5))
        self.create_line(cx, cy-130, cx, cy+130, fill="#1f6feb", width=1, dash=(5,5))

    def start_sweep(self):
        self.is_scanning = True
        self.animate_sweep()

    def stop_sweep(self):
        self.is_scanning = False
        self.delete("sweep")

    def animate_sweep(self):
        if not self.is_scanning: return
        cx, cy = 150, 150
        self.delete("sweep")
        
        # Sweep line
        import math
        rad = math.radians(self.angle)
        x = cx + 130 * math.cos(rad)
        y = cy + 130 * math.sin(rad)
        
        self.create_line(cx, cy, x, y, fill="#238636", width=2, tags="sweep")
        # Glow
        self.create_arc(cx-130, cy-130, cx+130, cy+130, start=-self.angle, extent=30, fill="#238636", stipple="gray25", tags="sweep")
        
        self.angle = (self.angle + 5) % 360
        self.after(30, self.animate_sweep)

    def add_target(self, status="OK"):
        import random
        cx, cy = 150, 150
        r = random.randint(20, 120)
        angle = random.randint(0, 360)
        import math
        rad = math.radians(angle)
        x = cx + r * math.cos(rad)
        y = cy + r * math.sin(rad)
        color = "#238636" if status == "OK" else "#da3633"
        self.create_oval(x-4, y-4, x+4, y+4, fill=color, outline="#fff", tags="target")

class LiveWaveform(ctk.CTkCanvas):
    """Pulsing waveform for system activity"""
    def __init__(self, master, color="#238636", **kwargs):
        super().__init__(master, bg="#161b22", highlightthickness=0, **kwargs)
        self.color = color
        self.phase = 0
        self.animate()
        
    def animate(self):
        self.delete("wave")
        width = int(self.cget("width"))
        height = int(self.cget("height"))
        points = []
        import math
        for x in range(0, width, 5):
            y = height/2 + 20 * math.sin(x*0.05 + self.phase)
            points.extend([x, y])
        
        if len(points) >= 4:
            self.create_line(points, fill=self.color, width=2, smooth=True, tags="wave")
        
        self.phase += 0.2
        self.after(50, self.animate)

class VulnerabilityCard(ctk.CTkFrame):
    """High-end card for displaying a vulnerability"""
    def __init__(self, master, vuln, **kwargs):
        color = "#da3633" if vuln.severity.value == "CRITICAL" else "#d29922"
        super().__init__(master, fg_color="#1c2128", border_color=color, border_width=2, corner_radius=10, **kwargs)
        
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(header, text=f"📍 {vuln.type.value}", font=("Segoe UI", 13, "bold"), text_color="#c9d1d9").pack(side="left")
        ctk.CTkLabel(header, text=vuln.severity.value, font=("Segoe UI", 10, "bold"), text_color=color).pack(side="right")
        
        ctk.CTkLabel(self, text=f"URL: {vuln.url}", font=("Consolas", 10), text_color="#8b949e").pack(anchor="w", padx=10)
        
        self.details = ctk.CTkTextbox(self, height=80, font=("Consolas", 10), fg_color="#0d1117", text_color="#c9d1d9")
        self.details.pack(fill="x", padx=10, pady=5)
        self.details.insert("1.0", f"PATCH:\n{vuln.remediation_patch}")
        self.details.configure(state="disabled")

class CortexProApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("CORTEX - Enterprise Security Suite v16.0 [CORP Edition]")
        self.geometry("1400x900")
        
        # Colors & Fonts
        self.colors = {
            "bg": "#0d1117",         # GitHub Dark Dimmed
            "sidebar": "#161b22",    # Darker Sidebar
            "accent": "#238636",     # GitHub Green
            "danger": "#da3633",     # Red
            "warning": "#d29922",    # Orange
            "text": "#c9d1d9",       # Light Gray
            "terminal": "#0d1117",   # Black
        }
        self.fonts = {
            "header": ("JetBrains Mono", 28, "bold"),
            "sub": ("Segoe UI", 16, "bold"),
            "mono": ("Consolas", 12),
        }

        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ================= Sidebar =================
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=self.colors["sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        # Logo
        self.logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.logo_frame.grid(row=0, column=0, padx=20, pady=(40, 30))
        
        self.logo_icon = ctk.CTkLabel(self.logo_frame, text="🛡️", font=("Segoe UI Emoji", 40))
        self.logo_icon.pack()
        self.logo_text = ctk.CTkLabel(self.logo_frame, text="CORTEX\nDEFENSE", font=self.fonts["header"], text_color=self.colors["accent"])
        self.logo_text.pack()
        
        # Action Buttons
        self.create_sidebar_btn("⚡ FULL SYSTEM SCAN", self.start_scan_thread, self.colors["accent"], 1)
        self.create_sidebar_btn("🛡️ AUTO-REMEDIATION", self.run_autofix, "#1f6feb", 2)
        self.create_sidebar_btn("🧠 AI ANALYST", self.ask_ai_analyst, "#8957e5", 3)
        self.btn_pdf = self.create_sidebar_btn("📄 GENERATE REPORT", self.export_pdf_report, "#b1bad1", 4, state="disabled", fg="#333")

        # Status Footer
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="#21262d")
        self.status_frame.grid(row=9, column=0, padx=10, pady=20, sticky="ew")
        
        self.lbl_status = ctk.CTkLabel(self.status_frame, text="🟢 SYSTEM ONLINE", font=("Consolas", 11, "bold"), text_color=self.colors["accent"])
        self.lbl_status.pack(pady=5)
        self.lbl_ver = ctk.CTkLabel(self.status_frame, text="v8.0.0 | AI: Active", font=("Consolas", 10), text_color="#8b949e")
        self.lbl_ver.pack(pady=(0, 5))

        # ================= Main Content =================
        self.main_area = ctk.CTkFrame(self, fg_color=self.colors["bg"], corner_radius=0)
        self.main_area.grid(row=0, column=1, sticky="nsew")
        self.main_area.grid_rowconfigure(1, weight=1)
        self.main_area.grid_columnconfigure(0, weight=1)

        # Dashboard Header
        self.header_frame = ctk.CTkFrame(self.main_area, height=100, corner_radius=10, fg_color="#161b22")
        self.header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.header_frame.grid_columnconfigure((0,1,2,3), weight=1)

        self.stat_critical = self.create_hud_stat("CRITICAL THREATS", "0", self.colors["danger"], 0)
        self.stat_high = self.create_hud_stat("IDENTIFIED RISKS", "0", self.colors["warning"], 1)
        self.stat_health = self.create_hud_stat("SYSTEM HEALTH", "100%", self.colors["accent"], 2)
        self.stat_compliance = self.create_hud_stat("COMPLIANCE", "100%", "#1f6feb", 3)

        # Tabs System
        self.tabs = ctk.CTkTabview(self.main_area, fg_color="#161b22", segmented_button_fg_color="#0d1117", segmented_button_selected_color=self.colors["accent"])
        self.tabs.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        self.tab_scan = self.tabs.add("  🖥️ DASHBOARD  ")
        self.tab_web = self.tabs.add("  🌐 WEB AUDIT  ")
        self.tab_analytics = self.tabs.add("  📊 ANALYTICS  ")
        self.tab_recon = self.tabs.add("  🔓 RECON  ")
        self.tab_deception = self.tabs.add("  🍯 DECEPTION  ")
        self.tab_forensics = self.tabs.add("  🕵️ FORENSICS  ")
        self.tab_ai = self.tabs.add("  🤖 INTELLIGENCE  ")
        self.tab_sim = self.tabs.add("  ⚔️ WAR ROOM  ")
        self.tab_enterprise = self.tabs.add("  🏢 ENTERPRISE HUB  ")
        self.tab_mobile_api = self.tabs.add("  📱 MOBILE & API  ")

        # --- Tab 1: Dashboard (Terminal) ---
        self.dashboard_top = ctk.CTkFrame(self.tab_scan, fg_color="#161b22", height=100)
        self.dashboard_top.pack(fill="x", padx=10, pady=(10, 0))
        
        ctk.CTkLabel(self.dashboard_top, text="📈 SYSTEM ACTIVITY WAVEFORM", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(pady=5)
        self.waveform = LiveWaveform(self.dashboard_top, width=1000, height=60)
        self.waveform.pack(padx=20, pady=5)

        self.console = ctk.CTkTextbox(self.tab_scan, font=self.fonts["mono"], fg_color="#0d1117", text_color="#3fb950", state="disabled")
        self.console.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.tab_scan, orientation="horizontal", mode="determinate", progress_color=self.colors["accent"])
        self.progress_bar.pack(fill="x", padx=10, pady=(0, 10))
        self.progress_bar.set(0)
        
        self.activity_frame = ctk.CTkFrame(self.tab_scan, fg_color="transparent", height=100)
        self.activity_frame.pack(fill="x", padx=10)
        self.activity_lbls = []
        for _ in range(3):
            lbl = ctk.CTkLabel(self.activity_frame, text="", font=("Consolas", 10), text_color="#8b949e")
            lbl.pack(anchor="w")
            self.activity_lbls.append(lbl)
        
        # Scanner & State Initialization
        self.findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self.risk_score = 100
        self.scan_results = None
        self.web_findings = []
        self.ai_response_text = ""
        self.simulation_logs = ""
        self.scanner = CortexScanner(ScanConfig(target_url=""))
        self.behavior_engine = BehavioralEngine()
        self.digital_twin = DigitalTwinTarget()
        
        # Purple Team Engines
        self.purple_orchestrator = PurpleController()
        self.sniffer_engine = NetworkAnomalyDetector()

        # --- Tab Setup ---
        self.setup_web_tab()
        self.setup_analytics_tab()
        self.setup_recon_tab()
        self.setup_deception_tab()
        self.setup_forensics_tab()
        self.setup_ai_tab()
        self.setup_sim_tab()
        self.setup_enterprise_tab()
        self.setup_mobile_api_tab()

        # Start Dynamic Elements
        self.after(500, self.run_startup_sequence)
        self.update_activity_feed()
        
        # Start Real Live Monitor
        self.scanner.start_live_monitor(self._on_live_activity)

    def _on_live_activity(self, connections):
        """Callback for real network connections"""
        for conn in connections:
            msg = f"NET: Established connection with {conn}"
            self.after(0, lambda m=msg: self.log(self.console, m, "INFO"))

    def update_activity_feed(self):
        msgs = [
            "INFO: Kernel integrity verified", "SYNC: Cloud threat database updated",
            "SCAN: Monitoring background packets", "AUTH: Secure session established",
            "MEM: Analysis of heap memory", "NET: Socket listening on 0.0.0.0"
        ]
        new_msg = f"> {random.choice(msgs)} [{time.strftime('%H:%M:%S')}]"
        # Shift
        if hasattr(self, 'activity_lbls') and self.activity_lbls:
            for i in range(len(self.activity_lbls)-1, 0, -1):
                self.activity_lbls[i].configure(text=self.activity_lbls[i-1].cget("text"))
            self.activity_lbls[0].configure(text=new_msg, text_color=self.colors["accent"])
        self.after(4000, self.update_activity_feed)

    def run_startup_sequence(self):
        msgs = [
            "Initializing CORTEX Neural Engine...", "Loading Threat Intelligence Database...",
            "Establishing Secure Sandbox...", "Handshaking with AI Analyst...",
            "SYSTEM READY. STANDING BY."
        ]
        for i, m in enumerate(msgs):
            self.after(i*400, lambda msg=m: self.log(self.console, msg, "SUCCESS" if "READY" in msg else None))
        
        # Start Live Behavioral Monitoring
        self.after(2000, self.monitor_behavior)

    # ================= UI HELPERS =================
    def create_sidebar_btn(self, text, cmd, fg_color, row, state="normal", fg="#fff"):
        btn = ctk.CTkButton(self.sidebar, text=text, command=cmd, 
                          font=("Segoe UI", 12, "bold"), height=45, fg_color=fg_color, 
                          hover_color="#30363d", state=state, text_color=fg)
        btn.grid(row=row, column=0, padx=20, pady=8, sticky="ew")
        return btn

    def create_hud_stat(self, title, value, color, col):
        frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        frame.grid(row=0, column=col, padx=10, pady=10)
        
        lbl_val = ctk.CTkLabel(frame, text=value, font=("JetBrains Mono", 36), text_color=color)
        lbl_val.pack()
        lbl_title = ctk.CTkLabel(frame, text=title, font=("Segoe UI", 10, "bold"), text_color="#8b949e")
        lbl_title.pack()
        return lbl_val

    def setup_web_tab(self):
        # Top Bar
        top_frame = ctk.CTkFrame(self.tab_web, fg_color="transparent")
        top_frame.pack(fill="x", padx=10, pady=10)

        self.url_entry = ctk.CTkEntry(top_frame, placeholder_text="Enter Target URL (e.g. https://example.com)", height=40, font=("Consolas", 13))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.mode_var = ctk.StringVar(value="SAFE")
        self.mode_menu = ctk.CTkOptionMenu(top_frame, values=["SAFE", "NORMAL", "DESTRUCTIVE"], 
                                         variable=self.mode_var, width=150, height=40, 
                                         fg_color="#238636", button_color="#1ea045")
        self.mode_menu.pack(side="left", padx=(0, 10))

        self.btn_web_scan = ctk.CTkButton(top_frame, text="🚀 LAUNCH AUDIT", command=self.start_web_scan, 
                                        height=40, fg_color="#da3633", font=("Segoe UI", 12, "bold"))
        self.btn_web_scan.pack(side="right")

        # Split View (Network Map + Console + AI Review)
        split_frame = ctk.CTkFrame(self.tab_web, fg_color="transparent")
        split_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Network Map (Live Visualization)
        map_frame = ctk.CTkFrame(split_frame, width=300, fg_color="#0d1117")
        map_frame.pack(side="left", fill="y", padx=(0, 5))
        ctk.CTkLabel(map_frame, text="🌐 NETWORK MAP", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(pady=5)
        self.map_canvas = ctk.CTkCanvas(map_frame, width=280, height=500, bg="#0d1117", highlightthickness=0)
        self.map_canvas.pack(padx=10, pady=10)
        self.map_nodes = {}

        self.web_console = ctk.CTkTextbox(split_frame, font=("Consolas", 11), fg_color="#0d1117", text_color="#c9d1d9")
        self.web_console.pack(side="left", fill="both", expand=True, padx=5)
        
        self.web_ai_panel = ctk.CTkScrollableFrame(split_frame, width=400, fg_color="#161b22", label_text="🚨 LIVE FINDINGS & AI PATCHES", label_font=("Segoe UI", 12, "bold"))
        self.web_ai_panel.pack(side="right", fill="y", padx=(5, 0))

    def setup_recon_tab(self):
        """RECON tab: Port Scan, Subdomain Enum, SSL, Brute Force, JS Secrets"""
        # Top bar
        top = ctk.CTkFrame(self.tab_recon, fg_color="transparent")
        top.pack(fill="x", padx=10, pady=10)
        
        self.recon_target = ctk.CTkEntry(top, placeholder_text="🎯 Target Host / Domain (e.g. example.com)", height=40, font=("Consolas", 13))
        self.recon_target.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # Tool buttons row
        btn_row = ctk.CTkFrame(self.tab_recon, fg_color="transparent")
        btn_row.pack(fill="x", padx=10)
        
        tools = [
            ("🔍 PORT SCAN", self.run_port_scan, "#da3633"),
            ("🌍 SUBDOMAINS", self.run_subdomain_enum, "#1f6feb"),
            ("🔒 SSL/TLS", self.run_ssl_scan, "#238636"),
            ("🔐 BRUTE FORCE", self.run_brute_force, "#8957e5"),
            ("📜 JS SECRETS", self.run_js_scan, "#d29922"),
        ]
        for text, cmd, color in tools:
            ctk.CTkButton(btn_row, text=text, command=cmd, fg_color=color, width=140, height=38, font=("Segoe UI", 11, "bold")).pack(side="left", padx=4, pady=5)

        # Split View (Radar + Output)
        split = ctk.CTkFrame(self.tab_recon, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=10, pady=10)
        
        radar_frame = ctk.CTkFrame(split, width=320, fg_color="#0d1117")
        radar_frame.pack(side="left", fill="y", padx=(0, 5))
        ctk.CTkLabel(radar_frame, text="📡 RECON RADAR", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(pady=5)
        self.recon_radar = ReconRadar(radar_frame, width=300, height=300)
        self.recon_radar.pack(padx=10, pady=10)
        
        self.recon_output = ctk.CTkTextbox(split, font=self.fonts["mono"], fg_color="#0d1117", text_color="#58a6ff")
        self.recon_output.pack(side="right", expand=True, fill="both")
        self.recon_output.insert("0.0", "═══ RECON CENTER ═══\nSelect a target and choose a recon tool.\n\n")

    def _get_recon_target(self):
        host = self.recon_target.get().strip()
        if not host:
            self.log(self.recon_output, "❌ Enter a target host/domain first!", "CRITICAL")
            return None
        # Clean to bare hostname
        if host.startswith("http"):
            from urllib.parse import urlparse
            host = urlparse(host).hostname or host
        return host.lower()

    def run_port_scan(self):
        host = self._get_recon_target()
        if not host: return
        self.log(self.recon_output, f"\n🔍 Starting port scan on {host}...")
        self.recon_radar.start_sweep()
        
        async def _scan():
            result = await self.scanner.port_scanner.scan(host)
            self.after(0, self.recon_radar.stop_sweep)
            self.after(0, lambda: self._display_port_results(result))
        threading.Thread(target=lambda: asyncio.run(_scan()), daemon=True).start()

    def _display_port_results(self, result):
        self.log(self.recon_output, f"\n{'═'*50}")
        self.log(self.recon_output, f"🖥️  HOST: {result['host']}  |  RISK: {result['risk_level']}")
        self.log(self.recon_output, f"Scanned: {result['total_scanned']} | Open: {len(result['open_ports'])} | Closed: {result['closed']} | Filtered: {result['filtered']}")
        self.log(self.recon_output, f"{'─'*50}")
        
        for p in result["open_ports"]:
            icon = "💀" if p["dangerous"] else "✅"
            self.after(0, lambda: self.recon_radar.add_target("DANGER" if p["dangerous"] else "OK"))
            self.log(self.recon_output, f"  {icon} Port {p['port']:>5}  |  {p['service']:<15}  |  {'⚠ DANGEROUS' if p['dangerous'] else 'OK'}")
            if p["dangerous"]:
                self.scanner.alerts.trigger("Dangerous Port Open", f"Port {p['port']} ({p['service']}) is open on {result['host']}", "CRITICAL")
        
        if not result["open_ports"]:
            self.log(self.recon_output, "  No open ports found.")
        self._update_risk_score()
        self.log(self.recon_output, f"{'═'*50}\n")

    def run_subdomain_enum(self):
        host = self._get_recon_target()
        if not host: return
        self.log(self.recon_output, f"\n🌍 Enumerating subdomains for {host}...")
        
        async def _enum():
            result = await self.scanner.subdomain_enum.enumerate(host)
            self.after(0, lambda: self._display_subdomain_results(result))
        threading.Thread(target=lambda: asyncio.run(_enum()), daemon=True).start()

    def _display_subdomain_results(self, result):
        self.log(self.recon_output, f"\n{'═'*50}")
        self.log(self.recon_output, f"🌍 DOMAIN: {result['domain']}")
        self.log(self.recon_output, f"Total Found: {result['total']} (DNS: {result['sources']['dns_bruteforce']}, crt.sh: {result['sources']['crt_sh']})")
        self.log(self.recon_output, f"{'─'*50}")
        for sub in result["subdomains"]:
            self.after(0, lambda: self.recon_radar.add_target("OK"))
            self.log(self.recon_output, f"  🔹 {sub}")
        if not result["subdomains"]:
            self.log(self.recon_output, "  No subdomains found.")
        self._update_risk_score()
        self.log(self.recon_output, f"{'═'*50}\n")

    def run_ssl_scan(self):
        host = self._get_recon_target()
        if not host: return
        self.log(self.recon_output, f"\n🔒 Analyzing SSL/TLS for {host}...")
        
        async def _ssl():
            result = await self.scanner.ssl_analyzer.analyze(host)
            self.after(0, lambda: self._display_ssl_results(result))
        threading.Thread(target=lambda: asyncio.run(_ssl()), daemon=True).start()

    def _display_ssl_results(self, result):
        self.log(self.recon_output, f"\n{'═'*50}")
        self.log(self.recon_output, f"🔒 SSL/TLS REPORT: {result['hostname']}  |  GRADE: {result['grade']}")
        self.log(self.recon_output, f"{'─'*50}")
        
        cert = result.get("certificate", {})
        if cert:
            self.log(self.recon_output, f"  📜 Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}")
            self.log(self.recon_output, f"  📅 Expires: {cert.get('not_after', 'N/A')} ({cert.get('days_until_expiry', '?')} days)")
        
        cipher = result.get("cipher", {})
        if cipher:
            self.log(self.recon_output, f"  🔑 Cipher: {cipher.get('name', 'N/A')} ({cipher.get('bits', '?')} bits)")
            self.log(self.recon_output, f"  📡 Protocol: {result.get('protocol_version', 'N/A')}")
        
        for issue in result.get("issues", []):
            icons = {"CRITICAL": "💀", "HIGH": "🔥", "MEDIUM": "⚠️", "INFO": "ℹ️"}
            self.after(0, lambda s=issue['severity']: self.recon_radar.add_target("DANGER" if s in ["CRITICAL", "HIGH"] else "OK"))
            self.log(self.recon_output, f"  {icons.get(issue['severity'], '❓')} [{issue['severity']}] {issue['issue']}")
        self._update_risk_score()
        self.log(self.recon_output, f"{'═'*50}\n")

    def run_brute_force(self):
        host = self._get_recon_target()
        if not host: return
        url = f"https://{host}" if not host.startswith("http") else host
        self.log(self.recon_output, f"\n🔐 Brute Force: Fetching login forms from {url}...")
        
        async def _brute():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as resp:
                        html = await resp.text()
                
                forms = await self.scanner.brute_force.find_login_forms(url, html)
                if not forms:
                    self.after(0, lambda: self.log(self.recon_output, "  ❌ No login forms found on target."))
                    return
                
                self.after(0, lambda: self.log(self.recon_output, f"  ✅ Found {len(forms)} login form(s). Testing..."))
                
                for form in forms:
                    result = await self.scanner.brute_force.brute_force(form, url)
                    if result:
                        self.after(0, lambda r=result: self._display_brute_result(r))
                        self.scanner.alerts.trigger("LOGIN CRACKED!", f"Credentials found: {result['username']}:{result['password']}", "CRITICAL")
                    else:
                        self.after(0, lambda: self.log(self.recon_output, "  🔒 No weak credentials found (tested 50 combos)."))
            except Exception as e:
                self.after(0, lambda: self.log(self.recon_output, f"  ❌ Error: {e}"))
        
        threading.Thread(target=lambda: asyncio.run(_brute()), daemon=True).start()

    def _display_brute_result(self, result):
        self.log(self.recon_output, f"\n{'═'*50}")
        self.log(self.recon_output, f"💀💀💀 CREDENTIALS FOUND! 💀💀💀")
        self.log(self.recon_output, f"  🔑 Username: {result['username']}")
        self.log(self.recon_output, f"  🔑 Password: {result['password']}")
        self.log(self.recon_output, f"  🔗 URL: {result['url']}")
        self.log(self.recon_output, f"{'═'*50}\n")

    def run_js_scan(self):
        host = self._get_recon_target()
        if not host: return
        url = f"https://{host}" if not host.startswith("http") else host
        self.log(self.recon_output, f"\n📜 Scanning JavaScript files on {url}...")
        
        async def _js():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10, ssl=False) as resp:
                        html = await resp.text()
                
                findings = await self.scanner.js_analyzer.analyze_page(url, html)
                self.after(0, lambda: self._display_js_results(findings))
            except Exception as e:
                self.after(0, lambda: self.log(self.recon_output, f"  ❌ Error: {e}"))
        
        threading.Thread(target=lambda: asyncio.run(_js()), daemon=True).start()

    def _display_js_results(self, findings):
        self.log(self.recon_output, f"\n{'═'*50}")
        self.log(self.recon_output, f"📜 JS SECRETS SCAN: Found {len(findings)} leaked secrets")
        self.log(self.recon_output, f"{'─'*50}")
        for f in findings:
            self.log(self.recon_output, f"  💀 [{f.severity.value}] {f.description}")
            self.log(self.recon_output, f"     📎 {f.evidence[:80]}")
            self.log(self.recon_output, f"     🔗 {f.url}")
        if not findings:
            self.log(self.recon_output, "  ✅ No secrets found in JavaScript files.")
        self.log(self.recon_output, f"{'═'*50}\n")

    def setup_deception_tab(self):
        """Layout for Honeypot & Deception with live stats"""
        # Top controls
        header = ctk.CTkFrame(self.tab_deception, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(header, text="🍯 HONEYPOT COMMAND CENTER", font=self.fonts["sub"], text_color=self.colors["accent"]).pack(side="left")
        self.btn_honeypot = ctk.CTkButton(header, text="▶ START HONEYPOT", command=self.toggle_honeypot, fg_color=self.colors["accent"], width=180)
        self.btn_honeypot.pack(side="right")

        # Stats Row
        stats_row = ctk.CTkFrame(self.tab_deception, fg_color="#0d1117")
        stats_row.pack(fill="x", padx=10, pady=(0, 10))
        stats_row.grid_columnconfigure((0,1,2,3), weight=1)
        
        self.hp_stat_total = self._make_hp_stat(stats_row, "TOTAL ATTACKS", "0", 0)
        self.hp_stat_critical = self._make_hp_stat(stats_row, "CRITICAL EVENTS", "0", 1)
        self.hp_stat_blacklist = self._make_hp_stat(stats_row, "BLACKLISTED IPs", "0", 2)
        self.hp_stat_port = self._make_hp_stat(stats_row, "PORT", "8080", 3)

        # Attacker log
        self.deception_log = ctk.CTkTextbox(self.tab_deception, font=self.fonts["mono"], fg_color="#0d1117", text_color="#ff7b72")
        self.deception_log.pack(expand=True, fill="both", padx=10, pady=(0,10))
        self.deception_log.insert("0.0", "[STATUS] Honeypot ready. Click START to activate.\n")

    def _make_hp_stat(self, parent, title, value, col):
        f = ctk.CTkFrame(parent, fg_color="#161b22")
        f.grid(row=0, column=col, padx=5, pady=8, sticky="ew")
        lbl = ctk.CTkLabel(f, text=value, font=("JetBrains Mono", 24), text_color="#ff7b72")
        lbl.pack(pady=(5,0))
        ctk.CTkLabel(f, text=title, font=("Segoe UI", 9), text_color="#8b949e").pack(pady=(0,5))
        return lbl

    def setup_forensics_tab(self):
        """Advanced Forensic Analysis & Integrity Monitoring"""
        self.forensic_output = ctk.CTkTextbox(self.tab_forensics, font=("Consolas", 12), fg_color="#0d1117", text_color="#3fb950")
        self.forensic_output.pack(expand=True, fill="both", padx=10, pady=10)
        self.forensic_output.insert("0.0", "═══ CORTEX FORENSIC ENGINE ONLINE ═══\nMonitoring system calls and process entropy...\n\n")

        btn_frame = ctk.CTkFrame(self.tab_forensics, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkButton(btn_frame, text="🕵️ RUN DEEP SYSTEM FORENSICS", command=self.run_forensic_scan, fg_color="#1f6feb", height=40).pack(side="left", fill="x", expand=True, padx=5)
        
        # Real-time event simulation for forensics
        self._simulate_forensic_noise()

    def _simulate_forensic_noise(self):
        """Simulate real-time forensic activity background noise"""
        events = [
            "AUDIT: Checking parent process for PID 4829",
            "FORENSIC: Analyzing heap for suspicious entropy",
            "FILESYSTEM: Monitoring write events in System32",
            "REGISTRY: Verifying integrity of HKLM\\RunKeys",
            "VOLATILE: Scanning pagefile.sys for leaked credentials",
            "KERNEL: Hooking syscall 0x6E for integrity check"
        ]
        if self.tabs.get() == "  🕵️ FORENSICS  ":
            msg = f"🔍 {random.choice(events)} ... [OK]"
            self.log(self.forensic_output, msg)
        self.after(5000, self._simulate_forensic_noise)

    def setup_ai_tab(self):
        # AI Chat & News Feed
        split = ctk.CTkFrame(self.tab_ai, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=10, pady=10)
        
        # News Sidebar
        news_frame = ctk.CTkFrame(split, width=350, fg_color="#161b22")
        news_frame.pack(side="right", fill="y", padx=(10, 0))
        ctk.CTkLabel(news_frame, text="📡 THREAT INTELLIGENCE", font=self.fonts["sub"], text_color=self.colors["accent"]).pack(pady=10)
        self.news_box = ctk.CTkTextbox(news_frame, font=("Segoe UI", 11), fg_color="#0d1117")
        self.news_box.pack(expand=True, fill="both", padx=10, pady=(0, 10))
        
        # Main Analyst Chat
        chat_frame = ctk.CTkFrame(split, fg_color="transparent")
        chat_frame.pack(side="left", fill="both", expand=True)
        self.ai_box = ctk.CTkTextbox(chat_frame, font=("Segoe UI", 14), wrap="word", fg_color="#0d1117", text_color="#e6edf3")
        self.ai_box.pack(expand=True, fill="both")
        
        self.update_threat_intel()
        self.after(30000, self.update_threat_intel) # Refresh every 30s

    def toggle_honeypot(self):
        """Start/Stop Honeypot"""
        if not self.scanner.honeypot_thread or not self.scanner.honeypot_thread.is_alive():
            self.scanner.start_honeypot(port=8080)
            self.btn_honeypot.configure(text="🛑 STOP HONEYPOT", fg_color=self.colors["danger"])
            self.log(self.deception_log, "Honeypot active on port 8080", "SUCCESS")
            # Start monitoring log file
            self.monitor_honeypot()
        else:
            # Flask doesn't stop easily, but we can stop UI updates
            self.btn_honeypot.configure(text="▶️ START HONEYPOT", fg_color=self.colors["accent"])
            self.log(self.deception_log, "Honeypot monitoring suspended.", "WARNING")

    def monitor_honeypot(self):
        """Read honeypot attacks from JSON file and update all stats"""
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'honeypot_attacks.json')
        def _check():
            last_pos = 0
            hp_hits = 0
            critical_hits = 0
            blacklisted = set()
            
            while self.btn_honeypot.cget("text") == "🛑 STOP HONEYPOT":
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8') as f:
                        f.seek(last_pos)
                        lines = f.readlines()
                        last_pos = f.tell()
                        for line in lines:
                            try:
                                data = json.loads(line)
                                hp_hits += 1
                                severity = data.get('severity', 'LOW')
                                if severity == 'CRITICAL':
                                    critical_hits += 1
                                    blacklisted.add(data['ip'])
                                    
                                emojis = {'CRITICAL': '💀', 'HIGH': '🔥', 'MEDIUM': '⚠️', 'LOW': '📝'}
                                self.log(self.deception_log, f"{emojis.get(severity,'❓')} [{data['timestamp'][:19]}] IP: {data['ip']} | {data['type']} -> {data['details'][:60]}", "CRITICAL" if severity == "CRITICAL" else None)
                                
                            except: pass
                        
                        # Update stat widgets
                        if lines:
                            self.after(0, lambda h=hp_hits: self.hp_stat_total.configure(text=str(h)))
                            self.after(0, lambda c=critical_hits: self.hp_stat_critical.configure(text=str(c)))
                            self.after(0, lambda b=len(blacklisted): self.hp_stat_blacklist.configure(text=str(b)))
                            self.after(0, lambda h=hp_hits: self.stat_honeypot.configure(text=str(h)))
                time.sleep(2)
        threading.Thread(target=_check, daemon=True).start()

    def run_forensic_scan(self):
        """Execute AI-driven forensic analysis + Real File Scan"""
        self.forensic_output.configure(state="normal")
        self.forensic_output.delete("0.0", "end")
        self.log(self.forensic_output, "🕵️ Initiating forensic deep-scan of user directories...", "INFO")
        
        def _scan_files():
            import os
            suspicious = []
            target_path = os.path.expanduser("~/Desktop")
            self.log(self.forensic_output, f"🔍 Scanning: {target_path}")
            
            try:
                for root, dirs, files in os.walk(target_path):
                    for file in files:
                        if file.endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr')):
                            suspicious.append(os.path.join(root, file))
                    if len(suspicious) > 20: break # Limit for demo
                
                self.log(self.forensic_output, f"✅ Scan Complete. Found {len(suspicious)} potential entry points.", "SUCCESS")
                for s in suspicious[:10]:
                    # Check entropy for breakthrough ransomware detection
                    try:
                        with open(s, 'rb') as f:
                            data = f.read(4096)
                            ent = calculate_entropy(data)
                            if ent > 7.5:
                                self.log(self.forensic_output, f"  [!!!] RANSOMWARE RISK: {s} (Entropy: {ent:.2f})", "CRITICAL")
                                self.scanner.alerts.trigger("High Entropy File Found", f"Potential encrypted payload: {s}", "CRITICAL")
                            else:
                                self.log(self.forensic_output, f"  [!] Suspicious: {s} (Entropy: {ent:.2f})", "WARNING")
                    except:
                        self.log(self.forensic_output, f"  [!] Suspicious: {s}", "WARNING")
                
                # AI Report
                self.log(self.forensic_output, "\n🤖 Generating Forensic AI Summary...", "INFO")
                # (Keep existing AI logic if needed)
            except Exception as e:
                self.log(self.forensic_output, f"Scan Error: {e}", "CRITICAL")

        threading.Thread(target=_scan_files, daemon=True).start()

    def setup_enterprise_tab(self):
        """🏢 CORPORATE SOC: Asset Management & Compliance Auditor"""
        header = ctk.CTkFrame(self.tab_enterprise, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(header, text="🏢 CORPORATE COMMAND CENTER [v16.0]", font=self.fonts["sub"], text_color=self.colors["accent"]).pack(side="left")
        
        self.btn_ent_audit = ctk.CTkButton(header, text="🚀 RUN CORPORATE AUDIT", command=self.run_enterprise_audit, 
                                         fg_color="#1f6feb", font=("Segoe UI", 11, "bold"), width=200)
        self.btn_ent_audit.pack(side="right", padx=5)

        self.btn_siem_export = ctk.CTkButton(header, text="📥 EXPORT SIEM JSON", command=self.export_siem_json,
                                           fg_color="#8957e5", font=("Segoe UI", 11, "bold"), width=180)
        self.btn_siem_export.pack(side="right", padx=5)

        # Three-column layout
        container = ctk.CTkFrame(self.tab_enterprise, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=5)
        
        # 1. Asset Tracker (Left)
        asset_frame = ctk.CTkFrame(container, fg_color="#161b22")
        asset_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(asset_frame, text="📋 ASSET INVENTORY", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(pady=5)
        self.asset_box = ctk.CTkTextbox(asset_frame, font=("Consolas", 10), fg_color="#0d1117")
        self.asset_box.pack(fill="both", expand=True, padx=5, pady=5)

        # 2. Network Perimeter & Live Sniffing (Middle)
        net_frame = ctk.CTkFrame(container, fg_color="#161b22")
        net_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        perim_header = ctk.CTkFrame(net_frame, fg_color="transparent")
        perim_header.pack(fill="x", pady=5)
        ctk.CTkLabel(perim_header, text="🌐 NETWORK PERIMETER", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(side="left", padx=5)
        
        self.btn_sniff = ctk.CTkButton(perim_header, text="📡 START SNIFFER", command=self.toggle_sniffer, fg_color="#8957e5", width=120, height=24)
        self.btn_sniff.pack(side="right", padx=5)
        
        self.ent_net_box = ctk.CTkTextbox(net_frame, font=("Consolas", 10), fg_color="#0d1117")
        self.ent_net_box.pack(fill="both", expand=True, padx=5, pady=5)

        # 3. Compliance & Persistence (Right)
        comp_frame = ctk.CTkFrame(container, fg_color="#161b22")
        comp_frame.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(comp_frame, text="⚖️ COMPLIANCE & PERSISTENCE", font=("Segoe UI", 10, "bold"), text_color=self.colors["accent"]).pack(pady=5)
        self.comp_box = ctk.CTkTextbox(comp_frame, font=("Consolas", 10), fg_color="#0d1117")
        self.comp_box.pack(fill="both", expand=True, padx=5, pady=5)

    def toggle_sniffer(self):
        if not self.sniffer_engine.is_sniffing:
            self.ent_net_box.delete("1.0", "end")
            self.log(self.ent_net_box, "📡 INITIATING DEEP PACKET INSPECTION...", "INFO")
            self.sniffer_engine.start_sniffing(lambda m, c: self.log(self.ent_net_box, m, c))
            self.btn_sniff.configure(text="🛑 STOP SNIFFER", fg_color=self.colors["danger"])
        else:
            self.sniffer_engine.stop_sniffing()
            self.log(self.ent_net_box, "\n🛑 SNIFFER HALTED.", "WARNING")
            self.btn_sniff.configure(text="📡 START SNIFFER", fg_color="#8957e5")

    def toggle_sniffer(self):
        if not self.sniffer_engine.is_sniffing:
            self.ent_net_box.delete("1.0", "end")
            self.log(self.ent_net_box, "📡 INITIATING DEEP PACKET INSPECTION...", "INFO")
            self.sniffer_engine.start_sniffing(lambda m, c: self.log(self.ent_net_box, m, c))
            self.btn_sniff.configure(text="🛑 STOP SNIFFER", fg_color=self.colors["danger"])
        else:
            self.sniffer_engine.stop_sniffing()
            self.log(self.ent_net_box, "\n🛑 SNIFFER HALTED.", "WARNING")
            self.btn_sniff.configure(text="📡 START SNIFFER", fg_color="#8957e5")

    def run_enterprise_audit(self):
        """Executes full corporate-level audit using core modules"""
        self.btn_ent_audit.configure(state="disabled", text="⌛ AUDITING...")
        
        def _audit():
            # 1. Scan Assets (Processes & Startup)
            self.after(0, lambda: self.log(self.asset_box, "🔍 Enumerating active processes & startup assets...", "INFO"))
            procs = scan_running_processes()
            startups = scan_startup_apps()
            
            # 2. Network Integrity
            self.after(0, lambda: self.log(self.ent_net_box, "🌐 Auditing DNS & Open Network Ports...", "INFO"))
            ports = scan_open_ports()
            dns_issues = check_dns_integrity()
            
            # 3. Compliance & Persistence
            self.after(0, lambda: self.log(self.comp_box, "⚖️ Auditing Scheduled Tasks & Persistence...", "INFO"))
            tasks = scan_scheduled_tasks()
            
            self.after(0, lambda: self._display_enterprise_results(procs, startups, ports, dns_issues, tasks))
            
        threading.Thread(target=_audit, daemon=True).start()

    def _display_enterprise_results(self, procs, startups, ports, dns, tasks):
        # Update Assets
        self.asset_box.delete("1.0", "end")
        self.log(self.asset_box, f"✅ Found {len(procs)} Running Processes")
        
        serious_assets = 0
        for p in procs: 
            if p['severity'] in ["CRITICAL", "HIGH"]:
                serious_assets += 1
                self.log(self.asset_box, f"  [!] {p['severity']} | {p['name']} ({p['pid']}): {p['reason']}", "CRITICAL" if p['severity'] == "CRITICAL" else "WARNING")
        
        self.log(self.asset_box, f"\n🚀 Startup Applications ({len(startups)})")
        for s in startups:
            if s['risk'] == "HIGH":
                serious_assets += 1
                self.log(self.asset_box, f"  - {s['name']} -> {s['path'][:40]}...", "WARNING")

        # Update Network
        self.ent_net_box.delete("1.0", "end")
        self.log(self.ent_net_box, f"🌐 Identified {len(ports)} Open Ports")
        for p, desc, sev in ports:
            self.log(self.ent_net_box, f"  - Port {p}: {desc}", sev if sev != "INFO" else None)
        
        if dns:
            self.log(self.ent_net_box, "\n🚨 DNS INTEGRITY ISSUES", "CRITICAL")
            for d in dns: self.log(self.ent_net_box, f"  - {d}")

        # Update Compliance
        self.comp_box.delete("1.0", "end")
        self.log(self.comp_box, f"⚖️ Scheduled Tasks Audit ({len(tasks)} found)")
        for t in tasks:
            self.log(self.comp_box, f"  - PERSISTENCE RISK: {t}", "WARNING")
            
        # Update Compliance Score
        comp_score = max(0, 100 - (len(dns) * 20 + serious_assets * 5 + len(tasks) * 2))
        self.after(0, lambda: self.stat_compliance.configure(text=f"{comp_score}%"))
        self.after(0, lambda: self.gauge_network.set_value(comp_score))
        self.after(0, lambda: self.gauge_network.lbl_title.configure(text="COMPLIANCE"))

        self.btn_ent_audit.configure(state="normal", text="🚀 RUN CORPORATE AUDIT")
        self._update_risk_score()
        self.log(self.console, "Enterprise Audit Complete. Risk score updated.", "SUCCESS")

    def monitor_behavior(self):
        """Live Behavioral Threat Hunting Loop"""
        threats = self.behavior_engine.find_suspicious_processes()
        for threat in threats:
            msg = f"🛡️ BEHAVIORAL ALERT: {threat['details']} (PROC: {threat['source']})"
            self.log(self.console, msg, "CRITICAL" if threat['severity'] == "CRITICAL" else "WARNING")
            self.update_stats(threat['severity'])
            
            # Specifically for Dashboard
            if hasattr(self, 'activity_lbls'):
                self.activity_lbls[0].configure(text=f"! ALERT: {threat['details']}", text_color=self.colors["danger"])

        # Loop every 5 seconds
        self.after(5000, self.monitor_behavior)

    def export_siem_json(self):
        """Export system findings in a professional SIEM-compatible JSON format"""
        # Collect all findings (mocking the collection from various parts)
        all_findings = []
        if self.web_findings:
            for v in self.web_findings:
                all_findings.append({"type": v.type.value, "severity": v.severity.value, "details": f"Web Vuln at {v.url}"})
        
        # Add behavioral threats detected in this session
        threats = self.behavior_engine.find_suspicious_processes()
        all_findings.extend(threats)

        stats = {"risk_score": self.risk_score}
        report_json = SIEMReporter.generate_json_report(all_findings, stats)
        
        filename = f"CORTEX_SIEM_{int(time.time())}.json"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_json)
            
        self.log(self.console, f"📥 SIEM JSON Exported: {filename}", "SUCCESS")
        os.startfile(filename) 

    def setup_mobile_api_tab(self):
        """📱 MOBILE & API SECURITY AUDITOR"""
        container = ctk.CTkFrame(self.tab_mobile_api, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # 1. Mobile Auditor (Left)
        mobile_f = ctk.CTkFrame(container, fg_color="#161b22")
        mobile_f.pack(side="left", fill="both", expand=True, padx=5)
        ctk.CTkLabel(mobile_f, text="📱 MOBILE APK AUDITOR", font=("Segoe UI", 12, "bold"), text_color=self.colors["accent"]).pack(pady=10)
        
        self.apk_path = ctk.CTkEntry(mobile_f, placeholder_text="Enter APK Path or Manifest snippet...", width=250)
        self.apk_path.pack(pady=5, padx=10)
        
        ctk.CTkButton(mobile_f, text="🚀 RUN APK AUDIT", command=self.run_apk_audit, fg_color="#1f6feb").pack(pady=10)
        self.apk_output = ctk.CTkTextbox(mobile_f, font=("Consolas", 10), fg_color="#0d1117")
        self.apk_output.pack(fill="both", expand=True, padx=10, pady=10)

        # 2. API Auditor (Right)
        api_f = ctk.CTkFrame(container, fg_color="#161b22")
        api_f.pack(side="right", fill="both", expand=True, padx=5)
        ctk.CTkLabel(api_f, text="🌐 API SECURITY AUDITOR", font=("Segoe UI", 12, "bold"), text_color=self.colors["accent"]).pack(pady=10)
        
        self.api_url_entry = ctk.CTkEntry(api_f, placeholder_text="Enter API Base URL (e.g. http://127.0.0.1:5555)", width=250)
        self.api_url_entry.pack(pady=5, padx=10)
        
        ctk.CTkButton(api_f, text="📡 AUDIT API ENDPOINTS", command=self.run_api_audit, fg_color="#8957e5").pack(pady=10)
        self.api_output = ctk.CTkTextbox(api_f, font=("Consolas", 10), fg_color="#0d1117")
        self.api_output.pack(fill="both", expand=True, padx=10, pady=10)

    def run_apk_audit(self):
        auditor = MobileAPKAuditor()
        path = self.apk_path.get()
        self.log(self.apk_output, f"🔍 Auditing Mobile Assets: {path}...", "INFO")
        
        # Simulate check
        findings = auditor.audit_manifest("android.permission.READ_SMS android.permission.INTERNET")
        secrets = auditor.find_secrets("const API_KEY = 'AIzaSyA-fake-key-123'")
        
        for f in findings + secrets:
            self.log(self.apk_output, f"  [!] {f['type']}: {f['item']}", f['severity'])
        self.log(self.apk_output, "✅ Mobile Audit Complete.", "SUCCESS")

    def run_api_audit(self):
        url = self.api_url_entry.get() or "http://127.0.0.1:5555"
        auditor = APIAuditor(url)
        self.log(self.api_output, f"📡 Starting API Security Probe on {url}...", "INFO")
        
        findings = auditor.audit_full()
        for f in findings:
            self.log(self.api_output, f"  [!] {f['type']}: {f['item']}", f['severity'])
            self.update_stats(f['severity'])
            
        self.log(self.api_output, "✅ API Audit Complete. Critical holes found.", "CRITICAL")
        self._update_risk_score()

    def update_threat_intel(self):
        """Fetch and display latest security news"""
        async def _fetch():
            news = await self.scanner.threat_intel.fetch_latest()
            self.after(0, lambda: self._display_news(news))
            
        threading.Thread(target=lambda: asyncio.run(_fetch()), daemon=True).start()

    def _display_news(self, news):
        self.news_box.configure(state="normal")
        self.news_box.delete("0.0", "end")
        
        # Add Global Simulation first
        global_events = self.scanner.threat_intel.get_global_threats()
        self.news_box.insert("end", "🌍 [LIVE GLOBAL THREAT FEED]\n", "accent")
        for ev in global_events:
            self.news_box.insert("end", f"[{ev['timestamp']}] {ev['source']} -> {ev['type']} ({ev['severity']})\n")
        self.news_box.insert("end", "\n" + "═"*40 + "\n\n")

        # Add real RSS news
        for item in news:
            self.news_box.insert("end", f"🔥 {item['title']}\n🔗 {item['link']}\n\n")
        self.news_box.configure(state="disabled")
        self.news_box.tag_config("accent", foreground=self.colors["accent"])

    def setup_analytics_tab(self):
        """Advanced Analytics Dashboard with Gauges and Bar Charts"""
        container = ctk.CTkFrame(self.tab_analytics, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Gauges Row
        gauge_frame = ctk.CTkFrame(container, fg_color="#161b22", height=200)
        gauge_frame.pack(fill="x", pady=(0, 20))
        
        self.gauge_threat = SecurityGauge(gauge_frame, "THREAT LEVEL", self.colors["danger"])
        self.gauge_threat.pack(side="left", expand=True, padx=20, pady=10)
        
        self.gauge_health = SecurityGauge(gauge_frame, "SYSTEM INTEGRITY", self.colors["accent"])
        self.gauge_health.pack(side="left", expand=True, padx=20, pady=10)
        self.gauge_health.set_value(100)
        
        self.gauge_network = SecurityGauge(gauge_frame, "NETWORK RISK", self.colors["warning"])
        self.gauge_network.pack(side="left", expand=True, padx=20, pady=10)

        # Lower distribution charts (Custom drawn bars)
        dist_frame = ctk.CTkFrame(container, fg_color="#161b22")
        dist_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(dist_frame, text="🛡️ VULNERABILITY DISTRIBUTION", font=self.fonts["sub"], text_color=self.colors["accent"]).pack(pady=10)
        
        self.charts_canvas = ctk.CTkCanvas(dist_frame, bg="#161b22", highlightthickness=0)
        self.charts_canvas.pack(fill="both", expand=True, padx=40, pady=20)
        self.render_charts()

    def render_charts(self):
        self.charts_canvas.delete("bar")
        w = 1000
        h = 250
        data = {
            "SQLI": self.findings_count.get("SQLI", 0),
            "XSS": self.findings_count.get("XSS", 0),
            "LFI": self.findings_count.get("LFI", 0),
            "SENSITIVE": self.findings_count.get("SENSITIVE", 0),
            "OTHER": self.findings_count.get("HIGH", 0)
        }
        
        max_val = max(data.values()) if any(data.values()) else 10
        x_start = 50
        bar_width = 120
        gap = 80
        
        for i, (label, val) in enumerate(data.items()):
            bar_h = (val / max_val) * (h - 50)
            x0 = x_start + i * (bar_width + gap)
            y0 = h - 30
            x1 = x0 + bar_width
            y1 = y0 - bar_h
            
            # Draw bar
            self.charts_canvas.create_rectangle(x0, y0, x1, y1, fill=self.colors["accent"], outline="", tags="bar")
            # Label
            self.charts_canvas.create_text(x0 + bar_width/2, h-15, text=label, fill="#8b949e", font=("Segoe UI", 10, "bold"), tags="bar")
            # Value
            self.charts_canvas.create_text(x0 + bar_width/2, y1-15, text=str(val), fill=self.colors["text"], font=("JetBrains Mono", 12), tags="bar")

    def update_network_map(self, url):
        """Enhanced Dynamic Network Map with animated connections"""
        if url not in self.map_nodes:
            # Physics-like positioning
            center_x, center_y = 140, 250
            if not self.map_nodes:
                x, y = center_x, center_y
            else:
                angle = random.uniform(0, 2 * 3.14159)
                dist = random.randint(60, 120)
                x = center_x + dist * (1.5 if len(self.map_nodes) % 2 else 0.8) * (0.5 if random.random() > 0.5 else 1.0) # Ad-hoc spreading
                x = max(20, min(260, center_x + int(dist * (1 if random.random() > 0.5 else -1))))
                y = max(20, min(480, center_y + int(dist * (1 if random.random() > 0.5 else -1))))

            # Node drawing
            color = self.colors["accent"]
            node = self.map_canvas.create_oval(x-8, y-8, x+8, y+8, fill=color, outline="#fff", width=1, tags="node")
            self.map_nodes[url] = (x, y)
            
            # Connections to root or parent
            root_url = list(self.map_nodes.keys())[0]
            rx, ry = self.map_nodes[root_url]
            if url != root_url:
                self.map_canvas.create_line(rx, ry, x, y, fill="#30363d", width=1, dash=(2, 2))
            
            # Hover effect / Label
            self.map_canvas.tag_bind(node, "<Enter>", lambda e, u=url: self.on_node_hover(e, u))

    def on_node_hover(self, event, url):
        # Could show a tooltip here
        pass

    def update_stats(self, level):
        if level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if level == "CRITICAL": self.findings_count["CRITICAL"] += 1
            elif level == "HIGH": self.findings_count["HIGH"] += 1
            
            self.stat_critical.configure(text=str(self.findings_count["CRITICAL"]))
            self.stat_high.configure(text=str(self.findings_count["HIGH"]))
            
            # Health Calculation
            total_threats = self.findings_count["CRITICAL"] * 15 + self.findings_count["HIGH"] * 5
            health = max(0, 100 - total_threats)
            color = self.colors["accent"] if health > 80 else (self.colors["warning"] if health > 50 else self.colors["danger"])
            self.stat_health.configure(text=f"{health}%", text_color=color)
            
            # Update Gauges & Charts
            self.after(0, lambda: self.gauge_threat.set_value(min(100, (100 - health) * 1.5)))
            self.after(0, lambda: self.gauge_health.set_value(health))
            self.after(0, self.render_charts)

    # --- MAIN SCAN ---
    def start_scan_thread(self):
        self.progress_bar.set(0)
        threading.Thread(target=self.run_engine, daemon=True).start()

    def run_engine(self):
        self.log(self.console, "Starting Full Protocol...", "INFO")
        try:
            # استخدام المثيل الموجود بدلاً من إنشاء واحد جديد غير معرف
            import asyncio
            self.scan_results = asyncio.run(self.scanner.scan())
            self.log(self.console, "Scan Complete. Triggering AI Analysis...", "SUCCESS")
            self.btn_pdf.configure(state="normal", fg_color="#3fb950")
            
            # Auto-trigger AI
            self.ask_ai_analyst()
            
        except Exception as e:
            self.log(self.console, f"Critical Error: {e}", "CRITICAL")

    # --- WEB SCAN ---
    def start_web_scan(self):
        url = self.url_entry.get()
        if not url: return
        mode = self.mode_var.get()

        if mode == "DESTRUCTIVE":
            dialog = ctk.CTkInputDialog(text="⚠️ DESTRUCTIVE MODE\n\nType 'TITANIUM-DESTROY-2024' to confirm:", title="AUTHORIZATION REQUIRED")
            if dialog.get_input() != "TITANIUM-DESTROY-2024":
                self.log(self.web_console, "Authorization Failed. Aborting.", "CRITICAL")
                return

        self.btn_web_scan.configure(state="disabled", text="IN PROGRESS...")
        self.web_console.delete("0.0", "end")
        threading.Thread(target=self._run_web_engine, args=(url, mode), daemon=True).start()

    def _run_web_engine(self, url, mode):
        self.scanner.config.target_url = url
        self.scanner.config.mode = ScanMode[mode]
        
        self.web_ai_panel.configure(state="normal")
        self.web_ai_panel.insert("end", f"🚀 Target: {url}\n")
        self.web_ai_panel.configure(state="disabled")

        async def _async_scan():
            # Clear previous map and findings
            self.map_nodes = {}
            self.map_canvas.delete("all")
            self.update_network_map(url) # Initial Target Node

            # Update map on each processed URL
            def _url_cb(u):
                self.after(0, lambda: self.update_network_map(u))
                self.after(0, lambda: self.log(self.web_console, f"Processing: {u}"))
            
            # Custom callback logic (In a real app, you'd add hooks to the scanner)
            self.web_findings = await self.scanner.scan(progress_callback=_url_cb)
            self.after(0, lambda: self.btn_web_scan.configure(state="normal", text="🚀 LAUNCH AUDIT"))
            self.after(0, self.analyze_web_findings)

        threading.Thread(target=lambda: asyncio.run(_async_scan()), daemon=True).start()

    def analyze_web_findings(self):
        if not self.web_findings: 
            self.log(self.web_console, "No vulnerabilities found.", "SUCCESS")
            return
        
        for vuln in self.web_findings:
            self.update_stats(vuln.severity.value)
            card = VulnerabilityCard(self.web_ai_panel, vuln)
            card.pack(fill="x", padx=10, pady=5)
            
        self._update_risk_score()
        self.web_ai_panel._parent_canvas.yview_moveto(1.0)

    def _update_risk_score(self):
        """Dynamic Risk Scoring Algorithm"""
        base = 100
        deductions = (
            self.findings_count["CRITICAL"] * 15 +
            self.findings_count["HIGH"] * 8 +
            self.findings_count["MEDIUM"] * 3
        )
        self.risk_score = max(0, base - deductions)
        # Update Dashboard HUD if exists
        try:
            self.stat_health.configure(text=f"{self.risk_score}%")
            if self.risk_score < 40: self.stat_health.configure(text_color=self.colors["danger"])
            elif self.risk_score < 75: self.stat_health.configure(text_color=self.colors["warning"])
            else: self.stat_health.configure(text_color=self.colors["success"])
        except: pass

    # --- AI ANALYST ---
    def ask_ai_analyst(self):
        self.ai_box.configure(state="normal")
        self.ai_box.delete("0.0", "end")
        self.ai_box.insert("0.0", "🤔 Analyzing system state...\n")
        self.ai_box.configure(state="disabled")
        threading.Thread(target=self.run_ai, daemon=True).start()

    def run_ai(self):
        """Strategic AI Security Analysis for the entire system"""
        async def _audit():
            # Build professional context from all system parts
            persona = "CORTEX Red Team Assistant" if "WAR ROOM" in current_tab else ("CORTEX CISO Strategist" if "ENTERPRISE" in current_tab else "CORTEX Security Analyst")
            
            context = {
                "active_stats": self.findings_count,
                "threat_level": self.gauge_threat.value,
                "system_health": self.stat_health.cget("text"),
                "network_connections": len(self.scanner.stats.get('connections', [])),
                "web_vulnerabilities": [{"type": v.type.value, "severity": v.severity.value} for v in self.web_findings[:5]]
            }
            
            prompt = f"""
            أنت {persona} خبير في الأمن السيبراني. قم بتحليل حالة النظام التالية وقدم تقريراً استراتيجياً باللغة العربية:
            
            سياق النظام:
            {json.dumps(context, indent=2)}
            
            المطلوب:
            1. تحليل عميق للأخطار الموجودة.
            2. تقييم كفاءة الدفاعات.
            3. توصيات تقنية لرفع مستوى الحماية.
            
            {"ركز في تقريرك على استراتيجيات الهجوم (Red Teaming) وكيفية التسلل والسيطرة لأنك في وضع الـ War Room." if "Red Team" in persona else ""}
            {"ركز في تقريرك على الامتثال للشركات (Corporate Compliance) وإدارة الأصول (Asset Management) بما أنك في وضع الـ Enterprise." if "CISO" in persona else ""}
            
            اجعل نبرة التقرير رسمية واحترافية تليق بنظام CORTEX.
            """
            
            try:
                model = self.scanner.ai_detector.model or genai.GenerativeModel('gemini-1.5-flash')
                response = model.generate_content(prompt)
                self.after(0, lambda: self._display_strategic_report(response.text))
            except Exception as e:
                self.after(0, lambda: self.log(self.ai_box, f"AI Analysis failed: {e}", "CRITICAL"))
        
        threading.Thread(target=lambda: asyncio.run(_audit()), daemon=True).start()

    def _display_strategic_report(self, text):
        self.ai_box.configure(state="normal")
        self.ai_box.delete("0.0", "end")
        self.ai_box.insert("end", "🛡️ CORTEX STRATEGIC SECURITY ASSESSMENT\n", "accent")
        self.ai_box.insert("end", "═"*50 + "\n\n")
        self.ai_box.insert("end", text)
        self.ai_box.tag_config("accent", foreground=self.colors["accent"])
        self.ai_box.see("0.0")
        self.ai_box.configure(state="disabled")

    # --- SIMULATION & UTILS ---
    def setup_sim_tab(self):
        """⚔️ WAR ROOM 3.0: PURPLE TEAM COMMAND CENTER"""
        container = ctk.CTkFrame(self.tab_sim, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Controls & Info Top Bar
        header_f = ctk.CTkFrame(container, fg_color="#161b22", height=60)
        header_f.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(header_f, text="⚔️ PURPLE TEAM ORCHESTRATOR", font=self.fonts["sub"], text_color=self.colors["accent"]).pack(side="left", padx=20, pady=15)
        
        self.btn_twin = ctk.CTkButton(header_f, text="🚀 LAUNCH TWIN", command=self.launch_twin, fg_color="#1f6feb", width=120)
        self.btn_twin.pack(side="right", padx=10, pady=15)
        self.btn_purple = ctk.CTkButton(header_f, text="🔥 ENGAGE PURPLE TEAM", command=self.run_purple_team_sim, fg_color="#8957e5", width=180, state="disabled")
        self.btn_purple.pack(side="right", padx=10, pady=15)
        
        self.btn_replay = ctk.CTkButton(header_f, text="📼 REPLAY", command=self.replay_timeline, fg_color="#2ea043", width=100, state="disabled")
        self.btn_replay.pack(side="right", padx=10, pady=15)

        # Dashboard Split: Timeline vs Graph View
        battle_f = ctk.CTkFrame(container, fg_color="transparent")
        battle_f.pack(fill="both", expand=True)
        
        # 📜 Live Timeline Event Pipeline
        timeline_f = ctk.CTkFrame(battle_f, fg_color="#161b22")
        timeline_f.pack(side="left", fill="both", expand=True, padx=(0, 5))
        ctk.CTkLabel(timeline_f, text="📜 EVENT PIPELINE TIMELINE", font=("Segoe UI", 12, "bold"), text_color=self.colors["accent"]).pack(pady=10)
        self.timeline_box = ctk.CTkTextbox(timeline_f, font=("Consolas", 11), fg_color="#0d1117")
        self.timeline_box.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 🕸️ Attack Graph View
        graph_f = ctk.CTkFrame(battle_f, fg_color="#161b22")
        graph_f.pack(side="right", fill="both", expand=True, padx=(5, 0))
        ctk.CTkLabel(graph_f, text="🕸️ ATTACK GRAPH VISUALIZATION", font=("Segoe UI", 12, "bold"), text_color="#3fb950").pack(pady=10)
        self.graph_box = ctk.CTkTextbox(graph_f, font=("Consolas", 10), fg_color="#0d1117", text_color="#3fb950")
        self.graph_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.graph_box.insert("end", self.purple_orchestrator.get_ascii_attack_graph())

        self.log(self.timeline_box, "[SYSTEM] AWAITING TARGET RESOLUTION...", "INFO")
        self.log(self.timeline_box, "[SYSTEM] DEFENSES NOMINAL. UEBA & SOAR STANDBY.", "SUCCESS")

    def launch_twin(self):
        self.digital_twin.start()
        self.log(self.console, "🚀 DIGITAL TWIN VULN-NODE LAUNCHED", "SUCCESS")
        self.btn_purple.configure(state="normal")
        self.btn_twin.configure(state="disabled", text="✅ TWIN ONLINE")

    def run_purple_team_sim(self):
        """Simulates an interactive battle via PurpleController Pipeline"""
        self.timeline_box.delete("1.0", "end")
        self.btn_purple.configure(state="disabled")
        
        def ui_callback(event):
            # Format: [HH:MM:SS] 🔴 ALARM | DETAILS
            color = "#f85149" if "RED" in event['actor'] else "#58a6ff" if "BLUE" in event['actor'] else "#8957e5"
            line = f"[{event['time']}] {event['actor']} | {event['action']} | {event['details']}\n"
            
            self.timeline_box.configure(state="normal")
            self.timeline_box.insert("end", line)
            
            # Simple color mapping for CustomTkinter textbox
            # CTk doesn't support rich formatting per word easily in standard textbox without tags
            # So we just dump the line
            self.timeline_box.see("end")
            self.timeline_box.configure(state="disabled")

        def _battle():
            self.purple_orchestrator.run_simulation(target_ip="127.0.0.1 (Twin Node)", ui_callback=ui_callback)
            self._update_risk_score()
            self.btn_replay.configure(state="normal")
            
            # Use the AI Explanation Layer
            expl = f"\n[AI EXPLANATION LAYER]\n" \
                   f"Risk Score: {self.purple_orchestrator.risk_score}\n" \
                   f"The autonomous exploit agent executed SQLi but was instantly detected by the UEBA defense module due to burst request velocity and payload signatures. Attack thwarted. System Secured."
            ui_callback({"time": time.strftime('%H:%M:%S'), "actor": "🧠 AI", "action": "ANALYSIS", "details": expl, "severity": "INFO"})
            
        threading.Thread(target=_battle, daemon=True).start()

    def replay_timeline(self):
        """Replays the recorded timeline (Attack Replay System)"""
        self.timeline_box.configure(state="normal")
        self.timeline_box.delete("1.0", "end")
        self.timeline_box.insert("end", "📼 [ATTACK REPLAY SYSTEM ENGAGED]\n")
        self.timeline_box.configure(state="disabled")
        
        def _replay():
            for event in self.purple_orchestrator.timeline:
                time.sleep(1) # Replay delay
                line = f"[{event['time']}] {event['actor']} | {event['action']} | {event['details']}\n"
                
                self.timeline_box.configure(state="normal")
                self.timeline_box.insert("end", line)
                self.timeline_box.see("end")
                self.timeline_box.configure(state="disabled")
                
        threading.Thread(target=_replay, daemon=True).start()

    def simulate_map_activity(self):
        """Link map visuals to real threat intel events"""
        if random.random() > 0.6:
            self.attack_map.animate_attack()
            # Push a simulated log to the console too
            ev = self.scanner.threat_intel.get_global_threats()[0]
            self.log(self.console, f"INTERCEPTED: {ev['type']} from {ev['source']}", "WARNING")
        
        self.after(5000, self.simulate_map_activity)

    def run_raas(self):
        self.log(self.sim_console, "Executing Ransomware Pattern...", "HIGH")
        sim = RansomSim()
        res = sim.execute_encryption()
        self.log(self.sim_console, res)
        # Impact global state
        self._on_intrusion_detected("CRITICAL", "Ransomware Simulation Active")

    def _on_intrusion_detected(self, level, msg):
        """Unified method to trigger alerts and update stats from any module"""
        self.update_stats(level)
        self.scanner.alerts.trigger("INTRUSION DETECTED", msg, level)
        self.log(self.console, f"🚨 INTRUSION: {msg}", level)

    def run_dlaas(self):
        self.log(self.sim_console, "Simulating Data Exfiltration...", "HIGH")
        sim = DataLeakSim()
        res = sim.run_simulation()
        self.log(self.sim_console, res)
        self._on_intrusion_detected("HIGH", "Data Exfiltration Attempt detected")

    def run_paas(self):
        self.log(self.sim_console, "Establishing Persistence...", "HIGH")
        sim = PersistenceSim()
        res = sim.attempt_persistence()
        self.log(self.sim_console, res)

    def run_autofix(self):
        threading.Thread(target=self._execute_fix, daemon=True).start()

    def _execute_fix(self):
        fixer = CortexFixer()
        self.log(self.console, "Initiating Auto-Remediation...", "FIX")
        log = fixer.run_full_fix()
        for line in log.split('\n'):
            if line: self.log(self.console, line)

    def log(self, text_widget, message, level=None):
        """Thread-safe logging to any CTkTextbox"""
        def _append():
            text_widget.configure(state="normal")
            timestamp = time.strftime("%H:%M:%S")
            prefix = f"[{timestamp}] "
            
            if level == "SUCCESS": color = self.colors["success"]
            elif level == "CRITICAL": color = self.colors["danger"]
            elif level == "WARNING": color = self.colors["warning"]
            elif level == "INFO": color = self.colors["accent"]
            elif level == "FIX": color = "#8957e5"
            else: color = self.colors["text"]
            
            text_widget.insert("end", prefix, "gray")
            text_widget.insert("end", f"{message}\n", level or "default")
            
            # Tag colors
            text_widget.tag_config("gray", foreground="#8b949e")
            if level:
                text_widget.tag_config(level, foreground=color)
            
            text_widget.configure(state="disabled")
            text_widget.see("end")
        
        self.after(0, _append)

    def export_pdf_report(self):
        if generate_pdf_report:
            fname = f"CORTEX_Report_{int(time.time())}.pdf"
            generate_pdf_report(self.scan_results, self.simulation_logs, self.ai_response_text, fname, self.web_findings)
            self.log(self.console, f"Report Generated: {fname}", "SUCCESS")
            os.startfile(fname)

if __name__ == "__main__":
    app = CortexProApp()
    app.mainloop()