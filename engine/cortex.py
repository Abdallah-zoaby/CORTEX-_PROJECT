import time
import sys
import os
from colorama import init
from core import network, system, forensics
from engine.scorer import RiskEngine

init(autoreset=True)

class CortexScanner:
    def __init__(self):
        self.risk_engine = RiskEngine()

    def run_full_scan(self, ui_callback=None, progress_callback=None):
        def log(msg, lvl="INFO"):
            print(f"[{lvl}] {msg}")
            if ui_callback: ui_callback(msg, lvl)

        log("🚀 INITIALIZING DEEP FORENSIC SCAN (TITANIUM MODE)...", "SUCCESS")
        if progress_callback: progress_callback(0.02)
        time.sleep(0.5)

        # 1. Network & DNS
        log("🌐 Deep Network Analysis...", "INFO")
        ports = network.scan_open_ports()
        for p in ports:
            if p[2] == "CRITICAL":
                log(f"   ❌ Critical Port: {p[0]} ({p[1]})", "CRITICAL")
                self.risk_engine.add_finding(f"OPEN PORT {p[0]}", "CRITICAL")
        
        dns_issues = network.check_dns_integrity()
        for issue in dns_issues:
            log(f"   💀 DNS/Hosts Alert: {issue}", "CRITICAL")
            self.risk_engine.add_finding(f"DNS Hijack: {issue}", "CRITICAL")
            
        if progress_callback: progress_callback(0.20)

        # 2. System Processes (RAM)
        log("🧠 Scanning Active Processes (RAM)...", "INFO")
        procs = system.scan_running_processes()
        if not procs:
            log("   ✅ Active processes look clean.", "SUCCESS")
        for proc in procs:
            log(f"   🔥 Malicious Process: {proc['name']} (PID: {proc['pid']})", "CRITICAL")
            log(f"      Reason: {proc['reason']}", "SUB")
            self.risk_engine.add_finding(f"Active Malware: {proc['name']}", "CRITICAL")
            
        if progress_callback: progress_callback(0.40)

        # 3. Scheduled Tasks
        log("⏰ Checking Hidden Scheduled Tasks...", "INFO")
        tasks = system.scan_scheduled_tasks()
        for task in tasks:
            log(f"   ⚠️ Suspicious Task: {task}", "HIGH")
            self.risk_engine.add_finding(f"Hidden Task: {task}", "HIGH")

        if progress_callback: progress_callback(0.60)

        # 4. Deep Forensics (Files)
        log("🕵️‍♂️ Deep Filesystem Forensics (User Profile)...", "INFO")
        # وسعنا النطاق: ديسكتوب، دوكيومنتس، آب داتا، تيمب
        user_path = os.path.expanduser("~")
        targets = [
            os.path.join(user_path, "Desktop"),
            os.path.join(user_path, "Documents"),
            os.path.join(user_path, "AppData", "Roaming"),
            os.environ.get('TEMP')
        ]
        
        for target in targets:
            if target and os.path.exists(target):
                log(f"   📂 Analyzing: {os.path.basename(target)}", "SUB")
                try:
                    bad_files = forensics.scan_suspicious_files(target)
                    for item in bad_files:
                        log(f"   💀 THREAT DETECTED: {os.path.basename(item['path'])}", "CRITICAL")
                        self.risk_engine.add_finding(f"File Threat: {item['path']}", "CRITICAL")
                except: pass

        if progress_callback: progress_callback(1.0)
        log("✅ TITANIUM SCAN COMPLETE.", "SUCCESS")
        return self.risk_engine