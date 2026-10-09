import psutil
import math
import json
import time
from datetime import datetime

class BehavioralEngine:
    """Breakthrough Behavioral Monitor: Watches for live suspicious activity"""
    
    def __init__(self):
        self.suspicious_patterns = [
            " -enc ", " hidden ", "invoke-expression", "bypass", ".downloadstring",
            "reflected", "base64", "minidump", "lsass"
        ]
        self.monitored_pids = set()

    def find_suspicious_processes(self):
        """Monitor running processes for hacker-like behaviors"""
        findings = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                pinfo = proc.info
                cmdline = " ".join(pinfo['cmdline'] or []).lower()
                
                # Detect PowerShell/CMD tricks
                for pattern in self.suspicious_patterns:
                    if pattern in cmdline:
                        findings.append({
                            "type": "BEHAVIORAL_THREAT",
                            "severity": "CRITICAL",
                            "source": pinfo['name'],
                            "pid": pinfo['pid'],
                            "details": f"Suspicious Command: {pattern}",
                            "timestamp": datetime.now().isoformat()
                        })
                        break
                        
                # Detect unusual process locations (running from AppData/Temp)
                try:
                    exe = proc.exe().lower()
                    if "appdata" in exe or "temp" in exe:
                        if pinfo['name'].lower() not in ["chrome.exe", "msedge.exe", "code.exe"]:
                            findings.append({
                                "type": "PATH_ANOMALY",
                                "severity": "HIGH",
                                "source": pinfo['name'],
                                "pid": pinfo['pid'],
                                "details": f"Process running from volatile path: {exe}",
                                "timestamp": datetime.now().isoformat()
                            })
                except: pass

                # C2 Simulation Detection: Check network connections for malicious IPs
                connections = proc.connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED':
                        remote_ip = conn.raddr.ip
                        # (Integrate with ThreatIntel check in practical use)
                        if remote_ip.startswith("185.") or remote_ip.startswith("45."):
                             findings.append({
                                "type": "C2_COMMUNICATION",
                                "severity": "CRITICAL",
                                "source": pinfo['name'],
                                "pid": pinfo['pid'],
                                "details": f"Established connection to known C2 IP: {remote_ip}",
                                "timestamp": datetime.now().isoformat()
                            })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

def calculate_entropy(data):
    """Calculate Shannon Entropy to detect Ransomware/Encryption (High randomness)"""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

class SIEMReporter:
    """Generates Enterprise-Level SIEM JSON reports for SOC integration"""
    
    @staticmethod
    def generate_json_report(findings, system_stats):
        report = {
            "version": "16.0.0-ENTERPRISE",
            "origin": "CORTEX-SOC-ENGINE",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_threats": len(findings),
                "risk_score": system_stats.get('risk_score', 100)
            },
            "events": findings,
            "host_info": {
                "os": "Windows",
                "uptime": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        }
        return json.dumps(report, indent=4, ensure_ascii=False)

# Example Usage logic
def check_ransomware_risk(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4096) # Read first 4KB
            ent = calculate_entropy(data)
            # Normal text/code is usually 3-5. Encrypted/Compressed is 7.5+
            if ent > 7.5:
                return {"path": file_path, "entropy": ent, "risk": "CRITICAL (Encrypted/Ransomware?)"}
            return {"path": file_path, "entropy": ent, "risk": "SAFE"}
    except:
        return None
