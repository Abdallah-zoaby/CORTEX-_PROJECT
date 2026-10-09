import time
import random
from collections import deque

class UEBAEngine:
    """User and Entity Behavior Analytics for Anomaly Detection (Blue Team)"""
    def __init__(self):
        self.baseline_established = False
        self.request_history = deque(maxlen=100)
        self.login_attempts = deque(maxlen=50)

    def log_request(self, ip, endpoint):
        """Analyze request velocity to detect scanning/brute force"""
        self.request_history.append((time.time(), ip, endpoint))
        return self._analyze_anomalies(ip)

    def log_auth_attempt(self, ip, success):
        self.login_attempts.append((time.time(), ip, success))
        return self._detect_brute_force(ip)

    def _analyze_anomalies(self, target_ip):
        """Detect automated scanning tools (DirBuster, Nmap) based on velocity"""
        recent = [t for t, i, e in self.request_history if i == target_ip and time.time() - t < 10]
        if len(recent) > 15:
            return {
                "alert": "ANOMALOUS_VELOCITY",
                "severity": "CRITICAL",
                "details": f"High automated request rate from {target_ip} (Likely Recon/Scanning)"
            }
        return None

    def _detect_brute_force(self, target_ip):
        """Mathematical likelihood of Bruteforce"""
        recent_fails = [t for t, i, s in self.login_attempts if i == target_ip and not s and time.time() - t < 30]
        if len(recent_fails) > 5:
            return {
                "alert": "BRUTE_FORCE_PATTERN",
                "severity": "CRITICAL",
                "details": f"Repeated authentication failures from {target_ip}."
            }
        return None

class AutoResponseEngine:
    """Automated Blue Team Actions (SOAR-like Response)"""
    def __init__(self):
        self.blocked_ips = set()
        self.isolated_endpoints = set()

    def process_ueba_alert(self, alert_data, log_callback=None):
        if not alert_data: return
        
        # Simulate Network Isolation or IP Ban
        if "VELOCITY" in alert_data["alert"]:
            ip = alert_data["details"].split()[-1] # Simple extraction for simulation
            self.blocked_ips.add(ip)
            if log_callback:
                log_callback(f"🛡️ [BLUE TEAM] Banning IP at Firewall: {ip}", "SUCCESS")
                
        elif "BRUTE_FORCE" in alert_data["alert"]:
            if log_callback:
                log_callback(f"🛡️ [BLUE TEAM] Initiating rate-limit & MFA lock-down on auth endpoint.", "SUCCESS")
        
        return True
