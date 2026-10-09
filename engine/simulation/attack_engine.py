import requests
import time
import json
from abc import ABC, abstractmethod

class AttackStep(ABC):
    def __init__(self, name):
        self.name = name
        self.status = "PENDING"
        self.result = {}

    @abstractmethod
    def execute(self, target_url):
        pass

class ReconStep(AttackStep):
    def execute(self, target_url):
        self.status = "RUNNING"
        try:
            r = requests.get(target_url, timeout=2)
            if r.status_code == 200:
                self.result = {"found": True, "server": r.headers.get("Server")}
                self.status = "SUCCESS"
            else:
                self.status = "FAILED"
        except:
            self.status = "ERROR"
        return self.result

class BruteForceStep(AttackStep):
    def execute(self, target_url):
        self.status = "RUNNING"
        login_url = f"{target_url}/login"
        passwords = ["123", "password", "password123"]
        for p in passwords:
            payload = {"username": "admin", "password": p}
            try:
                r = requests.post(login_url, data=payload, timeout=2)
                if r.status_code == 200:
                    self.result = {"found": True, "creds": f"admin:{p}"}
                    self.status = "SUCCESS"
                    return self.result
            except: break
        self.status = "FAILED"
        return self.result

class IDS_EvasionStep(AttackStep):
    def execute(self, target_url):
        self.status = "RUNNING"
        # Simulate Evasion (Sending encoded payloads)
        time.sleep(1)
        self.status = "SUCCESS"
        self.result = {"bypass": True, "technique": "Base64 Encoding"}
        return self.result

class AttackGraph:
    """Orchestrates the entire Red Team workflow"""
    def __init__(self, target_url):
        self.target_url = target_url
        self.steps = [
            ReconStep("Passive Recon"),
            BruteForceStep("Admin Bruteforce"),
            IDS_EvasionStep("WAF Evasion")
        ]
        self.history = []

    def run_full_sim(self, logger_callback):
        logger_callback("🚩 Starting Professional Attack Simulation...", "INFO")
        for step in self.steps:
            logger_callback(f"🚀 Executing Step: {step.name}", "INFO")
            res = step.execute(self.target_url)
            self.history.append({"step": step.name, "status": step.status, "result": res})
            
            if step.status == "SUCCESS":
                color = "SUCCESS"
                logger_callback(f"✅ Step Success: {json.dumps(res)}", color)
            else:
                logger_callback(f"❌ Step Failed: {step.name}", "CRITICAL")
                break # Stop the chain if a step fails
            time.sleep(0.5)
            
        logger_callback("🏁 Simulation Completed. Impact: DATA_EXPOSURE", "CRITICAL")
        return self.history
