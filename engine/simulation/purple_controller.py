import time
import json
from datetime import datetime
from engine.simulation.attack_graph import AttackGraphEngine
from engine.simulation.ueba_engine import UEBAEngine, AutoResponseEngine

class BaseAgent:
    """Base class for Autonomous Red Team Agents"""
    def __init__(self, name):
        self.name = name

class ReconAgent(BaseAgent):
    def execute(self, target):
        return {"action": "Port Scanning & Service Enum", "target": target, "status": "SUCCESS"}

class ExploitAgent(BaseAgent):
    def __init__(self, graph_engine):
        super().__init__("Exploiter")
        self.graph = graph_engine
        
    def execute(self, target):
        return {"action": "SQL Injection Payload Delivery", "target": target, "status": "SUCCESS", "payload": "1' OR 1=1--"}

class PersistenceAgent(BaseAgent):
    def execute(self, target):
        return {"action": "WebShell Upload / Backdoor", "target": target, "status": "ATTEMPTED"}

class PurpleController:
    """Orchestrator: Binds Red (Offense) and Blue (Defense) in a closed-loop simulation"""
    
    def __init__(self):
        # Engines
        self.red_graph = AttackGraphEngine()
        self.blue_ueba = UEBAEngine()
        self.blue_soar = AutoResponseEngine()
        
        # Red Agents
        self.agents = [
            ReconAgent("Recon"),
            ExploitAgent(self.red_graph),
            PersistenceAgent("Persistence")
        ]
        
        # Data
        self.timeline = []
        self.risk_score = 0

    def log_event(self, actor, action, details, severity="INFO"):
        """Central Timeline Logging"""
        event = {
            "classification": "simulation",
            "time": datetime.now().strftime("%H:%M:%S"),
            "actor": actor,
            "action": action,
            "details": details,
            "severity": severity
        }
        self.timeline.append(event)
        return event

    def run_simulation(self, target_ip="127.0.0.1", ui_callback=None):
        """Executes the closed-loop battle"""
        self.timeline = []
        self.risk_score = 0
        self.blue_ueba = UEBAEngine()
        self.blue_soar = AutoResponseEngine()
        self.log_event("SYSTEM", "INIT", f"SYNTHETIC training for {target_ip}; no requests, isolation or firewall changes", "INFO")
        if ui_callback: ui_callback(self.timeline[-1])
        
        for agent in self.agents:
            time.sleep(1) # Stealth Delay Simulation
            
            # 1. RED ACTION
            red_act = agent.execute(target_ip)
            self.log_event("🟥 RED", red_act['action'], f"Agent: {agent.name} operating on {target_ip}", "WARNING")
            if ui_callback: ui_callback(self.timeline[-1])
            
            # Apply Risk Score
            if "SQL" in red_act['action']: self.risk_score += 5
            elif "Port" in red_act['action']: self.risk_score += 1
            elif "Shell" in red_act['action']: self.risk_score += 10
            
            # 2. BLUE DETECTION (UEBA)
            time.sleep(0.5)
            # Simulating UEBA catching the exploit agent due to velocity/payload
            alert = None
            if isinstance(agent, ExploitAgent):
                alert = self.blue_ueba.log_auth_attempt(target_ip, False) # Forced trigger for demo
                if not alert: # Force a baseline alert if history wasn't populated enough
                    alert = {"alert": "UEBA_ANOMALY", "severity": "CRITICAL", "details": "Unusual Payload execution pattern detected."}
                    
            if alert:
                self.log_event("🟦 BLUE", "DETECTION", alert['details'], alert['severity'])
                if ui_callback: ui_callback(self.timeline[-1])
                
                # 3. BLUE RESPONSE (SOAR)
                time.sleep(1)
                self.blue_soar.process_ueba_alert(alert)
                self.log_event("🟦 BLUE", "RESPONSE", f"SIMULATED response for {target_ip}; no endpoint isolated or IP blocked", "INFO")
                if ui_callback: ui_callback(self.timeline[-1])
                break # Attack halted by defense
                
        self.log_event("SYSTEM", "COMPLETE", f"Simulation End. Final Risk Score: {self.risk_score}", "INFO")
        if ui_callback: ui_callback(self.timeline[-1])
        
        self.export_logs()
        return self.timeline

    def export_logs(self):
        """Saves the timeline to a physical file as requested in architecture"""
        import os
        os.makedirs("data", exist_ok=True)
        with open("data/logs.json", "w", encoding="utf-8") as f:
            json.dump(self.timeline, f, indent=4)
        print("[+] Timeline exported to data/logs.json for Forensics.")

    def get_ascii_attack_graph(self):
        """Fallback ASCII representation of the NetworkX graph for the UI"""
        return r'''
        [Initial_Access]
               |
               v
          [Port_Scan]
               |
               v
        [Discover_Web]
         /           \  
        v             v
 [Brute_Force]   [SQL_Injection]
       |                |
       v                v
 [Admin_Panel]  [Data_Exfiltration]
       |
       v
 [Web_Shell_Upload]
       |
       v
 [System_Compromise]
        '''
