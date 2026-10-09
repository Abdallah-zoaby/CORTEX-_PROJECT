import networkx as nx
import random
import time
from datetime import datetime

class SmartPayloadGenerator:
    """Generates dynamic and encoded payloads to evade basic WAFs (Stealth Mode)"""
    def __init__(self):
        self.sql_bases = ["' OR 1=1--", "' UNION SELECT NULL--", "admin' #"]
        self.xss_bases = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "CORTEX-RedTeam-Agent/1.0"
        ]

    def mutate_sql(self, payload):
        # Subvert space checks
        return payload.replace(" ", random.choice(["/**/", "%20", "%09"]))

    def get_stealth_headers(self):
        return {
            "User-Agent": random.choice(self.user_agents),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }

    def craft_payload(self, attack_type):
        if attack_type == "SQLi":
            return self.mutate_sql(random.choice(self.sql_bases))
        elif attack_type == "XSS":
            return random.choice(self.xss_bases)
        return "default_payload"

class AttackGraphEngine:
    """Uses NetworkX to build and traverse an Autonomous Attack Path"""
    def __init__(self):
        self.graph = nx.DiGraph()
        self.payload_gen = SmartPayloadGenerator()
        self.build_knowledge_graph()

    def build_knowledge_graph(self):
        """Constructs the theoretical path of least resistance"""
        # Nodes: Recon -> Entry -> Privilege Escalation -> Impact
        self.graph.add_edge("Initial_Access", "Port_Scan", weight=1)
        self.graph.add_edge("Port_Scan", "Discover_Web", weight=1)
        self.graph.add_edge("Discover_Web", "SQL_Injection", weight=3)
        self.graph.add_edge("Discover_Web", "Brute_Force", weight=2)
        
        self.graph.add_edge("SQL_Injection", "Data_Exfiltration", weight=1)
        self.graph.add_edge("Brute_Force", "Admin_Panel", weight=1)
        self.graph.add_edge("Admin_Panel", "Web_Shell_Upload", weight=2)
        self.graph.add_edge("Web_Shell_Upload", "System_Compromise", weight=1)

    def get_shortest_path(self, start_node, target_node):
        """Find the optimal attack path (Graph Theory)"""
        try:
            return nx.shortest_path(self.graph, start_node, target_node, weight='weight')
        except nx.NetworkXNoPath:
            return []

    def simulate_autonomous_attack(self, target="System_Compromise", log_callback=None):
        """Autonomous AI Red Team Agent executing the path"""
        path = self.get_shortest_path("Initial_Access", target)
        if not path:
            if log_callback: log_callback("❌ No viable attack path found.", "CRITICAL")
            return []

        history = []
        if log_callback: log_callback(f"🧠 AI Red Team Agent determined optimal path: {' -> '.join(path)}", "INFO")
        
        for i in range(len(path) - 1):
            current_step = path[i]
            next_step = path[i+1]
            
            # Simulate Stealth Delay
            time.sleep(random.uniform(0.5, 1.5)) 
            
            payload = ""
            if "SQL" in next_step:
                payload = f" Payload: {self.payload_gen.craft_payload('SQLi')}"
            
            headers = self.payload_gen.get_stealth_headers()
            
            msg = f"⚔️ Executing {current_step} -> {next_step}. [Stealth] IP: {headers['X-Forwarded-For']}{payload}"
            if log_callback: log_callback(msg, "WARNING")
            
            history.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "action": next_step,
                "status": "SUCCESS" if random.random() > 0.1 else "FAILED" # 90% success rate in sim
            })
            
            if history[-1]["status"] == "FAILED":
                if log_callback: log_callback(f"⛔ Attack blocked at {next_step} by Blue Team Defenses.", "CRITICAL")
                break
                
        return history
