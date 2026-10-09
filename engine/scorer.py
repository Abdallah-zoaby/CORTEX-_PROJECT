# engine/scorer.py

class RiskEngine:
    def __init__(self):
        self.total_score = 0
        self.findings = []

    def add_finding(self, description, severity):
        """
        severity:
        - LOW = 5 points
        - MEDIUM = 15 points
        - HIGH = 30 points
        - CRITICAL = 50 points
        """
        points = 0
        color = "BLACK"
        
        if severity == "LOW":
            points = 5
            color = "GREEN"
        elif severity == "MEDIUM":
            points = 15
            color = "ORANGE"
        elif severity == "HIGH":
            points = 30
            color = "RED"
        elif severity == "CRITICAL":
            points = 50
            color = "DARKRED"

        self.total_score += points
        self.findings.append({
            "desc": description,
            "severity": severity,
            "color": color
        })

    def get_verdict(self):
        if self.total_score == 0:
            return "CLEAN SYSTEM 🛡️", "GREEN"
        elif self.total_score < 40:
            return f"LOW RISK (Score: {self.total_score}) ⚠️", "ORANGE"
        elif self.total_score < 80:
            return f"HIGH RISK (Score: {self.total_score}) 🚨", "RED"
        else:
            return f"SYSTEM COMPROMISED (Score: {self.total_score}) 💀", "DARKRED"