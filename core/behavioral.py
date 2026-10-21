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
        """Cheap live observations; names, path and IP prefixes never prove C2."""
        from .system import scan_running_processes
        findings = []
        for process in scan_running_processes():
            if not process.get('signals'):
                continue
            findings.append(dict(process, type='Behavioral observation',
                source=process['name'], details=process['reason'],
                timestamp=datetime.now().isoformat()))
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
        from .findings import normalize, summary
        from .privacy import sanitize
        records = [normalize(f, 'web' if hasattr(f, 'url') else 'host') for f in findings]
        report = {
            "version": "16.0.0-ENTERPRISE",
            "origin": "CORTEX-SOC-ENGINE",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                **summary(records),
                "posture_index": system_stats.get('posture_index'),
                "limitations": "Counts describe collected records, not confirmed threats or a safety certificate"
            },
            "events": records,
            "coverage": system_stats.get('coverage', {}),
            "host_info": {
                "os": "Windows",
                "uptime": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        }
        return json.dumps(sanitize(report), indent=4, ensure_ascii=False)

# Example Usage logic
def check_ransomware_risk(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read(4096) # Read first 4KB
            ent = calculate_entropy(data)
            # Normal text/code is usually 3-5. Encrypted/Compressed is 7.5+
            if ent > 7.5:
                return {"path": file_path, "entropy": ent, "risk": "OBSERVATION: High entropy (also common in compressed files); not proof of ransomware"}
            return {"path": file_path, "entropy": ent, "risk": "UNKNOWN: entropy alone cannot establish safety"}
    except:
        return None
