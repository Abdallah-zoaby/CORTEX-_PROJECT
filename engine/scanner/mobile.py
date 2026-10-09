import os
import re

class MobileAPKAuditor:
    """Static Analysis for Android/iOS apps (Simulated/Regex based)"""
    
    def __init__(self):
        self.risky_permissions = [
            "android.permission.INTERNET", "android.permission.READ_SMS",
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO"
        ]
        self.secret_patterns = [
            r"AIza[0-9A-Za-z-_]{35}", # Google API Key
            r"sk_live_[0-9a-zA-Z]{24}", # Stripe Key
            r"(?i)password\s*[:=]\s*['\"](.*?)['\"]" 
        ]

    def audit_manifest(self, manifest_content):
        findings = []
        for perm in self.risky_permissions:
            if perm in manifest_content:
                findings.append({"type": "RISKY_PERMISSION", "item": perm, "severity": "MEDIUM"})
        return findings

    def find_secrets(self, code_content):
        secrets = []
        for pattern in self.secret_patterns:
            matches = re.findall(pattern, code_content)
            for m in matches:
                secrets.append({"type": "HARDCODED_SECRET", "item": m, "severity": "CRITICAL"})
        return secrets
