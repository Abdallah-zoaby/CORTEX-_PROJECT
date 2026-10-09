import requests
import jwt
import base64

class APIAuditor:
    """Security Auditor for RESTful APIs (IDOR, Auth, Exposure)"""
    
    def __init__(self, base_url):
        self.base_url = base_url

    def test_broken_auth(self, endpoint):
        """Test if endpoint requires a valid token"""
        try:
            r = requests.get(f"{self.base_url}{endpoint}", timeout=2)
            if r.status_code == 200:
                return {"type": "BROKEN_AUTH", "item": endpoint, "severity": "CRITICAL"}
            return None
        except: return None

    def test_idor(self, endpoint, param_name, current_val, target_val):
        """Test for Insecure Direct Object Reference"""
        url_now = f"{self.base_url}{endpoint.replace(str(current_val), str(target_val))}"
        try:
            r = requests.get(url_now, timeout=2)
            if r.status_code == 200:
                return {"type": "IDOR_DETECTED", "item": url_now, "severity": "HIGH"}
            return None
        except: return None

    def test_login_brute(self, endpoint, username):
        """Legal Dictionary Attack Simulation"""
        common_passwords = ["123456", "password", "admin123", "qwerty"]
        try:
            for pwd in common_passwords:
                r = requests.post(f"{self.base_url}{endpoint}", data={"username": username, "password": pwd}, timeout=1)
                if r.status_code == 200 and "invalid" not in r.text.lower():
                    return {"type": "WEAK_PASSWORD_CRACKED", "item": f"User: '{username}' has weak password: '{pwd}'", "severity": "CRITICAL"}
        except: return None
        return None

    def test_jwt_weak_signature(self, token):
        """Analyze JWT for 'None' algorithm or empty signature vulnerabilities"""
        try:
            header_b64 = token.split('.')[0]
            header = base64.b64decode(header_b64 + "==").decode('utf-8')
            if '"alg":"none"' in header.lower() or '"alg":"none"' in header.replace(" ", "").lower():
                return {"type": "JWT_WEAK_CRYPTO", "item": "Algorithm 'none' accepted", "severity": "CRITICAL"}
                
            # Test unsafe decoding (Simulation of testing an endpoint with a stripped signature)
            decoded = jwt.decode(token, options={"verify_signature": False})
            if decoded:
                return {"type": "JWT_VULNERABILITY", "item": "Application might not strictly verify signatures", "severity": "HIGH"}
        except: return None
        return None

    def audit_full(self):
        # Simulated run against known endpoints
        findings = []
        findings.append(self.test_broken_auth("/api/config"))
        findings.append(self.test_idor("/api/user/1", "id", 1, 0))
        # Simulated JWT Test
        fake_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        findings.append(self.test_jwt_weak_signature(fake_jwt))
        
        # Simulated Password Cracking Test
        findings.append(self.test_login_brute("/login", "admin"))
        
        return [f for f in findings if f]
