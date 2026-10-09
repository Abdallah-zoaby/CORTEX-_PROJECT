
import re
import html
from urllib.parse import urlparse, parse_qs
from .base import BasePlugin
from ..data.types import Vulnerability, VulnerabilityType, SeverityLevel

class SQLiPlugin(BasePlugin):
    """Advanced SQL Injection detection plugin"""
    
    name = "SQLiDetector"
    version = "2.0"
    description = "Advanced SQL Injection detection with exploitation"
    supported_hooks = ['response_received', 'vulnerability_detected']
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"PostgreSQL.*ERROR",
            r"Microsoft OLE DB Provider for ODBC Drivers",
            r"ODBC SQL Server Driver",
        ]
    
    def _load_payloads(self):
        """Load SQLi payloads"""
        return [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--",
            "' OR EXISTS(SELECT * FROM information_schema.tables)--",
        ]
    
    async def response_received(self, scanner, url, response, headers):
        """Check for SQLi in response"""
        if not response or '?' not in url:
            return None
        
        # Check for error patterns
        for pattern in self.patterns:
            if re.search(pattern, response, re.I):
                return Vulnerability(
                    type=VulnerabilityType.SQL_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.9,
                    url=url,
                    description="SQL Injection detected via error messages",
                    evidence=f"Pattern matched: {pattern}"
                )
        
        return None

class XSSPlugin(BasePlugin):
    """XSS detection plugin"""
    
    name = "XSSDetector"
    version = "2.0"
    description = "XSS detection with context-aware payloads"
    supported_hooks = ['response_received']
    
    async def response_received(self, scanner, url, response, headers):
        """Check for XSS reflection"""
        if not response or '?' not in url:
            return None
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        for param, values in query.items():
            for value in values:
                if value and value in response:
                    return Vulnerability(
                        type=VulnerabilityType.XSS,
                        severity=SeverityLevel.HIGH,
                        confidence=0.7,
                        url=url,
                        parameter=param,
                        description="User input reflected without sanitization",
                        evidence=f"Parameter '{param}' value reflected in response"
                    )
        
        return None

class LFIPlugin(BasePlugin):
    """LFI/RFI detection plugin"""
    
    name = "LFIDetector"
    version = "1.5"
    supported_hooks = ['response_received']
    
    async def response_received(self, scanner, url, response, headers):
        """Check for LFI/RFI"""
        if not response:
            return None
        
        lfi_indicators = [
            "root:x:0:0",
            "[boot loader]",
            "<?php",
            "Warning: include(",
            "failed to open stream",
        ]
        
        for indicator in lfi_indicators:
            if indicator in response:
                return Vulnerability(
                    type=VulnerabilityType.LFI_RFI,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    url=url,
                    description="Local/Remote File Inclusion detected",
                    evidence=f"Found indicator: {indicator}"
                )
        
        return None

class HeaderSecurityPlugin(BasePlugin):
    """Security headers checker"""
    
    name = "HeaderSecurity"
    version = "1.2"
    supported_hooks = ['response_received']
    
    async def response_received(self, scanner, url, response, headers):
        """Check security headers"""
        missing_headers = []
        
        required = {
            'X-Frame-Options': 'LOW',
            'Content-Security-Policy': 'MEDIUM',
            'X-Content-Type-Options': 'LOW',
            'Strict-Transport-Security': 'HIGH',
        }
        
        for header, severity in required.items():
            if header.lower() not in {k.lower() for k in headers}:
                missing_headers.append((header, severity))
        
        if missing_headers:
            missing_str = ', '.join([h[0] for h in missing_headers])
            return Vulnerability(
                type=VulnerabilityType.INFO_DISCLOSURE,
                severity=SeverityLevel.MEDIUM,
                confidence=0.9,
                url=url,
                description="Missing security headers",
                evidence=f"Missing: {missing_str}"
            )
        
        return None

class SensitiveDataPlugin(BasePlugin):
    """Sensitive data detection"""
    
    name = "SensitiveData"
    version = "1.3"
    supported_hooks = ['response_received']
    
    def __init__(self):
        self.patterns = {
            "API Key": r'(?i)(api[_-]?key)[\s=:]+([a-zA-Z0-9]{32,})',
            "JWT": r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*',
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Credit Card": r'\b(?:\d[ -]*?){13,16}\b',
            "Password": r'(?i)(password|passwd|pwd)[\s=:]+([^\s<>&]+)',
        }
    
    async def response_received(self, scanner, url, response, headers):
        """Check for sensitive data"""
        findings = []
        
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, response)
            if matches:
                for match in matches[:2]:  # Limit to 2 matches per type
                    findings.append(Vulnerability(
                        type=VulnerabilityType.INFO_DISCLOSURE,
                        severity=SeverityLevel.HIGH if data_type in ["API Key", "Credit Card"] else SeverityLevel.MEDIUM,
                        confidence=0.95,
                        url=url,
                        description=f"Sensitive {data_type} exposed",
                        evidence=f"Found: {str(match)}"
                    ))
        
        return findings if findings else None

class IDORPlugin(BasePlugin):
    """IDOR detection plugin"""
    
    name = "IDORDetector"
    version = "1.1"
    supported_hooks = ['response_received']
    
    async def response_received(self, scanner, url, response, headers):
        """Check for potential IDOR"""
        if '?' not in url:
            return None
        
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        id_params = ['id', 'user', 'uid', 'account', 'doc', 'file']
        
        for param in query:
            if any(id_word in param.lower() for id_word in id_params):
                return Vulnerability(
                    type=VulnerabilityType.IDOR,
                    severity=SeverityLevel.HIGH,
                    confidence=0.6,
                    url=url,
                    parameter=param,
                    description="Potential Insecure Direct Object Reference",
                    evidence=f"Parameter '{param}' found with ID-like values"
                )
        
        return None
