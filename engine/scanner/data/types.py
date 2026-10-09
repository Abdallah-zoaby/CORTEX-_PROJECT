
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import datetime

class ScanMode(Enum):
    SAFE = "safe"
    DESTRUCTIVE = "destructive"
    STEALTH = "stealth"
    COMPREHENSIVE = "comprehensive"

class SeverityLevel(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class VulnerabilityType(Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    LFI_RFI = "LFI/RFI"
    RCE = "Remote Code Execution"
    IDOR = "Insecure Direct Object Reference"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    CSRF = "Cross-Site Request Forgery"
    AUTH_BYPASS = "Authentication Bypass"
    INFO_DISCLOSURE = "Information Disclosure"
    FILE_UPLOAD = "Unrestricted File Upload"
    API_VULN = "API Vulnerability"
    CUSTOM = "Custom"

@dataclass
class ScanConfig:
    target_url: str
    mode: ScanMode = ScanMode.SAFE
    max_depth: int = 5
    max_concurrency: int = 25
    timeout: int = 15
    enable_bruteforce: bool = False
    enable_exploitation: bool = False
    respect_robots: bool = True
    custom_headers: Dict[str, str] = field(default_factory=dict)
    auth_credentials: Optional[Dict[str, str]] = None
    proxy: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)

@dataclass
class Vulnerability:
    type: VulnerabilityType
    severity: SeverityLevel
    confidence: float  # 0.0 to 1.0
    url: str
    parameter: Optional[str] = None
    description: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    references: List[str] = field(default_factory=list)
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    tags: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    scan_id: str
    target: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    total_urls_scanned: int
    vulnerabilities_found: int
    vulnerabilities: List[Vulnerability]
    tech_stack: Dict[str, Any]
    scan_config: ScanConfig
    summary: Dict[str, Any]
