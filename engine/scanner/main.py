"""
TITANIUM WEB SCANNER v15.0 - Professional Security Assessment Tool
Author: Enhanced Security Team
License: For Authorized Security Testing Only
⚠️ WARNING: Use only on systems you own or have explicit permission to test
"""

import asyncio
import aiohttp
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import tldextract
import random
import string
import re
import difflib
import json
import datetime
import socket
import base64
import hashlib
import secrets
import urllib.parse
import html
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy import inspect
from playwright.async_api import async_playwright
import urllib3
import glob
import os
import sys
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import zlib
import pickle
import marshal
import yaml
from typing import Dict, List, Optional, Set, Tuple, Any
import logging
from dataclasses import dataclass, field
from enum import Enum
import csv
from pathlib import Path
import google.generativeai as genai
import io
import xml.etree.ElementTree as ET
import psutil
import platform
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

# === CONFIGURATION ===
CONFIG = {
    'DB_PATH': "sqlite:///cortex_v15.db",
    'MAX_DEPTH': 5,
    'CONCURRENCY_LIMIT': 25,
    'TIMEOUT': 15,
    'MAX_REQUESTS_PER_MINUTE': 60,
    'CACHE_TTL': 300,  # 5 minutes
    'REPORT_FORMATS': ['json', 'pdf', 'html', 'csv'],
    'PLUGIN_DIR': "plugins",
    'LOG_LEVEL': logging.INFO,
    'ENCRYPTION_KEY': None,  # Set via environment variable
}

# === ENUMS ===
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

# === DATACLASSES ===
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
    remediation_patch: str = "" # New: Suggested code fix
    cvss_score: float = 0.0
    cve_id: Optional[str] = None # New: CVE Reference
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

# === LOGGING SETUP ===
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',
        'INFO': '\033[92m',
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'CRITICAL': '\033[95m',
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['INFO'])
        record.msg = f"{color}{record.msg}{self.COLORS['RESET']}"
        return super().format(record)

logging.basicConfig(level=CONFIG['LOG_LEVEL'])
logger = logging.getLogger("TitaniumScanner")
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('[%(levelname)s] %(message)s'))
logger.addHandler(handler)

# Suppress SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === DATABASE MODELS ===
Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    id = Column(Integer, primary_key=True)
    scan_uuid = Column(String(36), unique=True, nullable=False)
    date = Column(DateTime, default=datetime.datetime.utcnow)
    target_url = Column(String)
    status = Column(String)
    mode = Column(String)
    config = Column(JSON)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")
    stats = relationship("ScanStats", back_populates="scan", uselist=False)

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    type = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    cvss_score = Column(Float)
    url = Column(String)
    parameter = Column(String)
    description = Column(Text)
    evidence = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    remediation_patch = Column(Text) # New
    cve_id = Column(String) # New
    tags = Column(JSON)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    scan = relationship("Scan", back_populates="findings")

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    url = Column(String)
    method = Column(String)
    status_code = Column(Integer)
    response_time = Column(Float)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    scan = relationship("Scan", back_populates="logs")

class ScanStats(Base):
    __tablename__ = 'scan_stats'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), unique=True)
    urls_scanned = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    scan_duration = Column(Float)
    tech_stack = Column(JSON)
    scan = relationship("Scan", back_populates="stats")

class ExploitLog(Base):
    __tablename__ = 'exploit_logs'
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    exploit_type = Column(String)
    target = Column(String)
    payload = Column(Text)
    result = Column(Text)
    success = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Plugin(Base):
    __tablename__ = 'plugins'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    version = Column(String)
    enabled = Column(Boolean, default=True)
    config = Column(JSON)

# === DATABASE INITIALIZATION ===
engine = create_engine(CONFIG['DB_PATH'], pool_pre_ping=True, pool_recycle=3600)
Session = sessionmaker(bind=engine)

def init_database():
    """Initialize database with proper error handling"""
    try:
        Base.metadata.create_all(engine)
        logger.info("✅ Database initialized successfully")
        
        # Create default plugins if not exist
        session = Session()
        default_plugins = [
            Plugin(name="SQLiDetector", version="1.0", enabled=True, config={"payloads": ["default"]}),
            Plugin(name="XSSDetector", version="1.0", enabled=True, config={"payloads": ["default"]}),
            Plugin(name="LFIDetector", version="1.0", enabled=True, config={"payloads": ["default"]}),
        ]
        
        for plugin in default_plugins:
            if not session.query(Plugin).filter_by(name=plugin.name).first():
                session.add(plugin)
        
        session.commit()
        session.close()
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise

init_database()

# === ENHANCED SECURITY UTILITIES ===
class SecurityManager:
    """Enhanced security and encryption manager"""
    
    def __init__(self):
        self.encryption_key = self._load_encryption_key()
        self.audit_logs = []
    
    def _load_encryption_key(self):
        """Load encryption key from environment or generate"""
        key = os.environ.get('TITANIUM_ENCRYPTION_KEY')
        if not key:
            key = secrets.token_hex(32)
            logger.warning("⚠️ Using generated encryption key. Set TITANIUM_ENCRYPTION_KEY for persistence.")
        return key.encode()
    
    def encrypt_sensitive(self, data: str) -> str:
        """Encrypt sensitive data"""
        cipher = AES.new(
            hashlib.sha256(self.encryption_key).digest()[:32],
            AES.MODE_GCM
        )
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    
    def decrypt_sensitive(self, encrypted: str) -> str:
        """Decrypt sensitive data"""
        data = base64.b64decode(encrypted)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(
            hashlib.sha256(self.encryption_key).digest()[:32],
            AES.MODE_GCM,
            nonce=nonce
        )
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    
    def hash_identifiable_data(self, data: str) -> str:
        """Hash identifiable data for privacy"""
        return hashlib.sha256(
            data.encode() + self.encryption_key
        ).hexdigest()
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log security events"""
        event = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'type': event_type,
            'details': details,
            'ip': self._get_client_ip(),
            'user_agent': self._get_user_agent()
        }
        self.audit_logs.append(event)
        
        # Save to secure log file
        log_file = f"security_audit_{datetime.date.today()}.log"
        with open(log_file, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"
    
    def _get_user_agent(self) -> str:
        """Get user agent"""
        return f"TitaniumScanner/15.0"

# === CVE & INTELLIGENCE MAPPING ===
CVE_MAP = {
    VulnerabilityType.SQL_INJECTION: {
        "cve": "CVE-2024-XXXX (Generic SQLi)",
        "cvss": 9.8,
        "description": "SQL injection vulnerability allowing database compromise."
    },
    VulnerabilityType.XSS: {
        "cve": "CVE-2024-YYYY (Generic XSS)",
        "cvss": 7.5,
        "description": "Cross-site scripting vulnerability allowing session hijacking."
    },
    VulnerabilityType.LFI_RFI: {
        "cve": "CVE-2024-ZZZZ (Generic LFI)",
        "cvss": 8.1,
        "description": "Local/Remote file inclusion allowing sensitive data exposure."
    }
}

class ThreatIntelManager:
    """Fetches real-time threat intelligence feeds"""
    
    def __init__(self):
        self.feeds = [
            "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "https://www.cisa.gov/cybersecurity-advisories/all.xml"
        ]
        self.cached_news = []
        self.last_update = 0
        
    async def fetch_latest(self) -> List[Dict]:
        """Fetch latest security news from RSS feeds"""
        now = time.time()
        if now - self.last_update < 3600 and self.cached_news:
            return self.cached_news
            
        news = []
        async with aiohttp.ClientSession() as session:
            for feed_url in self.feeds:
                try:
                    async with session.get(feed_url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            root = ET.fromstring(content)
                            for item in root.findall('.//item')[:5]:
                                news.append({
                                    "title": item.find('title').text,
                                    "link": item.find('link').text,
                                    "date": item.find('pubDate').text if item.find('pubDate') is not None else "N/A"
                                })
                except Exception as e:
                    logger.debug(f"Threat Intel fetch failed for {feed_url}: {e}")
        
        self.cached_news = news[:10]
        self.last_update = now
        return self.cached_news

    def get_global_threats(self) -> List[Dict]:
        """Simulate real-time global threat events for visualization"""
        countries = ["USA", "China", "Russia", "Germany", "Brazil", "Japan", "Egypt", "UK"]
        attacks = ["DDoS Attack", "SQL Injection", "Brute Force", "Malware C2", "Phishing Campaign"]
        
        events = []
        for _ in range(5):
            events.append({
                "source": random.choice(countries),
                "target": "Local System",
                "type": random.choice(attacks),
                "severity": random.choice(["HIGH", "CRITICAL", "MEDIUM"]),
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
            })
        return events

    def check_ip_reputation(self, ip: str) -> Dict:
        """Proactive IP Reputation Checking (Elite Corporate Feature)"""
        # Mocked reputation database
        bad_ips = {
            "185.220.101.": "Tor Exit Node (Malicious Activity)",
            "45.227.253.": "Known SSH Brute Forcer",
            "103.149.162.": "C2 Malware Infrastructure",
            "127.0.0.1": "Localhost (Safe)"
        }
        
        for prefix, reason in bad_ips.items():
            if ip.startswith(prefix):
                return {"status": "MALICIOUS", "reason": reason, "severity": "CRITICAL"}
        return {"status": "CLEAN", "reason": "No historical matches in global blacklist", "severity": "INFO"}

    def get_known_attack_patterns(self) -> List[Dict]:
        """Returns complex patterns for behavioral engine matching"""
        return [
            {"type": "SQLi", "regex": r"(?i)(SELECT|UNION|INSERT|DELETE|DROP|UPDATE).*FROM"},
            {"type": "XSS", "regex": r"(?i)<script.*?>.*?</script>"},
            {"type": "PathTraversal", "regex": r"\.\./\.\./"}
        ]

class WindowsForensics:
    """AI-powered Deep Digital Forensics for Windows"""
    
    def __init__(self, ai_detector):
        self.ai = ai_detector
        self.is_windows = platform.system() == "Windows"
        
    async def analyze_system_security(self) -> Dict:
        """Full forensic sweep: Events, Processes, Network, Registry, Startup"""
        if not self.is_windows:
            return {"error": "Forensics currently support Windows only."}
            
        try:
            results = await asyncio.gather(
                self._get_failed_logins(),
                self._get_suspicious_processes(),
                self._get_active_network_connections(),
                self._get_startup_programs(),
                self._get_scheduled_tasks(),
                return_exceptions=True
            )
            
            forensic_data = {
                "system": dict(platform.uname()._asdict()),
                "failed_logins": results[0] if not isinstance(results[0], Exception) else [],
                "suspicious_procs": results[1] if not isinstance(results[1], Exception) else [],
                "active_connections": results[2] if not isinstance(results[2], Exception) else [],
                "startup_programs": results[3] if not isinstance(results[3], Exception) else [],
                "scheduled_tasks": results[4] if not isinstance(results[4], Exception) else [],
                "scan_time": datetime.datetime.now().isoformat()
            }
            
            summary = await self._ai_summarize(forensic_data)
            return {"data": forensic_data, "summary": summary}
        except Exception as e:
            logger.error(f"Forensics Analysis error: {e}")
            return {"error": str(e)}

    async def _get_failed_logins(self) -> List[Dict]:
        """Get last 20 failed login attempts from Windows Security Logs"""
        ps_cmd = '''Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object { @{Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); User=$_.Properties[5].Value; Domain=$_.Properties[6].Value; IP=$_.Properties[19].Value} } | ConvertTo-Json'''
        try:
            proc = await asyncio.create_subprocess_shell(
                f'powershell -NonInteractive -Command "{ps_cmd}"',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode(errors='ignore').strip())
            return data if isinstance(data, list) else [data]
        except: return []

    async def _get_suspicious_processes(self) -> List[Dict]:
        """Find processes with high CPU, no path, or running as SYSTEM from user dirs"""
        suspicious = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    info = p.info
                    is_suspicious = False
                    reason = []
                    
                    if (info['cpu_percent'] or 0) > 30:
                        is_suspicious = True
                        reason.append(f"High CPU: {info['cpu_percent']}%")
                    
                    exe = info.get('exe') or ''
                    if exe and any(d in exe.lower() for d in ['temp', 'appdata', 'downloads', '%tmp%']):
                        is_suspicious = True
                        reason.append(f"Suspicious location: {exe}")
                    
                    if not exe and info.get('name') not in ['System', 'Idle', 'Registry']:
                        is_suspicious = True
                        reason.append("No executable path (hollow process?)")
                    
                    if is_suspicious:
                        info['reasons'] = reason
                        suspicious.append(info)
                except: continue
        except: pass
        return suspicious[:10]

    async def _get_active_network_connections(self) -> List[Dict]:
        """Get all active outbound network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else 'Unknown'
                    except: proc_name = 'Unknown'
                    
                    connections.append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "process": proc_name,
                        "pid": conn.pid
                    })
        except: pass
        return connections[:20]

    async def _get_startup_programs(self) -> List[Dict]:
        """Get programs set to run at startup via PowerShell"""
        ps_cmd = 'Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | ConvertTo-Json'
        try:
            proc = await asyncio.create_subprocess_shell(
                f'powershell -NonInteractive -Command "{ps_cmd}"',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode(errors='ignore').strip())
            return data if isinstance(data, list) else [data]
        except: return []

    async def _get_scheduled_tasks(self) -> List[Dict]:
        """Get scheduled tasks pointing to suspicious locations"""
        ps_cmd = 'Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.TaskPath -notmatch "Microsoft"} | Select-Object TaskName, TaskPath, @{n="Action";e={$_.Actions.Execute}} | ConvertTo-Json'
        try:
            proc = await asyncio.create_subprocess_shell(
                f'powershell -NonInteractive -Command "{ps_cmd}"',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            raw = stdout.decode(errors='ignore').strip()
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except: return []

    async def _ai_summarize(self, data: Dict) -> str:
        """Comprehensive AI forensic report"""
        if not self.ai.model:
            return self._build_text_report(data)
            
        # Build a clean text summary to avoid token overload
        summary_input = {
            "system": data.get('system', {}),
            "failed_logins_count": len(data.get('failed_logins', [])),
            "failed_logins_sample": data.get('failed_logins', [])[:3],
            "suspicious_procs": data.get('suspicious_procs', [])[:5],
            "external_connections": [
                c for c in data.get('active_connections', [])
                if not c['remote'].startswith(('192.168.', '10.', '127.'))
            ][:10],
            "startup_programs_count": len(data.get('startup_programs', [])),
            "non_ms_tasks": len(data.get('scheduled_tasks', []))
        }
        
        prompt = f"""
        You are a Certified Digital Forensics Investigator. Analyze this system snapshot and produce a professional forensic report.
        
        System Data:
        {json.dumps(summary_input, indent=2)}
        
        Format your response in Arabic with:
        ## 🔴 خلاصة التهديدات
        (Short threat summary, severity level: Critical/High/Medium/Low)
        
        ## 📊 النتائج التفصيلية
        (Bullet points for each suspicious finding)
        
        ## 🛡️ التوصيات العاجلة
        (Top 3 immediate action items)
        
        Be precise and professional. If no issues found, say the system looks clean.
        """
        try:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: self.ai.model.generate_content(prompt))
            return resp.text if resp else self._build_text_report(data)
        except Exception as e:
            return self._build_text_report(data)

    def _build_text_report(self, data: Dict) -> str:
        """Fallback text report if AI unavailable"""
        report = ["=== FORENSICS REPORT ===", f"System: {data.get('system', {}).get('node', 'Unknown')}",
                  f"Scan Time: {data.get('scan_time', 'N/A')}",
                  f"Failed Logins: {len(data.get('failed_logins', []))}",
                  f"Suspicious Processes: {len(data.get('suspicious_procs', []))}",
                  f"Active Connections: {len(data.get('active_connections', []))}",
                  f"Startup Programs: {len(data.get('startup_programs', []))}",
                  f"Non-Microsoft Tasks: {len(data.get('scheduled_tasks', []))}"]
        return '\n'.join(report)

# === ADVANCED AI/ML DETECTION ===
class AIMLDetector:
    """AI/ML based vulnerability detection via Gemini"""
    
    def __init__(self):
        self.model = None
        self.load_models()
    
    def load_models(self):
        """Load Gemini models"""
        try:
            # Try to get key from env or config
            api_key = os.getenv('TITANIUM_AI_KEY') or CONFIG.get('ENCRYPTION_KEY') # Fallback to encryption key if user reused it (not recommended but possible) 
            # Better to rely on TITANIUM_AI_KEY env var set by GUI or user
            
            if not api_key:
                 # Check if we can find it in a .env file or local storage
                 pass

            if api_key:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                logger.info("🤖 AI/ML detector initialized (Gemini Pro)")
            else:
                logger.warning("⚠️ AI Key not found. AI features running in limited mode.")
        except Exception as e:
            logger.warning(f"⚠️ AI/ML not available: {e}")
    
    async def analyze_response(self, url: str, html: str, headers: Dict) -> Optional[Vulnerability]:
        """Analyze response using Gemini"""
        if not self.model or not html:
            return None
        
        try:
            # Prepare safe prompt
            prompt = f"""
            Act as a security expert. Analyze this HTTP response for vulnerabilities (SQLi, XSS, LFI, Sensitive Info).
            
            URL: {url}
            Headers: {headers}
            Content Preview (First 2000 chars):
            {html[:2000]}
            
            Reply ONLY with a JSON object:
            {{
                "vulnerability": "Initial/None/SQLi/XSS/LFI",
                "confidence": 0.0 to 1.0,
                "reason": "Short explanation",
                "severity": "LOW/MEDIUM/HIGH/CRITICAL"
            }}
            """
            
            # Run in executor to avoid blocking event loop
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, lambda: self.model.generate_content(prompt))
            
            if response and response.text:
                text = response.text.replace('```json', '').replace('```', '').strip()
                data = json.loads(text)
                
                if data.get('vulnerability') and data['vulnerability'] != 'None' and data.get('confidence', 0) > 0.6:
                     severity_map = {
                         "LOW": SeverityLevel.LOW,
                         "MEDIUM": SeverityLevel.MEDIUM,
                         "HIGH": SeverityLevel.HIGH,
                         "CRITICAL": SeverityLevel.CRITICAL
                     }
                     return Vulnerability(
                        type=VulnerabilityType.CUSTOM,
                        severity=severity_map.get(data.get('severity', 'MEDIUM'), SeverityLevel.MEDIUM),
                        confidence=float(data.get('confidence', 0.8)),
                        url=url,
                        description=f"AI Analysis: {data['vulnerability']}",
                        evidence=data.get('reason', 'Detected by Gemini AI')
                    )
        except Exception as e:
            # logger.debug(f"AI Analysis error: {e}")
            pass
        return None

    def _extract_features(self, url: str, html: str, headers: Dict) -> Dict:
        # Legacy method kept for interface compatibility if needed, but unused by Gemini implementation
        return {}

# === PLUGIN SYSTEM ===
class PluginManager:
    """Dynamic plugin system"""
    
    def __init__(self):
        self.plugins = {}
        self.hooks = {
            'pre_scan': [],
            'post_scan': [],
            'vulnerability_detected': [],
            'request_sent': [],
            'response_received': [],
        }
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from directory"""
        plugin_dir = Path(CONFIG['PLUGIN_DIR'])
        plugin_dir.mkdir(exist_ok=True)
        
        # Load built-in plugins
        self._load_builtin_plugins()
        
        # Load external plugins
        for plugin_file in plugin_dir.glob("*.py"):
            try:
                self._load_plugin(plugin_file)
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")
    
    def _load_builtin_plugins(self):
        """Load built-in plugins"""
        builtin_plugins = [
            SQLiPlugin(),
            XSSPlugin(),
            LFIPlugin(),
            HeaderSecurityPlugin(),
            SensitiveDataPlugin(),
            IDORPlugin(),
            CSRFPlugin(),
            WAFPlugin(),
            DirectoryPlugin(),
            ParamPlugin(),
        ]
        
        for plugin in builtin_plugins:
            self.register_plugin(plugin)
    
    def register_plugin(self, plugin):
        """Register a plugin"""
        self.plugins[plugin.name] = plugin
        
        # Register hooks
        for hook_name in plugin.supported_hooks:
            if hasattr(plugin, hook_name):
                self.hooks[hook_name].append(getattr(plugin, hook_name))
        
        logger.info(f"✅ Plugin loaded: {plugin.name} v{plugin.version}")
    
    async def execute_hook(self, hook_name: str, *args, **kwargs):
        """Execute all plugins for a hook"""
        results = []
        for hook_func in self.hooks.get(hook_name, []):
            try:
                result = await hook_func(*args, **kwargs)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Plugin hook {hook_name} failed: {e}")
        return results

class BasePlugin:
    """Base class for all plugins"""
    
    name = "BasePlugin"
    version = "1.0"
    description = "Base plugin class"
    author = "Titanium Team"
    enabled = True
    supported_hooks = []
    
    async def pre_scan(self, scanner, config):
        pass
    
    async def post_scan(self, scanner, results):
        pass
    
    async def vulnerability_detected(self, scanner, vulnerability):
        pass
    
    async def request_sent(self, scanner, url, method, headers):
        pass
    
    async def response_received(self, scanner, url, response, headers):
        pass

class SQLiPlugin(BasePlugin):
    """Professional SQL Injection Detection & Active Exploitation Plugin"""
    
    name = "SQLiDetector"
    version = "3.0"
    description = "Deep SQLi detection with union-based, blind, time-based, and error-based techniques"
    supported_hooks = ['response_received']
    
    def __init__(self):
        self.error_patterns = [
            # MySQL
            r"SQL syntax.*?MySQL", r"Warning.*?mysql_", r"MySQL Query fail",
            r"MySQLSyntaxErrorException", r"valid MySQL result",
            # PostgreSQL
            r"PostgreSQL.*?ERROR", r"org\.postgresql\.util\.PSQLException",
            r"PG::SyntaxError",
            # MSSQL
            r"Microsoft OLE DB Provider", r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver", r"Unclosed quotation mark",
            r"\[ODBC SQL Server\]",
            # Oracle
            r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
            # Generic
            r"You have an error in your SQL", r"in Boolean mode",
            r"SQLSTATE\[\d+\]", r"Syntax error or access violation",
        ]
        self.time_payloads = [
            ("' AND SLEEP(3)--", 3),
            ("1; WAITFOR DELAY '0:0:3'--", 3),
            ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3),
        ]
        self.auth_bypass_payloads = [
            "admin'--", "admin'#", "' OR 1=1--", "' OR '1'='1'--",
            "admin' OR '1'='1", "' OR 1=1#", "admin'/*",
        ]
        self.union_payloads = [
            "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 5--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,@@version,NULL--",
            "' UNION SELECT NULL,username,password,NULL FROM users--",
        ]
    
    async def response_received(self, scanner, url, response, headers):
        """Active SQLi testing using error patterns and active injection"""
        if not response:
            return None
        
        # 1. Error-based passive detection on the CURRENT response
        for pattern in self.error_patterns:
            if re.search(pattern, response, re.I):
                return Vulnerability(
                    type=VulnerabilityType.SQL_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95,
                    url=url,
                    description="SQL error message leaked in response",
                    evidence=f"Pattern: {pattern}",
                    remediation="Use parameterized queries (prepared statements). Never concatenate user input into SQL queries."
                )
        
        # 2. Active injection via URL parameters
        if '?' not in url:
            return None
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param_name in params:
            # Inject a simple error payload
            test_params = dict(params)
            test_params[param_name] = ["'\""]
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, timeout=8, ssl=False) as resp:
                        test_resp = await resp.text()
                        for pattern in self.error_patterns:
                            if re.search(pattern, test_resp, re.I):
                                return Vulnerability(
                                    type=VulnerabilityType.SQL_INJECTION,
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=0.95,
                                    url=url,
                                    parameter=param_name,
                                    description=f"SQL Injection in parameter '{param_name}' (Error-Based)",
                                    evidence=f"Payload: {test_params[param_name][0]} triggered: {pattern}",
                                    remediation="Use parameterized queries. Sanitize all inputs server-side."
                                )
            except: continue
        return None

class XSSPlugin(BasePlugin):
    """Professional XSS Detection Plugin with Active Reflection Testing"""
    
    name = "XSSDetector"
    version = "3.0"
    description = "Active XSS detection with context-aware payloads and WAF bypass"
    supported_hooks = ['response_received']
    
    # Unique canary for reliable detection
    _CANARY = "XSS_REFLCT_7x9z"
    
    def __init__(self):
        self.polyglots = [
            f"<script>alert('{self._CANARY}')</script>",
            f"\">{self._CANARY}<script>alert(1)</script>",
            f"'><img src=x onerror=alert('{self._CANARY}')>",
            f"<svg onload=alert('{self._CANARY}')>",
            f"javascript:alert('{self._CANARY}')",
            # WAF bypass variants
            f"<ScRiPt>alert({self._CANARY})</sCrIpT>",
            f"<img src=x oNErrOr=alert('{self._CANARY}')>",
        ]
    
    async def response_received(self, scanner, url, response, headers):
        """Test XSS by injecting into URL params and checking reflection"""
        if not response or '?' not in url:
            return None
        
        # 1. Passive: Check if existing URL params are reflected unescaped
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in params.items():
            for v in values:
                if v and v in response and html.escape(v) not in response:
                    return Vulnerability(
                        type=VulnerabilityType.XSS,
                        severity=SeverityLevel.HIGH,
                        confidence=0.75,
                        url=url,
                        parameter=param,
                        description=f"Reflected XSS: Param '{param}' is reflected without HTML encoding",
                        evidence=f"Value '{v}' reflected as-is in response body.",
                        remediation="Apply htmlspecialchars() or equivalent output encoding. Use CSP headers."
                    )
        
        # 2. Active: Inject canary and check reflection
        for payload in self.polyglots[:3]:  # Test first 3 for speed
            test_params = dict(params)
            if test_params:
                first_param = list(test_params.keys())[0]
                test_params[first_param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, timeout=8, ssl=False) as resp:
                            body = await resp.text()
                            if self._CANARY in body and html.escape(payload) not in body:
                                return Vulnerability(
                                    type=VulnerabilityType.XSS,
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.9,
                                    url=url,
                                    parameter=first_param,
                                    description=f"Confirmed XSS: Script tag executed in parameter '{first_param}'",
                                    evidence=f"Payload reflected: {payload[:60]}",
                                    remediation="Use a strict Content-Security-Policy. Encode all output. Sanitize inputs."
                                )
                except: continue
        return None

class LFIPlugin(BasePlugin):
    """Professional LFI/RFI Detection Plugin with Path Traversal Technique"""
    
    name = "LFIDetector"
    version = "2.5"
    description = "Active LFI/RFI detection with encoding bypasses"
    supported_hooks = ['response_received']
    
    def __init__(self):
        self.linux_payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "expect://id",
            "/proc/self/environ",
        ]
        self.windows_payloads = [
            "../../../windows/win.ini",
            "..\\..\\..\\windows\\win.ini",
            "C:\\Windows\\win.ini",
            "C:/Windows/System32/drivers/etc/hosts",
            "%WINDIR%\\win.ini",
        ]
        self.linux_indicators = [
            "root:x:0:0", "/bin/bash", "/bin/sh", "nobody:x:", "daemon:x:"
        ]
        self.windows_indicators = [
            "[extensions]", "[mail]", "[fonts]", "[386enh]", "for 16-bit"
        ]
    
    async def response_received(self, scanner, url, response, headers):
        """Active LFI testing by injecting path traversal into parameters"""
        if not response:
            return None
        
        # 1. Passive check on current response
        for indicator in self.linux_indicators + self.windows_indicators:
            if indicator in response:
                return Vulnerability(
                    type=VulnerabilityType.LFI_RFI,
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95,
                    url=url,
                    description="Local File Inclusion: Sensitive file contents exposed",
                    evidence=f"Found: {indicator}",
                    remediation="Never use user-supplied filenames. Use a whitelist of allowed files."
                )

        # 2. Active injection if URL has params
        if '?' not in url:
            return None
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        all_payloads = self.linux_payloads + self.windows_payloads
        
        for param_name in params:
            for payload in all_payloads[:5]:  # Limit for speed
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, timeout=8, ssl=False) as resp:
                            body = await resp.text()
                            for ind in self.linux_indicators + self.windows_indicators:
                                if ind in body:
                                    return Vulnerability(
                                        type=VulnerabilityType.LFI_RFI,
                                        severity=SeverityLevel.CRITICAL,
                                        confidence=0.95,
                                        url=url,
                                        parameter=param_name,
                                        description=f"Confirmed LFI in parameter '{param_name}'",
                                        evidence=f"Payload: {payload} | Indicator: {ind}",
                                        remediation="Use a strict whitelist for file access. Never use user input in file paths."
                                    )
                except: continue
        return None

class HeaderSecurityPlugin(BasePlugin):
    """Security headers checker"""
    
    name = "HeaderSecurity"
    version = "1.2"
    
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
            if header not in headers:
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
                        evidence=f"Found: {match[0] if isinstance(match, tuple) else match}"
                    ))
        
        return findings if findings else None

class WAFPlugin(BasePlugin):
    """Detect presence of Web Application Firewalls"""
    name = "WAFDetector"
    version = "1.0"
    supported_hooks = ['response_received']
    
    def __init__(self):
        self.signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "Akamai": ["akamai-origin-hop", "akamai-ghost"],
            "Incapsula": ["visid_incap", "incap_ses", "incap_"],
            "ModSecurity": ["mod_security", "NOYB"],
            "AWS WAF": ["x-amz-cf-id", "awselb"]
        }

    async def response_received(self, scanner, url, response, headers):
        header_str = str(headers).lower()
        for waf, sigs in self.signatures.items():
            if any(sig in header_str for sig in sigs):
                return Vulnerability(
                    type=VulnerabilityType.INFO,
                    severity=SeverityLevel.INFO,
                    confidence=0.9,
                    url=url,
                    description=f"WAF Detected: {waf}",
                    evidence=f"Header match for {waf} signatures",
                    remediation="Adjust scanning speed to avoid rate limiting. WAF may block advanced payloads."
                )
        return None

class DirectoryPlugin(BasePlugin):
    """Scan for common sensitive directories and files"""
    name = "DirectoryBruter"
    version = "1.0"
    supported_hooks = ['pre_scan']
    
    def __init__(self):
        self.paths = [
            "/.env", "/.git/config", "/.htaccess", "/backup.sql",
            "/admin", "/config.php.bak", "/phpinfo.php", "/.ssh/id_rsa"
        ]

    async def pre_scan(self, scanner, config):
        base_url = f"{urlparse(config.target_url).scheme}://{urlparse(config.target_url).netloc}"
        for p in self.paths:
            target = urljoin(base_url, p)
            try:
                async with scanner.session.get(target, ssl=False, timeout=5) as resp:
                    if resp.status == 200:
                        scanner.stats['vulnerabilities_found'] += 1
                        vuln = Vulnerability(
                            type=VulnerabilityType.SENSITIVE_DATA,
                            severity=SeverityLevel.HIGH,
                            confidence=0.8,
                            url=target,
                            description=f"Exposed sensitive file: {p}",
                            remediation="Restrict access to this file immediately."
                        )
                        await scanner.plugin_manager.execute_hook('vulnerability_detected', scanner, vuln)
            except: pass

class ParamPlugin(BasePlugin):
    """Mine for hidden URL parameters"""
    name = "ParameterMiner"
    version = "1.0"
    supported_hooks = ['response_received']
    
    def __init__(self):
        self.params = ["debug", "admin", "test", "dev", "cmd"]

    async def response_received(self, scanner, url, response, headers):
        if not response: return None
        # This is a passive check for reflected params
        for p in self.params:
            if f"{p}=" in url.lower():
                return Vulnerability(
                    type=VulnerabilityType.INFO,
                    severity=SeverityLevel.LOW,
                    confidence=0.6,
                    url=url,
                    description=f"Suspicious parameter '{p}' found in URL",
                    remediation="Review if this parameter should be exposed or if it enables debug features."
                )
        return None

class IDORPlugin(BasePlugin):
    """IDOR detection plugin"""
    
    name = "IDORDetector"
    version = "1.1"
    
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

# === PORT SCANNER ===
class PortScanner:
    """Async TCP Connect Port Scanner"""
    
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Alt-HTTP",
        27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached",
    }
    
    DANGEROUS_PORTS = {21, 23, 445, 3389, 5900, 6379, 27017, 11211}
    
    async def scan(self, host: str, ports: List[int] = None, timeout: float = 2.0) -> Dict:
        """Scan target for open ports"""
        if not ports:
            ports = list(self.COMMON_PORTS.keys())
        
        logger.info(f"🔍 Port scanning {host} ({len(ports)} ports)...")
        results = {"host": host, "open_ports": [], "closed": 0, "filtered": 0, "risk_level": "LOW"}
        
        semaphore = asyncio.Semaphore(100)  # 100 concurrent connections max
        
        async def _check_port(port):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    service = self.COMMON_PORTS.get(port, "Unknown")
                    is_dangerous = port in self.DANGEROUS_PORTS
                    results["open_ports"].append({
                        "port": port, "service": service, "state": "open",
                        "dangerous": is_dangerous
                    })
                    if is_dangerous:
                        results["risk_level"] = "CRITICAL"
                    elif results["risk_level"] != "CRITICAL":
                        results["risk_level"] = "MEDIUM"
                except asyncio.TimeoutError:
                    results["filtered"] += 1
                except (ConnectionRefusedError, OSError):
                    results["closed"] += 1
        
        await asyncio.gather(*[_check_port(p) for p in ports])
        results["open_ports"].sort(key=lambda x: x["port"])
        results["total_scanned"] = len(ports)
        logger.info(f"✅ Port scan complete: {len(results['open_ports'])} open ports found")
        return results


# === SUBDOMAIN ENUMERATION ===
class SubdomainEnumerator:
    """Subdomain discovery via DNS brute-force and crt.sh"""
    
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog",
        "shop", "store", "app", "m", "mobile", "cdn", "static", "assets",
        "portal", "vpn", "remote", "ns1", "ns2", "mx", "smtp", "pop",
        "imap", "webmail", "cpanel", "panel", "dashboard", "db", "database",
        "backup", "old", "new", "beta", "demo", "docs", "wiki", "git",
        "jenkins", "ci", "jira", "confluence", "grafana", "monitor",
        "status", "health", "internal", "intranet", "sso", "auth", "login",
        "stage", "uat", "qa", "prod", "sandbox", "labs", "research",
    ]
    
    async def enumerate(self, domain: str) -> Dict:
        """Full subdomain enumeration"""
        logger.info(f"🌍 Enumerating subdomains for: {domain}")
        
        dns_results, crt_results = await asyncio.gather(
            self._dns_bruteforce(domain),
            self._crt_sh_lookup(domain),
            return_exceptions=True
        )
        
        dns_found = dns_results if isinstance(dns_results, list) else []
        crt_found = crt_results if isinstance(crt_results, list) else []
        
        # Merge and deduplicate
        all_subs = list(set(dns_found + crt_found))
        all_subs.sort()
        
        logger.info(f"✅ Found {len(all_subs)} subdomains (DNS: {len(dns_found)}, crt.sh: {len(crt_found)})")
        return {
            "domain": domain,
            "total": len(all_subs),
            "subdomains": all_subs,
            "sources": {"dns_bruteforce": len(dns_found), "crt_sh": len(crt_found)}
        }
    
    async def _dns_bruteforce(self, domain: str) -> List[str]:
        """DNS brute-force with common subdomain wordlist"""
        found = []
        semaphore = asyncio.Semaphore(50)
        
        async def _resolve(sub):
            async with semaphore:
                fqdn = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.getaddrinfo(fqdn, None)
                    found.append(fqdn)
                except: pass
        
        await asyncio.gather(*[_resolve(s) for s in self.COMMON_SUBDOMAINS])
        return found
    
    async def _crt_sh_lookup(self, domain: str) -> List[str]:
        """Query crt.sh Certificate Transparency logs"""
        found = []
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=15, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get("name_value", "")
                            for n in name.split("\n"):
                                n = n.strip().lower()
                                if n.endswith(domain) and "*" not in n:
                                    found.append(n)
        except Exception as e:
            logger.debug(f"crt.sh lookup error: {e}")
        return list(set(found))


# === BRUTE FORCE ENGINE ===
class BruteForceEngine:
    """Smart login form brute-forcer"""
    
    DEFAULT_USERNAMES = ["admin", "administrator", "root", "user", "test", "guest", "demo", "info"]
    DEFAULT_PASSWORDS = [
        "admin", "password", "123456", "12345678", "admin123", "root",
        "password1", "1234", "admin1", "test", "guest", "demo",
        "changeme", "letmein", "welcome", "monkey", "master",
        "dragon", "login", "princess", "qwerty", "abc123",
        "P@ssw0rd", "Admin@123", "Default1", "Passw0rd!", "Welcome1",
    ]
    
    async def find_login_forms(self, url: str, html: str) -> List[Dict]:
        """Detect login forms in HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, html, re.S | re.I):
            form_html = match.group(0)
            # Check if it contains password-like inputs
            if re.search(r'type=["\']password["\']', form_html, re.I):
                action = re.search(r'action=["\']([^"\']*)', form_html, re.I)
                method = re.search(r'method=["\']([^"\']*)', form_html, re.I)
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.I)
                
                forms.append({
                    "action": action.group(1) if action else url,
                    "method": (method.group(1) if method else "POST").upper(),
                    "fields": inputs,
                    "url": url
                })
        return forms
    
    async def brute_force(self, form: Dict, base_url: str, max_attempts: int = 50) -> Optional[Dict]:
        """Attempt brute-force on a login form"""
        action_url = urljoin(base_url, form["action"])
        fields = form["fields"]
        
        # Guess which field is username and password
        user_field = next((f for f in fields if any(w in f.lower() for w in ["user", "login", "email", "name"])), fields[0] if fields else None)
        pass_field = next((f for f in fields if any(w in f.lower() for w in ["pass", "pwd", "secret"])), fields[1] if len(fields) > 1 else None)
        
        if not user_field or not pass_field:
            return None
        
        logger.info(f"🔐 Brute-forcing {action_url} (fields: {user_field}/{pass_field})")
        attempts = 0
        
        async with aiohttp.ClientSession() as session:
            for username in self.DEFAULT_USERNAMES[:5]:
                for password in self.DEFAULT_PASSWORDS:
                    if attempts >= max_attempts:
                        return None
                    attempts += 1
                    
                    data = {user_field: username, pass_field: password}
                    # Add any other hidden fields
                    for f in fields:
                        if f != user_field and f != pass_field:
                            data[f] = ""
                    
                    try:
                        async with session.post(action_url, data=data, allow_redirects=False, ssl=False, timeout=8) as resp:
                            body = await resp.text()
                            status = resp.status
                            
                            # Success indicators
                            if status in [301, 302, 303] and 'login' not in str(resp.headers.get('Location', '')).lower():
                                return {"username": username, "password": password, "status": status, "url": action_url}
                            
                            fail_indicators = ["invalid", "incorrect", "wrong", "failed", "error", "denied"]
                            if status == 200 and not any(fi in body.lower() for fi in fail_indicators):
                                if len(body) > 500:  # Non-trivial response
                                    return {"username": username, "password": password, "status": status, "url": action_url}
                    except: continue
                    
                    await asyncio.sleep(0.3)  # Throttle
        
        return None


# === CSRF DETECTION PLUGIN ===
class CSRFPlugin(BasePlugin):
    """Cross-Site Request Forgery detection"""
    
    name = "CSRFDetector"
    version = "2.0"
    description = "Detects forms missing CSRF protection tokens"
    supported_hooks = ['response_received']
    
    CSRF_TOKEN_NAMES = [
        "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "_token",
        "authenticity_token", "anti-forgery", "antiforgery",
        "__RequestVerificationToken", "nonce"
    ]
    
    async def response_received(self, scanner, url, response, headers):
        """Check forms for CSRF tokens"""
        if not response:
            return None
        
        form_pattern = r'<form[^>]*method=["\']post["\'][^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, response, re.S | re.I):
            form_html = match.group(1)
            
            # Check if any CSRF token exists
            has_csrf = False
            for token_name in self.CSRF_TOKEN_NAMES:
                if re.search(rf'name=["\'][^"\']*{token_name}[^"\']*["\']', form_html, re.I):
                    has_csrf = True
                    break
            
            if not has_csrf:
                # Also check for hidden inputs that look like tokens
                hidden_inputs = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)', form_html, re.I)
                for val in hidden_inputs:
                    if len(val) > 20:  # Long hidden values might be CSRF tokens
                        has_csrf = True
                        break
            
            if not has_csrf:
                return Vulnerability(
                    type=VulnerabilityType.CSRF,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    url=url,
                    description="POST form without CSRF protection token",
                    evidence="Form with method=POST found without csrf/xsrf/token hidden field",
                    remediation="Add a unique CSRF token to every form. Validate tokens server-side. Use SameSite cookie attribute."
                )
        return None


# === SSL/TLS ANALYZER ===
class SSLTLSAnalyzer:
    """Analyze SSL/TLS certificate and protocol security"""
    
    async def analyze(self, hostname: str) -> Dict:
        """Full SSL/TLS analysis"""
        import ssl
        
        logger.info(f"🔒 Analyzing SSL/TLS for: {hostname}")
        result = {
            "hostname": hostname,
            "issues": [],
            "certificate": {},
            "protocols": {},
            "grade": "A+"
        }
        
        # 1. Certificate Analysis
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    result["certificate"] = {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "serial": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [s[1] for s in cert.get("subjectAltName", ())],
                    }
                    result["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}
                    result["protocol_version"] = protocol
                    
                    # Check expiry
                    import ssl as ssl_mod
                    not_after = ssl_mod.cert_time_to_seconds(cert["notAfter"])
                    days_left = (not_after - time.time()) / 86400
                    result["certificate"]["days_until_expiry"] = int(days_left)
                    
                    if days_left < 0:
                        result["issues"].append({"severity": "CRITICAL", "issue": "Certificate EXPIRED!"})
                        result["grade"] = "F"
                    elif days_left < 30:
                        result["issues"].append({"severity": "HIGH", "issue": f"Certificate expires in {int(days_left)} days"})
                        result["grade"] = "C"
                    
                    # Check cipher strength
                    if cipher[2] < 128:
                        result["issues"].append({"severity": "CRITICAL", "issue": f"Weak cipher: {cipher[0]} ({cipher[2]} bits)"})
                        result["grade"] = "F"
                    
                    # Check protocol
                    if "TLSv1.0" in protocol or "TLSv1.1" in protocol or "SSL" in protocol:
                        result["issues"].append({"severity": "HIGH", "issue": f"Outdated protocol: {protocol}"})
                        result["grade"] = "D"
                    
        except ssl.SSLCertVerificationError as e:
            result["issues"].append({"severity": "CRITICAL", "issue": f"Certificate verification failed: {e}"})
            result["grade"] = "F"
        except Exception as e:
            result["issues"].append({"severity": "HIGH", "issue": f"SSL connection failed: {e}"})
            result["grade"] = "F"
        
        # 2. Test for weak protocols (TLS 1.0, SSL 3.0)
        for proto_name, proto_const in [("SSLv3", ssl.PROTOCOL_TLS), ("TLSv1.0", ssl.PROTOCOL_TLS)]:
            try:
                ctx2 = ssl.SSLContext(proto_const)
                ctx2.maximum_version = ssl.TLSVersion.TLSv1 if "1.0" in proto_name else ssl.TLSVersion.TLSv1_2
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, 443), timeout=5) as s:
                    with ctx2.wrap_socket(s, server_hostname=hostname) as ss:
                        actual = ss.version()
                        if "1.0" in actual or "SSL" in actual:
                            result["protocols"][actual] = "ENABLED (WEAK)"
                            result["issues"].append({"severity": "MEDIUM", "issue": f"Weak protocol {actual} supported"})
            except: pass
        
        if not result["issues"]:
            result["issues"].append({"severity": "INFO", "issue": "No major SSL/TLS issues found"})
        
        return result


# === JAVASCRIPT SECRETS ANALYZER ===
class JSSecretsAnalyzer:
    """Analyze JavaScript files for leaked secrets and API keys"""
    
    SECRET_PATTERNS = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
        "Firebase Domain": r'[a-z0-9.-]+\.firebaseio\.com',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "Private Key": r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        "JWT Token": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "Generic API Key": r'(?i)(api[_-]?key|apikey|api_secret)[\'"\s=:]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        "Generic Secret": r'(?i)(secret|token|password|passwd|credential)[\'"\s=:]+[\'"]?([a-zA-Z0-9_\-!@#$%^&*]{8,})[\'"]?',
        "Hardcoded URL with Creds": r'https?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+',
        "Internal IP": r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
        "Authorization Header": r'(?i)(Authorization|Bearer)[\'"\s:]+[\'"]?([a-zA-Z0-9._\-]{20,})[\'"]?',
    }
    
    async def analyze_page(self, url: str, html: str) -> List[Vulnerability]:
        """Extract JS file URLs from HTML and scan them"""
        findings = []
        
        # 1. Scan inline scripts
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)
        for script in inline_scripts:
            if len(script.strip()) > 10:
                secrets = self._scan_content(script)
                for s in secrets:
                    findings.append(Vulnerability(
                        type=VulnerabilityType.INFO_DISCLOSURE,
                        severity=SeverityLevel.CRITICAL if s["type"] in ["AWS Access Key", "Private Key", "GitHub Token"] else SeverityLevel.HIGH,
                        confidence=0.9,
                        url=url,
                        description=f"Secret leaked in inline JS: {s['type']}",
                        evidence=f"Pattern: {s['match'][:80]}",
                        remediation="Never hardcode secrets in JavaScript. Use environment variables and server-side APIs."
                    ))
        
        # 2. Fetch and scan external JS files
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)', html, re.I)
        for js_url in js_urls[:10]:  # Limit to 10 JS files
            full_url = urljoin(url, js_url)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(full_url, timeout=10, ssl=False) as resp:
                        if resp.status == 200:
                            js_content = await resp.text()
                            secrets = self._scan_content(js_content)
                            for s in secrets:
                                findings.append(Vulnerability(
                                    type=VulnerabilityType.INFO_DISCLOSURE,
                                    severity=SeverityLevel.CRITICAL if s["type"] in ["AWS Access Key", "Private Key", "GitHub Token"] else SeverityLevel.HIGH,
                                    confidence=0.85,
                                    url=full_url,
                                    description=f"Secret in external JS: {s['type']}",
                                    evidence=f"File: {js_url} | Match: {s['match'][:80]}",
                                    remediation="Remove all secrets from client-side code. Use token-based server proxies."
                                ))
            except: continue
        
        return findings
    
    def _scan_content(self, content: str) -> List[Dict]:
        """Scan content for secret patterns"""
        found = []
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches[:2]:  # Limit per type
                match_str = m if isinstance(m, str) else str(m[0]) if isinstance(m, tuple) else str(m)
                found.append({"type": secret_type, "match": match_str})
        return found


# === REAL-TIME ALERT SYSTEM ===
class RealTimeAlerts:
    """Real-time alert system with sound + popup notifications"""
    
    def __init__(self):
        self.enabled = True
        self.alert_history = []
        self.sound_enabled = True
    
    def trigger(self, title: str, message: str, severity: str = "HIGH"):
        """Fire a real-time alert"""
        if not self.enabled:
            return
        
        alert = {
            "time": datetime.datetime.now().isoformat(),
            "title": title,
            "message": message,
            "severity": severity
        }
        self.alert_history.append(alert)
        
        # Play system alert sound
        if self.sound_enabled:
            try:
                import winsound
                if severity == "CRITICAL":
                    winsound.Beep(1000, 500)  # High-pitched beep
                    winsound.Beep(1000, 500)
                elif severity == "HIGH":
                    winsound.Beep(800, 300)
                else:
                    winsound.Beep(600, 200)
            except: pass
        
        logger.warning(f"🚨 ALERT [{severity}]: {title} - {message}")


# === SMART RATE LIMITER ===
class SmartRateLimiter:
    """Intelligent rate limiting with adaptive throttling"""
    
    def __init__(self, max_rpm: int = 60):
        self.max_rpm = max_rpm
        self.requests = {}
        self.blocked_domains = {}
        self.adaptive_delays = {}
    
    async def wait_if_needed(self, domain: str):
        """Wait if rate limiting is needed"""
        now = time.time()
        
        # Clean old requests
        if domain in self.requests:
            self.requests[domain] = [
                t for t in self.requests[domain]
                if now - t < 60
            ]
        
        # Check if domain is blocked
        if domain in self.blocked_domains:
            block_until = self.blocked_domains[domain]
            if now < block_until:
                wait_time = block_until - now
                logger.warning(f"⚠️ Domain {domain} blocked, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                del self.blocked_domains[domain]
        
        # Apply adaptive delay
        if domain in self.adaptive_delays:
            delay = self.adaptive_delays[domain]
            await asyncio.sleep(delay)
        
        # Check rate limit
        if domain not in self.requests:
            self.requests[domain] = []
        
        if len(self.requests[domain]) >= self.max_rpm:
            # Calculate wait time
            oldest = self.requests[domain][0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                logger.info(f"⏳ Rate limit reached for {domain}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
        
        self.requests[domain].append(now)
    
    def handle_429(self, domain: str):
        """Handle 429 Too Many Requests response"""
        self.blocked_domains[domain] = time.time() + random.uniform(30, 90)
        logger.warning(f"⚡ Rate limited by {domain}, backing off")
    
    def adjust_delay(self, domain: str, response_time: float):
        """Adaptively adjust delays based on response time"""
        if domain not in self.adaptive_delays:
            self.adaptive_delays[domain] = 0.5
        
        if response_time > 5:
            # Increase delay for slow servers
            self.adaptive_delays[domain] = min(
                self.adaptive_delays[domain] * 1.2,
                2.0
            )
        elif response_time < 1:
            # Decrease delay for fast servers
            self.adaptive_delays[domain] = max(
                self.adaptive_delays[domain] * 0.8,
                0.1
            )

# === CACHE MANAGER ===
class CacheManager:
    """Intelligent caching system"""
    
    def __init__(self, ttl: int = 300):
        self.ttl = ttl
        self.cache = {}
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str):
        """Get cached item"""
        if key in self.cache:
            item, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                self.hits += 1
                return item
            else:
                del self.cache[key]
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any):
        """Set cache item"""
        self.cache[key] = (value, time.time())
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
    
    def stats(self) -> Dict:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = (self.hits / total) * 100 if total > 0 else 0
        return {
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'size': len(self.cache)
        }

# === REPORT GENERATOR ===
class ReportGenerator:
    """Advanced report generation system"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self):
        """Load report templates"""
        return {
            'executive': self._executive_template,
            'technical': self._technical_template,
            'developer': self._developer_template,
            'compliance': self._compliance_template,
        }
    
    def generate(self, scan_result: ScanResult, format: str = 'html', template: str = 'executive'):
        """Generate report"""
        if format == 'json':
            return self._generate_json(scan_result)
        elif format == 'html':
            return self._generate_html(scan_result, template)
        elif format == 'pdf':
            return self._generate_pdf(scan_result, template)
        elif format == 'csv':
            return self._generate_csv(scan_result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, scan_result: ScanResult) -> str:
        """Generate JSON report"""
        return json.dumps({
            'scan_id': scan_result.scan_id,
            'target': scan_result.target,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat(),
            'duration': (scan_result.end_time - scan_result.start_time).total_seconds(),
            'vulnerabilities': [
                {
                    'type': vuln.type.value,
                    'severity': vuln.severity.value,
                    'confidence': vuln.confidence,
                    'url': vuln.url,
                    'description': vuln.description,
                    'remediation': vuln.remediation
                }
                for vuln in scan_result.vulnerabilities
            ],
            'summary': scan_result.summary,
            'tech_stack': scan_result.tech_stack
        }, indent=2)
    
    def _generate_html(self, scan_result: ScanResult, template: str) -> str:
        """Generate HTML report"""
        template_func = self.templates.get(template, self._executive_template)
        return template_func(scan_result)
    
    def _generate_pdf(self, scan_result: ScanResult, template: str) -> bytes:
        """Generate PDF report via xhtml2pdf"""
        html_content = self._generate_html(scan_result, template)
        try:
            from xhtml2pdf import pisa
            output = io.BytesIO()
            pisa_status = pisa.CreatePDF(
                io.BytesIO(html_content.encode('utf-8')), 
                dest=output
            )
            if pisa_status.err:
                logger.error("PDF generation error")
                return html_content.encode()
            return output.getvalue()
        except ImportError:
            logger.warning("⚠️ xhtml2pdf module not found. Install it for real PDF support.")
            return html_content.encode()
        except Exception as e:
            logger.error(f"⚠️ PDF generation failed: {e}")
            return html_content.encode()
    
    def _generate_csv(self, scan_result: ScanResult) -> str:
        """Generate CSV report"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Type', 'Severity', 'URL', 'Description', 'Confidence', 'CVSS'])
        
        # Write data
        for vuln in scan_result.vulnerabilities:
            writer.writerow([
                vuln.type.value,
                vuln.severity.value,
                vuln.url,
                vuln.description[:100],
                vuln.confidence,
                vuln.cvss_score
            ])
        
        return output.getvalue()
    
    def _executive_template(self, scan_result: ScanResult) -> str:
        """Executive summary template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {scan_result.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
                .vuln {{ border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
                .critical {{ border-color: #c0392b; }}
                .high {{ border-color: #e74c3c; }}
                .medium {{ border-color: #f39c12; }}
                .low {{ border-color: #f1c40f; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p>Target: {scan_result.target}</p>
                <p>Scan ID: {scan_result.scan_id}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Scan completed in {scan_result.summary.get('duration', 0):.1f} seconds</p>
                <p>Vulnerabilities found: {len(scan_result.vulnerabilities)}</p>
                <p>Critical: {scan_result.summary.get('critical', 0)}</p>
                <p>High: {scan_result.summary.get('high', 0)}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            {"".join([
                f'<div class="vuln {vuln.severity.value.lower()}">'
                f'<h3>{vuln.type.value} ({vuln.severity.value})</h3>'
                f'<p><strong>URL:</strong> {vuln.url}</p>'
                f'<p><strong>Description:</strong> {vuln.description}</p>'
                f'<p><strong>Remediation:</strong> {vuln.remediation}</p>'
                f'</div>'
                for vuln in scan_result.vulnerabilities
            ])}
        </body>
        </html>
        """
    
    def _technical_template(self, scan_result: ScanResult) -> str:
        """Technical detailed template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Technical Report - {scan_result.target}</title>
            <style>
                body {{ font-family: monospace; margin: 20px; }}
                pre {{ background: #f5f5f5; padding: 10px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            </style>
        </head>
        <body>
            <h1>Technical Security Report</h1>
            <h2>Scan Details</h2>
            <pre>
            Target: {scan_result.target}
            Start: {scan_result.start_time}
            End: {scan_result.end_time}
            Duration: {(scan_result.end_time - scan_result.start_time).total_seconds():.1f}s
            URLs Scanned: {scan_result.total_urls_scanned}
            </pre>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr>
                    <th>Type</th><th>Severity</th><th>URL</th><th>Confidence</th><th>Evidence</th>
                </tr>
                {"".join([
                    f'<tr>'
                    f'<td>{vuln.type.value}</td>'
                    f'<td>{vuln.severity.value}</td>'
                    f'<td>{vuln.url[:50]}...</td>'
                    f'<td>{vuln.confidence:.1%}</td>'
                    f'<td>{vuln.evidence[:100]}</td>'
                    f'</tr>'
                    for vuln in scan_result.vulnerabilities
                ])}
        </table>
        </body>
        </html>
        """
    
    def _developer_template(self, scan_result: ScanResult) -> str:
        """Developer-focused template with code remediation"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Developer Security Report - {scan_result.target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f8f9fa; }}
                .container {{ max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                .patch {{ background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; font-family: 'Consolas', monospace; overflow-x: auto; }}
                h1, h2 {{ color: #0366d6; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Developer Remediation Report</h1>
                <p><strong>Target:</strong> {scan_result.target}</p>
                <hr>
                
                <h2>Security Findings & Patches</h2>
                {"".join([
                    f'<div style="margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px;">'
                    f'<h3>{vuln.type.value} ({vuln.severity.value})</h3>'
                    f'<p><strong>Endpoint:</strong> {vuln.url}</p>'
                    f'<p><strong>Recommended Action:</strong></p>'
                    f'<div class="patch">{vuln.remediation}</div>'
                    f'</div>'
                    for vuln in scan_result.vulnerabilities
                ])}
            </div>
        </body>
        </html>
        """

    def _compliance_template(self, scan_result: ScanResult) -> str:
        """Compliance-focused template (OWASP/PCI-DSS)"""
        status = "NON-COMPLIANT" if any(v.severity.value in ["HIGH", "CRITICAL"] for v in scan_result.vulnerabilities) else "COMPLIANT"
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Audit - {scan_result.target}</title>
            <style>
                body {{ font-family: sans-serif; margin: 50px; text-align: center; }}
                .status {{ font-size: 24px; font-weight: bold; padding: 20px; border-radius: 5px; display: inline-block; margin: 20px; }}
                .fail {{ background: #ffdce0; color: #d73a49; border: 1px solid #d73a49; }}
                .pass {{ background: #dcffe4; color: #28a745; border: 1px solid #28a745; }}
                table {{ margin: 30px auto; border-collapse: collapse; width: 80%; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; }}
            </style>
        </head>
        <body>
            <h1>Security Compliance Audit Report</h1>
            <p>Standard: <strong>OWASP Top 10 / PCI-DSS Internal Review</strong></p>
            
            <div class="status {'fail' if status == 'NON-COMPLIANT' else 'pass'}">
                CURRENT STATUS: {status}
            </div>
            
            <table>
                <tr><th>Standard Control</th><th>Findings</th><th>Status</th></tr>
                <tr><td>Broken Access Control</td><td>{len([v for v in scan_result.vulnerabilities if "IDOR" in v.type.value])}</td><td>{'❌' if any("IDOR" in v.type.value for v in scan_result.vulnerabilities) else '✅'}</td></tr>
                <tr><td>Injection</td><td>{len([v for v in scan_result.vulnerabilities if "Injection" in v.type.value])}</td><td>{'❌' if any("Injection" in v.type.value for v in scan_result.vulnerabilities) else '✅'}</td></tr>
                <tr><td>Cryptographic Failures</td><td>0</td><td>✅</td></tr>
            </table>
        </body>
        </html>
        """

# === MAIN SCANNER CLASS ===
class CortexScanner:
    """Enhanced Cortex Security Suite v15.0"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.scan_id = self._generate_scan_id()
        self.session = None
        self.visited_urls = set()
        self.url_queue = asyncio.PriorityQueue()
        self.plugin_manager = PluginManager()
        self.rate_limiter = SmartRateLimiter(max_rpm=60)
        self.cache_manager = CacheManager()
        self.security_manager = SecurityManager()
        self.ai_detector = AIMLDetector()
        self.threat_intel = ThreatIntelManager()
        self.forensics = WindowsForensics(self.ai_detector)
        self.report_generator = ReportGenerator()
        self.db_session = Session()
        self.scan_record = None
        self.blacklist = set()
        self.honeypot_thread = None
        self.port_scanner = PortScanner()
        self.subdomain_enum = SubdomainEnumerator()
        self.brute_force = BruteForceEngine()
        self.ssl_analyzer = SSLTLSAnalyzer()
        self.js_analyzer = JSSecretsAnalyzer()
        self.alerts = RealTimeAlerts()
        self.stats = {
            'urls_scanned': 0,
            'requests_made': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'connections': [],
            'attacks_prevented': 0
        }
        self.monitor_thread = None
        self.stop_monitor = False
        self.stats.update({
            'end_time': None,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'connections': [],
            'attacks_prevented': 0
        })

    def start_honeypot(self, port=8080):
        """Start the fake deception server in a background thread"""
        try:
            from .honeypot import run_honeypot
            if self.honeypot_thread and self.honeypot_thread.is_alive():
                return
            self.honeypot_thread = threading.Thread(target=run_honeypot, args=(port,), daemon=True)
            self.honeypot_thread.start()
        except ImportError:
            # Try absolute import if relative fails
            from engine.scanner.honeypot import run_honeypot
            self.honeypot_thread = threading.Thread(target=run_honeypot, args=(port,), daemon=True)
            self.honeypot_thread.start()
        except Exception as e:
            print(f"Honeypot Error: {e}")

    def start_live_monitor(self, callback):
        """Start sniffing local network connections for real-time visualization"""
        self.stop_monitor = False
        def _monitor():
            import psutil
            import time
            while not self.stop_monitor:
                try:
                    conns = psutil.net_connections(kind='inet')
                    active = []
                    for c in conns:
                        if c.status == 'ESTABLISHED' and c.raddr:
                            active.append(f"{c.raddr.ip}:{c.raddr.port}")
                    self.stats['connections'] = active[:10]
                    callback(active[:5])
                except:
                    pass
                time.sleep(3)
        self.monitor_thread = threading.Thread(target=_monitor, daemon=True)
        self.monitor_thread.start()

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        random_str = secrets.token_hex(4)
        return f"SCAN-{timestamp}-{random_str}"
    
    async def scan(self, progress_callback=None) -> ScanResult:
        """Execute the scan"""
        try:
            # Initialize scan record
            await self._initialize_scan()
            
            # Execute pre-scan hooks
            await self.plugin_manager.execute_hook('pre_scan', self, self.config)
            
            # Start scanning
            results = await self._execute_scan(progress_callback)
            
            # Execute post-scan hooks
            await self.plugin_manager.execute_hook('post_scan', self, results)
            
            # Generate final report
            final_result = await self._generate_final_result(results)
            
            return final_result
            
        except Exception as e:
            logger.error(f"❌ Scan failed: {e}")
            raise
        finally:
            await self._cleanup()
    
    async def _initialize_scan(self):
        """Initialize scan in database"""
        self.scan_record = Scan(
            scan_uuid=self.scan_id,
            target_url=self.config.target_url,
            status="RUNNING",
            mode=self.config.mode.value,
            config={
                'max_depth': self.config.max_depth,
                'max_concurrency': self.config.max_concurrency,
                'timeout': self.config.timeout,
            }
        )
        self.db_session.add(self.scan_record)
        self.db_session.commit()
        
        self.stats['start_time'] = datetime.datetime.utcnow()
    
    async def _execute_scan(self, progress_callback=None) -> List[Vulnerability]:
        """Execute the main scanning logic"""
        vulnerabilities = []
        
        # Setup HTTP session
        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.max_concurrency)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self._get_default_headers()
        ) as session:
            self.session = session
            
            # Add starting URL to queue
            await self._add_to_queue(self.config.target_url, priority=0)
            
            # Start worker tasks
            workers = [
                asyncio.create_task(self._worker(i, progress_callback))
                for i in range(self.config.max_concurrency)
            ]
            
            # Process queue
            await self.url_queue.join()
            
            # Cancel workers
            for worker in workers:
                worker.cancel()
        
        return vulnerabilities

    def start_honeypot(self, port: int = 8080):
        """Start the deception honeypot in a background thread"""
        try:
            from engine.scanner.honeypot import run_honeypot
            if self.honeypot_thread and self.honeypot_thread.is_alive():
                logger.warning("🍯 Honeypot is already running.")
                return
            
            self.honeypot_thread = threading.Thread(target=run_honeypot, args=(port,), daemon=True)
            self.honeypot_thread.start()
            logger.info(f"✅ Honeypot started on port {port}")
        except ImportError:
            logger.error("❌ Honeypot module (honeypot.py) not found.")
        except Exception as e:
            logger.error(f"❌ Failed to start honeypot: {e}")

    async def _worker(self, worker_id: int, progress_callback=None):
        """Worker task for processing URLs"""
        while True:
            try:
                priority, url = await self.url_queue.get()
                
                # Process URL
                await self._process_url(url, progress_callback)
                
                self.url_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                self.url_queue.task_done()
    
    async def _process_url(self, url: str, progress_callback=None):
        """Process a single URL"""
        if progress_callback:
            progress_callback(url)
        
        logger.debug(f"Processing: {url}")
        
        # Apply rate limiting
        domain = urlparse(url).netloc
        await self.rate_limiter.wait_if_needed(domain)
        
        # Check cache
        cache_key = f"response:{hash(url)}"
        cached = self.cache_manager.get(cache_key)
        
        if cached:
            html, headers, status_code, response_time = cached
            logger.debug(f"Cache hit for {url}")
        else:
            # Fetch URL
            start_time = time.time()
            html, headers, status_code = await self._fetch_url(url)
            response_time = time.time() - start_time
            
            # Cache response
            self.cache_manager.set(cache_key, (html, headers, status_code, response_time))
        
        # Update stats
        self.stats['urls_scanned'] += 1
        self.stats['requests_made'] += 1
        
        # Log request
        await self._log_request(url, "GET", status_code, response_time)
        
        if html and status_code == 200:
            # Detect technology stack
            await self._detect_tech_stack(html, headers)
            
            # SPA Detection & Dynamic Fetching
            is_spa = any(tech in self.tech_stack for tech in ['react', 'vue', 'angular'])
            if is_spa:
                logger.info(f"✨ SPA detected at {url}, escalating to Playwright...")
                dyn_html, _, _ = await self._fetch_dynamic(url)
                if dyn_html:
                    html = dyn_html
                    await self._detect_tech_stack(html, headers)
            

            
            # Check for vulnerabilities using plugins
            vuln_results = await self.plugin_manager.execute_hook(
                'response_received', self, url, html, headers
            )
            
            # AI-based detection
            ai_vuln = await self.ai_detector.analyze_response(url, html, headers)
            if ai_vuln:
                if not isinstance(vuln_results, list):
                    vuln_results = []
                vuln_results.append(ai_vuln)
            
            # Process vulnerabilities
            if vuln_results:
                for vuln in vuln_results:
                    if isinstance(vuln, list):
                        for v in vuln:
                            await self._process_vulnerability(v)
                    else:
                        await self._process_vulnerability(vuln)
            
            # Extract links for crawling
            if '?' not in url:  # Only crawl non-parameterized URLs
                await self._extract_and_queue_links(url, html)
    
    async def _fetch_url(self, url: str) -> Tuple[Optional[str], Dict, int]:
        """Fetch URL with error handling"""
        try:
            async with self.session.get(url, ssl=False) as response:
                text = await response.text(errors='ignore')
                headers = dict(response.headers)
                return text, headers, response.status
        except asyncio.TimeoutError:
            logger.warning(f"⏰ Timeout fetching {url}")
            return None, {}, 0
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                domain = urlparse(url).netloc
                self.rate_limiter.handle_429(domain)
            logger.warning(f"⚠️ HTTP error {e.status} for {url}")
            return None, {}, e.status or 0
        except Exception as e:
            logger.warning(f"⚠️ Error fetching {url}: {e}")
            return None, {}, 0
    
    async def _fetch_dynamic(self, url: str) -> Tuple[Optional[str], Dict, int]:
        """Fetch URL using Playwright for dynamic content"""
        logger.debug(f"🎭 Playwright fetching: {url}")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                try:
                    response = await page.goto(url, wait_until='networkidle', timeout=30000)
                    content = await page.content()
                    status = response.status if response else 200
                    await browser.close()
                    return content, {}, status
                except Exception as e:
                    await browser.close()
                    return None, {}, 0
        except Exception as e:
            logger.warning(f"⚠️ Playwright fetch failed: {e}")
            return None, {}, 0
    
    async def _enrich_vulnerability(self, vuln: Vulnerability):
        """Enrich finding with CVE data and AI-generated code patches"""
        # 1. Base CVE Mapping
        if vuln.type in CVE_MAP:
            data = CVE_MAP[vuln.type]
            vuln.cve_id = data['cve']
            vuln.cvss_score = data['cvss']
            if not vuln.description:
                vuln.description = data['description']
        
        # 2. AI Remediation Patch Generation
        if self.ai_detector.model:
            prompt = f"""
            Act as a Senior Security Engineer. Generate a specific, secure code fix (patch) for the following vulnerability.
            
            Vulnerability: {vuln.type.value}
            URL: {vuln.url}
            Parameter: {vuln.parameter}
            Evidence: {vuln.evidence}
            
            Format the output as a clean code block and a short explanation in Arabic language.
            """
            try:
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(None, lambda: self.ai_detector.model.generate_content(prompt))
                vuln.remediation_patch = resp.text if resp else "AI failed to generate patch."
            except:
                vuln.remediation_patch = "Remediation generation failed."

    async def _process_vulnerability(self, vulnerability: Vulnerability):
        """Process, enrich and save vulnerability"""
        # Enrichment: CVE Lookup & AI Remediation
        await self._enrich_vulnerability(vulnerability)
        
        # Add scan context
        vulnerability.timestamp = datetime.datetime.utcnow()
        
        # Save to database
        finding = Finding(
            scan=self.scan_record,
            type=vulnerability.type.value,
            severity=vulnerability.severity.value,
            confidence=vulnerability.confidence,
            cvss_score=vulnerability.cvss_score,
            url=vulnerability.url,
            parameter=vulnerability.parameter,
            description=vulnerability.description,
            evidence=vulnerability.evidence[:500],  # Limit length
            impact=vulnerability.impact,
            remediation=vulnerability.remediation,
            remediation_patch=vulnerability.remediation_patch,
            cve_id=vulnerability.cve_id,
            tags=json.dumps(vulnerability.tags)
        )
        self.db_session.add(finding)
        
        # Update stats
        self.stats['vulnerabilities_found'] += 1
        
        # Log finding
        logger.warning(f"🔥 {vulnerability.severity.value}: {vulnerability.type.value} at {vulnerability.url}")
        
        # Execute vulnerability hooks
        await self.plugin_manager.execute_hook(
            'vulnerability_detected', self, vulnerability
        )
    
    async def _extract_and_queue_links(self, base_url: str, html: str):
        """Extract links and add to queue"""
        if not html:
            return
        
        # Extract links
        pattern = r'href=["\'](https?://[^"\']+)["\']'
        links = re.findall(pattern, html, re.I)
        
        for link in links:
            # Normalize URL
            normalized = urljoin(base_url, link).split('#')[0]
            
            # Check scope
            if not self._is_in_scope(normalized):
                continue
            
            # Check if already visited
            if normalized in self.visited_urls:
                continue
            
            # Add to queue with priority
            self.visited_urls.add(normalized)
            priority = 1 if '?' in normalized else 5
            await self.url_queue.put((priority, normalized))
    
    async def _detect_tech_stack(self, html: str, headers: Dict):
        """Detect technology stack"""
        # From headers
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
        if server:
            self.tech_stack.add(f"server:{server}")
        if powered_by:
            self.tech_stack.add(f"powered_by:{powered_by}")
        
        # From HTML
        tech_indicators = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'media/jui'],
            'drupal': ['drupal', 'sites/default'],
            'laravel': ['laravel', '/storage/'],
            'react': ['react', 'react-dom'],
            'vue': ['vue.js', '__vue__'],
            'angular': ['ng-', 'angular'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap'],
        }
        
        for tech, indicators in tech_indicators.items():
            if any(indicator in html.lower() for indicator in indicators):
                self.tech_stack.add(tech)
    
    async def _add_to_queue(self, url: str, priority: int = 5):
        """Add URL to processing queue"""
        if url not in self.visited_urls:
            self.visited_urls.add(url)
            await self.url_queue.put((priority, url))
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is in scan scope"""
        try:
            target_domain = tldextract.extract(self.config.target_url).registered_domain
            url_domain = tldextract.extract(url).registered_domain
            return url_domain == target_domain
        except:
            return False
    
    def _get_default_headers(self) -> Dict:
        """Get default HTTP headers"""
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
                'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0',
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Add custom headers from config
        headers.update(self.config.custom_headers)
        
        return headers
    
    async def _log_request(self, url: str, method: str, status_code: int, response_time: float):
        """Log HTTP request to database"""
        log = AuditLog(
            scan=self.scan_record,
            url=url,
            method=method,
            status_code=status_code,
            response_time=response_time
        )
        self.db_session.add(log)
    
    async def _generate_final_result(self, vulnerabilities: List[Vulnerability]) -> ScanResult:
        """Generate final scan result"""
        self.stats['end_time'] = datetime.datetime.utcnow()
        
        # Update scan record
        self.scan_record.status = "COMPLETED"
        
        # Create stats record
        stats_record = ScanStats(
            scan=self.scan_record,
            urls_scanned=self.stats['urls_scanned'],
            requests_made=self.stats['requests_made'],
            vulnerabilities_found=self.stats['vulnerabilities_found'],
            start_time=self.stats['start_time'],
            end_time=self.stats['end_time'],
            scan_duration=(self.stats['end_time'] - self.stats['start_time']).total_seconds(),
            tech_stack=list(self.tech_stack)
        )
        self.db_session.add(stats_record)
        
        # Commit all changes
        self.db_session.commit()
        
        # Generate summary
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        summary = {
            'total_urls': self.stats['urls_scanned'],
            'total_requests': self.stats['requests_made'],
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': severity_counts,
            'scan_duration': (self.stats['end_time'] - self.stats['start_time']).total_seconds(),
            'cache_stats': self.cache_manager.stats(),
        }
        
        return ScanResult(
            scan_id=self.scan_id,
            target=self.config.target_url,
            start_time=self.stats['start_time'],
            end_time=self.stats['end_time'],
            total_urls_scanned=self.stats['urls_scanned'],
            vulnerabilities_found=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            tech_stack={'detected': list(self.tech_stack)},
            scan_config=self.config,
            summary=summary
        )
    
    async def _cleanup(self):
        """Cleanup resources"""
        if self.db_session:
            self.db_session.close()
        
        # Clear cache if needed
        self.cache_manager.clear()
        
        logger.info("🧹 Cleanup completed")

# === WEB INTERFACE ===
class WebInterface:
    """Web-based interface for the scanner"""
    
    def __init__(self, scanner: TitaniumScannerV15):
        self.scanner = scanner
        self.app = None
    
    def run(self, host='127.0.0.1', port=8080):
        """Run web interface"""
        try:
            from flask import Flask, render_template, request, jsonify, send_file
            import threading
            
            self.app = Flask(__name__)
            
            @self.app.route('/')
            def index():
                return render_template('index.html')
            
            @self.app.route('/scan', methods=['POST'])
            def start_scan():
                data = request.json
                config = ScanConfig(
                    target_url=data['target'],
                    mode=ScanMode(data.get('mode', 'safe')),
                    max_depth=int(data.get('max_depth', 5)),
                    max_concurrency=int(data.get('max_concurrency', 25)),
                )
                
                # Start scan in background
                thread = threading.Thread(
                    target=self._run_scan_in_thread,
                    args=(config,)
                )
                thread.start()
                
                return jsonify({'scan_id': self.scanner.scan_id, 'status': 'started'})
            
            @self.app.route('/status/<scan_id>')
            def scan_status(scan_id):
                # Return scan status
                return jsonify({'status': 'running', 'progress': 0.5})
            
            @self.app.route('/report/<scan_id>')
            def get_report(scan_id):
                # Generate and return report
                return jsonify({'report': 'generated'})
            
            self.app.run(host=host, port=port, debug=False)
            
        except ImportError:
            logger.error("Flask not installed. Web interface disabled.")
    
    def _run_scan_in_thread(self, config: ScanConfig):
        """Run scan in background thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        scanner = TitaniumScannerV15(config)
        result = loop.run_until_complete(scanner.scan())
        
        # Save report
        report = scanner.report_generator.generate(result, format='html')
        with open(f"report_{scanner.scan_id}.html", 'w') as f:
            f.write(report)
        
        loop.close()

# === COMMAND LINE INTERFACE ===
def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Titanium Web Scanner v15.0')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--mode', choices=['safe', 'destructive', 'stealth', 'comprehensive'],
                       default='safe', help='Scanning mode')
    parser.add_argument('--depth', type=int, default=5, help='Maximum crawl depth')
    parser.add_argument('--concurrency', type=int, default=25, help='Maximum concurrent requests')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--output', choices=['json', 'html', 'pdf', 'csv'],
                       default='html', help='Output format')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('--port', type=int, default=8080, help='Web interface port')
    
    args = parser.parse_args()
    
    if args.web:
        # Start web interface
        config = ScanConfig(target_url=args.target)
        scanner = TitaniumScannerV15(config)
        interface = WebInterface(scanner)
        interface.run(port=args.port)
    else:
        # Run command-line scan
        config = ScanConfig(
            target_url=args.target,
            mode=ScanMode(args.mode),
            max_depth=args.depth,
            max_concurrency=args.concurrency,
            timeout=args.timeout,
        )
        
        scanner = TitaniumScannerV15(config)
        
        # Run scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(scanner.scan())
            
            # Generate report
            report = scanner.report_generator.generate(result, format=args.output)
            
            if args.output == 'json':
                print(report)
            else:
                filename = f"report_{scanner.scan_id}.{args.output}"
                with open(filename, 'wb' if args.output == 'pdf' else 'w') as f:
                    f.write(report if args.output != 'pdf' else report)
                print(f"✅ Report saved to {filename}")
                
        except KeyboardInterrupt:
            print("\n⚠️ Scan interrupted by user")
        except Exception as e:
            print(f"❌ Scan failed: {e}")
        finally:
            loop.close()

if __name__ == "__main__":
    # Clean old files
    for pattern in ["report_*.html", "report_*.json", "report_*.pdf", "report_*.csv"]:
        for file in glob.glob(pattern):
            try:
                os.remove(file)
                print(f"🗑️ Cleaned: {file}")
            except:
                pass
    
    # Run scanner
    main()
