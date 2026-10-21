
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import datetime
import logging
from ..config import CONFIG

logger = logging.getLogger("TitaniumScanner")

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
    remediation_patch = Column(Text)
    cve_id = Column(String)
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
    scan_id = Column(Integer)  # Optional linking
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
        from .migrations import upgrade_legacy_schema
        upgrade_legacy_schema(engine)
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
