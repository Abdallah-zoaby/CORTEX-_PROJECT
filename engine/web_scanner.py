
import asyncio
import logging
from typing import Dict, List, Any
from .scanner.main import TitaniumScannerV15
from .scanner.data.types import ScanConfig, ScanMode, SeverityLevel

class WebScanner:
    """
    Adapter class for Titanium Scanner V15 to be compatible with legacy GUI.
    """
    def __init__(self):
        self.findings = []
        
    def scan_target(self, url: str, callback: callable, mode: str = "SAFE") -> List[Dict[str, Any]]:
        """
        Run the scanner and return results as a list of dictionaries.
        """
        # Configure logging to use the callback
        logger = logging.getLogger("TitaniumScanner")
        logger.setLevel(logging.INFO)
        
        # Remove old handlers
        for h in logger.handlers:
            logger.removeHandler(h)
            
        class CallbackHandler(logging.Handler):
            def emit(self, record):
                level_map = {
                    'INFO': 'INFO',
                    'WARNING': 'HIGH',
                    'ERROR': 'CRITICAL',
                    'CRITICAL': 'CRITICAL',
                    'DEBUG': 'LOW'
                }
                lvl = level_map.get(record.levelname, 'INFO')
                callback(record.getMessage(), lvl)
                
        handler = CallbackHandler()
        logger.addHandler(handler)
        
        # Map mode string to Enum
        mode_enum = ScanMode.SAFE
        if mode.upper() == "DESTRUCTIVE":
            mode_enum = ScanMode.DESTRUCTIVE
        elif mode.upper() == "NORMAL":
            mode_enum = ScanMode.COMPREHENSIVE
            
        # Create Config
        config = ScanConfig(
            target_url=url,
            mode=mode_enum,
            max_concurrency=10, # Reduce for GUI stability
            timeout=20
        )
        
        # Run Scanner
        try:
            callback(f"🚀 Initializing Titanium V15 Engine ({mode})...", "INFO")
            scanner = TitaniumScannerV15(config)
            
            # Run async scan synchronously
            result = asyncio.run(scanner.scan())
            
            # Process results
            findings_list = []
            if result and result.vulnerabilities:
                for v in result.vulnerabilities:
                    findings_list.append({
                        'type': "Vulnerability", # Simplified
                        'severity': v.severity.value,
                        'url': v.url,
                        'desc': v.description,
                        'evidence': v.evidence
                    })
                    
            callback(f"✅ Scan Complete. Found {len(findings_list)} issues.", "SUCCESS")
            return findings_list
            
        except Exception as e:
            callback(f"❌ Scan Error: {e}", "CRITICAL")
            return []