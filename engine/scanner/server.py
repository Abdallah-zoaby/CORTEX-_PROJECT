
import logging
import asyncio
import threading
from typing import Optional
from .main import TitaniumScannerV15
from .data.types import ScanConfig, ScanMode

logger = logging.getLogger("TitaniumScanner")

class WebInterface:
    """Web-based interface for the scanner"""
    
    def __init__(self, scanner: TitaniumScannerV15):
        self.scanner = scanner
        self.app = None
    
    def run(self, host='127.0.0.1', port=8080):
        """Run web interface"""
        try:
            from flask import Flask, render_template, request, jsonify, send_file
            
            self.app = Flask(__name__)
            
            @self.app.route('/')
            def index():
                return "Titanium Scanner V15 API is Running" # Simplified for now
            
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
            print("❌ Flask not installed. Install with: pip install flask")
    
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
