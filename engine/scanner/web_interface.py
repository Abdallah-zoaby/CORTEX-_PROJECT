"""Shared HTTP job tracking; scanner dependencies are supplied by callers."""
import asyncio
import logging
from pathlib import Path
import threading
from urllib.parse import urlsplit
import uuid

logger = logging.getLogger("TitaniumScanner")


class ScannerWebInterface:
    def __init__(self, scanner, scanner_factory, config_factory, mode_factory):
        self.scanner = scanner
        self.app = None
        self._scanner_factory = scanner_factory
        self._config_factory = config_factory
        self._mode_factory = mode_factory
        self._jobs = {}
        self._lock = threading.Lock()

    def create_app(self):
        from flask import Flask, jsonify, request, Response

        if self.app is not None:
            return self.app
        app = self.app = Flask(__name__)

        @app.get('/')
        def index():
            return "Titanium Scanner V15 API is Running"

        @app.post('/scan')
        def start_scan():
            data = request.get_json(silent=True)
            try:
                if not isinstance(data, dict):
                    raise ValueError()
                target = data.get('target')
                if not isinstance(target, str):
                    raise ValueError()
                parsed = urlsplit(target)
                if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                    raise ValueError()
                parsed.port  # Validate malformed port values too.
                depth = data.get('max_depth', 5)
                concurrency = data.get('max_concurrency', 25)
                for value in (depth, concurrency):
                    if isinstance(value, bool) or not isinstance(value, (int, str)):
                        raise ValueError()
                depth, concurrency = int(depth), int(concurrency)
                if depth < 0 or concurrency < 1:
                    raise ValueError()
                config = self._config_factory(
                    target_url=target, mode=self._mode_factory(data.get('mode', 'safe')),
                    max_depth=depth, max_concurrency=concurrency,
                )
            except (ValueError, TypeError):
                return jsonify(error='Invalid scan configuration'), 400

            job_id = 'SCAN-' + uuid.uuid4().hex
            with self._lock:
                self._jobs[job_id] = dict(status='queued', progress=0.0, report=None)
            try:
                threading.Thread(target=self._run_scan_in_thread,
                                 args=(config, job_id), daemon=True).start()
            except Exception:
                self._update(job_id, status='failed')
                logger.exception('Could not start scan worker')
                return jsonify(scan_id=job_id, error='Unable to start scan'), 500
            return jsonify(scan_id=job_id, status='started')

        @app.get('/status/<scan_id>')
        def scan_status(scan_id):
            with self._lock:
                job = self._jobs.get(scan_id)
                snapshot = dict(job) if job is not None else None
            if snapshot is None:
                return jsonify(error='Unknown scan'), 404
            return jsonify(status=snapshot['status'], progress=snapshot['progress'])

        @app.get('/report/<scan_id>')
        def get_report(scan_id):
            with self._lock:
                job = self._jobs.get(scan_id)
                snapshot = dict(job) if job is not None else None
            if snapshot is None:
                return jsonify(error='Unknown scan'), 404
            if snapshot['status'] != 'completed':
                return jsonify(status=snapshot['status'], error='Report unavailable'), 409
            return Response(snapshot['report'], mimetype='text/html')

        return app

    def _update(self, job_id, **values):
        with self._lock:
            self._jobs[job_id].update(values)

    def run(self, host='127.0.0.1', port=8080):
        try:
            app = self.create_app()
        except ImportError:
            logger.error('Flask not installed. Web interface disabled.')
            return
        app.run(host=host, port=port, debug=False)

    def _run_scan_in_thread(self, config, job_id):
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._update(job_id, status='running')
            scanner = self._scanner_factory(config)
            result = loop.run_until_complete(scanner.scan())
            report = scanner.report_generator.generate(result, format='html')
            Path(f'report_{job_id}.html').write_text(report, encoding='utf-8')
            self._update(job_id, status='completed', progress=1.0, report=report)
        except Exception:
            logger.exception('Scan job %s failed', job_id)
            self._update(job_id, status='failed')
        finally:
            if loop is not None:
                loop.close()
                asyncio.set_event_loop(None)
