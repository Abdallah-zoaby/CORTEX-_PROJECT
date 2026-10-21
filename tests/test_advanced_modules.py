"""Advanced-module regressions use fixtures, loopback servers and mocked capture only."""
import base64
from contextlib import closing
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.analytics import AnalyticsState
from core.behavioral import SIEMReporter
from core.twin import app, DigitalTwinTarget
from engine.scanner.api_audit import APIAuditor
from engine.scanner.mobile import MobileAPKAuditor
from engine.scanner.network_sniffer import NetworkAnomalyDetector
from engine.simulation.purple_controller import PurpleController


XML = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.CAMERA"/><application android:debuggable="true"/></manifest>'


class AdvancedModuleTests(unittest.TestCase):
    def test_manifest_reads_actual_input_and_no_invented_permissions(self):
        records = MobileAPKAuditor().audit_input(XML)
        self.assertEqual([r['item'] for r in records], ['android.permission.CAMERA', 'debuggable'])
        self.assertTrue(all(r['severity'] == 'INFO' for r in records))
        self.assertEqual(MobileAPKAuditor().audit_input('<manifest/>'), [])

    def test_manifest_file_and_text_apk(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'AndroidManifest.xml'
            path.write_text(XML, encoding='utf-8')
            apk = Path(folder) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('AndroidManifest.xml', XML)
            auditor = MobileAPKAuditor()
            self.assertEqual(auditor.audit_input(str(path)), auditor.audit_input(str(apk)))

    def test_manifest_invalid_binary_missing_and_oversized_are_not_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = Path(folder) / 'binary.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00')
            with self.assertRaisesRegex(ValueError, 'Binary'):
                MobileAPKAuditor().audit_input(str(apk))
            for value in ('', str(Path(folder) / 'missing.xml'), '<notmanifest/>',
                          '<!DOCTYPE manifest><manifest/>'):
                with self.assertRaises(ValueError):
                    MobileAPKAuditor().audit_input(value)
            auditor = MobileAPKAuditor()
            auditor.MAX_BYTES = 16
            with self.assertRaises(ValueError):
                auditor.audit_input(XML)

    def test_secret_candidate_never_exposes_literal(self):
        findings = MobileAPKAuditor().find_secrets("password = 'private-test-value'")
        self.assertEqual(len(findings), 1)
        self.assertNotIn('private-test-value', json.dumps(findings))

    def test_api_200_and_redirect_are_observations_no_post_or_redirect_follow(self):
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302 if self.path.endswith('/0') else 200)
                self.send_header('Location', '/must-not-follow')
                self.end_headers()
            def do_POST(self):
                hits.append('POST')
                self.send_response(500)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings = APIAuditor(f'http://127.0.0.1:{server.server_port}').audit_full()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.assertEqual(hits, ['/api/config', '/api/user/0'])
        self.assertEqual([f['status_code'] for f in findings], [200, 302])
        self.assertTrue(all(f['classification'] == 'observation' and f['severity'] == 'INFO' for f in findings))

    def test_api_transport_failure_is_unknown(self):
        import requests
        with patch('engine.scanner.api_audit.requests.get', side_effect=requests.Timeout):
            findings = APIAuditor('http://127.0.0.1:1').audit_full()
        self.assertEqual([f['classification'] for f in findings], ['unknown', 'unknown'])

    def test_api_url_validation(self):
        for url in ('', 'file:///x', 'http://user:password@localhost', 'https://localhost:bad', 'http://localhost?q=1'):
            with self.assertRaises(ValueError):
                APIAuditor(url)

    def test_jwt_header_is_not_proof_of_server_acceptance(self):
        auditor = APIAuditor('http://localhost')
        for algorithm in ('none', 'HS256'):
            header = base64.urlsafe_b64encode(json.dumps({'alg': algorithm}).encode()).decode().rstrip('=')
            finding = auditor.test_jwt_weak_signature(header + '.e30.')
            self.assertEqual(finding['classification'], 'observation')
            self.assertEqual(finding['severity'], 'INFO')
        self.assertEqual(auditor.test_jwt_weak_signature('invalid')['classification'], 'unknown')

    def test_capture_missing_backend_generates_no_simulation(self):
        detector = NetworkAnomalyDetector()
        detector.scapy_available = False
        callback = Mock()
        self.assertFalse(detector.start_sniffing(callback))
        self.assertFalse(detector.is_sniffing)
        self.assertEqual(callback.call_count, 1)
        self.assertIn('unavailable', callback.call_args.args[0])

    def test_capture_error_stops_and_notifies(self):
        detector = NetworkAnomalyDetector()
        detector.scapy_available = True
        detector._sniff = Mock(side_effect=OSError('fixture'))
        stopped = threading.Event()
        callback = Mock()
        self.assertTrue(detector.start_sniffing(callback, stopped.set))
        self.assertTrue(stopped.wait(2))
        detector._thread.join(2)
        self.assertFalse(detector.is_sniffing)
        self.assertIn('Capture failed', callback.call_args.args[0])

    def test_capture_stop_without_packets_and_no_concurrent_restart(self):
        detector = NetworkAnomalyDetector()
        detector.scapy_available = True
        entered = threading.Event()
        release = threading.Event()
        def capture(**kwargs):
            entered.set()
            release.wait(2)
        detector._sniff = capture
        self.assertTrue(detector.start_sniffing(Mock()))
        self.assertTrue(entered.wait(2))
        detector.stop_sniffing()
        self.assertFalse(detector.start_sniffing(Mock()))
        release.set()
        detector._thread.join(2)
        self.assertFalse(detector.is_sniffing)

    def test_packet_keyword_is_not_a_critical_threat(self):
        detector = NetworkAnomalyDetector()
        detector.scapy_available = True
        def capture(**kwargs):
            kwargs['prn'](Mock(summary=lambda: 'TCP SELECT benign test'))
            detector.stop_sniffing()
        detector._sniff = capture
        callback = Mock()
        detector.start_sniffing(callback)
        detector._thread.join(2)
        self.assertEqual(callback.call_args.args[1], 'INFO')

    def test_purple_repeat_resets_and_labels_synthetic_events(self):
        controller = PurpleController()
        with patch('engine.simulation.purple_controller.time.sleep'), patch.object(controller, 'export_logs'):
            first = controller.run_simulation()
            score = controller.risk_score
            second = controller.run_simulation()
        self.assertEqual(len(first), len(second))
        self.assertEqual(score, controller.risk_score)
        self.assertTrue(all(e['classification'] == 'simulation' for e in second))
        self.assertIn('no endpoint isolated', next(e['details'] for e in second if e['action'] == 'RESPONSE'))

    def test_twin_missing_credentials_do_not_log_in(self):
        client = app.test_client()
        self.assertEqual(client.post('/login').status_code, 401)
        self.assertEqual(client.post('/login', data={'username': 'missing'}).status_code, 401)
        self.assertEqual(client.post('/login', data={'username': 'admin', 'password': 'password123'}).status_code, 200)
        self.assertNotIn('CVE-', str(client.get('/').headers))

    def test_twin_port_conflict_is_reported(self):
        target = DigitalTwinTarget()
        with patch('werkzeug.serving.make_server', side_effect=SystemExit(1)):
            with self.assertRaisesRegex(RuntimeError, '5555'):
                target.start()
        self.assertIsNone(target.thread)

    def test_siem_preserves_sources_and_counts_observations_separately(self):
        rows = [dict(type='Process', classification='observation', severity='HIGH', command_line='private command'),
                dict(type='Defender detection', classification='engine_detection', activity='active', severity='HIGH'),
                dict(type='Unknown file', classification='unknown', severity='INFO'),
                dict(type='Training', classification='simulation', severity='CRITICAL')]
        report = json.loads(SIEMReporter.generate_json_report(rows, {'coverage': {'host': 'partial'}}))
        self.assertEqual(report['summary']['active_engine'], 1)
        self.assertEqual(report['summary']['observations'], 1)
        self.assertEqual(report['summary']['unknown'], 1)
        self.assertNotIn('total_threats', report['summary'])
        self.assertIsNone(report['summary']['posture_index'])
        self.assertNotIn('private command', json.dumps(report))
        self.assertEqual(rows[0]['command_line'], 'private command')

    def test_partial_sources_never_show_perfect_overall_score(self):
        state = AnalyticsState()
        state.replace('web', [])
        state.replace('system', [], assessed=False)
        self.assertIsNone(state.snapshot()['posture'])
        state.replace('system', [])
        self.assertEqual(state.snapshot()['posture'], 100)
        state.replace('training', [dict(type='demo', classification='simulation', severity='CRITICAL')])
        self.assertEqual(state.snapshot()['risk'], 0)

    def test_wifi_compatibility_hook_never_reads_credentials(self):
        from core.network import audit_wifi_security
        with patch('subprocess.check_output') as query:
            findings = audit_wifi_security()
        query.assert_not_called()
        self.assertEqual(findings[0]['classification'], 'unknown')

    def test_old_database_upgrades_with_backup_and_retains_history(self):
        from sqlalchemy import create_engine, inspect
        from engine.scanner.data.migrations import upgrade_legacy_schema
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'old.db'
            engine = create_engine('sqlite:///' + str(path))
            try:
                with engine.begin() as connection:
                    connection.exec_driver_sql('CREATE TABLE findings (id INTEGER PRIMARY KEY, description TEXT)')
                    connection.exec_driver_sql("INSERT INTO findings VALUES (1, 'existing fixture history')")
                    connection.exec_driver_sql('CREATE TABLE exploit_logs (id INTEGER PRIMARY KEY)')
                backup = upgrade_legacy_schema(engine)
                self.assertTrue(backup.is_file())
                self.assertIn('remediation_patch', {c['name'] for c in inspect(engine).get_columns('findings')})
                with engine.connect() as connection:
                    self.assertEqual(connection.exec_driver_sql('SELECT description FROM findings').scalar(), 'existing fixture history')
                with closing(sqlite3.connect(backup)) as connection:
                    self.assertEqual(connection.execute('SELECT description FROM findings').fetchone()[0], 'existing fixture history')
                    self.assertNotIn('remediation_patch', {r[1] for r in connection.execute('PRAGMA table_info(findings)')})
                self.assertIsNone(upgrade_legacy_schema(engine))
            finally:
                engine.dispose()

    def test_backup_failure_does_not_change_old_database(self):
        from sqlalchemy import create_engine, inspect
        from engine.scanner.data.migrations import upgrade_legacy_schema
        with tempfile.TemporaryDirectory() as folder:
            engine = create_engine('sqlite:///' + str(Path(folder) / 'old.db'))
            try:
                with engine.begin() as connection:
                    connection.exec_driver_sql('CREATE TABLE findings (id INTEGER PRIMARY KEY)')
                with patch('engine.scanner.data.migrations.sqlite3.connect', side_effect=OSError('fixture')):
                    with self.assertRaises(OSError):
                        upgrade_legacy_schema(engine)
                self.assertNotIn('remediation_patch', {c['name'] for c in inspect(engine).get_columns('findings')})
            finally:
                engine.dispose()

    def test_task_query_is_bounded_and_failure_propagates(self):
        from core.system import scan_scheduled_tasks
        import subprocess
        with patch('core.system.subprocess.check_output', side_effect=subprocess.TimeoutExpired('schtasks', 20)) as query:
            with self.assertRaises(subprocess.TimeoutExpired):
                scan_scheduled_tasks()
        self.assertEqual(query.call_args.kwargs['timeout'], 20)
        self.assertNotIn('shell', query.call_args.kwargs)

    def test_twin_starts_on_loopback_and_can_restart_after_stop(self):
        import requests
        target = DigitalTwinTarget(port=0)
        try:
            url = target.start()
            first_thread = target.thread
            self.assertEqual(target.start(), url)
            self.assertIs(target.thread, first_thread)
            self.assertEqual(requests.get(url, timeout=2).status_code, 200)
            target.stop()
            target.port = 0
            self.assertEqual(requests.get(target.start(), timeout=2).status_code, 200)
        finally:
            target.stop()

