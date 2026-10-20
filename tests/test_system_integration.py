"""Integration checks use temporary databases and loopback HTTP only."""
import asyncio
import importlib
import json
import logging
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch


class SystemIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous = Path.cwd()
        cls.folder = tempfile.TemporaryDirectory(prefix='cortex-integration-')
        os.chdir(cls.folder.name)
        cls.scanner_module = importlib.import_module('engine.scanner.main')
        cls.gui = importlib.import_module('gui_main')

    @classmethod
    def tearDownClass(cls):
        cls.scanner_module.engine.dispose()
        for handler in list(logging.getLogger('TitaniumScanner').handlers):
            if isinstance(handler, logging.FileHandler):
                handler.close()
                logging.getLogger('TitaniumScanner').removeHandler(handler)
        os.chdir(cls.previous)
        cls.folder.cleanup()

    def test_real_scan_retains_findings_and_can_run_twice(self):
        m = self.scanner_module

        async def exercise():
            from aiohttp import web
            app = web.Application()
            async def page(request):
                return web.Response(text='<html>SQL syntax error MySQL</html>', content_type='text/html')
            app.router.add_get('/', page)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            scanner = m.CortexScanner(m.ScanConfig(
                target_url=f'http://127.0.0.1:{port}/', max_concurrency=2))
            scanner.plugin_manager.hooks = {
                'response_received': [m.SQLiPlugin().response_received]}
            scanner.ai_detector.model = None
            try:
                first = await asyncio.wait_for(scanner.scan(), timeout=15)
                second = await asyncio.wait_for(scanner.scan(), timeout=15)
                for result in (first, second):
                    self.assertEqual(result.total_urls_scanned, 1)
                    self.assertEqual(len(result.vulnerabilities), 1)
                    self.assertEqual(result.vulnerabilities_found, 1)
                    self.assertEqual(result.summary['total_vulnerabilities'], 1)
                    self.assertEqual(result.vulnerabilities[0].type, m.VulnerabilityType.SQL_INJECTION)
                    report = json.loads(scanner.report_generator.generate(result, format='json'))
                    self.assertEqual(len(report['vulnerabilities']), 1)
                    self.assertTrue(scanner.report_generator.generate(result, format='pdf').startswith(b'%PDF-'))
                self.assertNotEqual(first.scan_id, second.scan_id)
            finally:
                scanner.db_session.close()
                await runner.cleanup()

        asyncio.run(exercise())

    def test_gui_web_handler_consumes_scan_result(self):
        finding = SimpleNamespace(type='test')
        scanner = SimpleNamespace(config=SimpleNamespace(),
                                  scan=AsyncMock(return_value=SimpleNamespace(vulnerabilities=[finding])))
        ui = Mock()
        ui.scanner = scanner
        ui.after.side_effect = lambda delay, callback: callback()
        self.gui.CortexProApp._run_web_engine(ui, 'http://127.0.0.1', 'SAFE')
        self.assertEqual(ui.web_findings, [finding])
        ui.analyze_web_findings.assert_called_once()
        ui.btn_web_scan.configure.assert_called_with(state='normal', text='🚀 LAUNCH AUDIT')

    def test_web_api_runs_real_worker_and_returns_report(self):
        from engine.scanner.server import WebInterface
        m = self.scanner_module

        async def exercise():
            from aiohttp import web

            async def page(request):
                return web.Response(text='SQL syntax error MySQL', content_type='text/html')

            app = web.Application()
            app.router.add_get('/', page)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            interface = WebInterface(SimpleNamespace(scan_id='unused'))

            def factory(config):
                scanner = m.CortexScanner(config)
                scanner.plugin_manager.hooks = {'response_received': [m.SQLiPlugin().response_received]}
                scanner.ai_detector.model = None
                return scanner

            interface._scanner_factory = factory
            client = interface.create_app().test_client()
            try:
                response = client.post('/scan', json={'target': f'http://127.0.0.1:{port}/'})
                self.assertEqual(response.status_code, 200)
                job_id = response.json['scan_id']
                for _ in range(200):
                    status = client.get('/status/' + job_id).json['status']
                    if status in ('failed', 'completed'):
                        break
                    await asyncio.sleep(0.05)
                self.assertEqual(status, 'completed')
                report = client.get('/report/' + job_id)
                self.assertEqual(report.status_code, 200)
                self.assertIn('SQL Injection', report.get_data(as_text=True))
                self.assertTrue(Path(f'report_{job_id}.html').is_file())
            finally:
                await runner.cleanup()

        asyncio.run(exercise())

    def test_gui_web_failure_restores_button(self):
        ui = Mock()
        ui.scanner = SimpleNamespace(config=SimpleNamespace(), scan=AsyncMock(side_effect=RuntimeError('test')))
        ui.after.side_effect = lambda delay, callback: callback()
        self.gui.CortexProApp._run_web_engine(ui, 'http://127.0.0.1', 'SAFE')
        ui.analyze_web_findings.assert_not_called()
        ui.btn_web_scan.configure.assert_called_with(state='normal', text='🚀 LAUNCH AUDIT')

    def test_full_system_button_uses_system_engine(self):
        ui = Mock()
        result = SimpleNamespace(findings=[])
        ui.system_scanner.run_full_scan.return_value = result
        ui.after.side_effect = lambda delay, callback: callback()
        self.gui.CortexProApp.run_engine(ui)
        ui.system_scanner.run_full_scan.assert_called_once()
        self.assertIs(ui.scan_results, result)
        ui.scanner.scan.assert_not_called()

    def test_both_web_entrypoints_use_shared_implementation(self):
        from engine.scanner.server import WebInterface
        for interface_type in (WebInterface, self.scanner_module.WebInterface):
            interface = interface_type(SimpleNamespace(scan_id='old'))
            client = interface.create_app().test_client()
            self.assertEqual(client.get('/').status_code, 200)
            self.assertEqual(client.post('/scan', json={}).status_code, 400)
            self.assertEqual(client.get('/status/missing').status_code, 404)

    def test_encryption_and_mobile_detection(self):
        from core.behavioral import calculate_entropy
        from engine.scanner.mobile import MobileAPKAuditor
        security = self.scanner_module.SecurityManager()
        encrypted = security.encrypt_sensitive('اختبار CORTEX')
        self.assertEqual(security.decrypt_sensitive(encrypted), 'اختبار CORTEX')
        self.assertEqual(calculate_entropy(b'A' * 100), 0)
        self.assertEqual(len(MobileAPKAuditor().find_secrets("password = 'test-only'")), 1)

    def test_gui_builds_all_tabs_without_background_network(self):
        with patch.object(self.scanner_module.CortexScanner, 'start_live_monitor'), \
                patch.object(self.gui.CortexProApp, 'update_threat_intel'), \
                patch.object(self.gui.CortexProApp, 'run_startup_sequence'):
            app = self.gui.CortexProApp()
            try:
                app.withdraw()
                app.update_idletasks()
                for name in ('tab_scan', 'tab_web', 'tab_analytics', 'tab_recon',
                             'tab_deception', 'tab_forensics', 'tab_ai', 'tab_sim',
                             'tab_enterprise', 'tab_mobile_api'):
                    self.assertTrue(getattr(app, name).winfo_exists())
                app.render_charts()
            finally:
                app.scanner.db_session.close()
                app.destroy()

    def test_pdf_accepts_real_web_findings_and_system_findings(self):
        from reports.pdf_generator import generate_pdf_report
        from engine.scorer import RiskEngine
        m = self.scanner_module
        result = RiskEngine()
        result.add_finding('System test', 'HIGH')
        finding = m.Vulnerability(type=m.VulnerabilityType.XSS,
                                  severity=m.SeverityLevel.HIGH, confidence=0.9,
                                  url='http://127.0.0.1/?x=<test>',
                                  description='Literal <script> and & text', evidence='<script>test</script>')
        for label, findings in [('system', None), ('web', [finding]), ('empty', [])]:
            output = Path(self.folder.name) / f'{label}.pdf'
            generate_pdf_report(result, filename=str(output), web_findings=findings)
            self.assertTrue(output.read_bytes().startswith(b'%PDF-'))

    def test_all_project_modules_import_without_running_actions(self):
        modules = [
            'main', 'check_models', 'engine.cortex', 'engine.web_scanner',
            'core.system', 'core.network', 'core.forensics', 'core.remediation',
            'core.behavioral', 'core.twin', 'simulation.leak', 'simulation.persist',
            'engine.scanner.cli', 'engine.scanner.api_audit', 'engine.scanner.mobile',
            'engine.scanner.network_sniffer', 'engine.scanner.honeypot',
            'engine.scanner.core.ai', 'engine.scanner.core.security',
            'engine.scanner.data.models', 'engine.scanner.data.types',
            'engine.scanner.plugins.manager', 'engine.scanner.utils.report',
            'engine.simulation.attack_engine', 'engine.simulation.attack_graph',
            'engine.simulation.purple_controller', 'engine.simulation.ueba_engine',
            'cortex.backend.proto.cortex_pb2', 'cortex.backend.proto.cortex_pb2_grpc',
        ]
        for name in modules:
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_real_chromium_renders_dynamic_page(self):
        async def exercise():
            from aiohttp import web

            async def page(request):
                return web.Response(text='''<html><body><div id="result"></div>
                    <script>document.getElementById('result').textContent='dynamic-ready';</script>
                    </body></html>''', content_type='text/html')

            app = web.Application()
            app.router.add_get('/', page)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            scanner = self.scanner_module.CortexScanner()
            try:
                content, _, status = await scanner._fetch_dynamic(f'http://127.0.0.1:{port}/')
                self.assertEqual(status, 200)
                self.assertIn('<div id="result">dynamic-ready</div>', content)
            finally:
                scanner.db_session.close()
                await runner.cleanup()

        asyncio.run(exercise())

    def test_full_system_engine_does_not_accumulate_previous_results(self):
        from engine.cortex import CortexScanner
        import engine.cortex as system_engine
        scanner = CortexScanner()
        with patch.object(system_engine.time, 'sleep'), \
                patch.object(system_engine.network, 'scan_open_ports', return_value=[(445, 'SMB', 'CRITICAL')]), \
                patch.object(system_engine.network, 'check_dns_integrity', return_value=[]), \
                patch.object(system_engine.system, 'scan_running_processes', return_value=[]), \
                patch.object(system_engine.system, 'scan_scheduled_tasks', return_value=[]), \
                patch.object(system_engine.forensics, 'scan_suspicious_files', return_value=[]):
            first = scanner.run_full_scan()
            second = scanner.run_full_scan()
        self.assertEqual(len(first.findings), 1)
        self.assertEqual(len(second.findings), 1)
        self.assertIsNot(first, second)

    def test_ai_success_invalid_data_and_transport_failure(self):
        detector = self.scanner_module.AIMLDetector()
        model = Mock()
        detector.model = model
        payload = {'vulnerability': 'SQLi', 'confidence': 0.95,
                   'severity': 'HIGH', 'reason': 'Synthetic test only'}
        model.generate_content.return_value = SimpleNamespace(text=json.dumps(payload))
        finding = asyncio.run(detector.analyze_response('http://127.0.0.1', '<html>test</html>', {}))
        self.assertEqual(finding.severity, self.scanner_module.SeverityLevel.HIGH)
        model.generate_content.return_value = SimpleNamespace(text='invalid JSON')
        self.assertIsNone(asyncio.run(detector.analyze_response('http://127.0.0.1', 'test', {})))
        model.generate_content.side_effect = RuntimeError('Synthetic transport failure')
        self.assertIsNone(asyncio.run(detector.analyze_response('http://127.0.0.1', 'test', {})))

    def test_worker_failure_cannot_be_reported_as_completed(self):
        m = self.scanner_module
        scanner = m.CortexScanner(m.ScanConfig(target_url='http://127.0.0.1', max_concurrency=1))
        scanner.plugin_manager.hooks = {}
        with patch.object(scanner, '_process_url', new=AsyncMock(side_effect=RuntimeError('Synthetic failure'))):
            with self.assertRaises(RuntimeError):
                asyncio.run(asyncio.wait_for(scanner.scan(), timeout=5))
        session = m.Session()
        try:
            record = session.query(m.Scan).filter_by(scan_uuid=scanner.scan_id).one()
            self.assertEqual(record.status, 'FAILED')
        finally:
            session.close()


if __name__ == '__main__':
    unittest.main()
