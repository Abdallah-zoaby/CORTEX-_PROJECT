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
                self.assertIsNone(app.gauge_threat.value)
                self.assertEqual(app.stat_health.cget('text'), 'N/A')
                alert = dict(type='PATH_ANOMALY', severity='HIGH', source='synthetic.exe',
                             pid=123, details='Synthetic AppData observation')
                with patch.object(app.behavior_engine, 'find_suspicious_processes', return_value=[alert]):
                    app.monitor_behavior()
                    app.monitor_behavior()
                self.assertEqual(app.stat_high.cget('text'), '0')
                self.assertIn('Live heuristic alerts: 1', app.analytics_status.cget('text'))
                self.assertIsNone(app.gauge_threat.value)
                finding = dict(type='SQL Injection', severity='MEDIUM', url='http://local/')
                app._set_analytics_findings('web', [finding, finding])
                app._set_analytics_findings('web', [finding])
                self.assertEqual(app.stat_high.cget('text'), '1')
                self.assertEqual(app.gauge_threat.value, 3)
                self.assertEqual(app.gauge_health.value, 97)
                self.assertEqual(app.stat_health.cget('text'), '97/100')
                with patch.object(app.scanner.alerts, 'trigger'):
                    app._on_intrusion_detected('CRITICAL', 'Synthetic simulation')
                self.assertEqual(app.gauge_threat.value, 3)
                app.analytics.sources.pop('web', None)
                active = dict(type='Defender detection', source='Microsoft Defender',
                              classification='engine_detection', confidence='engine_reported', activity='active',
                              severity='HIGH', path=r'C:\synthetic-only.exe', detection_id='test-detection',
                              threat_name='Synthetic test only', action_status='detected', desc='Synthetic engine detection')
                coverage = dict(defender_status='available', defender_health={'AntivirusEnabled': True},
                                scope='Synthetic GUI fixture')
                app.display_evidence([active], coverage)
                self.assertEqual(len(app.evidence_tree.get_children()), 1)
                app.evidence_tree.selection_set('0')
                app.show_evidence_detail()
                detail = json.loads(app.forensic_output.get('1.0', 'end'))
                self.assertEqual(detail['confidence'], 'engine_reported')
                app.append_file_evidence([dict(type='File evidence', classification='observation',
                    severity='INFO', confidence='weak_indicators', path=r'C:\benign.exe')])
                self.assertEqual(app.findings_count['HIGH'], 1)
                self.assertEqual(len(app.evidence_records), 2)
                app.evidence_filter.set('History')
                app.render_evidence_list()
                self.assertEqual(len(app.evidence_tree.get_children()), 0)
                app.evidence_filter.set('All')
                app._apply_defender_snapshot(dict(status='unavailable', error='Synthetic permission failure'))
                self.assertEqual(app.findings_count['HIGH'], 0)
                self.assertIsNone(app.gauge_threat.value)
                with patch.object(self.gui.filedialog, 'askopenfilename', return_value=r'C:\benign.txt'), \
                        patch.object(self.gui.messagebox, 'askyesno', return_value=False), \
                        patch.object(app.system_scanner.defender_client, 'scan_file') as scan:
                    app.scan_selected_file()
                    scan.assert_not_called()
                exported = Path(self.folder.name) / 'evidence.json'
                with patch.object(self.gui.filedialog, 'asksaveasfilename', return_value=str(exported)):
                    app.export_evidence_json()
                exported_data = json.loads(exported.read_text(encoding='utf-8'))
                self.assertEqual(exported_data['schema_version'], 1)
                self.assertEqual(exported_data['findings'], app.evidence_records)
                from core.history import ScanHistory
                from core.lifecycle import ScanControl
                app.history = ScanHistory(Path(self.folder.name) / 'gui-history.db')
                app.history.save('host', 'fixture', [active], coverage)
                app.history.save('host', 'fixture', [], coverage, 'cancelled')
                app.open_scan_history()
                windows = [w for w in app.winfo_children() if isinstance(w, self.gui.ctk.CTkToplevel)]
                self.assertEqual(len(windows), 1)
                window = windows[0]
                tree = next(w for w in window.winfo_children() if isinstance(w, self.gui.ttk.Treeview))
                self.assertEqual(len(tree.get_children()), 2)
                tree.selection_set(tree.get_children())
                tree.event_generate('<<TreeviewSelect>>')
                app.update()
                output = next(w for w in window.winfo_children() if isinstance(w, self.gui.ctk.CTkTextbox))
                self.assertIn('not_observed', output.get('1.0', 'end'))
                window.destroy()
                app._scan_control = ScanControl()
                app.cancel_assessment()
                self.assertTrue(app._scan_control.event.is_set())
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

    def test_pdf_keeps_host_and_web_evidence_with_confidence_and_coverage(self):
        from pypdf import PdfReader
        from reports.pdf_generator import generate_pdf_report
        from engine.scorer import RiskEngine
        result = RiskEngine()
        result.coverage = {'defender_status': 'unavailable', 'scope': 'Synthetic bounded sample'}
        result.add_finding('Host observation', 'HIGH', type='File evidence', classification='observation',
                           confidence='weak_indicators', path=r'C:\fixture.exe', sha256='a' * 64)
        output = Path(self.folder.name) / 'combined-evidence.pdf'
        generate_pdf_report(result, filename=str(output), web_findings=[
            dict(type='Web test finding', severity='MEDIUM', desc='Web fixture', url='http://127.0.0.1')])
        text = '\n'.join(page.extract_text() for page in PdfReader(output).pages)
        for expected in ('Host observation', 'Web fixture', 'weak_indicators', 'unavailable', 'sha256'):
            self.assertIn(expected, text)

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

    def test_ai_decline_sends_nothing_and_preview_contains_only_aggregates(self):
        ui = Mock()
        ui._ai_running = False
        ui.evidence_records = [dict(classification='observation', path=r'C:\private-user\private.exe',
                                    command_line='synthetic-private-secret')]
        ui.web_findings = []
        ui.evidence_coverage = {'defender_status': 'unavailable'}
        with patch.object(self.gui.messagebox, 'askyesno', return_value=False) as consent, \
                patch.object(self.gui.threading, 'Thread') as thread:
            self.gui.CortexProApp.ask_ai_analyst(ui)
        thread.assert_not_called()
        preview = consent.call_args.args[1]
        self.assertNotIn('private-user', preview)
        self.assertNotIn('synthetic-private-secret', preview)
        self.assertIn('unavailable', preview)

    def test_scope_rejects_other_hosts_ports_credentials_and_schemes(self):
        scanner = self.scanner_module.CortexScanner(self.scanner_module.ScanConfig(target_url='http://127.0.0.1:5555'))
        try:
            self.assertTrue(scanner._is_in_scope('http://127.0.0.1:5555/path'))
            for url in ('http://127.0.0.1:5556', 'http://localhost:5555', 'https://127.0.0.1:5555',
                        'http://user:password@127.0.0.1:5555', 'http://external.test', 'file:///test'):
                self.assertFalse(scanner._is_in_scope(url), url)
        finally:
            scanner.db_session.close()

    def test_hanging_prescan_hook_respects_deadline(self):
        from core.lifecycle import ScanControl, ScanStopped
        m = self.scanner_module
        async def exercise():
            scanner = m.CortexScanner(m.ScanConfig(target_url='http://127.0.0.1:5555'))
            async def hang(*args):
                await asyncio.sleep(30)
            scanner.plugin_manager.execute_hook = AsyncMock(side_effect=hang)
            try:
                with self.assertRaises(ScanStopped):
                    await scanner.scan(control=ScanControl(max_seconds=0.05))
                self.assertFalse(scanner._assessment_running)
            finally:
                scanner.db_session.close()
        asyncio.run(exercise())

    def test_crawl_depth_and_origin_limit_new_queue_entries(self):
        m = self.scanner_module
        async def exercise():
            scanner = m.CortexScanner(m.ScanConfig(target_url='http://127.0.0.1:5555/', max_depth=1))
            scanner._url_depths = {scanner.config.target_url: 0}
            try:
                await scanner._extract_and_queue_links(scanner.config.target_url,
                    '<a href="/inside">ok</a><a href="http://external.test/outside">outside</a>')
                self.assertEqual(scanner.url_queue.qsize(), 1)
                await scanner._extract_and_queue_links('http://127.0.0.1:5555/inside', '<a href="/too-deep">deep</a>')
                self.assertEqual(scanner.url_queue.qsize(), 1)
            finally:
                scanner.db_session.close()
        asyncio.run(exercise())

    def test_cancelled_web_scan_cleans_workers_session_and_restores_reusability(self):
        from core.lifecycle import ScanControl, ScanStopped
        m = self.scanner_module
        async def exercise():
            from aiohttp import web
            async def slow(request):
                await asyncio.sleep(0.4)
                return web.Response(text='<html>Fixture</html>')
            app = web.Application()
            app.router.add_get('/', slow)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            scanner = m.CortexScanner(m.ScanConfig(target_url=f'http://127.0.0.1:{port}', max_concurrency=1))
            scanner.plugin_manager.execute_hook = AsyncMock(return_value=[])
            scanner.ai_detector.analyze_response = AsyncMock()
            control = ScanControl(max_seconds=0.05)
            try:
                with self.assertRaises(ScanStopped):
                    await scanner.scan(control=control)
                self.assertFalse(scanner._assessment_running)
                self.assertTrue(scanner.session is None or scanner.session.closed)
                persisted = scanner.db_session.query(m.Scan).filter_by(scan_uuid=scanner.scan_id).one()
                self.assertEqual(persisted.status, 'TIMED_OUT')
                result = await scanner.scan(control=ScanControl(max_seconds=5))
                self.assertEqual(result.total_urls_scanned, 1)
                scanner.ai_detector.analyze_response.assert_not_awaited()
            finally:
                scanner.db_session.close()
                await runner.cleanup()
        asyncio.run(exercise())

    def test_report_formats_redact_secrets_escape_html_and_preserve_original(self):
        import datetime
        from pypdf import PdfReader
        m = self.scanner_module
        vuln = m.Vulnerability(type=m.VulnerabilityType.CUSTOM, severity=m.SeverityLevel.LOW,
            confidence=0.5, url='http://example.test/?session=synthetic-secret',
            description='<script>literal</script>', evidence='unlabelled-sensitive-value')
        result = m.ScanResult(scan_id='fixture', target='http://example.test/?token=synthetic-secret',
            start_time=datetime.datetime.now(), end_time=datetime.datetime.now(), total_urls_scanned=1,
            vulnerabilities_found=1, vulnerabilities=[vuln], tech_stack={}, scan_config=m.ScanConfig(target_url='http://example.test'), summary={})
        for format in ('html', 'json', 'csv', 'pdf'):
            output = m.ReportGenerator().generate(result, format=format)
            if format == 'pdf':
                import io
                text = '\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(output)).pages)
            else:
                text = output
            self.assertNotIn('synthetic-secret', text)
            self.assertNotIn('unlabelled-sensitive-value', text)
            if format == 'html':
                self.assertIn('&lt;script&gt;', text)
        self.assertEqual(vuln.evidence, 'unlabelled-sensitive-value')

    def test_unavailable_http_response_cannot_complete_as_empty_clean_scan(self):
        m = self.scanner_module
        async def exercise():
            scanner = m.CortexScanner(m.ScanConfig(target_url='http://127.0.0.1:5555', max_concurrency=1))
            scanner.plugin_manager.execute_hook = AsyncMock(return_value=[])
            scanner._fetch_url = AsyncMock(return_value=(None, {}, 0))
            try:
                with self.assertRaisesRegex(RuntimeError, 'could not be processed'):
                    await scanner.scan()
            finally:
                scanner.db_session.close()
        asyncio.run(exercise())

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
            scanner.config.target_url = f'http://127.0.0.1:{port}/'
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
        defender = Mock()
        defender.snapshot.return_value = dict(status='available', health={'AntivirusEnabled': True}, findings=[])
        scanner = CortexScanner(defender_client=defender)
        with patch.object(system_engine.network, 'scan_open_ports', return_value=[(445, 'SMB', 'CRITICAL')]), \
                patch.object(system_engine.network, 'check_dns_integrity', return_value=[]), \
                patch.object(system_engine.system, 'scan_running_processes', return_value=[]), \
                patch.object(system_engine.system, 'scan_scheduled_tasks', return_value=[]), \
                patch.object(system_engine.forensics, 'scan_suspicious_files', return_value=[]):
            first = scanner.run_full_scan()
            second = scanner.run_full_scan()
        self.assertEqual(len(first.findings), 1)
        self.assertEqual(len(second.findings), 1)
        self.assertIsNot(first, second)


    def test_advanced_gui_failure_recovery_inputs_and_export(self):
        with patch.object(self.scanner_module.CortexScanner, 'start_live_monitor'), \
                patch.object(self.gui.CortexProApp, 'update_threat_intel'), \
                patch.object(self.gui.CortexProApp, 'run_startup_sequence'):
            app = self.gui.CortexProApp()
            try:
                app.withdraw()
                from test_advanced_modules import XML
                app.apk_path.insert(0, XML)
                with patch.object(self.gui.threading, 'Thread',
                        side_effect=lambda target, daemon: SimpleNamespace(start=target)):
                    app.run_apk_audit()
                    app.update()
                self.assertEqual(app.btn_apk.cget('state'), 'normal')
                self.assertIn('android.permission.CAMERA', app.apk_output.get('1.0', 'end'))
                app.apk_path.delete(0, 'end')
                app.apk_path.insert(0, 'missing-file.xml')
                with patch.object(self.gui.threading, 'Thread',
                        side_effect=lambda target, daemon: SimpleNamespace(start=target)):
                    app.run_apk_audit()
                    app.update()
                self.assertEqual(app._mobile_records[0]['classification'], 'unknown')
                self.assertEqual(app.btn_apk.cget('state'), 'normal')
                with patch.object(self.gui.threading, 'Thread',
                        side_effect=lambda target, daemon: SimpleNamespace(start=target)), \
                        patch.object(self.gui, 'scan_running_processes', side_effect=OSError('fixture')), \
                        patch.object(self.gui, 'scan_startup_apps', return_value=[]), \
                        patch.object(self.gui, 'scan_open_ports', return_value=[(80, 'test HTTP', 'INFO')]), \
                        patch.object(self.gui, 'check_dns_integrity', return_value=[]), \
                        patch.object(self.gui, 'scan_scheduled_tasks', return_value=[]):
                    app.run_enterprise_audit()
                    app.update()
                self.assertFalse(app._enterprise_running)
                self.assertEqual(app.btn_ent_audit.cget('state'), 'normal')
                self.assertTrue(any(r['classification'] == 'unknown' for r in app._enterprise_records))
                app.api_url_entry.insert(0, 'http://127.0.0.1')
                with patch.object(self.gui.messagebox, 'askyesno', return_value=False), \
                        patch.object(self.gui, 'APIAuditor') as auditor:
                    app.run_api_audit()
                    auditor.assert_not_called()
                with patch.object(self.gui.messagebox, 'askyesno', return_value=True), \
                        patch.object(self.gui.threading, 'Thread',
                            side_effect=lambda target, daemon: SimpleNamespace(start=target)), \
                        patch.object(self.gui.APIAuditor, 'audit_full', side_effect=RuntimeError('fixture')):
                    app.run_api_audit()
                    app.update()
                self.assertEqual(app.btn_api.cget('state'), 'normal')
                self.assertEqual(app._api_records[0]['classification'], 'unknown')
                self.assertIsNone(app.risk_score)
                app.display_evidence([dict(type='Engine detection', classification='engine_detection',
                    activity='active', severity='HIGH')], dict(assessment_status='cancelled',
                    defender_status='available', defender_health={'AntivirusEnabled': True}))
                self.assertEqual(app.findings_count['HIGH'], 1)
                self.assertIsNone(app.gauge_health.value)
                exported = Path(self.folder.name) / 'advanced-siem.json'
                with patch.object(self.gui.filedialog, 'asksaveasfilename', return_value=str(exported)):
                    app.export_siem_json()
                report = json.loads(exported.read_text(encoding='utf-8'))
                self.assertGreaterEqual(report['summary']['unknown'], 3)
                self.assertTrue(any(r['type'] == 'Listening port' for r in report['events']))
                with patch.object(app.purple_orchestrator, 'run_simulation', side_effect=RuntimeError('fixture')), \
                        patch.object(self.gui.threading, 'Thread',
                            side_effect=lambda target, daemon: SimpleNamespace(start=target)):
                    app.run_purple_team_sim()
                    app.update()
                self.assertFalse(app._purple_running)
                self.assertEqual(app.btn_purple.cget('state'), 'normal')
            finally:
                app.scanner.db_session.close()
                app.destroy()

    def test_ip_reputation_without_provider_is_unknown(self):
        manager = self.scanner_module.ThreatIntelManager()
        for ip in ('127.0.0.1', '185.220.101.1', '192.0.2.1'):
            self.assertEqual(manager.check_ip_reputation(ip)['status'], 'UNKNOWN')

    def test_legacy_forensics_never_auto_submits_to_ai(self):
        ai = Mock()
        collector = self.scanner_module.WindowsForensics(ai)
        asyncio.run(collector._ai_summarize({'system': {'node': 'private-fixture'}}))
        ai.model.generate_content.assert_not_called()

    def test_ai_never_uses_encryption_key_as_provider_key(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.dict(self.scanner_module.CONFIG, {'ENCRYPTION_KEY': 'not-an-api-key'}), \
                patch.object(self.scanner_module.genai, 'configure') as configure:
            detector = self.scanner_module.AIMLDetector()
        configure.assert_not_called()
        self.assertIsNone(detector.model)

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
