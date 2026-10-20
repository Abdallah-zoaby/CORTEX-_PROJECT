"""Benign/synthetic fixtures exercise policy, never live malware."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from core.defender import DefenderClient, parse_snapshot, resource_path
from core.evidence import EvidenceInspector, classify, process_signals, volatile_path
from core.windows_security import signatures, powershell_json, SecurityQueryError
from core.analytics import AnalyticsState
from engine.scorer import RiskEngine


def snapshot_fixture(active=True, status=1, success=False, health=True, actions=0):
    return {'health': {'AntivirusEnabled': health, 'AMServiceEnabled': health},
            'threats': [dict(ThreatID=42, ThreatName='Synthetic:Fixture/NotReal', IsActive=active, SeverityID=5)],
            'detections': [dict(ThreatID=42, DetectionID='fixture-id', Resources=['file:_C:\\sample.exe'],
                                ThreatStatusID=status, ActionSuccess=success,
                                AdditionalActionsBitMask=actions, detected_at='2026-01-01T00:00:00Z')]}


class DetectionPolicyTests(unittest.TestCase):
    def test_writable_path_signed_or_unsigned_is_not_malware(self):
        for name in ('codex.exe', 'node_repl.exe', 'wps.exe', 'comet.exe', 'Antigravity IDE.exe', 'xmrig.exe'):
            for signature in ('Valid', 'NotSigned', 'NotTrusted', 'Unavailable'):
                with self.subTest(name=name, signature=signature):
                    result = classify(process_signals(name, r'C:\Users\User\AppData\Local\app.exe', []), signature)
                    self.assertEqual(result['classification'], 'observation')
                    self.assertEqual(result['severity'], 'INFO')

    def test_even_many_weak_indicators_cannot_become_confirmed_malware(self):
        signals = process_signals('powershell.exe', r'C:\Temp\script.exe', ['powershell', '-enc', 'test', '-w', 'hidden'])
        self.assertEqual(classify(signals, 'NotSigned')['classification'], 'observation')

    def test_cpu_entropy_and_generic_ip_prefixes_are_not_verdicts(self):
        from core.behavioral import check_ransomware_risk
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'compressed-looking.bin'
            path.write_bytes(bytes(range(256)) * 16)
            self.assertIn('not proof', check_ransomware_risk(path)['risk'])
        from core.behavioral import BehavioralEngine
        connection = Mock(status='ESTABLISHED', raddr=Mock(ip='185.1.2.3'))
        proc = Mock(info=dict(pid=1, name='safe.exe', exe=r'C:\Program Files\safe.exe', cmdline=[], ppid=None))
        proc.connections.return_value = [connection]
        with patch('core.system.psutil.process_iter', return_value=[proc]):
            self.assertEqual(BehavioralEngine().find_suspicious_processes(), [])
        proc.connections.assert_not_called()

    def test_two_independent_moderate_signals_require_review_not_malware_label(self):
        signals = process_signals('powershell.exe', r'C:\Windows\powershell.exe',
                                  ['powershell', 'iex', '(DownloadString(test))'])
        result = classify(signals, 'HashMismatch')
        self.assertEqual(result['classification'], 'corroborated_suspicion')
        self.assertEqual(result['severity'], 'MEDIUM')
        self.assertEqual(classify(signals, 'HashMismatch', inspected=False)['classification'], 'unknown')

    def test_ide_containing_attack_text_is_not_a_powershell_execution(self):
        signals = process_signals('node.exe', r'C:\Program Files\node.exe', ['test', 'iex DownloadString(test)'])
        self.assertEqual(signals, [])

    def test_path_matching_uses_components_not_substrings(self):
        self.assertFalse(volatile_path(r'C:\Apps\Attempt\safe.exe'))
        self.assertTrue(volatile_path(r'C:\Users\user\APPDATA\Local\app.exe'))

    def test_observations_and_history_cannot_raise_analytics_risk(self):
        state = AnalyticsState()
        state.replace('system', [dict(classification='unknown', severity='CRITICAL', desc='unknown'),
                                dict(classification='observation', severity='HIGH', desc='unsigned'),
                                dict(classification='engine_detection', activity='remediated', severity='CRITICAL')], assessed=False)
        result = state.snapshot()
        self.assertIsNone(result['risk'])
        self.assertEqual(result['total'], 0)
        self.assertEqual(result['observations'], 3)

    def test_summary_never_claims_compromise_from_observations(self):
        result = RiskEngine()
        for index in range(100):
            result.add_finding(str(index), 'CRITICAL', classification='observation')
        self.assertEqual(result.total_score, 0)
        self.assertIn('INCOMPLETE', result.get_verdict()[0])
        result.coverage.update(defender_status='available', defender_health={'AntivirusEnabled': False})
        self.assertIn('INCOMPLETE', result.get_verdict()[0])


class FileEvidenceTests(unittest.TestCase):
    def inspector(self, status='NotSigned', **kwargs):
        return EvidenceInspector(signature_reader=lambda paths: {
            os.path.normcase(path): dict(status=status, publisher='Synthetic publisher', thumbprint='fixture')
            for path in paths}, **kwargs)

    def test_sha256_and_publisher_are_preserved_without_fake_hash_verdict(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'not-a-real-program.exe'
            path.write_bytes(b'password')  # Former fake "WannaCry" hash in this project.
            result = self.inspector().inspect_file(path)
            self.assertEqual(result['sha256'], hashlib.sha256(b'password').hexdigest())
            self.assertEqual(result['signature']['publisher'], 'Synthetic publisher')
            self.assertEqual(result['classification'], 'observation')
            self.assertEqual(result['severity'], 'INFO')

    def test_missing_file_size_limit_and_timeout_remain_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'file.exe'
            self.assertEqual(self.inspector().inspect_file(path)['classification'], 'unknown')
            path.write_bytes(b'benign')
            for inspector in (self.inspector(max_hash_bytes=1), self.inspector(max_seconds=-1)):
                result = inspector.inspect_file(path)
                self.assertEqual(result['classification'], 'unknown')
                self.assertIsNone(result['sha256'])

    def test_file_changed_during_signature_check_discards_hash_and_signature(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'changing.exe'
            path.write_bytes(b'before')

            def changed(paths):
                path.write_bytes(b'changed-and-different-size')
                return {os.path.normcase(str(path)): {'status': 'Valid'}}

            result = EvidenceInspector(signature_reader=changed).inspect_file(path)
            self.assertEqual(result['classification'], 'unknown')
            self.assertIsNone(result['sha256'])
            self.assertEqual(result['signature']['status'], 'Unavailable')

    def test_signature_cache_invalidates_after_file_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.exe'
            path.write_bytes(b'first')
            reader = Mock(side_effect=lambda paths: {os.path.normcase(p): {'status': 'NotSigned'} for p in paths})
            inspector = EvidenceInspector(signature_reader=reader)
            first = inspector.inspect_file(path)
            inspector.inspect_file(path)
            self.assertEqual(reader.call_count, 1)
            path.write_bytes(b'second-different-size')
            second = inspector.inspect_file(path)
            if second['classification'] == 'unknown':
                self.assertIn('changed', second['inspection_error'].lower())
                second = inspector.inspect_file(path)
            self.assertNotEqual(first['sha256'], second['sha256'])
            self.assertEqual(reader.call_count, 2, json.dumps(second))

    def test_bounded_directory_collection_does_not_invent_malware(self):
        from core.forensics import scan_suspicious_files
        with tempfile.TemporaryDirectory() as folder:
            for index in range(10):
                (Path(folder) / f'{index}.exe').write_bytes(b'not malware')
            records = scan_suspicious_files(folder, max_files=3, inspector=self.inspector())
            self.assertEqual(len(records), 3)
            self.assertTrue(all(r['severity'] == 'INFO' for r in records))


class DefenderTests(unittest.TestCase):
    def test_active_detection_has_engine_source_and_qualitative_confidence(self):
        result = parse_snapshot(snapshot_fixture())['findings'][0]
        self.assertEqual(result['activity'], 'active')
        self.assertEqual(result['confidence'], 'engine_reported')
        self.assertEqual(result['severity'], 'CRITICAL')
        self.assertEqual(result['path'], r'C:\sample.exe')

    def test_cleaned_quarantined_removed_blocked_are_not_active(self):
        for status in (2, 3, 4, 6):
            for active in (True, False):
                result = parse_snapshot(snapshot_fixture(active=active, status=status, success=True))['findings'][0]
                self.assertEqual(result['activity'], 'remediated')
                self.assertEqual(result['severity'], 'INFO')

    def test_failed_or_followup_actions_are_not_reported_as_successfully_remediated(self):
        for status, success, actions in ((3, False, 0), (3, True, 8), (102, False, 0), (5, True, 0)):
            result = parse_snapshot(snapshot_fixture(status=status, success=success, actions=actions))['findings'][0]
            self.assertNotEqual(result['activity'], 'remediated')

    def test_missing_activity_stays_unresolved(self):
        data = snapshot_fixture(active=None)
        finding = parse_snapshot(data)['findings'][0]
        self.assertEqual(finding['activity'], 'unresolved')
        self.assertEqual(finding['severity'], 'INFO')

    def test_active_family_survives_remediated_history_without_accusing_old_path(self):
        findings = parse_snapshot(snapshot_fixture(active=True, status=3, success=True))['findings']
        self.assertEqual(findings[0]['activity'], 'remediated')
        active = [f for f in findings if f['activity'] == 'active']
        self.assertEqual(len(active), 1)
        self.assertIsNone(active[0]['path'])

    def test_historical_detection_stays_historical(self):
        finding = parse_snapshot(snapshot_fixture(active=False))['findings'][0]
        self.assertEqual(finding['activity'], 'historical')
        self.assertEqual(finding['severity'], 'INFO')

    def test_active_threat_without_resources_is_not_silently_lost(self):
        data = snapshot_fixture()
        data['detections'] = []
        result = parse_snapshot(data)['findings']
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['activity'], 'active')
        self.assertIsNone(result[0]['path'])

    def test_provider_failure_and_incomplete_payload_remain_unavailable(self):
        for runner in (Mock(side_effect=SecurityQueryError('Denied')), Mock(return_value={}),
                       Mock(return_value={'health': {}, 'threats': None, 'detections': []})):
            result = DefenderClient(runner).snapshot()
            self.assertEqual(result['status'], 'unavailable')

    def test_resource_paths_do_not_treat_process_or_archive_member_as_local_file(self):
        self.assertIsNone(resource_path('process:_pid:123'))
        self.assertIsNone(resource_path('file:_C:\\archive.zip->member.exe'))
        self.assertIsNone(resource_path('file:_\\\\server\\file.exe'))

    def test_scan_needs_consent_and_does_not_accept_nonexistent_file(self):
        runner = Mock()
        client = DefenderClient(runner)
        self.assertEqual(client.scan_file('missing')['status'], 'not_started')
        self.assertEqual(client.scan_file('missing', consent=True)['status'], 'unknown')
        runner.assert_not_called()

    def test_selected_scan_reports_command_not_a_clean_verdict(self):
        runner = Mock(side_effect=[{'command_completed': True}, snapshot_fixture(active=False)])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'benign.txt'
            path.write_text('benign')
            result = DefenderClient(runner).scan_file(path, consent=True)
        self.assertEqual(result['status'], 'command_completed')
        self.assertIn('not proof', result['note'])

    def test_scan_timeout_is_unknown_and_never_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'file.txt'
            path.write_text('benign')
            result = DefenderClient(Mock(side_effect=SecurityQueryError('timeout'))).scan_file(path, consent=True)
        self.assertEqual(result['status'], 'unknown')


class WindowsProviderTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows-only provider integration')
    def test_native_signature_cmdlet_loads_from_windows_modules(self):
        result = powershell_json("[pscustomobject]@{command=(Get-Command Get-AuthenticodeSignature -ErrorAction Stop).Name} | ConvertTo-Json")
        self.assertEqual(result['command'], 'Get-AuthenticodeSignature')

    def test_inherited_core_module_path_cannot_shadow_windows_security_module(self):
        with patch.dict(os.environ, {'PSMODULEPATH': r'C:\untrusted-module-path'}), \
                patch('core.windows_security.subprocess.run', return_value=Mock(returncode=0, stdout='[]')) as run:
            powershell_json('[]')
        paths = [v for k, v in run.call_args.kwargs['env'].items() if k.upper() == 'PSMODULEPATH']
        self.assertEqual(len(paths), 1)
        self.assertNotIn('untrusted-module-path', paths[0])

    def test_signature_status_is_exact_and_unknown_records_are_explicit(self):
        records = [dict(path='sample.exe', status='InvalidButContainsValid', publisher=None)]
        result = signatures(['sample.exe', 'missing.exe'], runner=Mock(return_value=records))
        self.assertEqual(result[os.path.normcase('sample.exe')]['status'], 'Unavailable')
        self.assertEqual(result[os.path.normcase('missing.exe')]['status'], 'Unavailable')

    def test_path_is_passed_as_json_data_not_interpolated_source(self):
        payload = 'C:\\test\\name\'$(Write-Output INJECTION).exe'
        with patch('core.windows_security.subprocess.run', return_value=Mock(returncode=0, stdout='[]')) as run:
            powershell_json('$null | ConvertTo-Json', payload)
        self.assertEqual(json.loads(run.call_args.kwargs['env']['CORTEX_SECURITY_INPUT']), payload)
        self.assertNotIn(payload, ' '.join(run.call_args.args[0]))
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertTrue(run.call_args.kwargs['env']['PSModulePath'].endswith(os.path.join('WindowsPowerShell', 'v1.0', 'Modules')))

    def test_error_malformed_json_and_timeout_are_not_empty_success(self):
        for response in (Mock(returncode=1, stdout=''), Mock(returncode=0, stdout='not json')):
            with patch('core.windows_security.subprocess.run', return_value=response):
                with self.assertRaises(SecurityQueryError):
                    powershell_json('test')
        with patch('core.windows_security.subprocess.run', side_effect=subprocess.TimeoutExpired('test', 1)):
            with self.assertRaises(SecurityQueryError):
                powershell_json('test')


if __name__ == '__main__':
    unittest.main()
