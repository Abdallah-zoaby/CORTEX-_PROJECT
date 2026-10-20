"""Privacy, comparison and interruption behavior with synthetic data only."""
from dataclasses import dataclass
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, patch
from core.findings import normalize
from core.history import ScanHistory
from core.lifecycle import ScanControl, ScanStopped
from core.privacy import sanitize, redact_text, shareable_copy
from engine.cortex import CortexScanner
from evaluation.run import evaluate


class PrivacyTests(unittest.TestCase):
    def test_secrets_commands_url_credentials_and_raw_body_are_omitted(self):
        fixture = {'password': 'synthetic-secret', 'api_key': 'synthetic-key',
                   'command_line': 'tool --unlabelled-private-value',
                   'evidence': 'Unlabelled private response contents',
                   'url': 'https://fixture:synthetic-password@example.test/path?session=private-value',
                   'nested': [{'Authorization': 'Bearer synthetic-token'}]}
        shared = json.dumps(sanitize(fixture))
        for secret in ('synthetic-secret', 'synthetic-key', 'unlabelled-private-value', 'private response contents',
                       'synthetic-password', 'private-value', 'synthetic-token'):
            self.assertNotIn(secret, shared)
        self.assertEqual(fixture['password'], 'synthetic-secret')

    def test_wifi_and_header_log_lines_do_not_leak_values_with_spaces(self):
        for line in ('WiFi: Fixture | Pass: synthetic secret with spaces',
                     'Authorization: Bearer synthetic token', 'Cookie: arbitrary=synthetic-value',
                     "password = 'synthetic secret with spaces'"):
            self.assertNotIn('synthetic', redact_text(line))

    def test_dataclass_report_copy_preserves_original_and_scrubs_evidence(self):
        @dataclass
        class Fixture:
            evidence: str
            url: str
        raw = Fixture('unlabelled-private-value', 'https://host.test/?unusual=secret')
        safe = shareable_copy(raw)
        self.assertEqual(raw.evidence, 'unlabelled-private-value')
        self.assertNotIn('unlabelled-private-value', safe.evidence)
        self.assertNotIn('secret', safe.url)

    def test_local_user_name_redacted(self):
        self.assertNotIn('FixtureUser', redact_text(r'C:\Users\FixtureUser\Documents\test.exe'))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.history = ScanHistory(Path(self.folder.name) / 'history.db', max_runs=3)

    def tearDown(self):
        self.folder.cleanup()

    def record(self, path='C:\\fixture.exe', **extra):
        return dict(type='File evidence', path=path, classification='observation', severity='INFO', **extra)

    def test_shared_schema_stable_id_excludes_time_pid_and_severity(self):
        first = normalize(self.record(pid=1, checked_at='first'))
        second = normalize(self.record(pid=2, checked_at='second'))
        self.assertEqual(first['finding_id'], second['finding_id'])
        for key in ('source', 'confidence', 'recommended_action', 'limitations'):
            self.assertIn(key, first)

    def test_numeric_detector_score_is_not_a_probability(self):
        result = normalize(dict(type='Synthetic', severity='MEDIUM', confidence=0.9), 'web')
        self.assertEqual(result['confidence'], 'detector_score_not_probability')
        self.assertEqual(result['detector_score'], 0.9)

    def test_compare_new_changed_persistent_and_not_observed(self):
        a = self.history.save('host', 'fixture', [self.record(sha256='a'), self.record('C:\\old.exe')], {})
        b = self.history.save('host', 'fixture', [self.record(sha256='b'), self.record('C:\\new.exe')], {}, 'cancelled')
        delta = self.history.compare(a, b)
        self.assertEqual([len(delta[k]) for k in ('new', 'persistent', 'changed', 'not_observed')], [1, 1, 1, 1])
        self.assertIn('does not establish remediation', delta['note'])
        self.assertIn('cancelled', delta['statuses'])

    def test_history_never_persists_sensitive_commands(self):
        run = self.history.save('host', 'fixture', [self.record(command_line='synthetic-secret')], {})
        self.assertNotIn('synthetic-secret', json.dumps(self.history.load(run)))
        self.assertNotIn(b'synthetic-secret', self.history.path.read_bytes())

    def test_comparison_rejects_distinct_redacted_scopes(self):
        a = self.history.save('web', 'https://test/?target=first', [], {})
        b = self.history.save('web', 'https://test/?target=second', [], {})
        with self.assertRaises(ValueError):
            self.history.compare(a, b)

    def test_retention_clear_and_missing_record(self):
        for _ in range(5):
            self.history.save('host', 'fixture', [], {})
        self.assertEqual(len(self.history.list_runs()), 3)
        self.history.clear()
        self.assertEqual(self.history.list_runs(), [])
        with self.assertRaises(KeyError):
            self.history.load('missing')


class LifecycleTests(unittest.TestCase):
    def test_cancel_before_scan_never_calls_provider(self):
        provider = Mock()
        control = ScanControl()
        control.cancel()
        result = CortexScanner(defender_client=provider).run_full_scan(control=control)
        provider.snapshot.assert_not_called()
        self.assertEqual(result.coverage['assessment_status'], 'cancelled')
        self.assertIn('INCOMPLETE', result.get_verdict()[0])

    def test_timeout_never_looks_like_completion(self):
        control = ScanControl()
        control.deadline = 0
        with self.assertRaises(ScanStopped) as error:
            control.checkpoint()
        self.assertEqual(error.exception.status, 'timed_out')

    def test_cancel_during_provider_read_does_not_continue_process_scan(self):
        control = ScanControl()
        def query():
            control.cancel()
            return {'status': 'available', 'findings': [], 'health': {}}
        with patch('engine.cortex.system.scan_running_processes') as processes:
            result = CortexScanner(defender_client=Mock(snapshot=query)).run_full_scan(control=control)
        processes.assert_not_called()
        self.assertEqual(result.coverage['assessment_status'], 'cancelled')

    def test_file_enumeration_honors_cancellation(self):
        from core.forensics import scan_suspicious_files
        control = ScanControl()
        control.cancel()
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ScanStopped):
                scan_suspicious_files(folder, control=control)


class EvaluationTests(unittest.TestCase):
    def test_replay_counts_unknown_positive_as_missed_review(self):
        result = evaluate()
        self.assertEqual(result['cases'], 12)
        self.assertEqual(result['counts']['false_positive'], 0)
        self.assertEqual(result['counts']['false_negative'], 1)
        self.assertEqual(result['counts']['unknown'], 2)
        self.assertAlmostEqual(result['recall'], 2 / 3)
        self.assertIn('not malware ground truth', result['scope'])
