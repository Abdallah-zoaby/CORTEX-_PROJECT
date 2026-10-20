"""Regression cases for misleading risk growth while the app is idle."""
import unittest
from core.analytics import AnalyticsState


class AnalyticsTests(unittest.TestCase):
    def test_idle_and_live_observations_are_not_a_completed_audit(self):
        state = AnalyticsState()
        alert = dict(pid=123, type='PATH_ANOMALY', severity='HIGH', source='test.exe',
                     details='Temp path', timestamp='first')
        self.assertEqual(len(state.observe([alert])), 1)
        for tick in range(300):
            self.assertEqual(state.observe([dict(alert, timestamp=str(tick))]), [])
        snapshot = state.snapshot()
        self.assertIsNone(snapshot['risk'])
        self.assertIsNone(snapshot['posture'])
        self.assertEqual(snapshot['live'], 1)
        self.assertEqual(snapshot['total'], 0)
        self.assertEqual(sum(snapshot['types'].values()), 0)

    def test_resolved_alert_is_removed(self):
        state = AnalyticsState()
        state.observe([dict(pid=1, type='test')])
        state.observe([])
        self.assertEqual(state.snapshot()['live'], 0)

    def test_repeated_audit_replaces_and_deduplicates(self):
        state = AnalyticsState()
        finding = dict(severity='HIGH', type='Cross-Site Scripting', url='http://local/', parameter='q')
        for _ in range(100):
            state.replace('web', [finding, finding])
        snapshot = state.snapshot()
        self.assertEqual(snapshot['total'], 1)
        self.assertEqual(snapshot['risk'], 8)
        self.assertEqual(snapshot['types']['XSS'], 1)
        state.replace('web', [])
        self.assertEqual(state.snapshot()['total'], 0)
        self.assertEqual(state.snapshot()['posture'], 100)

    def test_all_severities_are_counted_consistently(self):
        state = AnalyticsState()
        state.replace('web', [dict(severity='MEDIUM', type='SQL Injection'),
                              dict(severity='LOW', type='LFI'),
                              dict(severity='INFO', type='API key exposed')])
        state.replace('system', [dict(severity='HIGH', desc='Unique host finding')])
        snapshot = state.snapshot()
        self.assertEqual(sum(snapshot['levels'].values()), snapshot['total'])
        self.assertEqual(sum(snapshot['types'].values()), snapshot['total'])
        self.assertEqual(snapshot['risk'] + snapshot['posture'], 100)
        self.assertEqual(snapshot['risk'], 12)

    def test_duplicate_severity_uses_the_highest_level(self):
        state = AnalyticsState()
        state.replace('web', [dict(type='SQL Injection', url='local', severity='LOW'),
                              dict(type='SQL Injection', url='local', severity='CRITICAL')])
        self.assertEqual(state.snapshot()['levels']['CRITICAL'], 1)
        self.assertEqual(state.snapshot()['total'], 1)
