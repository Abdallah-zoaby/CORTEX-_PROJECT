"""Latest audit snapshots and live observations have separate meanings."""
from collections import Counter


LEVELS = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
CATEGORIES = ('SQLI', 'XSS', 'LFI', 'SENSITIVE', 'OTHER')


def category(value):
    text = str(getattr(value, 'value', value)).lower()
    if 'sql' in text:
        return 'SQLI'
    if 'xss' in text or 'cross-site scripting' in text:
        return 'XSS'
    if any(term in text for term in ('lfi', 'local file inclusion', 'path traversal')):
        return 'LFI'
    if any(term in text for term in ('secret', 'api key', 'apikey', 'sensitive', 'exposed')):
        return 'SENSITIVE'
    return 'OTHER'


def field(finding, name, default=''):
    value = finding.get(name, default) if isinstance(finding, dict) else getattr(finding, name, default)
    return str(getattr(value, 'value', value))


def identity(finding):
    return tuple(field(finding, key) for key in (
        'type', 'url', 'parameter', 'pid', 'source', 'item', 'details', 'desc', 'description'))


class AnalyticsState:
    def __init__(self):
        self.sources = {}
        self.live_alerts = {}

    def replace(self, source, findings):
        unique = {}
        for finding in findings:
            severity = field(finding, 'severity', 'INFO').upper()
            if severity not in LEVELS:
                continue
            key = identity(finding)
            previous = unique.get(key)
            if previous is None or LEVELS.index(severity) < LEVELS.index(previous['severity']):
                unique[key] = {'severity': severity, 'category': category(field(finding, 'type'))}
        self.sources[source] = unique

    def observe(self, alerts):
        current = {identity(alert): alert for alert in alerts}
        new = [alert for key, alert in current.items() if key not in self.live_alerts]
        self.live_alerts = current
        return new

    def snapshot(self):
        findings = [finding for source in self.sources.values() for finding in source.values()]
        levels = Counter(f['severity'] for f in findings)
        types = Counter(f['category'] for f in findings)
        risk = min(100, sum(levels[level] * weight for level, weight in (
            ('CRITICAL', 15), ('HIGH', 8), ('MEDIUM', 3), ('LOW', 1))))
        return {
            'assessed': bool(self.sources),
            'levels': {level: levels[level] for level in LEVELS},
            'types': {name: types[name] for name in CATEGORIES},
            'total': len(findings), 'live': len(self.live_alerts),
            'risk': risk if self.sources else None,
            'posture': 100 - risk if self.sources else None,
        }
