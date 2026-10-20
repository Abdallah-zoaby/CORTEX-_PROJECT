"""Stable, source-aware records shared by history, exports and review."""
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json


def now():
    return datetime.now(timezone.utc).isoformat()


def plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [plain(v) for v in value]
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return value


def normalize(finding, kind='host'):
    record = plain(finding)
    if not isinstance(record, dict):
        raise ValueError('Finding must be a mapping or dataclass')
    record = dict(record)
    record.setdefault('source', 'CORTEX web checks' if kind == 'web' else 'CORTEX local evidence')
    record.setdefault('classification', 'web_finding' if kind == 'web' else 'observation')
    record.setdefault('confidence', 'rule_reported_not_calibrated' if kind == 'web' else 'context_only')
    if isinstance(record['confidence'], (float, int)):
        record['detector_score'] = record['confidence']
        record['confidence'] = 'detector_score_not_probability'
    record.setdefault('checked_at', now())
    record.setdefault('recommended_action', record.get('remediation') or 'Review evidence and scope before taking action')
    record.setdefault('severity', 'INFO')
    record.setdefault('limitations', 'Observation of the reported scope; not proof of device safety or formal compliance')
    if record['severity'] not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
        record['severity'] = 'INFO'
    if record['classification'] in ('observation', 'configuration_observation', 'unknown', 'simulation'):
        record['severity'] = 'INFO'
    if record['classification'] == 'engine_detection' and record.get('activity') != 'active':
        record['severity'] = 'INFO'
    # Exclude volatile time/PID/severity so changes can be compared between scans.
    keys = ('source', 'classification', 'type', 'path', 'resource', 'url', 'parameter', 'threat_id')
    basis = {key: record.get(key) for key in keys}
    if not any(record.get(k) for k in ('path', 'resource', 'url', 'threat_id')):
        basis['description'] = record.get('desc') or record.get('description') or record.get('reason')
    record['finding_id'] = hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()
    return record


def summary(records):
    records = list(records)
    return dict(total=len(records),
        active_engine=sum(r.get('classification') == 'engine_detection' and r.get('activity') == 'active' for r in records),
        needs_review=sum(r.get('classification') in ('corroborated_suspicion', 'web_finding') for r in records),
        unknown=sum(r.get('classification') == 'unknown' for r in records),
        observations=sum(r.get('classification') in ('observation', 'configuration_observation') for r in records))
