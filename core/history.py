"""Bounded local history of sanitized snapshots; disappearance is not remediation."""
import json
import hashlib
from pathlib import Path
import sqlite3
import uuid
from contextlib import contextmanager
from .findings import normalize, now, summary
from .privacy import sanitize


class ScanHistory:
    def __init__(self, path=None, max_runs=100):
        self.path = Path(path or Path.home() / '.cortex' / 'scan_history.db')
        self.max_runs = max(2, int(max_runs))

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=5)
        try:
            with connection:
                connection.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created_at TEXT, kind TEXT, scope TEXT, status TEXT, payload TEXT)')
                yield connection
        finally:
            connection.close()

    def save(self, kind, scope, findings, coverage, status='completed'):
        if kind not in ('host', 'web') or status not in ('completed', 'cancelled', 'timed_out', 'failed'):
            raise ValueError('Invalid assessment kind or status')
        records = [normalize(r, kind) for r in findings]
        # Only sanitized, bounded local records are persisted, never Wi-Fi secrets.
        payload = sanitize(dict(coverage=coverage, findings=records, summary=summary(records)))
        payload['scope_id'] = hashlib.sha256(str(scope).encode()).hexdigest()
        run_id, timestamp = uuid.uuid4().hex, now()
        safe_scope = sanitize(str(scope))
        with self._connect() as db:
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?)',
                       (run_id, timestamp, kind, safe_scope, status, json.dumps(payload, ensure_ascii=False)))
            db.execute('DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY created_at DESC LIMIT ?)', (self.max_runs,))
        return run_id

    def list_runs(self):
        with self._connect() as db:
            return [dict(zip(('id', 'created_at', 'kind', 'scope', 'status'), row)) for row in db.execute(
                'SELECT id,created_at,kind,scope,status FROM runs ORDER BY created_at DESC')]

    def load(self, run_id):
        with self._connect() as db:
            row = db.execute('SELECT payload FROM runs WHERE id=?', (run_id,)).fetchone()
        if row is None:
            raise KeyError('Unknown assessment')
        return json.loads(row[0])

    def compare(self, older_id, newer_id):
        runs = {r['id']: r for r in self.list_runs()}
        old_meta, new_meta = runs[older_id], runs[newer_id]
        if (old_meta['kind'], old_meta['scope']) != (new_meta['kind'], new_meta['scope']):
            raise ValueError('Compare only assessments with the same kind and scope')
        old, new = self.load(older_id), self.load(newer_id)
        if old.get('scope_id') != new.get('scope_id'):
            raise ValueError('Underlying scopes differ even though their redacted labels match')
        before = {r['finding_id']: r for r in old['findings']}
        after = {r['finding_id']: r for r in new['findings']}
        changed = [key for key in before.keys() & after.keys() if any(
            before[key].get(k) != after[key].get(k) for k in ('severity', 'activity', 'sha256', 'signature'))]
        return dict(new=[after[k] for k in after.keys() - before.keys()],
                    persistent=[after[k] for k in after.keys() & before.keys()],
                    changed=[after[k] for k in changed],
                    not_observed=[before[k] for k in before.keys() - after.keys()],
                    statuses=[old_meta['status'], new_meta['status']],
                    note='Not observed in a later bounded/partial scan does not establish remediation. Review both coverage records.',
                    coverage=[old['coverage'], new['coverage']])

    def clear(self):
        with self._connect() as db:
            db.execute('DELETE FROM runs')
