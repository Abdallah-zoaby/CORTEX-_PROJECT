"""Local file/process evidence with qualitative, explainable classifications."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import time
from .windows_security import signatures


def volatile_path(path):
    return bool({'appdata', 'temp', 'tmp'} & set(str(path).replace('\\', '/').lower().split('/')))


def process_signals(name, path, command):
    signals = []
    if volatile_path(path):
        signals.append(dict(group='location', reason='Executable is in a user-writable/temporary location', strength='weak'))
    name = str(name or '').lower()
    if name in ('xmrig.exe', 'minerd.exe', 'nicehash.exe', 'nc.exe'):
        signals.append(dict(group='name', reason='Name resembles a dual-use tool; names do not establish maliciousness', strength='weak'))
    # Command text in an IDE/test runner is not evidence that PowerShell ran it.
    if name in ('powershell.exe', 'pwsh.exe', 'powershell', 'pwsh'):
        text = ' '.join(command or []).lower() if not isinstance(command, str) else command.lower()
        if re.search(r'(?:^|\s)-(?:enc|encodedcommand|windowstyle\s+hidden|w\s+hidden)(?:\s|$)', text):
            signals.append(dict(group='script_options', reason='Encoded/hidden PowerShell options observed; also used legitimately', strength='weak'))
        if any(term in text for term in ('downloadstring', 'invoke-webrequest')) and re.search(r'\b(?:iex|invoke-expression)\b', text):
            signals.append(dict(group='download_execute', reason='PowerShell command text combines download and evaluation', strength='moderate'))
    return signals


def classify(signals, signature_status='Unavailable', inspected=True):
    reasons = list(signals)
    if signature_status == 'NotSigned':
        reasons.append(dict(group='signature', reason='No Authenticode signature; unsigned does not mean malicious', strength='weak'))
    elif signature_status == 'HashMismatch':
        reasons.append(dict(group='integrity', reason='Authenticode reports a content/signature mismatch', strength='moderate'))
    elif signature_status in ('NotTrusted', 'UnknownError', 'Unavailable'):
        reasons.append(dict(group='verification', reason=f'Signature status: {signature_status}; trust is not established', strength='weak'))
    moderate = {s['group'] for s in reasons if s['strength'] == 'moderate'}
    # Multiple weak hints are still weak. Independent behavioral/integrity evidence is required.
    if not inspected:
        label, confidence, severity = 'unknown', 'insufficient_data', 'INFO'
    elif len(moderate) >= 2:
        label, confidence, severity = 'corroborated_suspicion', 'corroborated_indicators', 'MEDIUM'
    else:
        label, confidence, severity = 'observation', 'weak_indicators' if reasons else 'no_adverse_indicator_observed', 'INFO'
    return dict(classification=label, confidence=confidence, severity=severity, signals=reasons,
                recommended_action='Request a Defender scan or review evidence; do not delete based on heuristics')


def fingerprint(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


class EvidenceInspector:
    def __init__(self, signature_reader=signatures, max_hash_bytes=256 * 1024 * 1024,
                 max_seconds=90):
        self.signature_reader = signature_reader
        self.max_hash_bytes = max_hash_bytes
        self.deadline = time.monotonic() + max_seconds
        self.cache = {}

    def inspect_file(self, path, signature=None):
        record = dict(path=os.path.abspath(os.fspath(path)), hash=None, sha256=None,
                      signature={'status': 'Unavailable', 'publisher': None, 'thumbprint': None},
                      inspection_status='not_checked', checked_at=datetime.now(timezone.utc).isoformat(),
                      source='CORTEX local evidence', type='File evidence')
        try:
            target = Path(record['path'])
            if target.is_symlink() or not target.is_file():
                raise OSError('Not a regular file or is a symbolic link')
            before = target.stat()
            record.update(size=before.st_size, modified_at=datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat())
            cache_key = (os.path.normcase(record['path']), fingerprint(before))
            if cache_key in self.cache:
                return dict(self.cache[cache_key])
            if time.monotonic() >= self.deadline:
                raise OSError('Inspection time budget exhausted')
            if before.st_size > self.max_hash_bytes:
                record['signature'] = signature if signature is not None else self.signature_reader([record['path']]).get(
                    os.path.normcase(record['path']), record['signature'])
                if fingerprint(target.stat()) != fingerprint(before):
                    raise OSError('File changed during inspection; evidence discarded')
                record.update(classify([], record['signature']['status'], inspected=False))
                record.update(inspection_status='partial', inspection_error='Hashing size limit exceeded; SHA-256 not collected',
                              reason='Hashing size limit exceeded; signature metadata only; no safety verdict',
                              reasons='Hashing size limit exceeded; signature metadata only; no safety verdict')
                self.cache[cache_key] = dict(record)
                return record
            digest = hashlib.sha256()
            total_read = 0
            with target.open('rb') as stream:
                opened = os.fstat(stream.fileno())
                # Windows Python 3.12 stat/fstat disagree on the legacy ctime field.
                # Compare file identity, size and write time across APIs; retain ctime
                # for same-API path comparisons and cache invalidation.
                if fingerprint(opened)[:4] != fingerprint(before)[:4]:
                    raise OSError('File changed before inspection')
                for block in iter(lambda: stream.read(128 * 1024), b''):
                    total_read += len(block)
                    if total_read > self.max_hash_bytes:
                        raise OSError('File grew beyond the hashing size limit')
                    if time.monotonic() >= self.deadline:
                        raise OSError('Inspection time budget exhausted')
                    digest.update(block)
            record['signature'] = signature if signature is not None else self.signature_reader([record['path']]).get(
                os.path.normcase(record['path']), record['signature'])
            if fingerprint(target.stat()) != fingerprint(before):
                raise OSError('File changed during inspection; evidence discarded')
            record['hash'] = record['sha256'] = digest.hexdigest()
            complete = record['signature']['status'] not in ('Unavailable', 'UnknownError')
            record['inspection_status'] = 'metadata_collected' if complete else 'partial'
            record.update(classify(process_signals('', record['path'], []), record['signature']['status'], inspected=complete))
            record['reason'] = record['reasons'] = '; '.join(s['reason'] for s in record['signals']) or 'No adverse local indicator observed; not a malware clearance'
            self.cache[cache_key] = dict(record)
        except (OSError, ValueError) as exc:
            record['signature'] = {'status': 'Unavailable', 'publisher': None, 'thumbprint': None}
            record['inspection_error'] = str(exc)
            record.update(classify([], inspected=False))
            record.update(inspection_status='unknown', reason=str(exc), reasons=str(exc))
        return record

    def inspect_process(self, process):
        path = process.get('exe')
        if path:
            record = self.inspect_file(path)
        else:
            record = dict(path=None, hash=None, sha256=None, signature={'status': 'Unavailable'},
                          inspection_status='unknown', source='CORTEX local evidence',
                          checked_at=datetime.now(timezone.utc).isoformat())
        signals = process_signals(process.get('name'), path or '', process.get('cmdline'))
        record.update(classify(signals, record['signature']['status'], record['inspection_status'] == 'metadata_collected'))
        record.update(type='Process evidence', pid=process.get('pid'), name=process.get('name') or 'Unknown',
                      parent_pid=process.get('ppid'), parent_name=process.get('parent_name'),
                      parent_path=process.get('parent_path'),
                      command_line=' '.join(process.get('cmdline') or [])[:2000])
        record['reason'] = '; '.join(s['reason'] for s in record['signals']) or 'No adverse local indicator observed; not a malware clearance'
        if record.get('inspection_error'):
            record['reason'] += '; ' + record['inspection_error']
        return record
