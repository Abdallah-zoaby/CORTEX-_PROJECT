"""Bounded file evidence collection; no fabricated malware hash database."""
import hashlib
import os
from .evidence import EvidenceInspector
from .windows_security import signatures


def get_file_hash(file_path):
    digest = hashlib.sha256()
    try:
        with open(file_path, 'rb') as stream:
            for block in iter(lambda: stream.read(128 * 1024), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def check_digital_signature(file_path):
    path = os.path.abspath(os.fspath(file_path))
    result = signatures([path]).get(os.path.normcase(path), {})
    return result.get('status') == 'Valid'


def scan_suspicious_files(directory, max_files=15, inspector=None):
    """Compatibility name: returns observations, including explicit unknowns.

    This is a bounded sample, not a full-volume antivirus scan.
    """
    inspector = inspector or EvidenceInspector()
    results = []
    ignored = {'node_modules', '.git', 'venv', '.venv', '__pycache__', '.audit_deps',
               'cache', 'code cache', 'gpu_cache'}
    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d.lower() not in ignored and not d.startswith('.'))
        for name in sorted(files):
            if len(results) >= max_files:
                return results
            if name.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs')):
                results.append(inspector.inspect_file(os.path.join(root, name)))
    return results
