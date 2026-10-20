"""Evidence review only. Actual quarantine/restore belongs to Windows Security."""
import os
from .defender import DefenderClient


def open_windows_security():
    if os.name != 'nt':
        raise OSError('Windows Security is unavailable on this platform')
    os.startfile('windowsdefender://threat')


class CortexFixer:
    """Compatibility entry point: no heuristic deletion, killing or service edits."""
    def __init__(self, defender_client=None):
        self.log = []
        self.defender_client = defender_client or DefenderClient()

    def clean_registry(self):
        self.log.append('Registry unchanged: a startup entry is not proof of malware.')

    def remove_malicious_files(self):
        self.log.append('No files deleted: names, suffixes and paths are not sufficient evidence.')

    def kill_bad_processes(self):
        self.log.append('No processes terminated: process names are not reliable identities.')

    def network_flush(self):
        self.log.append('Network settings unchanged.')

    def harden_windows_services(self):
        self.log.append('Services unchanged: hardening requires a separate assessed configuration change.')

    def audit_hosts_file(self):
        self.log.append('Review hosts mappings with their owner; no automatic edits.')

    def run_full_fix(self):
        snapshot = self.defender_client.snapshot()
        self.log = ['EVIDENCE REVIEW: no file/process/registry/service changes were made.']
        if snapshot['status'] != 'available':
            self.log.append('Defender evidence unavailable; no safe/clean conclusion can be made.')
        else:
            for finding in snapshot.get('findings', []):
                self.log.append(f"{finding['desc']} | {finding.get('resource', finding.get('path'))}")
            if not snapshot.get('findings'):
                self.log.append('No Defender detections reported in this query. This is not a safety guarantee.')
        self.log.append('Use Windows Security to review individual detections and available quarantine/restore actions.')
        return '\n'.join(self.log)
