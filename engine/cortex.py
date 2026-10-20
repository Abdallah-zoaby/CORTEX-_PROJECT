"""Read-only evidence assessment; Defender scanning requires a separate action."""
import os
from core import network, system, forensics
from core.defender import DefenderClient
from core.evidence import EvidenceInspector
from engine.scorer import RiskEngine
from core.lifecycle import ScanControl, ScanStopped


class CortexScanner:
    def __init__(self, defender_client=None, inspector_factory=EvidenceInspector):
        self.risk_engine = RiskEngine()
        self.defender_client = defender_client or DefenderClient()
        self.inspector_factory = inspector_factory

    def run_full_scan(self, ui_callback=None, progress_callback=None, control=None):
        control = control or ScanControl()
        self.risk_engine = RiskEngine()
        try:
            control.checkpoint()
            result = self._collect(ui_callback, progress_callback, control)
            result.coverage['assessment_status'] = 'completed'
            return result
        except ScanStopped as stopped:
            self.risk_engine.coverage.update(assessment_status=stopped.status,
                scope='Interrupted bounded host assessment; remaining items were not assessed')
            return self.risk_engine

    def _collect(self, ui_callback, progress_callback, control):
        self.risk_engine = result = RiskEngine()
        inspector = self.inspector_factory()

        def log(message, level='INFO'):
            print(f'[{level}] {message}')
            if ui_callback:
                ui_callback(message, level)

        def progress(value):
            if progress_callback:
                progress_callback(value)

        def add(record):
            control.checkpoint()
            result.add_evidence(record)
            if record.get('classification') in ('engine_detection', 'corroborated_suspicion'):
                log(f"{record.get('classification')}: {record.get('desc', record.get('reason', ''))}", record.get('severity', 'INFO'))

        log('Starting local evidence assessment. No automatic deletion, process termination or cloud file submission.')
        progress(0.02)
        defender = self.defender_client.snapshot()
        control.checkpoint()
        result.coverage.update(defender_status=defender['status'], defender_health=defender.get('health', {}),
                               defender_error=defender.get('error'), defender_checked_at=defender.get('checked_at'))
        if defender['status'] != 'available':
            log('Defender evidence is unavailable. This must not be interpreted as a clean result.', 'WARNING')
        for finding in defender.get('findings', []):
            add(finding)
        progress(0.15)

        try:
            processes = system.scan_running_processes()
            result.coverage['processes_enumerated'] = len(processes)
            for process in processes:
                control.checkpoint()
                # Reuse file evidence for all processes backed by the same executable.
                raw = dict(process, exe=process.get('exe') or process.get('path'),
                           ppid=process.get('parent_pid'))
                add(inspector.inspect_process(raw))
            log(f'Collected {len(processes)} process observations; location/name alone is not malware.')
        except ScanStopped:
            raise
        except Exception as exc:
            result.coverage['process_error'] = type(exc).__name__
            log('Process enumeration incomplete; inaccessible items remain unknown.', 'WARNING')
        progress(0.5)

        try:
            for port, detail, severity in network.scan_open_ports():
                add(dict(type='Listening service', source='CORTEX configuration inventory',
                    classification='configuration_observation', confidence='context_only', severity='INFO',
                    desc=f'Listening port {port}: {detail}; exposure requires interface/firewall context',
                    recommended_action='Review whether this service is expected; an open port is not an infection'))
            for issue in network.check_dns_integrity():
                add(dict(type='Hosts entry', source='CORTEX configuration inventory', classification='configuration_observation',
                    confidence='context_only', severity='INFO', desc=issue,
                    recommended_action='Review the mapping and its owner before editing the hosts file'))
            for task in system.scan_scheduled_tasks():
                add(dict(type='Scheduled task', source='CORTEX task inventory', classification='configuration_observation',
                    confidence='context_only', severity='INFO', desc=str(task),
                    recommended_action='Review task executable, publisher and purpose; scripts are not automatically malware'))
        except ScanStopped:
            raise
        except Exception as exc:
            result.coverage['configuration_error'] = type(exc).__name__
        progress(0.65)

        user = os.path.expanduser('~')
        targets = [os.path.join(user, 'Desktop'), os.path.join(user, 'Documents'),
                   os.path.join(user, 'AppData', 'Roaming'), os.environ.get('TEMP')]
        result.coverage['sampled_locations'] = []
        for directory in dict.fromkeys(p for p in targets if p):
            control.checkpoint()
            if not os.path.isdir(directory):
                continue
            result.coverage['sampled_locations'].append(directory)
            try:
                for record in forensics.scan_suspicious_files(directory, max_files=15, inspector=inspector, control=control):
                    add(record)
            except ScanStopped:
                raise
            except Exception as exc:
                result.coverage.setdefault('file_errors', []).append(type(exc).__name__)
        files = {f.get('path'): f for f in result.findings if f.get('path') and 'inspection_status' in f}
        result.coverage.update(files_observed=len(files),
            metadata_collected=sum(f.get('inspection_status') == 'metadata_collected' for f in files.values()),
            unknown_files=sum(f.get('inspection_status') != 'metadata_collected' for f in files.values()),
            scope='Running process executables plus up to 15 candidate files per listed location; not a full-volume antivirus scan',
            limits='90-second content-inspection budget; 256 MiB per-file hashing limit; signature queries have their own timeout')
        log(result.coverage['scope'])
        log(result.get_verdict()[0])
        progress(1.0)
        return result
