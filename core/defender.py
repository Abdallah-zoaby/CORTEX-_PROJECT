"""Read Defender evidence without turning old detections into active infections."""
from datetime import datetime, timezone
import os
from pathlib import Path
from .windows_security import powershell_json, SecurityQueryError


SNAPSHOT_SCRIPT = r'''
$s = Get-MpComputerStatus -ErrorAction Stop
$threats = @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatID,ThreatName,SeverityID,CategoryID,IsActive,Resources)
$detections = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object DetectionID,ThreatID,Resources,ProcessName,ThreatStatusID,ActionSuccess,AdditionalActionsBitMask,
    @{n='detected_at';e={if($_.InitialDetectionTime){$_.InitialDetectionTime.ToUniversalTime().ToString('o')}}},
    @{n='changed_at';e={if($_.LastThreatStatusChangeTime){$_.LastThreatStatusChangeTime.ToUniversalTime().ToString('o')}}})
[pscustomobject]@{
    health=($s | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AMRunningMode,AntivirusSignatureAge,AntivirusSignatureVersion);
    threats=$threats; detections=$detections
} | ConvertTo-Json -Depth 8 -Compress
'''
SCAN_SCRIPT = r'''
$path = [string](ConvertFrom-Json $env:CORTEX_SECURITY_INPUT)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'File unavailable' }
Start-MpScan -ScanType CustomScan -ScanPath $path -ErrorAction Stop
[pscustomobject]@{command_completed=$true} | ConvertTo-Json -Compress
'''
STATUS_NAMES = {0: 'unknown', 1: 'detected', 2: 'cleaned', 3: 'quarantined',
                4: 'removed', 5: 'allowed', 6: 'blocked', 102: 'quarantine_failed',
                103: 'remove_failed', 104: 'allow_failed', 105: 'abandoned', 107: 'block_failed'}


def resource_path(resource):
    """Keep resource syntax intact if it is not an unambiguous local file."""
    for prefix in ('file:_', 'containerfile:_'):
        if isinstance(resource, str) and resource.lower().startswith(prefix):
            candidate = resource[len(prefix):]
            if len(candidate) > 2 and candidate[1:3] in (':\\', ':/') and '->' not in candidate:
                return candidate
    return None


def _list(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def parse_snapshot(data):
    if not isinstance(data, dict) or not isinstance(data.get('health'), dict):
        raise SecurityQueryError('Defender health response is incomplete')
    if not isinstance(data['health'].get('AntivirusEnabled'), bool):
        raise SecurityQueryError('Defender protection state is unknown')
    for key in ('threats', 'detections'):
        if key not in data or not isinstance(data[key], list):
            raise SecurityQueryError('Defender history response is incomplete')
        if any(not isinstance(row, dict) or row.get('ThreatID') is None for row in data[key]):
            raise SecurityQueryError('Defender history contains incomplete records')
    threats = {str(t.get('ThreatID')): t for t in data['threats'] if isinstance(t, dict)}
    findings = []
    seen = set()
    for detection in data['detections']:
        if not isinstance(detection, dict):
            continue
        threat = threats.get(str(detection.get('ThreatID')), {})
        status_id = detection.get('ThreatStatusID')
        status = STATUS_NAMES.get(status_id, 'unknown')
        handled = (status_id in (2, 3, 4, 6) and detection.get('ActionSuccess') is True
                   and detection.get('AdditionalActionsBitMask', 0) == 0)
        # Historical family state cannot establish that every old file is active.
        if handled:
            activity = 'remediated'
        elif threat.get('IsActive') is True and status_id in (1, 102, 103, 104, 105, 107):
            activity = 'active'
        elif threat.get('IsActive') is False:
            activity = 'historical'
        else:
            activity = 'unresolved'
        for resource in _list(detection.get('Resources')) or ['Resource not reported']:
            key = (str(detection.get('ThreatID')), str(detection.get('DetectionID')), str(resource))
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                'type': 'Defender detection', 'source': 'Microsoft Defender',
                'classification': 'engine_detection', 'confidence': 'engine_reported',
                'severity': {1: 'LOW', 2: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}.get(threat.get('SeverityID'), 'MEDIUM')
                            if activity == 'active' else 'INFO',
                'path': resource_path(resource), 'resource': resource,
                'threat_id': detection.get('ThreatID'), 'detection_id': detection.get('DetectionID'),
                'threat_name': threat.get('ThreatName', 'Name unavailable'),
                'detection_kind': 'potentially_unwanted' if str(threat.get('ThreatName', '')).startswith('PUA:') else 'engine_reported_threat',
                'activity': activity, 'action_status': status,
                'detected_at': detection.get('detected_at'), 'changed_at': detection.get('changed_at'),
                'action_success': detection.get('ActionSuccess'),
                'additional_actions': detection.get('AdditionalActionsBitMask'),
                'desc': f"Defender: {threat.get('ThreatName', 'Name unavailable')} ({activity}; {status})",
                'recommended_action': 'Review this detection in Windows Security; do not infer current infection from history alone',
            })
    # An active family can coexist with remediated historical resources. Keep the
    # family report visible without marking those old resource paths as active.
    reported_ids = {str(f['threat_id']) for f in findings if f['activity'] == 'active'}
    for threat_id, threat in threats.items():
        if threat_id not in reported_ids and threat.get('IsActive') is True:
            findings.append(dict(type='Defender detection', source='Microsoft Defender',
                classification='engine_detection', confidence='engine_reported', activity='active',
                severity={1: 'LOW', 2: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}.get(threat.get('SeverityID'), 'MEDIUM'),
                threat_id=threat.get('ThreatID'), detection_id=None, path=None,
                resource=threat.get('Resources', []), threat_name=threat.get('ThreatName', 'Name unavailable'),
                action_status='unknown', detected_at=None,
                desc=f"Defender active threat: {threat.get('ThreatName', 'Name unavailable')}",
                recommended_action='Review active detection in Windows Security'))
    return {'status': 'available', 'health': data['health'], 'findings': findings,
            'checked_at': datetime.now(timezone.utc).isoformat()}


class DefenderClient:
    def __init__(self, runner=powershell_json):
        self.runner = runner

    def snapshot(self):
        try:
            return parse_snapshot(self.runner(SNAPSHOT_SCRIPT, timeout=30))
        except (SecurityQueryError, ValueError, TypeError) as exc:
            return {'status': 'unavailable', 'health': {}, 'findings': [], 'error': str(exc),
                    'checked_at': datetime.now(timezone.utc).isoformat()}

    def scan_file(self, path, *, consent=False):
        if not consent:
            return {'status': 'not_started', 'error': 'Explicit consent is required; Defender may remediate according to Windows policy'}
        try:
            resolved = Path(path).resolve(strict=True)
            if not resolved.is_file() or any(c in str(resolved) for c in '*?[]'):
                raise ValueError('Select one existing file with no wildcard characters')
            response = self.runner(SCAN_SCRIPT, str(resolved), timeout=300)
            if not isinstance(response, dict) or response.get('command_completed') is not True:
                raise SecurityQueryError('Defender did not confirm scan completion')
            snapshot = self.snapshot()
            return {'status': 'command_completed', 'path': os.fspath(resolved), 'snapshot': snapshot,
                    'note': 'Command completed; absence of a matching detection is not proof of safety'}
        except (SecurityQueryError, OSError, ValueError) as exc:
            return {'status': 'unknown', 'error': str(exc),
                    'note': 'A timed-out Defender scan may continue in Windows; check Windows Security'}
