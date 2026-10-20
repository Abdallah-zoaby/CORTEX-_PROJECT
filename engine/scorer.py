"""Evidence-aware summary; numerical severity never proves compromise."""


from core.findings import normalize


class RiskEngine:
    def __init__(self):
        self.total_score = 0
        self.findings = []
        self.coverage = {}
        self._identities = set()

    def add_finding(self, description, severity, **evidence):
        classification = evidence.get('classification', 'observation')
        if classification in ('observation', 'unknown', 'configuration_observation'):
            severity = 'INFO'
        if classification == 'engine_detection' and evidence.get('activity') != 'active':
            severity = 'INFO'
        key = tuple(str(evidence.get(k, '')) for k in (
            'source', 'classification', 'path', 'pid', 'threat_id', 'detection_id')) + (description,)
        if key in self._identities:
            return
        self._identities.add(key)
        record = dict(evidence)
        record.update(desc=description, severity=severity,
                      color={'CRITICAL': 'DARKRED', 'HIGH': 'RED', 'MEDIUM': 'ORANGE',
                             'LOW': 'GREEN'}.get(severity, 'BLACK'))
        self.total_score += {'CRITICAL': 50, 'HIGH': 30, 'MEDIUM': 15, 'LOW': 5}.get(severity, 0)
        self.findings.append(normalize(record))

    def add_evidence(self, record):
        record = dict(record)
        description = record.pop('desc', None) or record.get('reason') or record.get('reasons') or 'Evidence observation'
        severity = record.pop('severity', 'INFO')
        self.add_finding(description, severity, **record)

    def get_verdict(self):
        if any(f.get('classification') == 'engine_detection' and f.get('activity') == 'active'
               for f in self.findings):
            return 'ACTIVE DETECTIONS REPORTED BY DEFENDER - review Windows Security', 'RED'
        if any(f.get('classification') == 'corroborated_suspicion' for f in self.findings):
            return 'CORROBORATED INDICATORS - investigation required', 'ORANGE'
        if (self.coverage.get('defender_status') != 'available'
                or self.coverage.get('assessment_status', 'completed') != 'completed'
                or self.coverage.get('defender_health', {}).get('AntivirusEnabled') is not True
                or self.coverage.get('unknown_files', 0)
                or any(self.coverage.get(key) for key in ('process_error', 'configuration_error', 'file_errors'))):
            return 'INCOMPLETE VERIFICATION - unknowns remain; no safety verdict', 'ORANGE'
        return 'NO ACTIVE ENGINE DETECTIONS REPORTED - not a guarantee of safety', 'GREEN'
