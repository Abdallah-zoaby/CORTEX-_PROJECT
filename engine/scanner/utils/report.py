
import json
import logging
from ..data.types import ScanResult
from core.privacy import shareable_copy
from core.findings import normalize
from html import escape

logger = logging.getLogger("TitaniumScanner")

class ReportGenerator:
    """Advanced report generation system"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self):
        """Load report templates"""
        return {
            'executive': self._executive_template,
            'technical': self._technical_template,
            'developer': self._developer_template,
            'compliance': self._compliance_template,
        }
    
    def generate(self, scan_result: ScanResult, format: str = 'html', template: str = 'executive'):
        """Generate report"""
        scan_result = shareable_copy(scan_result)
        if format == 'json':
            return self._generate_json(scan_result)
        elif format == 'html':
            return self._generate_html(scan_result, template)
        elif format == 'pdf':
            return self._generate_pdf(scan_result, template)
        elif format == 'csv':
            return self._generate_csv(scan_result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, scan_result: ScanResult) -> str:
        """Generate JSON report"""
        return json.dumps({
            'schema_version': 1,
            'scan_id': scan_result.scan_id,
            'target': scan_result.target,
            'start_time': scan_result.start_time.isoformat(),
            'end_time': scan_result.end_time.isoformat(),
            'duration': (scan_result.end_time - scan_result.start_time).total_seconds(),
            'vulnerabilities': [
                {
                    'type': vuln.type.value,
                    'severity': vuln.severity.value,
                    'confidence': vuln.confidence,
                    'confidence_basis': 'detector_score_not_probability',
                    'url': vuln.url,
                    'description': vuln.description,
                    'remediation': vuln.remediation
                }
                for vuln in scan_result.vulnerabilities
            ],
            'summary': scan_result.summary,
            'tech_stack': scan_result.tech_stack,
            'findings': [normalize(vuln, 'web') for vuln in scan_result.vulnerabilities]
        }, indent=2)
    
    def _generate_html(self, scan_result: ScanResult, template: str) -> str:
        """Generate HTML report"""
        template_func = self.templates.get(template, self._executive_template)
        # Escape all string fields before interpolation into legacy templates.
        from dataclasses import fields, is_dataclass
        for obj in [scan_result] + list(scan_result.vulnerabilities):
            if is_dataclass(obj):
                for field in fields(obj):
                    value = getattr(obj, field.name)
                    if isinstance(value, str):
                        setattr(obj, field.name, escape(value))
        return template_func(scan_result)
    
    def _generate_pdf(self, scan_result: ScanResult, template: str) -> bytes:
        """Generate PDF report"""
        from reports.pdf_generator import generate_scan_pdf_bytes
        return generate_scan_pdf_bytes(scan_result)
    
    def _generate_csv(self, scan_result: ScanResult) -> str:
        """Generate CSV report"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Type', 'Severity', 'URL', 'Description', 'Detector score (not probability)', 'CVSS (if established)'])
        
        # Write data
        for vuln in scan_result.vulnerabilities:
            values = [
                vuln.type.value,
                vuln.severity.value,
                vuln.url,
                vuln.description[:100],
                vuln.confidence,
                vuln.cvss_score or 'not established'
            ]
            writer.writerow(["'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else value for value in values])
        
        return output.getvalue()
    
    def _executive_template(self, scan_result: ScanResult) -> str:
        """Executive summary template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {scan_result.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
                .vuln {{ border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
                .critical {{ border-color: #c0392b; }}
                .high {{ border-color: #e74c3c; }}
                .medium {{ border-color: #f39c12; }}
                .low {{ border-color: #f1c40f; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p>Target: {scan_result.target}</p>
                <p>Scan ID: {scan_result.scan_id}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2><p>Only implemented checks and reachable pages were assessed. No malware clearance or formal compliance certification. Detector confidence scores are not calibrated probabilities. Shared reports omit raw response evidence and known secrets.</p>
                <p>Scan completed in {scan_result.summary.get('duration', 0):.1f} seconds</p>
                <p>Vulnerabilities found: {len(scan_result.vulnerabilities)}</p>
                <p>Critical: {scan_result.summary.get('critical', 0)}</p>
                <p>High: {scan_result.summary.get('high', 0)}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
            {"".join([
                f'<div class="vuln {vuln.severity.value.lower()}">'
                f'<h3>{vuln.type.value} ({vuln.severity.value})</h3>'
                f'<p><strong>URL:</strong> {vuln.url}</p>'
                f'<p><strong>Description:</strong> {vuln.description}</p>'
                f'<p><strong>Remediation:</strong> {vuln.remediation}</p>'
                f'</div>'
                for vuln in scan_result.vulnerabilities
            ])}
        </body>
        </html>
        """
    
    def _technical_template(self, scan_result: ScanResult) -> str:
        details = ''.join('<section><h3>' + escape(v.type.value) + '</h3><pre>' +
                          escape(json.dumps(normalize(v, 'web'), indent=2, default=str)) + '</pre></section>'
                          for v in scan_result.vulnerabilities)
        return self._executive_template(scan_result).replace('</body>', '<h2>Sanitized technical evidence</h2>' + details + '</body>')

    def _developer_template(self, scan_result: ScanResult) -> str:
        details = ''.join('<section><h3>' + escape(v.type.value) + '</h3><pre>' +
                          getattr(v, 'remediation_patch', '') + '</pre><p>' + v.remediation + '</p></section>'
                          for v in scan_result.vulnerabilities)
        return self._executive_template(scan_result).replace('</body>', '<h2>Review proposed remediation before applying</h2>' + details + '</body>')

    def _compliance_template(self, scan_result: ScanResult) -> str:
        return self._executive_template(scan_result).replace('</body>', '<h2>Compliance status: NOT ASSESSED</h2><p>These checks do not establish fulfillment of all controls. Independent scope and control evidence are required.</p></body>')
