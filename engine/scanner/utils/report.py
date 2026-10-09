
import json
import logging
from ..data.types import ScanResult

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
                    'url': vuln.url,
                    'description': vuln.description,
                    'remediation': vuln.remediation
                }
                for vuln in scan_result.vulnerabilities
            ],
            'summary': scan_result.summary,
            'tech_stack': scan_result.tech_stack
        }, indent=2)
    
    def _generate_html(self, scan_result: ScanResult, template: str) -> str:
        """Generate HTML report"""
        template_func = self.templates.get(template, self._executive_template)
        return template_func(scan_result)
    
    def _generate_pdf(self, scan_result: ScanResult, template: str) -> bytes:
        """Generate PDF report"""
        # Placeholder for PDF generation
        html_content = self._generate_html(scan_result, template)
        return html_content.encode()
    
    def _generate_csv(self, scan_result: ScanResult) -> str:
        """Generate CSV report"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Type', 'Severity', 'URL', 'Description', 'Confidence', 'CVSS'])
        
        # Write data
        for vuln in scan_result.vulnerabilities:
            writer.writerow([
                vuln.type.value,
                vuln.severity.value,
                vuln.url,
                vuln.description[:100],
                vuln.confidence,
                vuln.cvss_score
            ])
        
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
                <h2>Executive Summary</h2>
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
        return self._executive_template(scan_result)

    def _developer_template(self, scan_result: ScanResult) -> str:
        return self._executive_template(scan_result)

    def _compliance_template(self, scan_result: ScanResult) -> str:
        return self._executive_template(scan_result)
