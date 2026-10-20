from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.units import inch
import arabic_reshaper
from bidi.algorithm import get_display
import time
import os
import io
from xml.sax.saxutils import escape

# --- ARABIC SUPPORT ---
try:
    pdfmetrics.registerFont(TTFont('Arial', 'C:\\Windows\\Fonts\\arial.ttf'))
    FONT_NAME = 'Arial'
except:
    FONT_NAME = 'Helvetica'

def make_arabic(text):
    try:
        if FONT_NAME == 'Helvetica': return text # No arabic support without font
        reshaped_text = arabic_reshaper.reshape(text)
        bidi_text = get_display(reshaped_text)
        return bidi_text
    except:
        return text

# --- STYLES ---
styles = getSampleStyleSheet()
style_title = ParagraphStyle(name='Title', parent=styles['Heading1'], fontName=FONT_NAME, fontSize=24, alignment=1, spaceAfter=20, textColor=colors.darkgreen)
style_h1 = ParagraphStyle(name='H1', parent=styles['Heading1'], fontName=FONT_NAME, fontSize=18, spaceAfter=12, textColor=colors.darkblue)
style_normal = ParagraphStyle(name='Normal', parent=styles['Normal'], fontName=FONT_NAME, fontSize=10, leading=14)
style_arabic = ParagraphStyle(name='Arabic', parent=styles['Normal'], fontName=FONT_NAME, fontSize=12, leading=16, alignment=2) # Right align
style_code = ParagraphStyle(name='Code', parent=styles['Code'], fontName='Courier', fontSize=8, backColor=colors.lightgrey, borderPadding=5)

def generate_pdf_report(scan_results, simulation_logs='', ai_analysis='', filename='CORTEX_Final_Report.pdf', web_findings=None):
    # Support positional invocation: generate_pdf_report(result_engine, "output.pdf")
    if isinstance(simulation_logs, str) and simulation_logs.lower().endswith('.pdf'):
        filename = simulation_logs
        simulation_logs = ''
        ai_analysis = ''

    if not web_findings and hasattr(scan_results, 'findings'):
        web_findings = [
            {
                'severity': f.get('severity', 'INFO') if isinstance(f, dict) else getattr(f, 'severity', 'INFO'),
                'type': 'System Finding' if isinstance(f, dict) else getattr(f, 'type', 'System Finding'),
                'desc': f.get('desc', '') if isinstance(f, dict) else getattr(f, 'desc', str(f)),
                'url': 'Local Host / OS',
                'evidence': ''
            }
            for f in scan_results.findings
        ]

    normalized = []
    for finding in web_findings or getattr(scan_results, 'vulnerabilities', []):
        def field(name, default=''):
            value = finding.get(name, default) if isinstance(finding, dict) else getattr(finding, name, default)
            return str(getattr(value, 'value', value))
        normalized.append({
            'severity': field('severity', 'INFO'),
            'type': field('type', 'System Finding'),
            'desc': field('desc', field('description')),
            'url': field('url', 'Local Host / OS'),
            'evidence': field('evidence'),
        })
    web_findings = normalized

    ai_analysis = ai_analysis or ''
    simulation_logs = simulation_logs or ''

    doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []

    # --- 1. TITLE PAGE ---
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("TITANIUM SECURITY AUDIT", style_title))
    story.append(Paragraph(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}", style_normal))
    if web_findings:
        story.append(Paragraph(f"Total Findings: {len(web_findings)}", style_normal))
    
    # CHARTS (Severity Distribution)
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    if web_findings:
        for f in web_findings:
            if f['severity'] in severity_counts:
                severity_counts[f['severity']] += 1
    
    # Pie Chart
    d = Drawing(400, 200)
    pc = Pie()
    pc.x = 100
    pc.y = 50
    pc.width = 100
    pc.height = 100
    pc.data = [severity_counts['CRITICAL'], severity_counts['HIGH'], severity_counts['MEDIUM'], severity_counts['LOW']]
    pc.labels = ['Critical', 'High', 'Medium', 'Low']
    pc.slices[0].fillColor = colors.red
    pc.slices[1].fillColor = colors.orange
    pc.slices[2].fillColor = colors.yellow
    pc.slices[3].fillColor = colors.blue
    d.add(pc)
    story.append(Spacer(1, 0.5*inch))
    story.append(d)
    story.append(PageBreak())

    # --- 2. EXECUTIVE SUMMARY (ARABIC AI) ---
    story.append(Paragraph(make_arabic("1. الملخص التنفيذي"), style_h1))
    for line in ai_analysis.split('\n'):
        if line.strip():
            story.append(Paragraph(escape(make_arabic(line)), style_arabic))
    story.append(PageBreak())

    # --- 3. TECHNICAL FINDINGS (TABLE) ---
    story.append(Paragraph("2. Technical Findings", style_h1))
    
    if web_findings:
        data = [['Severity', 'Type', 'Description']]
        for f in web_findings:
            data.append([f['severity'], Paragraph(escape(f['type']), style_normal), Paragraph(escape(f['desc']), style_normal)])
        
        t = Table(data, colWidths=[80, 150, 300])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), FONT_NAME),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*inch))
        
        # Evidence Section
        story.append(Paragraph("3. Detailed Evidence", style_h1))
        for f in web_findings:
            story.append(Paragraph(escape(f"[{f['severity']}] {f['type']}"), style_normal))
            story.append(Paragraph(escape(f"URL: {f['url']}"), style_code))
            if 'evidence' in f and f['evidence']:
                 story.append(Paragraph(escape(f"Evidence: {f['evidence'][:500]}"), style_code))
            story.append(Spacer(1, 10))

    # --- 4. RED TEAM LOGS ---
    story.append(PageBreak())
    story.append(Paragraph("4. Red Team / Simulation Logs", style_h1))
    if simulation_logs:
        for line in simulation_logs.split('\n'):
            line = line.replace("❌", "[X]").replace("✅", "[OK]").replace("⚠️", "[!]").replace("🚀", ">>")
            story.append(Paragraph(escape(line), style_code))

    doc.build(story)


def generate_scan_pdf_bytes(scan_result):
    """Generate a real PDF using the project's existing ReportLab dependency."""
    output = io.BytesIO()
    generate_pdf_report(scan_result, filename=output)
    return output.getvalue()
