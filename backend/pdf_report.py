from fpdf import FPDF
from datetime import datetime
import os
import json

class SOCReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        self.primary_color = (30, 50, 80)
        self.accent_color = (0, 150, 200)
        self.bg_light = (245, 247, 250)
        
    def header(self):
        # Header background
        self.set_fill_color(*self.primary_color)
        self.rect(0, 0, 210, 30, 'F')
        
        self.set_y(10)
        self.set_font('Helvetica', 'B', 18)
        self.set_text_color(255, 255, 255)
        self.cell(10)
        self.cell(0, 10, 'ILA-SOC SECURITY OPERATIONS CENTER', align='L')
        
        self.set_font('Helvetica', '', 8)
        self.cell(-10)
        self.cell(0, 10, 'CONFIDENTIAL SECURITY REPORT', align='R', new_x='LMARGIN', new_y='NEXT')
        self.ln(10)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'ILA-SOC Intelligence Report | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Page {self.page_no()}/{{nb}}', align='C')

    def section_header(self, title):
        self.ln(5)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*self.primary_color)
        self.cell(0, 10, title.upper(), new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(*self.accent_color)
        self.set_line_width(0.5)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(5)

    def add_kpi_card(self, x, y, label, value, color=(30, 50, 80)):
        self.set_xy(x, y)
        self.set_fill_color(255, 255, 255)
        self.set_draw_color(220, 220, 220)
        self.rect(x, y, 40, 20, 'FD')
        
        self.set_xy(x, y + 2)
        self.set_font('Helvetica', 'B', 8)
        self.set_text_color(120, 120, 120)
        self.cell(40, 5, label.upper(), align='C', new_x='LMARGIN', new_y='NEXT')
        
        self.set_x(x)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*color)
        self.cell(40, 8, str(value), align='C')

def humanize_log(msg_obj):
    """Convert raw log dict/string into human-readable SOC description."""
    if isinstance(msg_obj, str):
        try:
            msg_obj = json.loads(msg_obj)
        except:
            return msg_obj
            
    if not isinstance(msg_obj, dict):
        return str(msg_obj)
        
    log_text = str(msg_obj.get('log_text', ''))
    event_type = str(msg_obj.get('event_type', ''))
    
    mapping = {
        'brute_force': 'Detected multiple failed authentication attempts suggesting a brute-force attack.',
        'sql_injection': 'Detected SQL injection patterns in inbound web traffic targeting database queries.',
        'xss': 'Identified Cross-Site Scripting (XSS) payload in web request parameters.',
        'path_traversal': 'Detected attempt to access restricted directories via path traversal sequences.',
        'port_scan': 'Identified systematic port scanning activity consistent with reconnaissance behavior.',
        'malware': 'Telemetry indicates execution or presence of known malicious binary or script.',
        'suspicious_command': 'Detected execution of high-risk system commands (e.g., encoded powershell).',
        'phishing': 'User interacted with or was redirected to a verified phishing URL.'
    }
    
    # Try to find a match in the mapping
    for key, description in mapping.items():
        if key in log_text.lower() or key in event_type.lower():
            return description
            
    return log_text if log_text else "Detected anomalous activity requiring analyst review."

def generate_incident_report(analytics, logs, incidents=None, start_date=None, end_date=None):
    pdf = SOCReport()
    pdf.alias_nb_pages()
    
    # --- PAGE 1: EXECUTIVE SUMMARY ---
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 15, 'Security Incident Intelligence Report', align='L', new_x='LMARGIN', new_y='NEXT')
    
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 100, 100)
    report_meta = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Period: Last 24 Hours"
    if start_date and end_date:
        report_meta = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Period: {start_date} to {end_date}"
    pdf.cell(0, 5, report_meta, align='L', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(10)
    
    pdf.section_header('Executive KPIs')
    y_kpi = pdf.get_y()
    pdf.add_kpi_card(10, y_kpi, 'Total Logs', analytics.get('total_logs', 0))
    pdf.add_kpi_card(55, y_kpi, 'Active Alerts', analytics.get('active_alerts', 0), (220, 50, 50))
    pdf.add_kpi_card(100, y_kpi, 'Open Incidents', analytics.get('open_incidents', 0), (255, 165, 0))
    pdf.add_kpi_card(145, y_kpi, 'Active Agents', analytics.get('active_agents', 0), (0, 150, 200))
    pdf.ln(25)
    
    pdf.section_header('Threat Posture Summary')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    
    posture_text = (
        f"During this reporting period, the ILA-SOC system monitored {analytics.get('total_logs', 0)} total events across "
        f"{analytics.get('active_agents', 0)} connected endpoints. Our detection engine identified {analytics.get('total_malicious', 0)} "
        f"verified malicious events and {analytics.get('total_suspicious', 0)} suspicious anomalies. "
        f"The current enterprise threat score is {analytics.get('threat_score', 0)}/100, with a detection accuracy of "
        f"{analytics.get('detection_accuracy', 0)}% based on analyst triage of {analytics.get('false_positives', 0)} false positives."
    )
    pdf.multi_cell(0, 6, posture_text)
    
    pdf.ln(5)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 10, 'Threat Category Distribution', new_x='LMARGIN', new_y='NEXT')
    
    attack_types = analytics.get('attack_types', {})
    if attack_types:
        pdf.set_font('Helvetica', '', 9)
        for name, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            pdf.cell(80, 6, name)
            # Simple bar
            pdf.set_fill_color(230, 230, 230)
            pdf.rect(100, pdf.get_y() + 1, 80, 4, 'F')
            width = min(80, (count / (analytics.get('total_malicious', 1) or 1)) * 80)
            pdf.set_fill_color(0, 150, 200)
            pdf.rect(100, pdf.get_y() + 1, width, 4, 'F')
            pdf.cell(0, 6, f"{count}", align='R', new_x='LMARGIN', new_y='NEXT')
    
    # --- PAGE 2: ALERT INTELLIGENCE ---
    pdf.add_page()
    pdf.section_header('Security Alert Intelligence')
    
    malicious_logs = [log for log in logs if log.get('status') == 'Malicious'][:15]
    if malicious_logs:
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(30, 50, 80)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(30, 8, 'Timestamp', border=1, fill=True)
        pdf.cell(20, 8, 'Host', border=1, fill=True)
        pdf.cell(15, 8, 'Severity', border=1, fill=True)
        pdf.cell(115, 8, 'Security Description & Analyst Insight', border=1, fill=True, new_x='LMARGIN', new_y='NEXT')
        
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(40, 40, 40)
        for i, log in enumerate(malicious_logs):
            fill = i % 2 == 0
            pdf.set_fill_color(250, 250, 250) if fill else pdf.set_fill_color(255, 255, 255)
            
            ts = str(log.get('timestamp', ''))[:16]
            host = str(log.get('blocked_ip') or 'N/A')[:12]
            desc = humanize_log(log.get('message', ''))
            
            pdf.cell(30, 8, ts, border=1, fill=fill)
            pdf.cell(20, 8, host, border=1, fill=fill)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(15, 8, 'CRITICAL', border=1, fill=fill, align='C')
            pdf.set_text_color(40, 40, 40)
            pdf.cell(115, 8, str(desc)[:85], border=1, fill=fill, new_x='LMARGIN', new_y='NEXT')
    else:
        pdf.cell(0, 10, 'No critical alerts identified in this reporting window.', align='C')

    # --- PAGE 3: INCIDENT INVESTIGATION ---
    pdf.add_page()
    pdf.section_header('Incident Investigation Summary')
    
    if incidents:
        for inc in incidents[:5]:
            pdf.set_font('Helvetica', 'B', 11)
            pdf.set_text_color(*pdf.primary_color)
            pdf.cell(0, 8, f"INC-{inc.get('id')}: {inc.get('title', 'Unknown Incident')}", new_x='LMARGIN', new_y='NEXT')
            
            pdf.set_font('Helvetica', 'B', 8)
            pdf.set_text_color(100, 100, 100)
            meta = f"Status: {inc.get('status')} | Severity: {inc.get('severity')} | Owner: {inc.get('owner', 'Unassigned')}"
            pdf.cell(0, 5, meta, new_x='LMARGIN', new_y='NEXT')
            
            pdf.ln(2)
            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(60, 60, 60)
            summary = inc.get('summary') or 'No executive summary available for this incident.'
            pdf.multi_cell(0, 5, str(summary)[:400] + '...')
            
            pdf.ln(2)
            # IOCs if available
            iocs = inc.get('iocs')
            if iocs:
                try:
                    ioc_list = json.loads(iocs) if isinstance(iocs, str) else iocs
                    if ioc_list and isinstance(ioc_list, list):
                        pdf.set_font('Helvetica', 'B', 8)
                        pdf.cell(20, 5, 'Key IOCs: ')
                        pdf.set_font('Helvetica', '', 8)
                        ioc_str = ", ".join([f"{str(i.get('type',''))}: {str(i.get('value',''))}" for i in ioc_list[:3]])
                        pdf.cell(0, 5, ioc_str, new_x='LMARGIN', new_y='NEXT')
                except: pass
            
            pdf.ln(5)
            pdf.set_draw_color(230, 230, 230)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
    else:
        pdf.cell(0, 10, 'No active incidents found.', align='C')

    # --- PAGE 4: THREAT INTEL & MITRE ---
    pdf.add_page()
    pdf.section_header('Threat Intelligence & MITRE Analysis')
    
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 10, 'MITRE ATT&CK® Tactic Breakdown', new_x='LMARGIN', new_y='NEXT')
    
    mitre = analytics.get('mitre_counts', {})
    tactics = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    
    pdf.set_font('Helvetica', '', 9)
    for t in tactics:
        count = mitre.get(t, 0)
        pdf.cell(60, 7, t)
        pdf.set_fill_color(240, 240, 240)
        pdf.rect(70, pdf.get_y() + 1.5, 100, 4, 'F')
        if count > 0:
            pdf.set_fill_color(0, 150, 200)
            pdf.rect(70, pdf.get_y() + 1.5, min(100, count * 10), 4, 'F')
        pdf.cell(0, 7, str(count), align='R', new_x='LMARGIN', new_y='NEXT')
        
    pdf.ln(10)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 10, 'Intelligence Indicators (IOC) Summary', new_x='LMARGIN', new_y='NEXT')
    
    # Extract unique IOCs from incidents
    unique_ips = set()
    unique_domains = set()
    if incidents:
        for inc in incidents:
            try:
                iocs = json.loads(inc.get('iocs', '[]')) if isinstance(inc.get('iocs'), str) else inc.get('iocs', [])
                for i in iocs:
                    if i.get('type') == 'IP': unique_ips.add(i.get('value'))
                    if i.get('type') == 'Domain': unique_domains.add(i.get('value'))
            except: pass

    pdf.set_font('Helvetica', '', 9)
    pdf.cell(50, 8, 'Malicious IPs Observed:')
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(0, 8, ", ".join(list(unique_ips)[:5]) or "None observed", new_x='LMARGIN', new_y='NEXT')
    
    pdf.set_font('Helvetica', '', 9)
    pdf.cell(50, 8, 'Suspicious Domains:')
    pdf.set_font('Helvetica', 'B', 9)
    pdf.cell(0, 8, ", ".join(list(unique_domains)[:5]) or "None observed", new_x='LMARGIN', new_y='NEXT')

    # --- PAGE 5: RESPONSE & ACTIONS ---
    pdf.add_page()
    pdf.section_header('Response & Analyst Workflows')
    
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 8, 'L1 Alert Triage Operations', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    pdf.multi_cell(0, 5, "Analyst monitors the real-time detection feed. High-confidence malicious alerts are promoted to incidents for L2 investigation. False positives are tagged and suppressed to tune detection heuristics.")
    
    pdf.ln(5)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 8, 'L2 Incident Investigation Workflow', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    pdf.multi_cell(0, 5, "Incidents are assigned to specialized analysts. Investigation includes process lineage analysis, timeline correlation, and IOC extraction. All findings are mapped to the MITRE ATT&CK framework.")
    
    pdf.ln(5)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(0, 8, 'Automated Countermeasures', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9)
    pdf.multi_cell(0, 5, "The platform triggers automated email escalations to L3 responders for critical threats. IP blocking and endpoint telemetry enrichment are active during the incident lifecycle.")

    # Save PDF
    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads', 'reports')
    os.makedirs(report_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'ILA_SOC_Intelligence_Report_{timestamp}.pdf'
    filepath = os.path.join(report_dir, filename)
    
    pdf.output(filepath)
    return filepath, filename
