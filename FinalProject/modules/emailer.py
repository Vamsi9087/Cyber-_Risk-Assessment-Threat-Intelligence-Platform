# modules/emailer.py
import smtplib
import os
from email.mime.text        import MIMEText
from email.mime.multipart   import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
import pandas as pd

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports')
REPORTS_DIR = os.path.normpath(REPORTS_DIR)
os.makedirs(REPORTS_DIR, exist_ok=True)

SEV_COLOURS = {
    'Critical': '#7f1d1d',
    'High':     '#dc2626',
    'Medium':   '#ea580c',
    'Low':      '#16a34a',
}


def _safe_str(val, max_len=None):
    """Convert any value to a plain ASCII string safe for fpdf Helvetica font."""
    if val is None or (isinstance(val, float) and pd.isna(val)):
        result = ''
    else:
        result = str(val)

    replacements = {
        '\u2014': '-',
        '\u2013': '-',
        '\u2012': '-',
        '\u2010': '-',
        '\u2018': "'",
        '\u2019': "'",
        '\u201c': '"',
        '\u201d': '"',
        '\u2026': '...',
        '\u2022': '*',
        '\u00b7': '.',
        '\u00a0': ' ',
    }
    for char, replacement in replacements.items():
        result = result.replace(char, replacement)

    result = result.encode('ascii', errors='ignore').decode('ascii')

    if max_len:
        result = result[:max_len]
    return result


def generate_pdf_report(df: pd.DataFrame, scan_time: str, output_path: str) -> str:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Header ────────────────────────────────────────────────────────────────
    pdf.set_fill_color(15, 17, 23)
    pdf.rect(0, 0, 210, 35, 'F')
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(255, 255, 255)
    pdf.set_y(10)
    pdf.cell(0, 10, 'CyberScan Pro - Scan Report', align='C', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, 'Generated: ' + _safe_str(scan_time), align='C', ln=True)
    pdf.ln(12)

    # ── Executive Summary ─────────────────────────────────────────────────────
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 8, 'Executive Summary', ln=True)
    pdf.set_font('Helvetica', '', 10)

    try:
        max_risk = '{:.2f} / 10.00'.format(df['risk_score'].max())
    except Exception:
        max_risk = 'N/A'

    try:
        vt_flagged = str(int((df['malicious_reports'] > 0).sum()))
    except Exception:
        vt_flagged = '0'

    kpis = [
        ('Hosts Scanned',     str(df['ip'].nunique())),
        ('Open Ports',        str(len(df))),
        ('Critical Findings', str(int((df['severity'] == 'Critical').sum()))),
        ('High Findings',     str(int((df['severity'] == 'High').sum()))),
        ('Max Risk Score',    max_risk),
        ('VT Flagged IPs',    vt_flagged),
    ]
    for label, val in kpis:
        pdf.cell(80, 7, _safe_str(label), border=1)
        pdf.cell(40, 7, _safe_str(val),   border=1, ln=True)
    pdf.ln(6)

    # ── Detailed Findings ─────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(0, 8, 'Detailed Findings (Critical + High)', ln=True)
    pdf.set_font('Helvetica', 'B', 8)

    headers = ['IP', 'Port', 'Service', 'Severity', 'Risk', 'Country', 'Recommendation']
    widths  = [30,    15,     20,        18,          12,     16,        79]

    for h, w in zip(headers, widths):
        pdf.set_fill_color(30, 58, 138)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(w, 7, h, border=1, fill=True)
    pdf.ln()

    pdf.set_font('Helvetica', '', 7)

    try:
        alert_df = df[df['severity'].isin(['Critical', 'High'])].sort_values(
            'risk_score', ascending=False
        )
    except Exception:
        alert_df = df

    for idx, (_, row) in enumerate(alert_df.iterrows()):
        bg = (249, 250, 251) if idx % 2 == 0 else (255, 255, 255)
        pdf.set_fill_color(*bg)
        pdf.set_text_color(30, 30, 30)

        try:
            risk_val = '{:.2f}'.format(float(row.get('risk_score', 0)))
        except Exception:
            risk_val = '0.00'

        vals = [
            _safe_str(row.get('ip',             ''), 30),
            _safe_str(row.get('port',           ''), 10),
            _safe_str(row.get('service',        ''), 15),
            _safe_str(row.get('severity',       ''), 12),
            risk_val,
            _safe_str(row.get('country',        ''), 12),
            _safe_str(row.get('recommendation', ''), 55),
        ]
        for val, w in zip(vals, widths):
            pdf.cell(w, 6, val, border=1, fill=True)
        pdf.ln()

    # ── Footer ────────────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.set_font('Helvetica', 'I', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(
        0, 6,
        'CyberScan Pro  |  Confidential  |  For authorised recipients only',
        align='C', ln=True
    )

    pdf.output(output_path)
    return output_path


def _build_html_body(df: pd.DataFrame, scan_time: str) -> str:
    alert_df = df.sort_values('risk_score', ascending=False)
    count    = len(alert_df)
    crit_cnt = int((df['severity'] == 'Critical').sum())
    high_cnt = int((df['severity'] == 'High').sum())
    med_cnt  = int((df['severity'] == 'Medium').sum())
    low_cnt  = int((df['severity'] == 'Low').sum())

    rows_html = ''
    for idx, (_, row) in enumerate(alert_df.iterrows()):
        bg  = '#f9fafb' if idx % 2 == 0 else '#ffffff'
        sev = str(row.get('severity', ''))
        col = SEV_COLOURS.get(sev, '#374151')
        rec = str(row.get('recommendation', ''))[:80]
        rows_html += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;color:#1e40af;">{row.get("ip","")}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{row.get("port","")}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{row.get("service","")}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;color:{col};font-weight:bold;">{sev}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;text-align:center;font-weight:bold;">{float(row.get("risk_score",0)):.1f}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;">{row.get("country","")}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;color:#374151;">{rec}</td>'
            f'</tr>'
        )

    return f'''
    <html><body style="font-family:Arial,sans-serif;background:#f3f4f6;margin:0;padding:20px;">
    <div style="max-width:900px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.12);">
      <div style="background:#0f172a;padding:24px 32px;">
        <h1 style="color:white;margin:0;font-size:22px;">CyberScan Pro - Security Alert</h1>
        <p style="color:#94a3b8;margin:6px 0 0;">Scan completed: {scan_time}</p>
      </div>
      <div style="padding:24px 32px;">
        <div style="display:flex;gap:16px;margin-bottom:24px;">
          <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:14px 20px;">
            <div style="font-size:28px;font-weight:bold;color:#7f1d1d;">{crit_cnt}</div>
            <div style="font-size:13px;color:#991b1b;">Critical</div>
          </div>
          <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:14px 20px;">
            <div style="font-size:28px;font-weight:bold;color:#dc2626;">{high_cnt}</div>
            <div style="font-size:13px;color:#c2410c;">High</div>
          </div>
          <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:14px 20px;">
            <div style="font-size:28px;font-weight:bold;color:#d97706;">{med_cnt}</div>
            <div style="font-size:13px;color:#b45309;">Medium</div>
          </div>
          <div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:14px 20px;">
            <div style="font-size:28px;font-weight:bold;color:#166534;">{low_cnt}</div>
            <div style="font-size:13px;color:#15803d;">Low</div>
          </div>
          <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:14px 20px;">
            <div style="font-size:28px;font-weight:bold;color:#1d4ed8;">{count}</div>
            <div style="font-size:13px;color:#1e40af;">Total</div>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead>
            <tr style="background:#1e3a5f;color:white;">
              <th style="padding:10px 12px;text-align:left;">IP Address</th>
              <th style="padding:10px 12px;">Port</th>
              <th style="padding:10px 12px;">Service</th>
              <th style="padding:10px 12px;">Severity</th>
              <th style="padding:10px 12px;">Score</th>
              <th style="padding:10px 12px;">Country</th>
              <th style="padding:10px 12px;text-align:left;">Action Required</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
        <p style="margin:20px 0 0;font-size:12px;color:#9ca3af;">Automated alert from CyberScan Pro. Full report attached.</p>
      </div>
    </div>
    </body></html>
    '''


def send_alert_email(
    sender:     str,
    password:   str,
    recipient:  str,
    df:         pd.DataFrame,
    scan_time:  str,
    attach_pdf: bool = True
) -> bool:
    if df is None or len(df) == 0:
        print('Email error: no scan data.')
        return False

    try:
        crit_cnt = int((df['severity'] == 'Critical').sum())
        high_cnt = int((df['severity'] == 'High').sum())

        msg = MIMEMultipart('mixed')
        msg['Subject'] = (
            'CyberScan Alert - {} findings ({} Critical, {} High) - {}'.format(
                len(df), crit_cnt, high_cnt, scan_time
            )
        )
        msg['From'] = sender
        msg['To']   = recipient

        # ✅ HTML body attached directly to mixed — no nested alternative wrapper
        msg.attach(MIMEText(_build_html_body(df, scan_time), 'html'))

        # ✅ PDF attachment
        if attach_pdf:
            try:
                ts       = str(scan_time).replace(' ', '_').replace(':', '-').replace('/', '-')
                pdf_path = os.path.join(REPORTS_DIR, 'scan_report_{}.pdf'.format(ts))
                generate_pdf_report(df, scan_time, pdf_path)
                with open(pdf_path, 'rb') as f:
                    pdf_part = MIMEApplication(f.read(), _subtype='pdf')
                    pdf_part.add_header(
                        'Content-Disposition', 'attachment',
                        filename=os.path.basename(pdf_path)
                    )
                    msg.attach(pdf_part)
                print('PDF attached successfully')
            except Exception as pdf_err:
                print('PDF generation failed, sending without PDF: {}'.format(pdf_err))

        # ✅ SMTP sending is OUTSIDE the if attach_pdf block
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())
        except smtplib.SMTPConnectError:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender, recipient, msg.as_string())

        print('Email sent to {}'.format(recipient))
        return True

    except Exception as e:
        print('Email error: {}'.format(e))
        import traceback
        traceback.print_exc()
        return False
