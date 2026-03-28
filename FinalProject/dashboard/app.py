import streamlit as st
import os
import sys
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'u.env'))

from modules.scanner  import run_nmap_scan, parse_nmap_xml, check_virustotal
from modules.analyser import enrich_dataframe, generate_summary, build_host_summary
from modules.database import save_scan
from modules.emailer  import send_alert_email

VT_KEY       = os.environ.get('VT_API_KEY', '')
API_KEY      = os.environ.get('CYBERSCAN_API_KEY', 'dev-key')
TARGETS_RAW  = os.environ.get('SCAN_TARGETS', 'scanme.nmap.org')
GMAIL_SENDER = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASS   = os.environ.get('GMAIL_PASSWORD', '')
GMAIL_RCPT   = os.environ.get('GMAIL_RECIPIENT', '')
TARGETS      = [t.strip() for t in TARGETS_RAW.split(',') if t.strip()]

st.set_page_config(
    page_title='CyberScan Pro',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded'
)

for key, val in [
    ('df', None), ('scan_time', None), ('host_sum', None),
    ('last_scan_id', None), ('scan_running', False),
    ('targets_override', None),
]:
    if key not in st.session_state:
        st.session_state[key] = val

with st.sidebar:
    st.title('🛡️ CyberScan Pro')
    st.divider()

    st.subheader('⚙️ Status')
    if VT_KEY:
        st.success('VT API key ready ✅')
    else:
        st.error('VT_API_KEY not set ❌')

    if GMAIL_SENDER and GMAIL_PASS:
        st.success('Email configured ✅')
    else:
        st.warning('Email not configured ⚠️')

    st.divider()

    st.subheader('🎯 Scan Targets')
    targets_input = st.text_area(
        'Enter targets (one per line or comma separated)',
        value='\n'.join(
            st.session_state.targets_override
            if st.session_state.targets_override
            else TARGETS
        ),
        height=100,
        help='e.g. scanme.nmap.org or 192.168.1.1'
    )
    if st.button('💾 Save Targets', use_container_width=True):
        new_targets = [
            t.strip()
            for line in targets_input.splitlines()
            for t in line.split(',')
            if t.strip()
        ]
        st.session_state.targets_override = new_targets
        st.success(f'✅ Targets saved: {new_targets}')

    st.divider()

    scan_btn    = st.button('🚀 Run Full Scan', use_container_width=True, type='primary')
    refresh_btn = st.button('🔄 Clear Results', use_container_width=True)

    st.divider()
    if st.session_state.scan_time:
        st.caption(f'Last scan: {st.session_state.scan_time}')

st.title('🛡️ CyberScan Pro')
st.caption('Professional Network Reconnaissance & Threat Intelligence Platform')
st.divider()

if refresh_btn:
    for key in ['df', 'scan_time', 'host_sum', 'last_scan_id']:
        st.session_state[key] = None
    st.rerun()

if scan_btn:
    if not VT_KEY:
        st.error('VT_API_KEY is not set. Add it to your u.env file.')
        st.stop()

    active_targets = st.session_state.targets_override or TARGETS

    bar    = st.progress(0, text='Starting scan...')
    status = st.empty()

    all_rows = []
    for i, target in enumerate(active_targets):
        status.info(f'🔍 Scanning {target}  ({i+1}/{len(active_targets)})')
        xml = run_nmap_scan(target)
        all_rows.extend(parse_nmap_xml(xml))
        bar.progress(int((i + 1) / len(active_targets) * 40))

    if not all_rows:
        st.warning('Nmap returned no results. Check targets and network connectivity.')
        st.stop()

    status.info('🌐 Querying VirusTotal...')
    df_raw     = pd.DataFrame(all_rows)
    unique_ips = df_raw['ip'].unique().tolist()
    vt_data    = {}
    for j, ip in enumerate(unique_ips):
        vt_data[ip] = check_virustotal(ip, VT_KEY)
        bar.progress(40 + int((j + 1) / len(unique_ips) * 30))

    status.info('📊 Running analysis engine...')
    df       = enrich_dataframe(df_raw, vt_data)
    host_sum = build_host_summary(df)
    bar.progress(80)

    status.info('💾 Saving to database...')
    scan_id = save_scan(df, active_targets)
    bar.progress(90)

    scan_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ── Auto email ────────────────────────────────────────────────────────────
    # ✅ FIXED: keyword args so df and scan_time land in the right parameters
    if GMAIL_SENDER and GMAIL_PASS and GMAIL_RCPT:
        status.info('📧 Sending alert email...')
        try:
            sent = send_alert_email(
                GMAIL_SENDER,
                GMAIL_PASS,
                GMAIL_RCPT,
                df=df,
                scan_time=scan_time_str,
                attach_pdf=True
            )
            if sent:
                st.success(f'✅ Alert email sent to {GMAIL_RCPT}!')
            else:
                st.warning('⚠️ Email returned False — check logs.')
        except Exception as e:
            st.warning(f'⚠️ Email failed: {e}')
    else:
        st.warning('⚠️ Email not configured — skipping alert.')

    bar.progress(100, text='Scan complete!')
    status.empty()

    st.session_state.df           = df
    st.session_state.host_sum     = host_sum
    st.session_state.scan_time    = scan_time_str
    st.session_state.last_scan_id = scan_id
    st.rerun()

df       = st.session_state.df
host_sum = st.session_state.host_sum

if df is None:
    st.info('🕐 No scan data yet. Click **Run Full Scan** in the sidebar.')
    st.stop()

summary = generate_summary(df, host_sum)

st.markdown(
    f'<div style="background:{summary["colour"]};padding:16px;border-radius:6px;'
    f'text-align:center;margin-bottom:16px;">'
    f'<h2 style="color:white;margin:0;">Overall Security Posture: {summary["posture"]}</h2>'
    f'</div>',
    unsafe_allow_html=True
)

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric('🖥️ Hosts',     summary['total_hosts'])
c2.metric('🔓 Open Ports', summary['total_ports'])
c3.metric('🚨 Critical',   summary['crit_hosts'])
c4.metric('⚠️ High',       summary['high_hosts'])
c5.metric('🦠 VT Flagged', summary['vt_flagged'])
c6.metric('📈 Max Risk',   f"{summary['max_risk']:.1f}")
st.divider()

st.subheader('⚡ Key Findings')
for finding in summary['findings']:
    if 'No critical' in finding:
        st.success(finding)
    elif 'Critical' in finding or 'malicious' in finding:
        st.error(finding)
    else:
        st.warning(finding)

st.divider()

st.subheader('🖥️ Host Overview')
sev_order    = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
host_display = host_sum.copy()
host_display['sort'] = host_display['overall_severity'].map(sev_order)
host_display = host_display.sort_values('sort').drop('sort', axis=1)
st.dataframe(
    host_display[['ip', 'open_ports', 'max_risk', 'overall_severity',
                  'country', 'categories', 'services']],
    use_container_width=True,
    hide_index=True,
)
