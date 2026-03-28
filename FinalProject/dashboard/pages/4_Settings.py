import streamlit as st
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from dotenv import load_dotenv
load_dotenv('u.env')

st.title('⚙️ Session Configuration')
st.caption('Update your API keys, scan targets, and email settings')

st.divider()

# ── API Credentials ───────────────────────────────────────────────────────────
st.subheader('🔑 API Credentials')

vt_key = st.text_input(
    'VirusTotal API Key',
    value=os.environ.get('VT_API_KEY', ''),
    type='password',
    placeholder='Enter VirusTotal API key'
)
api_key = st.text_input(
    'CyberScan API Key',
    value=os.environ.get('CYBERSCAN_API_KEY', 'dev-key'),
    placeholder='dev-key'
)

st.divider()

# ── Scan Targets ──────────────────────────────────────────────────────────────
st.subheader('🎯 Scan Targets')

targets_raw = st.text_input(
    'Scan Targets (comma separated)',
    value=os.environ.get('SCAN_TARGETS', 'scanme.nmap.org'),
    placeholder='host1,host2,192.168.1.1'
)

st.divider()

# ── Email Alerts ──────────────────────────────────────────────────────────────
st.subheader('📧 Email Alerts')

gmail_sender = st.text_input(
    'Gmail Sender',
    value=os.environ.get('GMAIL_SENDER', ''),
    placeholder='youremail@gmail.com'
)
gmail_pass = st.text_input(
    'Gmail App Password',
    value=os.environ.get('GMAIL_PASSWORD', ''),
    type='password',
    placeholder='16-char app password'
)
gmail_rcpt = st.text_input(
    'Alert Recipient',
    value=os.environ.get('GMAIL_RECIPIENT', ''),
    placeholder='recipient@company.com'
)

st.divider()

# ── Apply Button ──────────────────────────────────────────────────────────────
if st.button('💾 Apply Settings', type='primary', use_container_width=True):
    targets = [t.strip() for t in targets_raw.split(',') if t.strip()]

    st.session_state['vt_key']      = vt_key.strip()
    st.session_state['api_key']     = api_key.strip()
    st.session_state['targets']     = targets
    st.session_state['targets_raw'] = targets_raw.strip()
    st.session_state['gmail_sender']= gmail_sender.strip()
    st.session_state['gmail_pass']  = gmail_pass.strip()
    st.session_state['gmail_rcpt']  = gmail_rcpt.strip()

    st.success('Settings applied for this session ✅')
    st.write(f'VT Key:    {"✅ Set" if vt_key else "❌ Empty"}')
    st.write(f'Targets:   {targets}')
    st.write(f'From:      {gmail_sender or "❌ Empty"}')
    st.write(f'Recipient: {gmail_rcpt   or "❌ Empty"}')
    st.write(f'Password:  {"✅ Set" if gmail_pass else "❌ Empty"}')
    st.info('Re-run the scan on the main page to use new settings.')

st.divider()
st.caption('💡 Generate Gmail App Password at: myaccount.google.com → Security → App passwords')
