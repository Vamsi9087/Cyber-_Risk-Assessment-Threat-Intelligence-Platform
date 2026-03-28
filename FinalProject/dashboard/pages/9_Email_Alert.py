import streamlit as st
import os
import sys
import traceback
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from dotenv import load_dotenv
from pathlib import Path
_base = Path(__file__).resolve().parent.parent.parent
load_dotenv(_base / 'u.env', override=True)
load_dotenv('u.env', override=True)

from modules.emailer import send_alert_email

st.title('📧 Send Security Alert Email')
st.caption('Send a styled HTML report with optional PDF attachment to any recipient')

# ── Load env values ───────────────────────────────────────────────────────────
ENV_SENDER = os.environ.get('GMAIL_SENDER', '')
ENV_PASS   = os.environ.get('GMAIL_PASSWORD', '')
ENV_RCPT   = os.environ.get('GMAIL_RECIPIENT', '')

# ── Get scan data ─────────────────────────────────────────────────────────────
df        = st.session_state.get('df')
scan_time = st.session_state.get('scan_time', '')

# ── Guard: no scan data ───────────────────────────────────────────────────────
if df is None or len(df) == 0:
    st.error('❌ No scan data available. Please run a scan first.')
    st.info('👉 Go to the **Home page** and click **Run Full Scan**, then come back here.')
    if st.button('🔄 Refresh page', use_container_width=True):
        st.rerun()
    st.stop()

# ── Scan data summary banner ──────────────────────────────────────────────────
crit = int((df['severity'] == 'Critical').sum())
high = int((df['severity'] == 'High').sum())
med  = int((df['severity'] == 'Medium').sum())
low  = int((df['severity'] == 'Low').sum())

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric('🚨 Critical', crit)
col2.metric('⚠️ High',     high)
col3.metric('🟡 Medium',   med)
col4.metric('🟢 Low',      low)
col5.metric('📋 Total',    len(df))

st.divider()

# ── Email settings ────────────────────────────────────────────────────────────
st.subheader('📧 Email Settings')

st.info(
    '💡 **Gmail App Password required.** Go to '
    '[myaccount.google.com → Security → App passwords]'
    '(https://myaccount.google.com/apppasswords) '
    'to generate a 16-character password.',
    icon=None
)

sender = st.text_input(
    'Sender Gmail address',
    value=ENV_SENDER,
    placeholder='youremail@gmail.com',
    help='Must be a Gmail account with 2-Step Verification enabled'
)

password = st.text_input(
    'Gmail App Password',
    value=ENV_PASS,
    type='password',
    placeholder='16-character app password (no spaces)',
    help='This is NOT your regular Gmail password. Generate one at myaccount.google.com → Security → App passwords'
)

recipient = st.text_input(
    'Recipient email',
    value=ENV_RCPT,
    placeholder='recipient@company.com',
    help='Who should receive this security report'
)

attach_pdf = st.checkbox('Attach PDF report', value=True, help='Attach a formatted PDF alongside the HTML email')

st.divider()

# ── Live validation ───────────────────────────────────────────────────────────
ready   = True
reasons = []

if not sender or not sender.strip():
    reasons.append('Sender email is empty')
    ready = False
elif '@gmail.com' not in sender:
    reasons.append('Sender must be a @gmail.com address')
    ready = False

if not password or not password.strip():
    reasons.append('App password is empty')
    ready = False
elif len(password.replace(' ', '').strip()) != 16:
    # ✅ FIX: strip spaces BEFORE checking length
    # Google shows app passwords as "xxxx xxxx xxxx xxxx" (19 chars with spaces)
    # but the actual password is 16 chars. We must remove spaces first.
    reasons.append(f'App password should be exactly 16 characters (yours is {len(password.replace(" ", "").strip())} after removing spaces)')
    ready = False

if not recipient or not recipient.strip():
    reasons.append('Recipient email is empty')
    ready = False
elif '@' not in recipient:
    reasons.append('Recipient email looks invalid')
    ready = False

if not ready:
    for r in reasons:
        st.warning(f'⚠️ {r}')
else:
    st.success('✅ All fields look good — ready to send!')

st.divider()

# ── Send button ───────────────────────────────────────────────────────────────
send_clicked = st.button(
    '📧 Send Alert Email',
    type='primary',
    use_container_width=True,
    disabled=not ready
)

if send_clicked:
    # Clean the app password: remove any spaces Google adds
    password_clean = password.replace(' ', '').strip()

    with st.spinner(f'Sending report to {recipient}... this may take 10–20 seconds...'):
        try:
            ok = send_alert_email(
                sender.strip(),
                password_clean,
                recipient.strip(),
                df=df,
                scan_time=scan_time or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                attach_pdf=attach_pdf
            )
        except Exception as e:
            ok = False
            st.session_state['_email_last_error'] = traceback.format_exc()

    if ok:
        st.success(f'✅ Email sent successfully to **{recipient}**!')
        st.balloons()
        st.session_state.pop('_email_last_error', None)
    else:
        st.error('❌ Email failed to send. See the troubleshooting section below.')

        err = st.session_state.get('_email_last_error', '')
        with st.expander('🔍 Full error details'):
            if err:
                st.code(err)
            st.markdown("""
**Common fixes:**

1. **Wrong password type** — You must use a Gmail App Password, NOT your regular Gmail password.
   - Go to [myaccount.google.com → Security → App passwords](https://myaccount.google.com/apppasswords)
   - Create a new App password → select "Mail" → copy the 16-char password

2. **2-Step Verification not enabled** — App passwords only work when 2FA is on.
   - Go to [myaccount.google.com → Security → 2-Step Verification](https://myaccount.google.com/signinoptions/twosv)

3. **Spaces in the app password** — Google shows it as `xxxx xxxx xxxx xxxx`. Remove all spaces before pasting.

4. **Wrong sender address** — The sender must be the same Gmail account you generated the App Password for.

5. **Firewall / network blocking port 587** — Try on a different network or check your firewall rules.
""")

st.divider()

# ── Preview table ─────────────────────────────────────────────────────────────
st.subheader('👀 What will be emailed')
st.caption(f'{len(df)} findings from scan at {scan_time or "unknown time"} — sorted by risk score')

show_cols = [c for c in [
    'ip', 'port', 'service', 'severity', 'risk_score', 'country', 'recommendation'
] if c in df.columns]

st.dataframe(
    df[show_cols].sort_values('risk_score', ascending=False),
    use_container_width=True,
    hide_index=True,
    column_config={
        'risk_score': st.column_config.ProgressColumn(
            'Risk Score', min_value=0, max_value=10, format='%.2f'
        ),
    }
)

# ── Debug expander ────────────────────────────────────────────────────────────
with st.expander('🔧 Debug info'):
    st.write(f'**Sender:** `{sender or "empty"}`')
    st.write(f'**Recipient:** `{recipient or "empty"}`')
    pw_clean_len = len(password.replace(' ', '').strip()) if password else 0
    st.write(f'**Password length (spaces removed):** {pw_clean_len} chars '
             f'{"✅" if pw_clean_len == 16 else "❌ (should be 16)"}')
    st.write(f'**Scan time:** {scan_time or "not set"}')
    st.write(f'**Total findings:** {len(df)}')
    st.write(f'**Critical / High / Medium / Low:** {crit} / {high} / {med} / {low}')
    st.write(f'**Attach PDF:** {attach_pdf}')
    st.write(f'**Loaded from u.env — sender:** `{"set" if ENV_SENDER else "missing"}`')
    st.write(f'**Loaded from u.env — password:** `{"set (" + str(len(ENV_PASS)) + " chars)" if ENV_PASS else "missing"}`')
    st.write(f'**Loaded from u.env — recipient:** `{"set" if ENV_RCPT else "missing"}`')
