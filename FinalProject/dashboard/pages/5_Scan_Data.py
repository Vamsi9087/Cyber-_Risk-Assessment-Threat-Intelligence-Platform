import streamlit as st
import pandas as pd
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

st.title('📋 All Findings')
st.caption('Full port-level results sorted by Risk Score')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data yet. Run a scan on the main page.')
    st.stop()

# ── Filters ───────────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)
with col1:
    sev_filter = st.multiselect(
        'Filter by Severity',
        ['Critical','High','Medium','Low'],
        default=['Critical','High','Medium','Low']
    )
with col2:
    svc_filter = st.multiselect(
        'Filter by Service',
        sorted(df['service'].unique().tolist()),
        default=[]
    )
with col3:
    ip_search = st.text_input('Search IP', placeholder='e.g. 10.0.0')

# ── Apply filters ─────────────────────────────────────────────────────────────
filtered = df[df['severity'].isin(sev_filter)]
if svc_filter:
    filtered = filtered[filtered['service'].isin(svc_filter)]
if ip_search:
    filtered = filtered[filtered['ip'].str.contains(ip_search, na=False)]

st.caption(f'Showing {len(filtered)} of {len(df)} rows')

# ── Display columns ───────────────────────────────────────────────────────────
display_cols = [
    'ip','port','service','state','severity','risk_score',
    'exposure_score','threat_score','malicious_reports',
    'country','product','version','recommendation'
]
cols_to_show = [c for c in display_cols if c in filtered.columns]
table_df     = filtered[cols_to_show].sort_values('risk_score', ascending=False).reset_index(drop=True)

# ── Colour map for severity ───────────────────────────────────────────────────
def color_severity(val):
    colors = {
        'Critical': 'background-color: rgba(239,68,68,0.18); color: #ef4444',
        'High':     'background-color: rgba(249,115,22,0.18); color: #f97316',
        'Medium':   'background-color: rgba(234,179,8,0.18); color: #eab308',
        'Low':      'background-color: rgba(34,197,94,0.18); color: #22c55e',
    }
    return colors.get(val, '')

styled = (
    table_df.style
    .applymap(color_severity, subset=['severity'])
    .background_gradient(subset=['risk_score'], cmap='RdYlGn_r', vmin=0, vmax=10)
    .format({
        'risk_score':     '{:.2f}',
        'exposure_score': '{:.2f}',
        'threat_score':   '{:.2f}'
    })
    .hide(axis='index')
)

st.dataframe(
    table_df,
    use_container_width=True,
    hide_index=True,
    column_config={
        'risk_score':     st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=10, format='%.2f'),
        'exposure_score': st.column_config.ProgressColumn('Exposure',   min_value=0, max_value=10, format='%.2f'),
        'threat_score':   st.column_config.ProgressColumn('Threat',     min_value=0, max_value=10, format='%.2f'),
        'severity':       st.column_config.TextColumn('Severity'),
    }
)
