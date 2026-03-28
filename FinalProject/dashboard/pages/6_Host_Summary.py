import streamlit as st
import pandas as pd
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.analyser import build_host_summary

st.title('🖥️ Host-level Summary')
st.caption('One row per host — sorted by maximum risk score')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data yet. Run a scan on the main page.')
    st.stop()

# ✅ FIX: use 'is None' instead of 'or' with DataFrame
host_sum = st.session_state.get('host_sum')
if host_sum is None:
    host_sum = build_host_summary(df)

host_display = host_sum[['ip','open_ports','max_risk','overall_severity',
                          'country','categories','services']].copy()

def color_severity(val):
    colors = {
        'Critical': 'background-color: rgba(239,68,68,0.18); color: #ef4444',
        'High':     'background-color: rgba(249,115,22,0.18); color: #f97316',
        'Medium':   'background-color: rgba(234,179,8,0.18); color: #eab308',
        'Low':      'background-color: rgba(34,197,94,0.18); color: #22c55e',
    }
    return colors.get(val, '')

st.dataframe(
    host_display.sort_values('max_risk', ascending=False),
    use_container_width=True,
    hide_index=True,
    column_config={
        'max_risk': st.column_config.ProgressColumn(
            'Max Risk', min_value=0, max_value=10, format='%.2f'
        ),
        'overall_severity': st.column_config.TextColumn('Severity'),
        'open_ports':       st.column_config.NumberColumn('Open Ports'),
        'ip':               st.column_config.TextColumn('IP Address'),
        'country':          st.column_config.TextColumn('Country'),
        'categories':       st.column_config.TextColumn('Categories'),
        'services':         st.column_config.TextColumn('Services'),
    }
)

st.divider()

c1, c2, c3, c4 = st.columns(4)
c1.metric('Total Hosts',    len(host_display))
c2.metric('Critical Hosts', int((host_display['overall_severity'] == 'Critical').sum()))
c3.metric('High Hosts',     int((host_display['overall_severity'] == 'High').sum()))
c4.metric('Max Risk',       f"{host_display['max_risk'].max():.2f}")
