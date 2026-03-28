import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.database import load_history, load_scan_by_id

st.title('📜 Scan History')
st.caption('Historical trend data stored in SQLite')

history_df = load_history()
if history_df.empty:
    st.info('No scan history yet. Run at least one scan.')
    st.stop()

# ── Sort by scan id so charts are in correct order ────────────────────────────
history_df = history_df.sort_values('id').reset_index(drop=True)

CRIT   = '#ef4444'
HIGH   = '#f97316'
ACCENT = '#4f8ef7'

# ── All Scans Table with progress bars ───────────────────────────────────────
st.subheader('📋 All Scans')
st.dataframe(
    history_df,
    use_container_width=True,
    hide_index=True,
    column_config={
        'max_risk_score': st.column_config.ProgressColumn(
            'Max Risk', min_value=0, max_value=10, format='%.2f'
        ),
        'avg_risk_score': st.column_config.ProgressColumn(
            'Avg Risk', min_value=0, max_value=10, format='%.2f'
        ),
        'critical_count': st.column_config.NumberColumn('Critical'),
        'high_count':     st.column_config.NumberColumn('High'),
        'total_hosts':    st.column_config.NumberColumn('Hosts'),
        'total_ports':    st.column_config.NumberColumn('Ports'),
    }
)

st.divider()

# ── Risk Score Evolution ──────────────────────────────────────────────────────
if len(history_df) > 1:
    st.subheader('📈 Risk Score Evolution Over Time')
    risk_line = go.Figure()
    risk_line.add_trace(go.Scatter(
        x=history_df['scan_time'],
        y=history_df['avg_risk_score'],
        mode='lines+markers',
        line=dict(color=ACCENT, width=2),
        marker=dict(size=8, color=ACCENT),
        name='Avg Risk Score'
    ))
    risk_line.add_trace(go.Scatter(
        x=history_df['scan_time'],
        y=history_df['max_risk_score'],
        mode='lines+markers',
        line=dict(color=CRIT, width=2, dash='dash'),
        marker=dict(size=8, color=CRIT),
        name='Max Risk Score'
    ))
    risk_line.update_layout(
        template='plotly_dark', height=400,
        xaxis=dict(title='Scan Time'),          # ✅ No broken range=[0,11]
        yaxis=dict(title='Risk Score (0–10)', range=[0, 11]),
        margin=dict(t=60, b=40, l=60, r=40),
    )
    st.plotly_chart(risk_line, use_container_width=True)
else:
    st.info('Run at least 2 scans to see the Risk Score Evolution chart.')

st.divider()


# ── Hosts vs Ports Bubble Scatter ─────────────────────────────────────────────
st.subheader('🔵 Hosts vs Ports Across Scans')
hosts_ports = px.scatter(
    history_df,
    x='total_hosts', y='total_ports',
    size='avg_risk_score',
    color='max_risk_score',
    color_continuous_scale=['#22c55e', '#eab308', '#ef4444'],
    hover_data=['targets', 'scan_time'],
    title='Hosts vs Ports Across Scans',
    template='plotly_dark'
)
hosts_ports.update_layout(
    height=400,
    margin=dict(t=60, b=40, l=60, r=40),
)
st.plotly_chart(hosts_ports, use_container_width=True)

st.divider()

# ── Drill Into a Past Scan ────────────────────────────────────────────────────
st.subheader('🔎 Drill Into a Past Scan')
selected_id = st.selectbox('Select scan ID', history_df['id'].tolist())
if selected_id:
    past_df = load_scan_by_id(selected_id)
    if not past_df.empty:
        st.caption(f'Scan {selected_id}: {len(past_df)} rows, {past_df["ip"].nunique()} hosts')
        show_cols = [c for c in [
            'ip', 'port', 'service', 'risk_score',
            'severity', 'country', 'recommendation'
        ] if c in past_df.columns]
        st.dataframe(
            past_df[show_cols].sort_values('risk_score', ascending=False),
            use_container_width=True,
            hide_index=True
        )
