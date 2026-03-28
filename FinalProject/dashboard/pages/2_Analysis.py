import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.analyser import build_host_summary

st.title('🔍 Deep Analysis')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data yet. Run a scan on the main page.')
    st.stop()

host_sum = st.session_state.get('host_sum')
if host_sum is None:
    host_sum = build_host_summary(df)

BG     = '#0f1117'
CRIT   = '#ef4444'
HIGH   = '#f97316'
MED    = '#eab308'
LOW    = '#22c55e'
ACCENT = '#4f8ef7'
SEV_COLORS = {'Critical': CRIT, 'High': HIGH, 'Medium': MED, 'Low': LOW}

st.subheader('🎯 Exposure vs Threat Intelligence')
scatter = px.scatter(
    df,
    x='exposure_score', y='threat_score',
    size='risk_score',
    color='severity',
    hover_data=['ip','port','service','country','risk_score'],
    color_discrete_map=SEV_COLORS,
    title='Exposure vs Threat Intelligence (bubble size = overall risk)',
    labels={'exposure_score':'Exposure Score (0-10)','threat_score':'Threat Score (0-10)'},
    template='plotly_dark'
)
scatter.update_layout(
    height=450,
    margin=dict(t=60,b=40,l=40,r=20),
    xaxis=dict(range=[-0.5,11]),
    yaxis=dict(range=[-0.5,11]),
)
scatter.update_traces(marker=dict(line=dict(color=BG, width=1.5)))
st.plotly_chart(scatter, use_container_width=True)

st.subheader('🔧 Risk Score by Service')
svc_risk = df.groupby('service').agg(
    avg_risk=('risk_score','mean'),
    count=('port','count'),
    max_risk=('risk_score','max')
).reset_index().sort_values('avg_risk', ascending=False).head(12)

svc_bar = go.Figure()
svc_bar.add_trace(go.Bar(
    name='Avg Risk',
    x=svc_risk['service'], y=svc_risk['avg_risk'],
    marker_color=ACCENT, opacity=0.9
))
svc_bar.add_trace(go.Bar(
    name='Max Risk',
    x=svc_risk['service'], y=svc_risk['max_risk'],
    marker_color=CRIT, opacity=0.7
))
svc_bar.update_layout(
    barmode='group',
    template='plotly_dark', height=360,
    margin=dict(t=60,b=40,l=40,r=20),
    yaxis=dict(range=[0,11]),
)
st.plotly_chart(svc_bar, use_container_width=True)

st.subheader('🔓 Open Port Frequency')
port_counts = df['port'].value_counts().head(15).sort_values()
port_bar = go.Figure(go.Bar(
    x=port_counts.values, y=port_counts.index.astype(str),
    orientation='h',
    marker=dict(
        color=port_counts.values,
        colorscale=[[0,'#22c55e'],[0.5,'#eab308'],[1,'#ef4444']],
    ),
    text=port_counts.values, textposition='outside',
))
port_bar.update_layout(
    template='plotly_dark', height=420,
    margin=dict(t=60,b=20,l=60,r=40),
)
st.plotly_chart(port_bar, use_container_width=True)

st.subheader('🦠 VirusTotal Engine Reports per Host')
vt_df = df.groupby('ip').agg(
    malicious=('malicious_reports','max'),
    suspicious=('suspicious_count','max'),
    harmless=('harmless_count','max'),
).reset_index()

vt_bar = go.Figure()
for col, colour, label in [
    ('malicious',  CRIT, 'Malicious'),
    ('suspicious', HIGH, 'Suspicious'),
    ('harmless',   LOW,  'Harmless'),
]:
    vt_bar.add_trace(go.Bar(
        name=label, x=vt_df['ip'], y=vt_df[col],
        marker_color=colour, opacity=0.85
    ))
vt_bar.update_layout(
    barmode='group',
    template='plotly_dark', height=380,
    margin=dict(t=60,b=40,l=40,r=20),
)
st.plotly_chart(vt_bar, use_container_width=True)

st.subheader('🌡️ Host Risk Heatmap')
host_heatmap_df = host_sum.set_index('ip')[['max_risk','max_exposure','max_threat']].T
heatmap = go.Figure(go.Heatmap(
    z=host_heatmap_df.values,
    x=host_heatmap_df.columns.tolist(),
    y=['Max Risk','Max Exposure','Max Threat'],
    colorscale=[
        [0.0, '#16a34a'],
        [0.3, '#eab308'],
        [0.6, '#f97316'],
        [1.0, '#ef4444'],
    ],
    zmin=0, zmax=10,
    text=[[f'{v:.1f}' for v in row] for row in host_heatmap_df.values],
    texttemplate='%{text}',
    textfont=dict(size=13, color='white'),
))
heatmap.update_layout(
    template='plotly_dark', height=280,
    margin=dict(t=60,b=40,l=120,r=20),
)
st.plotly_chart(heatmap, use_container_width=True)

st.subheader('🏆 Top 10 Highest Risk Findings')
top_risks = df.sort_values('risk_score', ascending=True).tail(10)
top_bar = go.Figure(go.Bar(
    x=top_risks['risk_score'],
    y=[f"{r['ip']}:{r['port']} ({r['service']})" for _, r in top_risks.iterrows()],
    orientation='h',
    marker=dict(
        color=top_risks['risk_score'],
        colorscale=[[0,'#22c55e'],[0.5,'#f97316'],[1,'#ef4444']],
    ),
    text=[f"{v:.1f}" for v in top_risks['risk_score']],
    textposition='outside',
))
top_bar.update_layout(
    template='plotly_dark', height=420,
    xaxis=dict(range=[0,11]),
    margin=dict(t=60,b=20,l=200,r=60),
)
st.plotly_chart(top_bar, use_container_width=True)
