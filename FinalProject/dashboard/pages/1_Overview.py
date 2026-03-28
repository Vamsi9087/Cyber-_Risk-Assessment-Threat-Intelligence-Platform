import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.analyser import build_host_summary, generate_summary

st.title('🛡️ CyberScan Pro — Overview')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data yet. Run a scan on the main page.')
    st.stop()

host_sum = st.session_state.get('host_sum')
if host_sum is None:
    host_sum = build_host_summary(df)

summary = generate_summary(df, host_sum)

CRIT   = '#ef4444'
HIGH   = '#f97316'
MED    = '#eab308'
LOW    = '#22c55e'
ACCENT = '#4f8ef7'
SEV_COLORS = {'Critical': CRIT, 'High': HIGH, 'Medium': MED, 'Low': LOW}

posture_bg = {'CRITICAL': CRIT, 'HIGH RISK': HIGH, 'MODERATE': MED, 'LOW RISK': LOW}
posture_col = posture_bg.get(summary['posture'], ACCENT)

st.markdown(
    f'<div style="background:{posture_col};padding:20px;border-radius:8px;'
    f'text-align:center;margin-bottom:16px;">'
    f'<h2 style="color:white;margin:0;">🛡️ CYBERSCAN PRO</h2>'
    f'<p style="color:rgba(255,255,255,0.8);margin:6px 0 0;">'
    f'Security Posture: <strong>{summary["posture"]}</strong> | '
    f'Max Risk: {summary["max_risk"]:.1f}/10</p>'
    f'</div>',
    unsafe_allow_html=True
)

c1,c2,c3,c4,c5,c6 = st.columns(6)
c1.metric('🖥️ Hosts',     summary['total_hosts'])
c2.metric('🔓 Ports',      summary['total_ports'])
c3.metric('🚨 Critical',   summary['crit_hosts'])
c4.metric('⚠️ High',       summary['high_hosts'])
c5.metric('🦠 VT Flagged', summary['vt_flagged'])
c6.metric('📈 Max Risk',   f"{summary['max_risk']:.1f}")
st.divider()

# ── Key Findings ──────────────────────────────────────────────────────────────
st.subheader('⚡ Key Findings')
for finding in summary['findings']:
    if 'No critical' in finding:
        st.success(finding)
    elif 'malicious' in finding or 'Critical' in finding:
        st.error(finding)
    else:
        st.warning(finding)
st.divider()

# ── Row 1: Severity bar + pie ─────────────────────────────────────────────────
sev_counts = df['severity'].value_counts().reindex(
    ['Critical','High','Medium','Low'], fill_value=0
)
col1, col2 = st.columns(2)

with col1:
    st.subheader('📊 Findings by Severity')
    fig = go.Figure(go.Bar(
        x=sev_counts.index,
        y=sev_counts.values,
        marker=dict(color=[SEV_COLORS[s] for s in sev_counts.index]),
        text=sev_counts.values,
        textposition='outside',
    ))
    fig.update_layout(template='plotly_dark', height=320,
                      margin=dict(t=30,b=20,l=20,r=20))
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader('🥧 Severity Distribution')
    fig2 = go.Figure(go.Pie(
        labels=sev_counts.index,
        values=sev_counts.values,
        hole=0.55,
        marker=dict(colors=[SEV_COLORS[s] for s in sev_counts.index]),
    ))
    fig2.update_layout(
        template='plotly_dark', height=320,
        margin=dict(t=30,b=20,l=20,r=20),
        annotations=[dict(text='RISK', x=0.5, y=0.5,
                          font_size=18, showarrow=False)]
    )
    st.plotly_chart(fig2, use_container_width=True)

# ── Row 2: Country bar + Radar ────────────────────────────────────────────────
col3, col4 = st.columns(2)

with col3:
    st.subheader('🌍 Findings by Country')
    country_counts = df['country'].value_counts().head(8)
    fig3 = go.Figure(go.Bar(
        x=country_counts.values,
        y=country_counts.index,
        orientation='h',
        marker=dict(color=[
            CRIT if c in {'CN','RU','KP','IR','NG','UA','VN','RO'} else ACCENT
            for c in country_counts.index
        ]),
        text=country_counts.values,
        textposition='outside',
    ))
    fig3.update_layout(template='plotly_dark', height=340,
                       margin=dict(t=30,b=20,l=80,r=40))
    st.plotly_chart(fig3, use_container_width=True)

with col4:
    st.subheader('🎯 Score Radar')
    score_means = df[['exposure_score','threat_score',
                      'context_score','risk_score']].mean()
    fig4 = go.Figure(go.Scatterpolar(
        r=score_means.values.tolist() + [score_means.values[0]],
        theta=['Exposure','Threat','Context','Risk','Exposure'],
        fill='toself',
        fillcolor='rgba(79,142,247,0.25)',
        line=dict(color=ACCENT, width=2),
    ))
    fig4.update_layout(
        polar=dict(
            bgcolor='rgba(0,0,0,0)',
            angularaxis=dict(color='white'),
            radialaxis=dict(color='white', range=[0,10])
        ),
        template='plotly_dark', height=340,
        margin=dict(t=30,b=20,l=20,r=20)
    )
    st.plotly_chart(fig4, use_container_width=True)

# ── Row 3: Risk score histogram ───────────────────────────────────────────────
st.subheader('📈 Risk Score Distribution')
fig5 = px.histogram(
    df, x='risk_score', nbins=20,
    color='severity',
    color_discrete_map=SEV_COLORS,
    title='Distribution of Risk Scores Across All Findings',
    template='plotly_dark',
    labels={'risk_score': 'Risk Score (0-10)'}
)
fig5.update_layout(height=320, margin=dict(t=50,b=20,l=40,r=20))
st.plotly_chart(fig5, use_container_width=True)

# ── Row 4: Service risk treemap ───────────────────────────────────────────────
st.subheader('🗺️ Service Risk Treemap')
svc_data = df.groupby(['service','severity']).size().reset_index(name='count')
fig6 = px.treemap(
    svc_data,
    path=['severity','service'],
    values='count',
    color='severity',
    color_discrete_map=SEV_COLORS,
    template='plotly_dark',
)
fig6.update_layout(height=400, margin=dict(t=30,b=20,l=20,r=20))
st.plotly_chart(fig6, use_container_width=True)

# ── Row 5: Host risk gauge ────────────────────────────────────────────────────
st.subheader('🎰 Host Risk Gauges')
cols = st.columns(min(len(host_sum), 4))
for i, (_, row) in enumerate(host_sum.head(4).iterrows()):
    with cols[i]:
        gauge = go.Figure(go.Indicator(
            mode='gauge+number',
            value=float(row['max_risk']),
            title={'text': str(row['ip']), 'font': {'size': 11}},
            gauge=dict(
                axis=dict(range=[0, 10]),
                bar=dict(color=CRIT if row['max_risk'] >= 7
                         else HIGH if row['max_risk'] >= 5
                         else MED if row['max_risk'] >= 3
                         else LOW),
                steps=[
                    dict(range=[0, 3],   color='rgba(34,197,94,0.15)'),
                    dict(range=[3, 5],   color='rgba(234,179,8,0.15)'),
                    dict(range=[5, 7],   color='rgba(249,115,22,0.15)'),
                    dict(range=[7, 10],  color='rgba(239,68,68,0.15)'),
                ],
                threshold=dict(
                    line=dict(color='white', width=2),
                    thickness=0.75,
                    value=row['max_risk']
                )
            )
        ))
        gauge.update_layout(
            template='plotly_dark',
            height=220,
            margin=dict(t=40,b=10,l=20,r=20)
        )
        st.plotly_chart(gauge, use_container_width=True)
