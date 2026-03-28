import streamlit as st
import pandas as pd
import os, sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from modules.emailer import generate_pdf_report
from modules.analyser import build_host_summary

st.title('📥 Export Scan Results')
st.caption('Download PDF report, full CSV, and host summary CSV')

df = st.session_state.get('df')
if df is None:
    st.info('No scan data yet. Run a scan on the main page.')
    st.stop()

# ✅ FIX: use 'is None' instead of 'or' with DataFrame
host_sum = st.session_state.get('host_sum')
if host_sum is None:
    host_sum = build_host_summary(df)

scan_time = st.session_state.get('scan_time') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

os.makedirs('reports', exist_ok=True)

ts       = datetime.now().strftime('%Y%m%d_%H%M%S')
pdf_path = f'reports/cyberscan_report_{ts}.pdf'
csv_path = f'reports/cyberscan_data_{ts}.csv'
host_csv = f'reports/cyberscan_hosts_{ts}.csv'

export_cols = [
    'ip','port','service','state','severity','risk_score',
    'exposure_score','threat_score','context_score',
    'malicious_reports','suspicious_count','country',
    'categories','product','version','recommendation'
]
export_df = df[[c for c in export_cols if c in df.columns]]

if st.button('🔄 Generate Export Files', type='primary', use_container_width=True):
    with st.spinner('Generating files...'):
        generate_pdf_report(df, scan_time, pdf_path)
        export_df.to_csv(csv_path, index=False)
        host_sum.to_csv(host_csv, index=False)
    st.success('Files generated ✅')

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        with open(pdf_path, 'rb') as f:
            st.download_button(
                label='📄 Download PDF Report',
                data=f.read(),
                file_name=os.path.basename(pdf_path),
                mime='application/pdf',
                use_container_width=True
            )

    with col2:
        with open(csv_path, 'rb') as f:
            st.download_button(
                label='📊 Download Full CSV',
                data=f.read(),
                file_name=os.path.basename(csv_path),
                mime='text/csv',
                use_container_width=True
            )

    with col3:
        with open(host_csv, 'rb') as f:
            st.download_button(
                label='🖥️ Download Host CSV',
                data=f.read(),
                file_name=os.path.basename(host_csv),
                mime='text/csv',
                use_container_width=True
            )

    st.divider()

    st.caption(
        f'PDF: {os.path.getsize(pdf_path):,} bytes  |  '
        f'CSV: {os.path.getsize(csv_path):,} bytes  |  '
        f'Rows: {len(export_df)}'
    )
