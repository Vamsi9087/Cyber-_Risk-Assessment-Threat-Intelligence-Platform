import sqlite3
import pandas as pd
import json
from datetime import datetime

DB_FILE = "cyberscan.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time      TEXT    NOT NULL,
        targets        TEXT,
        total_hosts    INTEGER,
        total_ports    INTEGER,
        critical_count INTEGER,
        high_count     INTEGER,
        max_risk_score REAL,
        avg_risk_score REAL,
        results_json   TEXT
    )""")
    conn.commit()
    conn.close()


def save_scan(df, targets):
    conn = sqlite3.connect(DB_FILE)
    cur  = conn.execute(
        """INSERT INTO scans
           (scan_time, targets, total_hosts, total_ports,
            critical_count, high_count, max_risk_score, avg_risk_score, results_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ", ".join(targets),
            int(df["ip"].nunique()),
            len(df),
            int((df["severity"] == "Critical").sum()),
            int((df["severity"] == "High").sum()),
            float(df["risk_score"].max()),
            float(df["risk_score"].mean()),
            df.to_json(orient="records"),
        )
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def load_history():
    conn = sqlite3.connect(DB_FILE)
    df   = pd.read_sql_query(
        """SELECT id, scan_time, targets, total_hosts, total_ports,
                  critical_count, high_count, max_risk_score, avg_risk_score
           FROM scans ORDER BY id DESC""", conn
    )
    conn.close()
    return df


def load_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_FILE)
    row  = conn.execute(
        "SELECT results_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()

    if not row or not row[0]:
        return pd.DataFrame()

    try:
        # ✅ FIX: use json.loads first then DataFrame
        data = json.loads(row[0])
        if not data:
            return pd.DataFrame()
        df = pd.DataFrame(data)
        return df
    except Exception as e:
        print(f'load_scan_by_id error: {e}')
        return pd.DataFrame()


init_db()
