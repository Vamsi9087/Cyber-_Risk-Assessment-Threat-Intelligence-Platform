import pandas as pd

SERVICE_RISK = {
    "telnet": 10, "rdp": 9, "smb": 9, "ftp": 8, "vnc": 8,
    "mongodb": 8, "redis": 8, "mysql": 7, "mssql": 7, "postgresql": 7,
    "smtp": 4, "dns": 3, "ssh": 3, "http": 2, "https": 1,
}  # here iam Setting Up the Serviceports to it 

DANGEROUS_PORTS = {
    "21","23","135","137","139","445",
    "1433","3306","3389","5432","5900","6379","27017"
}  # and also iam Checking this Dangerous ports to here 

HIGH_RISK_COUNTRIES = {"CN","RU","KP","IR","NG","UA","VN","RO"}  # high risk countries also too

RECOMMENDATIONS = {
    "telnet":     "DISABLE IMMEDIATELY — replace with SSH. Telnet sends passwords in plaintext.",
    "ftp":        "Replace with SFTP or FTPS. Plain FTP credentials are visible on the network.",
    "rdp":        "Restrict to VPN only. Enable Network Level Authentication. Monitor login attempts.",
    "vnc":        "Ensure strong password is set. Restrict access to VPN or trusted IPs only.",
    "smb":        "Block port 445 at the perimeter. Verify MS17-010 (WannaCry) patch is applied.",
    "ssh":        "Disable password auth — use SSH keys only. Consider non-default port.",
    "http":       "Redirect all traffic to HTTPS. Check for outdated web application frameworks.",
    "https":      "Verify TLS version (1.2 minimum). Check certificate expiry and cipher suite.",
    "mysql":      "This port should NOT be internet-facing. Move behind VPN or firewall rule.",
    "postgresql": "Should not be internet-facing. Restrict to localhost or VPN.",
    "mssql":      "Restrict to internal network. Audit SQL Server authentication logs.",
    "redis":      "Redis has no authentication by default. Bind to localhost or require AUTH.",
    "mongodb":    "Enable authentication and restrict external access.",
    "smtp":       "Ensure relay is restricted. Check for open relay configuration.",
    "dns":        "If not a DNS server, close port 53. Disable recursion if public-facing.",
}
DEFAULT_REC = "Review this service. Confirm it is required and limit access to authorised sources."


def _exposure_score(row):
    svc   = str(row.get("service", "")).lower()
    port  = str(row.get("port",    "0"))
    state = str(row.get("state",   "open")).lower()
    score = SERVICE_RISK.get(svc, 0)
    if score == 0 and port in DANGEROUS_PORTS:
        score = 6
    if score == 0:
        score = 1
    if state == "filtered":
        score = max(0.5, score * 0.5)
    return min(10.0, float(score))


def _threat_score(row):
    malicious  = int(row.get("malicious_reports", 0))  # here checking the threat Score what are the Malicious and susicious  and Commuinty Score 
    suspicious = int(row.get("suspicious_count",  0))
    community  = int(row.get("community_score",   0))
    raw = (malicious * 2.0) + (suspicious * 0.5)
    if community < 0:
        raw += min(2.0, abs(community) * 0.1)
    return min(10.0, raw)


def _context_score(row):  # here iam checking like The country that Have high score like vulnerability
    score   = 0.0
    country = str(row.get("country",    "")).upper()
    cats    = str(row.get("categories", "")).lower()
    comm    = int(row.get("community_score", 0))
    if country in HIGH_RISK_COUNTRIES: score += 3.0
    if "malware"  in cats: score += 4.0
    if "phishing" in cats: score += 3.0
    if "spam"     in cats: score += 2.0
    if "botnet"   in cats: score += 3.5
    if comm < -5:          score += 1.0
    return min(10.0, score)


def _severity(score):  # here iam Checking like what are things are critical high and Medium Score 
    if score >= 7.0: return "Critical"
    if score >= 5.0: return "High"
    if score >= 3.0: return "Medium"
    return "Low"


def enrich_dataframe(df, vt_data=None):
    df = df.copy()
    if vt_data:
        vt_df = pd.DataFrame(vt_data).T.rename_axis("ip").reset_index() # here iaam using dataframe for Setting a Data in a organized in nrows and columns
        df    = df.merge(vt_df, on="ip", how="left")
    for col, default in [
        ("malicious_reports", 0), ("suspicious_count", 0),
        ("harmless_count",    0), ("community_score",  0),
        ("country", "Unknown"),   ("network", "Unknown"), ("categories", "")
    ]:
        if col not in df.columns:
            df[col] = default
    df["exposure_score"] = df.apply(_exposure_score, axis=1).round(2)
    df["threat_score"]   = df.apply(_threat_score,   axis=1).round(2)
    df["context_score"]  = df.apply(_context_score,  axis=1).round(2)
    df["risk_score"]     = (
        df["exposure_score"] * 0.40 +
        df["threat_score"]   * 0.40 +
        df["context_score"]  * 0.20
    ).round(2)
    df["severity"]       = df["risk_score"].apply(_severity)
    df["recommendation"] = df["service"].apply(
        lambda s: RECOMMENDATIONS.get(str(s).lower(), DEFAULT_REC)
    )
    return df

# Host Summary in DATA FRAME
def build_host_summary(df):
    agg = df.groupby("ip").agg(
        open_ports       = ("port",            "count"),
        max_risk         = ("risk_score",       "max"),
        max_exposure     = ("exposure_score",   "max"),
        max_threat       = ("threat_score",     "max"),
        malicious_total  = ("malicious_reports","max"),
        country          = ("country",          "first"),
        network          = ("network",          "first"),
        categories       = ("categories",       "first"),
        services         = ("service",          lambda x: ", ".join(sorted(set(x)))),
    ).reset_index()
    agg["overall_severity"] = agg["max_risk"].apply(_severity)
    return agg.sort_values("max_risk", ascending=False)


def generate_summary(df, host_sum=None):
    if host_sum is None:
        host_sum = build_host_summary(df)
    crit_hosts = int((host_sum["overall_severity"] == "Critical").sum())
    high_hosts = int((host_sum["overall_severity"] == "High").sum())
    vt_flagged = int(df.groupby("ip")["malicious_reports"].max().gt(0).sum())
    max_risk   = float(df["risk_score"].max()) if len(df) else 0.0
    if   crit_hosts > 0: posture, colour = "CRITICAL", "#7f1d1d"
    elif high_hosts > 0: posture, colour = "HIGH RISK", "#dc2626"
    elif max_risk  >= 3: posture, colour = "MODERATE", "#d97706"
    else:                posture, colour = "LOW RISK",  "#16a34a"
    findings = [] # finding the all the things in data Frame
    plaintext = df[df["service"].isin(["telnet","ftp"])]
    if len(plaintext):
        findings.append(f"Plaintext protocol(s) detected: {', '.join(plaintext['service'].unique())}")
    flagged_ips = df[df["malicious_reports"] > 0]["ip"].nunique()
    if flagged_ips:
        findings.append(f"{flagged_ips} IP(s) flagged as malicious by VirusTotal engines")
    db_ports = df[df["service"].isin(["mysql","mssql","postgresql","mongodb","redis"])]
    if len(db_ports):
        findings.append(f"Database port(s) exposed: {db_ports['service'].unique().tolist()}")
    risky_countries = df[df["country"].isin({"CN","RU","KP","IR","NG","UA","VN","RO"})]["ip"].nunique()
    if risky_countries:
        findings.append(f"{risky_countries} IP(s) registered in high-risk countries")
    suspicious = df[df["suspicious_count"] > 0]["ip"].nunique()
    if suspicious:
        findings.append(f"{suspicious} IP(s) have suspicious (unconfirmed) VT flags")
    rdp_smb = df[df["service"].isin(["rdp","smb","ms-wbt-server"])]
    if len(rdp_smb):
        findings.append(f"Remote access port(s) open: {rdp_smb['service'].unique().tolist()}")
    if not findings:
        findings.append("No critical findings detected in this scan")
    return {
        "total_hosts": int(df["ip"].nunique()),
        "total_ports": len(df),
        "crit_hosts":  crit_hosts,
        "high_hosts":  high_hosts,
        "vt_flagged":  vt_flagged,
        "max_risk":    max_risk,
        "posture":     posture,
        "colour":      colour,
        "findings":    findings,
    }
