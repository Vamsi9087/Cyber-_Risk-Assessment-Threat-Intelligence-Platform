import subprocess
import xml.etree.ElementTree as ET
import requests
import os

SCAN_DIR = "scan_results"
os.makedirs(SCAN_DIR, exist_ok=True)

VT_BASE = "https://www.virustotal.com/api/v3/ip_addresses"

def run_nmap_scan(target: str) -> str:
    xml_file = os.path.join(SCAN_DIR, f"{target}.xml")
    subprocess.run(
        [
            "nmap",
            "-Pn",
            "-sV",
            "-sC",
            "--open",
            "-p-",          # scan ALL 65535 ports
            "--min-rate", "1000",  # faster scan
            "-oX", xml_file,
            target
        ],
        capture_output=True,
        timeout=300
    )
    return xml_file

def parse_nmap_xml(xml_file: str) -> list:
    if not os.path.exists(xml_file):
        return []
    try:
        root = ET.parse(xml_file).getroot()
    except ET.ParseError:
        return []
    rows = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "unknown")
        for port in host.findall(".//port"):
            state_el = port.find("state")
            state    = state_el.get("state", "unknown") if state_el is not None else "unknown"
            if state not in ("open", "filtered"):
                continue
            svc = port.find("service")
            rows.append({
                "ip":       ip,
                "port":     port.get("portid", "0"),
                "protocol": port.get("protocol", "tcp"),
                "state":    state,
                "service":  svc.get("name",    "unknown") if svc is not None else "unknown",
                "product":  svc.get("product", "")        if svc is not None else "",
                "version":  svc.get("version", "")        if svc is not None else "",
            })
    return rows

def check_virustotal(ip: str, api_key: str) -> dict:
    _default = {
        "malicious_reports": 0, "suspicious_count":  0,
        "harmless_count":    0, "community_score":   0,
        "country": "Unknown",  "network": "Unknown", "categories": "",
    }
    if not api_key:
        return _default
    try:
        resp = requests.get(
            f"{VT_BASE}/{ip}",
            headers={"x-apikey": api_key},
            timeout=10
        )
        if resp.status_code != 200:
            return _default
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        votes = attrs.get("total_votes", {})
        cats  = attrs.get("categories", {})
        return {
            "malicious_reports": int(stats.get("malicious",  0)),
            "suspicious_count":  int(stats.get("suspicious", 0)),
            "harmless_count":    int(stats.get("harmless",   0)),
            "community_score":   int(votes.get("harmless",   0)) - int(votes.get("malicious", 0)),
            "country":           attrs.get("country",  "Unknown"),
            "network":           attrs.get("network",  "Unknown"),
            "categories":        ", ".join(set(cats.values())) if cats else "",
        }
    except Exception:
        return _default

def run_full_pipeline(targets: list, vt_api_key: str) -> list:
    all_rows = []
    for target in targets:
        xml_path = run_nmap_scan(target)
        all_rows.extend(parse_nmap_xml(xml_path))
    unique_ips = list({row["ip"] for row in all_rows})
    vt_cache   = {ip: check_virustotal(ip, vt_api_key) for ip in unique_ips}
    for row in all_rows:
        row.update(vt_cache.get(row["ip"], {}))
    return all_rows
