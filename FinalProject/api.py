from fastapi import FastAPI, HTTPException, Depends, Header, Request
from pydantic import BaseModel
from typing import List, Optional
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

CYBERSCAN_API_KEY = os.environ.get("CYBERSCAN_API_KEY", "dev-key")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="CyberScan Pro API",
    version="4.0",
    description="Authenticated REST API — full enriched scan results with aggregated analysis",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

SCAN_DATA: List[dict] = []


class ScanRecord(BaseModel):
    ip:                str
    port:              str
    protocol:          Optional[str]  = "tcp"
    state:             Optional[str]  = "open"
    service:           str
    product:           Optional[str]  = ""
    version:           Optional[str]  = ""
    malicious_reports: int            = 0
    suspicious_count:  int            = 0
    harmless_count:    int            = 0
    community_score:   int            = 0
    country:           Optional[str]  = "Unknown"
    network:           Optional[str]  = "Unknown"
    categories:        Optional[str]  = ""
    exposure_score:    float          = 0.0
    threat_score:      float          = 0.0
    context_score:     float          = 0.0
    risk_score:        float          = 0.0
    severity:          str            = "Low"
    recommendation:    Optional[str]  = ""


def verify_key(x_api_key: str = Header(..., description="CyberScan API key")):
    if x_api_key != CYBERSCAN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


@app.get("/")
def root():
    return {"status": "running", "version": "4.0", "records": len(SCAN_DATA)}


@app.post("/load", dependencies=[Depends(verify_key)])
@limiter.limit("20/minute")
def load_data(request: Request, records: List[ScanRecord]):
    global SCAN_DATA
    SCAN_DATA = [r.dict() for r in records]
    return {
        "status":  "loaded",
        "records": len(SCAN_DATA),
        "hosts":   len({r["ip"] for r in SCAN_DATA}),
    }


@app.get("/results", dependencies=[Depends(verify_key)])
@limiter.limit("60/minute")
def get_results(request: Request, severity: Optional[str] = None):
    if not SCAN_DATA:
        raise HTTPException(status_code=404, detail="No scan data loaded")
    data = SCAN_DATA
    if severity:
        data = [r for r in data if r["severity"].lower() == severity.lower()]
    return {"count": len(data), "results": data}


@app.get("/analysis", dependencies=[Depends(verify_key)])
@limiter.limit("30/minute")
def get_analysis(request: Request):
    if not SCAN_DATA:
        raise HTTPException(status_code=404, detail="No scan data loaded")
    sev_counts: dict = {}
    for r in SCAN_DATA:
        sev = r.get("severity", "Unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    scores = [r["risk_score"] for r in SCAN_DATA]
    return {
        "total_records":      len(SCAN_DATA),
        "total_hosts":        len({r["ip"] for r in SCAN_DATA}),
        "severity_breakdown": sev_counts,
        "max_risk_score":     max(scores),
        "avg_risk_score":     round(sum(scores) / len(scores), 2),
        "vt_flagged_ips":     len({r["ip"] for r in SCAN_DATA if r.get("malicious_reports", 0) > 0}),
    }


@app.get("/host/{ip}", dependencies=[Depends(verify_key)])
def get_host(ip: str, request: Request):
    host_records = [r for r in SCAN_DATA if r["ip"] == ip]
    if not host_records:
        raise HTTPException(status_code=404, detail=f"No records found for {ip}")
    return {"ip": ip, "count": len(host_records), "records": host_records}
