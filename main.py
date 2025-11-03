import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from typing import List

from schemas import Block, Alert, ActionLog, AnalyzeRequest, AnalyzeResponse
from database import create_document, get_documents, db

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = getattr(db, 'name', None) or "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response

# --- IDS Functional Endpoints ---

@app.post("/api/block-ip")
def block_ip(payload: Block):
    doc_id = create_document("block", payload)
    create_document("actionlog", ActionLog(action="block_ip", details=f"Blocked {payload.ip} ({payload.reason})"))
    return {"status": "ok", "id": doc_id}

@app.get("/api/blocks")
def list_blocks():
    items = get_documents("block", {}, limit=100)
    # Convert ObjectId to string
    for i in items:
        if "_id" in i:
            i["_id"] = str(i["_id"])
    return {"items": items}

@app.post("/api/alerts/export", response_class=PlainTextResponse)
def export_alerts_csv(alerts: List[Alert]):
    # Simple CSV generation
    headers = ["alert_id", "time", "src", "dest", "type", "severity"]
    rows = [",".join(headers)]
    for a in alerts:
        rows.append(
            ",".join([
                a.alert_id.replace(",", " "),
                a.time.replace(",", " "),
                a.src.replace(",", " "),
                a.dest.replace(",", " "),
                a.type.replace(",", " "),
                a.severity.replace(",", " "),
            ])
        )
    csv_text = "\n".join(rows)
    create_document("actionlog", ActionLog(action="export_csv", details=f"Exported {len(alerts)} alerts"))
    return csv_text

@app.post("/api/ai/analyze", response_model=AnalyzeResponse)
def analyze_logs(req: AnalyzeRequest):
    text = req.text.lower()
    findings = []
    if any(k in text for k in ["failed", "unauthorized", "denied", "forbidden"]):
        findings.append("Repeated authentication failures detected. Consider rate-limiting and MFA.")
    if any(k in text for k in ["sql", "select", "union", " or 1=1", "-- "]):
        findings.append("Potential SQL injection patterns found. Ensure parameterized queries and WAF rules.")
    if any(k in text for k in ["xss", "<script>", "onerror=", "alert("]):
        findings.append("Possible XSS attempt observed. Implement robust output encoding and CSP.")
    if any(k in text for k in ["scan", "nmap", "masscan", "port"]):
        findings.append("Port scan behavior detected. Enable adaptive blocking and tarpits.")
    if any(k in text for k in ["ssh", " 22 ", "brute"]):
        findings.append("SSH brute-force indicators present. Enforce key-based auth and fail2ban.")
    if not findings:
        findings.append("No clear malicious patterns detected. Continue monitoring with anomaly thresholds.")
    risk = "High" if len(findings) >= 3 else ("Medium" if len(findings) == 2 else "Low")
    create_document("actionlog", ActionLog(action="analyze", details=f"Risk {risk}"))
    return AnalyzeResponse(risk=risk, summary=findings)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
