from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", str(BASE_DIR.parent / "sentinel.db")))
API_KEY = os.getenv("SENTINEL_API_KEY", "change-me-before-deploy")
WAZUH_WEBHOOK_TOKEN = os.getenv("WAZUH_WEBHOOK_TOKEN", "change-wazuh-token")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.openai.com/v1")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4.1-mini")

app = FastAPI(title="SentinelAI SOC", version="0.1.0", description="Security event triage and incident dashboard starter.")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def db_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
            src_ip TEXT, dst_ip TEXT, host TEXT, username TEXT, status TEXT NOT NULL DEFAULT 'open',
            description TEXT, raw_json TEXT NOT NULL, ai_summary TEXT, created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL,
            event_id TEXT, details TEXT
        )""")


@app.on_event("startup")
def startup() -> None:
    init_db()


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not API_KEY or API_KEY == "change-me-before-deploy":
        # Deliberately allow local development with the documented default, but warn in README.
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Set X-API-Key to the configured SENTINEL_API_KEY")
        return
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


class EventIn(BaseModel):
    timestamp: Optional[str] = None
    source: str = Field(default="manual", max_length=80)
    title: str = Field(min_length=1, max_length=240)
    severity: str = "medium"
    category: str = "security"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    host: Optional[str] = None
    username: Optional[str] = None
    description: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


SEVERITIES = {"critical", "high", "medium", "low", "info"}


def normalize_severity(value: Any, default: str = "medium") -> str:
    if isinstance(value, (int, float)):
        if value >= 12: return "critical"
        if value >= 8: return "high"
        if value >= 4: return "medium"
        if value >= 1: return "low"
        return "info"
    text = str(value or default).lower()
    mapping = {"informational": "info", "warning": "medium", "error": "high", "fatal": "critical"}
    text = mapping.get(text, text)
    return text if text in SEVERITIES else default


def insert_event(event: EventIn) -> dict[str, Any]:
    event_id = str(uuid.uuid4())
    timestamp = event.timestamp or now_iso()
    severity = normalize_severity(event.severity)
    raw_json = json.dumps(event.raw, ensure_ascii=False, default=str)
    with db_conn() as conn:
        conn.execute("""INSERT INTO events
        (id,timestamp,source,title,severity,category,src_ip,dst_ip,host,username,status,description,raw_json,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            event_id, timestamp, event.source, event.title, severity, event.category,
            event.src_ip, event.dst_ip, event.host, event.username, "open", event.description,
            raw_json, now_iso()))
        conn.execute("INSERT INTO audit_log(timestamp,action,event_id,details) VALUES(?,?,?,?)",
                     (now_iso(), "event.created", event_id, f"source={event.source}; severity={severity}"))
    return get_event(event_id)


def get_event(event_id: str) -> dict[str, Any]:
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    item = dict(row)
    item["raw"] = json.loads(item.pop("raw_json"))
    return item


def normalize_wazuh(payload: dict[str, Any]) -> EventIn:
    alert = payload.get("parameters", {}).get("alert", payload.get("alert", payload))
    rule = alert.get("rule", {}) if isinstance(alert, dict) else {}
    agent = alert.get("agent", {}) if isinstance(alert, dict) else {}
    data = alert.get("data", {}) if isinstance(alert, dict) else {}
    src_ip = data.get("srcip") or data.get("src_ip")
    dst_ip = data.get("dstip") or data.get("dst_ip")
    return EventIn(
        timestamp=alert.get("timestamp") or now_iso(), source="wazuh",
        title=str(rule.get("description") or alert.get("full_log") or "Wazuh alert")[:240],
        severity=normalize_severity(rule.get("level", 4)),
        category=str(rule.get("groups", ["wazuh"])[0] if rule.get("groups") else "wazuh"),
        src_ip=src_ip, dst_ip=dst_ip, host=agent.get("name") or agent.get("id"),
        username=data.get("srcuser") or data.get("dstuser"),
        description=f"Wazuh rule {rule.get('id', 'unknown')}: {rule.get('description', 'alert received')}",
        raw=payload)


def normalize_suricata(payload: dict[str, Any]) -> EventIn:
    alert = payload.get("alert", {}) if isinstance(payload.get("alert"), dict) else {}
    event_type = payload.get("event_type", "unknown")
    title = alert.get("signature") or f"Suricata {event_type} event"
    severity = ({1: "high", 2: "medium", 3: "low"}.get(int(alert.get("severity", 3)), "medium")) if event_type == "alert" else "info"
    return EventIn(
        timestamp=payload.get("timestamp") or now_iso(), source="suricata",
        title=str(title)[:240], severity=severity, category=str(alert.get("category") or event_type),
        src_ip=payload.get("src_ip"), dst_ip=payload.get("dest_ip"),
        host=payload.get("host") or payload.get("in_iface"),
        description=f"Suricata event type: {event_type}; signature ID: {alert.get('signature_id', 'n/a')}",
        raw=payload)


def heuristic_summary(event: dict[str, Any]) -> str:
    parts = [f"{event['severity'].upper()} severity event from {event['source']}.", event.get("title", "Security event")]
    if event.get("src_ip"): parts.append(f"Source IP: {event['src_ip']}.")
    if event.get("dst_ip"): parts.append(f"Destination IP: {event['dst_ip']}.")
    if event.get("host"): parts.append(f"Host: {event['host']}.")
    parts.append("Validate the source telemetry, correlate nearby events, and confirm scope before taking containment action.")
    return " ".join(parts)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "SentinelAI SOC", "time": now_iso(), "ai_enabled": bool(AI_API_KEY)}


@app.get("/api/events", dependencies=[Depends(require_api_key)])
def list_events(limit: int = 100, severity: Optional[str] = None, status: Optional[str] = None) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    sql = "SELECT * FROM events WHERE 1=1"
    params: list[Any] = []
    if severity and severity in SEVERITIES:
        sql += " AND severity=?"; params.append(severity)
    if status in {"open", "investigating", "resolved"}:
        sql += " AND status=?"; params.append(status)
    sql += " ORDER BY timestamp DESC LIMIT ?"; params.append(limit)
    with db_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    items = []
    for row in rows:
        item = dict(row); item["raw"] = json.loads(item.pop("raw_json")); items.append(item)
    return {"items": items, "count": len(items)}


@app.get("/api/summary", dependencies=[Depends(require_api_key)])
def summary() -> dict[str, Any]:
    with db_conn() as conn:
        total = conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        open_count = conn.execute("SELECT COUNT(*) n FROM events WHERE status!='resolved'").fetchone()["n"]
        by_severity = {r["severity"]: r["n"] for r in conn.execute("SELECT severity,COUNT(*) n FROM events WHERE status!='resolved' GROUP BY severity")}
        by_source = {r["source"]: r["n"] for r in conn.execute("SELECT source,COUNT(*) n FROM events GROUP BY source")}
        recent = conn.execute("SELECT timestamp,severity FROM events ORDER BY timestamp DESC LIMIT 30").fetchall()
    return {"total_events": total, "open_incidents": open_count,
            "critical": by_severity.get("critical", 0), "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0), "low": by_severity.get("low", 0),
            "by_source": by_source, "recent": [dict(r) for r in reversed(recent)]}


@app.post("/api/events", dependencies=[Depends(require_api_key)])
def create_event(event: EventIn) -> dict[str, Any]:
    return insert_event(event)


@app.post("/api/demo/seed", dependencies=[Depends(require_api_key)])
def seed_demo() -> dict[str, Any]:
    samples = [
        EventIn(source="demo", title="Multiple failed SSH logins", severity="high", category="authentication", src_ip="198.51.100.23", dst_ip="10.20.0.14", host="linux-web-01", username="admin", description="Repeated authentication failures from one external address.", raw={"demo": True, "attempts": 37}),
        EventIn(source="demo", title="Suspicious PowerShell encoded command", severity="critical", category="execution", src_ip="10.20.0.33", host="finance-ws-07", username="analyst", description="Encoded PowerShell command flagged by endpoint telemetry.", raw={"demo": True, "rule_id": "SIM-PS-001"}),
        EventIn(source="demo", title="Possible port scan detected", severity="medium", category="network", src_ip="203.0.113.9", dst_ip="10.20.0.0/24", host="edge-sensor-01", description="High number of connection attempts across destination ports.", raw={"demo": True, "sensor": "suricata"}),
        EventIn(source="demo", title="New privileged account created", severity="high", category="privilege_change", src_ip="10.20.0.45", host="ad-01", username="svc-backup", description="A privileged account creation event needs validation.", raw={"demo": True, "event_id": 4720}),
        EventIn(source="demo", title="Outbound connection to rare destination", severity="low", category="network", src_ip="10.20.0.52", dst_ip="192.0.2.88", host="build-runner-02", description="Illustrative low-confidence network anomaly.", raw={"demo": True}),
    ]
    created = [insert_event(s) for s in samples]
    return {"created": len(created), "items": created}


@app.post("/api/events/{event_id}/status", dependencies=[Depends(require_api_key)])
def update_status(event_id: str, payload: dict[str, str]) -> dict[str, Any]:
    status = payload.get("status", "")
    if status not in {"open", "investigating", "resolved"}:
        raise HTTPException(status_code=400, detail="status must be open, investigating, or resolved")
    with db_conn() as conn:
        cur = conn.execute("UPDATE events SET status=? WHERE id=?", (status, event_id))
        if cur.rowcount == 0: raise HTTPException(status_code=404, detail="Event not found")
        conn.execute("INSERT INTO audit_log(timestamp,action,event_id,details) VALUES(?,?,?,?)", (now_iso(), "event.status_changed", event_id, status))
    return get_event(event_id)


@app.get("/api/audit", dependencies=[Depends(require_api_key)])
def audit(limit: int = 50) -> dict[str, Any]:
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 200)),)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.post("/api/integrations/wazuh")
async def wazuh_webhook(request: Request, x_webhook_token: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not WAZUH_WEBHOOK_TOKEN or x_webhook_token != WAZUH_WEBHOOK_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid webhook token")
    payload = await request.json()
    if not isinstance(payload, dict): raise HTTPException(status_code=400, detail="Expected a JSON object")
    event = insert_event(normalize_wazuh(payload))
    return {"accepted": True, "event_id": event["id"]}


@app.post("/api/integrations/suricata")
async def suricata_ingest(request: Request, x_api_key: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    payload = await request.json()
    if not isinstance(payload, dict): raise HTTPException(status_code=400, detail="Expected one Suricata EVE JSON object")
    event = insert_event(normalize_suricata(payload))
    return {"accepted": True, "event_id": event["id"]}


@app.post("/api/events/{event_id}/investigate", dependencies=[Depends(require_api_key)])
async def investigate(event_id: str) -> dict[str, Any]:
    event = get_event(event_id)
    if not AI_API_KEY:
        return {"event_id": event_id, "provider": "local-fallback", "ai_enabled": False, "analysis": heuristic_summary(event),
                "note": "Configure AI_API_KEY and AI_MODEL to enable LLM analysis. This fallback is template-based, not AI."}
    prompt = {
        "role": "user",
        "content": "Analyze this security event for a defensive SOC analyst. Separate observed facts from hypotheses, state confidence, give safe validation steps, and do not claim attribution or physical location from an IP. Do not recommend destructive actions. Event JSON: " + json.dumps({k: event[k] for k in ["timestamp", "source", "title", "severity", "category", "src_ip", "dst_ip", "host", "username", "description", "raw"]}, default=str)[:12000]
    }
    url = AI_BASE_URL.rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, headers=headers, json={"model": AI_MODEL, "messages": [
            {"role": "system", "content": "You are a careful defensive cybersecurity triage assistant. Never assert attacker identity without evidence."}, prompt], "temperature": 0.2})
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"AI provider error ({response.status_code}); check AI_BASE_URL, AI_MODEL and AI_API_KEY")
    body = response.json()
    analysis = body.get("choices", [{}])[0].get("message", {}).get("content", "No analysis returned")
    with db_conn() as conn:
        conn.execute("UPDATE events SET ai_summary=? WHERE id=?", (analysis, event_id))
        conn.execute("INSERT INTO audit_log(timestamp,action,event_id,details) VALUES(?,?,?,?)", (now_iso(), "event.ai_investigated", event_id, f"model={AI_MODEL}"))
    return {"event_id": event_id, "provider": AI_BASE_URL, "ai_enabled": True, "analysis": analysis}
