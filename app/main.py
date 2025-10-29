from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os, requests
from datetime import datetime
from typing import Dict, Any

app = FastAPI()

SN_URL = os.getenv("SN_URL", "https://example.service-now.com/api/now/table/incident")
SN_VERIFY_SSL = os.getenv("SN_VERIFY_SSL", "true").lower() == "true"
SN_CATEGORY = os.getenv("SN_CATEGORY", "software")
SN_ASSIGNMENT_GROUP = os.getenv("SN_ASSIGNMENT_GROUP", "")  # sys_id
SN_CALLER_ID = os.getenv("SN_CALLER_ID", "")  # sys_id
SN_STATE = os.getenv("SN_STATE", "1")
IMPACT_DEFAULT = os.getenv("IMPACT_DEFAULT", "3")
URGENCY_DEFAULT = os.getenv("URGENCY_DEFAULT", "3")
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", None)
CORRELATION_FORMAT = os.getenv("CORRELATION_FORMAT", "{groupKey}:{alertname}:{instance}")

SN_USER = os.getenv("SN_USER", "")
SN_PASSWORD = os.getenv("SN_PASSWORD", "")

SEV_TO_PRIORITY = {
    "critical": ("1", "1"),
    "warning": ("2", "2"),
    "warn": ("2", "2"),
    "info": ("3", "3"),
}


def sev_to_impact_urgency(sev: str):
    sev = (sev or "").lower()
    return SEV_TO_PRIORITY.get(sev, (IMPACT_DEFAULT, URGENCY_DEFAULT))


def to_sn_datetime(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def safe_get(d: Dict[str, Any], *keys, default=""):
    for k in keys:
        if d and k in d and d[k] is not None:
            return d[k]
    return default


def render_description(a: Dict[str, Any]) -> str:
    labels = a.get("labels", {})
    annotations = a.get("annotations", {})
    lines = []
    desc = safe_get(annotations, "description", default="")
    if desc:
        lines.append(desc)
    generator = safe_get(a, "generatorURL", default="")
    if generator:
        lines.append(f"
GeneratorURL: {generator}")
    lines.append("
Labels:")
    for k, v in sorted(labels.items()):
        lines.append(f"- {k}: {v}")
    if annotations:
        lines.append("
Annotations:")
        for k, v in sorted(annotations.items()):
            lines.append(f"- {k}: {v}")
    return "
".join(lines)


def build_short_desc(a: Dict[str, Any]) -> str:
    labels = a.get("labels", {})
    ann = a.get("annotations", {})
    sev = labels.get("severity", "n/a").upper()
    name = labels.get("alertname", "Alert")
    summary = ann.get("summary") or ann.get("description") or labels.get("instance") or ""
    return f"[{sev}] {name}: {summary}"[:160]


def build_correlation_id(payload: Dict[str, Any], a: Dict[str, Any]) -> str:
    labels = a.get("labels", {})
    vals = {
        "groupKey": payload.get("groupKey", ""),
        "alertname": labels.get("alertname", ""),
        "instance": labels.get("instance", labels.get("pod", labels.get("namespace", ""))),
        "fingerprint": safe_get(a, "fingerprint", default=""),
    }
    return CORRELATION_FORMAT.format(**vals).replace(" ", "_")[:255]


def post_incident(body: Dict[str, Any]) -> requests.Response:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    return requests.post(
        SN_URL, json=body, headers=headers, auth=(SN_USER, SN_PASSWORD), verify=SN_VERIFY_SSL, timeout=20
    )

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.get("/readyz")
async def readyz():
    return {"ready": True}

@app.post("/alertmanager")
async def alertmanager(request: Request):
    if WEBHOOK_TOKEN:
        token = request.headers.get("X-Webhook-Token")
        if token != WEBHOOK_TOKEN:
            raise HTTPException(status_code=401, detail="Invalid token")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    results = []
    for a in payload.get("alerts", []):
        if a.get("status") != "firing":
            results.append({"skipped": True, "reason": f"status={a.get('status')}"})
            continue
        labels = a.get("labels", {})
        impact, urgency = sev_to_impact_urgency(labels.get("severity", ""))
        incident = {
            "impact": impact,
            "urgency": urgency,
            "short_description": build_short_desc(a),
            "description": render_description(a),
            "caller_id": SN_CALLER_ID,
            "state": SN_STATE,
            "u_occurred_date": to_sn_datetime(a.get("startsAt", "")),
            "assignment_group": SN_ASSIGNMENT_GROUP,
            "correlation_id": build_correlation_id(payload, a),
            "category": SN_CATEGORY,
        }
        try:
            resp = post_incident(incident)
            ok = 200 <= resp.status_code < 300
            results.append({
                "alert": labels.get("alertname", "unknown"),
                "status_code": resp.status_code,
                "ok": ok,
                "response": resp.json() if ok else resp.text,
            })
        except Exception as e:
            results.append({"alert": labels.get("alertname", "unknown"), "ok": False, "error": str(e)})
    return JSONResponse({"sent": results})