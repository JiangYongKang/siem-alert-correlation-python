"""FastAPI 入口：本地威胁检测与告警关联流程的 HTTP 接口。"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from siem import DetectionRule, LogEvent, SiemPipeline
from siem.disposition import DispositionError

app = FastAPI(title="SIEM Alert Correlation")

pipeline = SiemPipeline(
    rules=[
        DetectionRule(
            "brute-force-login",
            "login_failed",
            "high",
            required_attributes=("user",),
            correlation_keys=("source", "user"),
        ),
        DetectionRule(
            "priv-escalation",
            "privilege_escalation",
            "critical",
            correlation_keys=("source",),
        ),
    ],
    suppression_window=600.0,
    max_lateness=300.0,
)


class EventIn(BaseModel):
    event_id: str
    timestamp: float
    event_type: str
    source: str
    attributes: dict = {}


class DispositionIn(BaseModel):
    actor: str
    timestamp: float


@app.post("/events")
def ingest_event(body: EventIn):
    event = LogEvent(
        body.event_id,
        body.timestamp,
        body.event_type,
        body.source,
        tuple(sorted(body.attributes.items())),
    )
    result, alerts = pipeline.process(event)
    return {
        "accepted": result.accepted,
        "reason": result.reason.value if result.reason else None,
        "detail": result.detail,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_id": a.rule_id,
                "status": a.status.value,
                "event_count": len(a.event_ids),
                "suppressed_count": a.suppressed_count,
            }
            for a in alerts
        ],
    }


@app.get("/alerts")
def list_alerts():
    return [
        {
            "alert_id": a.alert_id,
            "rule_id": a.rule_id,
            "severity": a.severity,
            "status": a.status.value,
            "event_ids": a.event_ids,
            "suppressed_count": a.suppressed_count,
        }
        for a in pipeline.correlator.alerts()
    ]


@app.post("/alerts/{alert_id}/{action}")
def dispose_alert(alert_id: str, action: str, body: DispositionIn):
    handlers = {
        "acknowledge": pipeline.disposition.acknowledge,
        "close": pipeline.disposition.close,
        "reopen": pipeline.disposition.reopen,
    }
    if action not in handlers:
        raise HTTPException(404, f"未知动作: {action}")
    try:
        record = handlers[action](alert_id, body.actor, body.timestamp)
    except DispositionError as exc:
        raise HTTPException(409, str(exc)) from exc
    return {
        "alert_id": record.alert_id,
        "action": record.action.value,
        "from_status": record.from_status.value,
        "to_status": record.to_status.value,
        "detail": record.detail,
    }


@app.get("/audit")
def audit(alert_id: str | None = None):
    return [
        {
            "alert_id": r.alert_id,
            "action": r.action.value,
            "actor": r.actor,
            "from_status": r.from_status.value,
            "to_status": r.to_status.value,
            "timestamp": r.timestamp,
            "detail": r.detail,
        }
        for r in pipeline.disposition.audit_trail(alert_id)
    ]


@app.get("/stats")
def stats():
    return pipeline.disposition.status_counts()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=0)
