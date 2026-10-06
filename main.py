"""FastAPI 入口：本地威胁检测与告警关联流程的 HTTP 接口。

原有接口字段保持可用；新增信息以新增字段给出：
- POST /events 响应新增 outcome（处理结论分类与命中明细）。
- POST /alerts/{id}/{action} 请求可携带 expected_version 做前置校验，
  响应新增 outcome 区分 applied/conflict/invalid_transition/not_found。
- GET /stats 新增 counters（三类计数口径）。
- POST /state/save、POST /state/reload 做本地状态保存与恢复。
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from siem import (
    AuditAction,
    DetectionRule,
    LogEvent,
    SiemPipeline,
    StateCorruptionError,
    TransitionOutcome,
)

app = FastAPI(title="SIEM Alert Correlation")


def _build_pipeline() -> SiemPipeline:
    return SiemPipeline(
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


pipeline = _build_pipeline()


class EventIn(BaseModel):
    event_id: str
    timestamp: float
    event_type: str
    source: str
    attributes: dict = {}


class DispositionIn(BaseModel):
    actor: str
    timestamp: float
    expected_version: int | None = None  # 前置校验：调用方认为的当前修订


class StateIn(BaseModel):
    path: str = "siem-state.json"


@app.post("/events")
def ingest_event(body: EventIn):
    event = LogEvent(
        body.event_id,
        body.timestamp,
        body.event_type,
        body.source,
        tuple(sorted(body.attributes.items())),
    )
    outcome = pipeline.process_explain(event)
    alerts = [pipeline.disposition.get(h.alert_id) for h in outcome.hits]
    return {
        # 原有字段
        "accepted": outcome.category.value
        in ("processed_no_match", "alert_created", "alert_suppressed"),
        "reason": outcome.reason.value if outcome.reason else None,
        "detail": outcome.detail,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_id": a.rule_id,
                "status": a.status.value,
                "event_count": len(a.event_ids),
                "suppressed_count": a.suppressed_count,
            }
            for a in alerts
            if a is not None
        ],
        # 新增字段：处理结论分类与命中明细
        "outcome": {
            "category": outcome.category.value,
            "hits": [
                {
                    "rule_id": h.rule_id,
                    "rule_version": h.rule_version,
                    "alert_id": h.alert_id,
                    "created": h.created,
                    "window_start": h.window_start,
                    "window_end": h.window_end,
                }
                for h in outcome.hits
            ],
        },
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
            "version": a.version,
        }
        for a in pipeline.correlator.alerts()
    ]


@app.post("/alerts/{alert_id}/{action}")
def dispose_alert(alert_id: str, action: str, body: DispositionIn):
    actions = {
        "acknowledge": AuditAction.ACKNOWLEDGE,
        "close": AuditAction.CLOSE,
        "reopen": AuditAction.REOPEN,
    }
    if action not in actions:
        raise HTTPException(404, f"未知动作: {action}")
    result = pipeline.disposition.try_transition(
        alert_id, actions[action], body.actor, body.timestamp, body.expected_version
    )
    if result.outcome is TransitionOutcome.NOT_FOUND:
        raise HTTPException(404, result.detail)
    if result.outcome is not TransitionOutcome.APPLIED:
        # 冲突与非法跃迁可区分：outcome 字段分别为 conflict / invalid_transition
        raise HTTPException(
            409, {"outcome": result.outcome.value, "detail": result.detail}
        )
    record = result.record
    return {
        "alert_id": record.alert_id,
        "action": record.action.value,
        "from_status": record.from_status.value,
        "to_status": record.to_status.value,
        "detail": record.detail,
        "outcome": result.outcome.value,
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
    counts = pipeline.disposition.status_counts()
    counters = {
        a.alert_id: pipeline.disposition.counters(a.alert_id).__dict__
        for a in pipeline.correlator.alerts()
        if pipeline.disposition.counters(a.alert_id) is not None
    }
    # 原有字段（状态计数平铺）保持可用，新增 counters 字段
    return {**counts, "counters": counters}


@app.post("/state/save")
def save_state(body: StateIn):
    pipeline.save_state(body.path)
    return {"saved": body.path}


@app.post("/state/reload")
def reload_state(body: StateIn):
    global pipeline
    try:
        pipeline = SiemPipeline.restore(body.path, rules=_build_pipeline().engine.current_rules())
    except StateCorruptionError as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"loaded": body.path}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=0)
