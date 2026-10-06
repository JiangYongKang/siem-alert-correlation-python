"""FastAPI 入口：本地威胁检测与告警关联流程的 HTTP 接口。

设置环境变量 SIEM_STATE_PATH 后，服务启动时从该文件恢复状态
（文件不存在则全新启动；损坏时回退备份，备份也损坏则拒绝启动），
每次状态变更后原子写回，进程重启后接着跑。
"""

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from siem import DetectionRule, LogEvent, SiemPipeline
from siem.disposition import ConflictError, DispositionError
from siem.models import AuditAction

app = FastAPI(title="SIEM Alert Correlation")

RULES = [
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
]

STATE_PATH = os.environ.get("SIEM_STATE_PATH")

if STATE_PATH and os.path.exists(STATE_PATH):
    pipeline = SiemPipeline.load(
        STATE_PATH, RULES, suppression_window=600.0, max_lateness=300.0
    )
else:
    pipeline = SiemPipeline(RULES, suppression_window=600.0, max_lateness=300.0)


def _persist() -> None:
    if STATE_PATH:
        pipeline.save(STATE_PATH)


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


@app.post("/events")
def ingest_event(body: EventIn):
    event = LogEvent(
        body.event_id,
        body.timestamp,
        body.event_type,
        body.source,
        tuple(sorted(body.attributes.items())),
    )
    result = pipeline.process_event(event)
    _persist()
    ingest = result.ingest
    return {
        # 原有字段保持可用
        "accepted": ingest.accepted,
        "reason": ingest.reason.value if ingest.reason else None,
        "detail": ingest.detail,
        "alerts": [
            {
                "alert_id": a.alert_id,
                "rule_id": a.rule_id,
                "status": a.status.value,
                "event_count": len(a.event_ids),
                "suppressed_count": a.suppressed_count,
            }
            for h in result.hits
            if (a := pipeline.correlator.get(h.alert_id)) is not None
        ],
        # 新增字段：可区分的处理结论分类与命中明细
        "outcome": result.outcome.value,
        "outcome_detail": result.detail,
        "hits": [
            {
                "rule_id": h.rule_id,
                "rule_version": h.rule_version,
                "alert_id": h.alert_id,
                "created": h.created,
            }
            for h in result.hits
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
            # 新增字段：当前修订，供前置校验处置使用
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
    try:
        record = pipeline.disposition.transition(
            alert_id, actions[action], body.actor, body.timestamp,
            expected_version=body.expected_version,
        )
    except ConflictError as exc:
        _persist()  # 被拒尝试的审计与计数同样落盘
        # 前置校验冲突：与非法跃迁可区分
        raise HTTPException(409, {"error": "conflict", "detail": str(exc)}) from exc
    except DispositionError as exc:
        _persist()
        raise HTTPException(409, {"error": "illegal_transition", "detail": str(exc)}) from exc
    _persist()
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
    # 原有字段（各状态告警数）保持可用，新增三类独立计数
    return {**pipeline.disposition.status_counts(), **pipeline.counters()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=0)
