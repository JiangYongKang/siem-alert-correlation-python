"""FastAPI HTTP 入口：与服务层/CLI 共用同一套确定性结论。

响应信封：
    成功 {"ok": true, "data": ...}
    失败 {"ok": false, "error": {"code": "...", "message": "..."}}
失败原因 code 与领域层枚举一一对应（DUPLICATE / MISSING_FIELD / ... /
ILLEGAL_TRANSITION / STALE_VERSION / RULE_VERSION / NOT_FOUND）。
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from siem.alerts import IllegalTransitionError, StaleVersionError
from siem.models import (
    Alert,
    AlertAction,
    AuditEntry,
    IngestionResult,
    Rule,
)
from siem.rules import RuleVersionError
from siem.service import SiemService


# ----------------------------------------------------------------------
# 序列化（dataclass -> JSON 安全 dict；用 asdict 之外的手写版本以控制枚举）
def _rule_out(r: Rule) -> dict[str, Any]:
    return {
        "rule_id": r.rule_id,
        "version": r.version,
        "match_type": r.match_type,
        "match_value": r.match_value,
        "severity": r.severity,
        "correlation_key": r.correlation_key,
        "threshold": r.threshold,
        "window_ms": r.window_ms,
        "suppression_ms": r.suppression_ms,
        "enabled": r.enabled,
    }


def _alert_out(a: Alert) -> dict[str, Any]:
    return {
        "alert_id": a.alert_id,
        "rule_id": a.rule_id,
        "rule_version": a.rule_version,
        "correlation_key": a.correlation_key,
        "correlation_value": a.correlation_value,
        "state": a.state.value,
        "severity": a.severity,
        "threshold": a.threshold,
        "window_ms": a.window_ms,
        "suppression_ms": a.suppression_ms,
        "anchor_ms": a.anchor_ms,
        "triggered_ms": a.triggered_ms,
        "suppress_until_ms": a.suppress_until_ms,
        "version": a.version,
        "event_ids": a.event_ids,
        "suppressed_count": a.suppressed_count,
        "correlated_count": a.correlated_count,
    }


def _audit_out(e: AuditEntry) -> dict[str, Any]:
    return {
        "audit_id": e.audit_id,
        "alert_id": e.alert_id,
        "action": e.action.value,
        "actor": e.actor,
        "reason": e.reason,
        "success": e.success,
        "from_state": e.from_state.value if e.from_state else None,
        "to_state": e.to_state.value if e.to_state else None,
        "expected_version": e.expected_version,
        "actual_version": e.actual_version,
        "at_ms": e.at_ms,
    }


def _ingest_out(r: IngestionResult) -> dict[str, Any]:
    return {
        "event_id": r.event_id,
        "accepted": r.accepted,
        "reject_reason": r.reject_reason.value if r.reject_reason else None,
        "ignore_reason": r.ignore_reason.value if r.ignore_reason else None,
        "matches": [
            {"rule_id": m.rule_id, "version": m.version, "correlation_value": m.correlation_value}
            for m in r.matches
        ],
        "alert_ids": r.alert_ids,
        "rule_decisions": [
            {
                "rule_id": d.rule_id,
                "version": d.version,
                "correlation_value": d.correlation_value,
                "status": d.status,
                "alert_id": d.alert_id,
                "reason": d.reason,
            }
            for d in r.rule_decisions
        ],
        "detail": r.detail,
    }


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"ok": False, "error": {"code": code, "message": message}},
    )


# ----------------------------------------------------------------------
class EventIn(BaseModel):
    # 顶层字段全部可选：字段级可区分的拒绝原因
    # （MISSING_FIELD / BAD_TIMESTAMP / MALFORMED）统一由服务层产出，
    # 保证 HTTP 入口与服务层/CLI 结论结构完全一致，而非 Pydantic 422。
    event_id: str | None = None
    timestamp_ms: int | None = None
    source: str | None = None
    event_type: str | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)


class RuleIn(BaseModel):
    rule_id: str
    version: int
    match_type: str
    match_value: str
    severity: str
    correlation_key: str
    threshold: int
    window_ms: int
    suppression_ms: int
    enabled: bool = True


class ActionIn(BaseModel):
    action: AlertAction
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    expected_version: int | None = None


# ----------------------------------------------------------------------
def create_app(service: SiemService | None = None) -> FastAPI:
    svc = service or SiemService()
    app = FastAPI(
        title="本地威胁检测与告警关联",
        version="0.1.0",
        description="事件摄入/规则匹配/攻击链聚合/抑制/告警状态机，全部本地内存可复现。",
    )

    @app.exception_handler(ValueError)
    async def _value_error_handler(_request, exc: ValueError) -> JSONResponse:  # noqa: ANN001
        code = "VALIDATION_ERROR"
        status = 422
        if isinstance(exc, RuleVersionError):
            code, status = "RULE_VERSION", 409
        return _error(code, str(exc), status)

    @app.get("/")
    def read_root() -> dict[str, str]:
        return {"ok": "true", "service": "siem-alert-correlation", "version": "0.1.0"}

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    # ---- 规则 ----
    @app.put("/rules")
    def put_rule(body: RuleIn) -> dict[str, Any]:
        rule = Rule(**body.model_dump())
        svc.upsert_rule(rule)
        return {"ok": True, "data": _rule_out(rule)}

    @app.get("/rules")
    def get_rules() -> dict[str, Any]:
        return {"ok": True, "data": [_rule_out(r) for r in svc.list_rules()]}

    # ---- 事件 ----
    @app.post("/events")
    def post_event(body: EventIn) -> JSONResponse:
        result = svc.ingest_event_dict(body.model_dump())
        # 重复/缺字段等拒绝是确定性业务结论，用 200 返回结构化结论，
        # 同时通过 reject_reason 可区分；HTTP 层仍视为一次成功处理。
        return JSONResponse(status_code=200, content={"ok": True, "data": _ingest_out(result)})

    # ---- 告警 ----
    @app.get("/alerts")
    def list_alerts() -> dict[str, Any]:
        return {"ok": True, "data": [_alert_out(a) for a in svc.list_alerts()]}

    @app.get("/alerts/{alert_id}")
    def get_alert(alert_id: str) -> JSONResponse:
        try:
            return JSONResponse(
                status_code=200,
                content={"ok": True, "data": _alert_out(svc.get_alert(alert_id))},
            )
        except KeyError as exc:
            return _error("NOT_FOUND", str(exc), 404)

    @app.post("/alerts/{alert_id}/actions")
    def act_alert(alert_id: str, body: ActionIn) -> JSONResponse:
        try:
            entry = svc.act_alert(
                alert_id,
                body.action,
                body.actor,
                body.reason,
                expected_version=body.expected_version,
            )
        except KeyError as exc:
            return _error("NOT_FOUND", str(exc), 404)
        except StaleVersionError as exc:
            return _error("STALE_VERSION", str(exc), 409)
        except IllegalTransitionError as exc:
            return _error("ILLEGAL_TRANSITION", str(exc), 409)
        return JSONResponse(status_code=200, content={"ok": True, "data": _audit_out(entry)})

    @app.get("/alerts/{alert_id}/audit")
    def get_audit(alert_id: str) -> JSONResponse:
        try:
            svc.get_alert(alert_id)
        except KeyError as exc:
            return _error("NOT_FOUND", str(exc), 404)
        return JSONResponse(
            status_code=200,
            content={"ok": True, "data": [_audit_out(e) for e in svc.audit_trail(alert_id)]},
        )

    @app.get("/audit")
    def all_audit() -> dict[str, Any]:
        return {"ok": True, "data": [_audit_out(e) for e in svc.all_audit()]}

    # ---- 持久化（未配置存储时 400） ----
    @app.post("/snapshot")
    def post_snapshot() -> JSONResponse:
        try:
            svc.save()
        except RuntimeError as exc:
            return _error("PERSISTENCE_DISABLED", str(exc), 400)
        return JSONResponse(status_code=200, content={"ok": True, "data": {"saved": True}})

    @app.post("/snapshot/load")
    def load_snapshot() -> JSONResponse:
        try:
            loaded = svc.load()
        except RuntimeError as exc:
            return _error("PERSISTENCE_DISABLED", str(exc), 400)
        return JSONResponse(
            status_code=200, content={"ok": True, "data": {"loaded": loaded}}
        )

    return app
