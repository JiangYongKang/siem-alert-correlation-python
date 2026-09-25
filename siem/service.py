"""门面服务：把规则、引擎、告警管理与持久化组装为一致入口。

CLI、FastAPI 与测试都只依赖本服务，保证各入口结论一致、可解释。
所有异常式拒绝在入口处被转换为带 RejectReason 的 IngestionResult，
不静默丢弃任何输入。
"""

from __future__ import annotations

import logging
from typing import Any

from siem.alerts import AlertManager, IllegalTransitionError, StaleVersionError
from siem.clock import Clock, FixedClock
from siem.engine import CorrelationEngine
from siem.models import (
    Alert,
    AlertAction,
    AuditEntry,
    Event,
    IgnoreReason,
    IngestionResult,
    MatchedRule,
    RejectReason,
    Rule,
    RuleDecision,
)
from siem.rules import RuleRegistry, RuleVersionError
from siem.storage import JsonSnapshotStore

logger = logging.getLogger("siem.service")

_REQUIRED_STR_FIELDS = ("event_id", "source", "event_type")


class SiemService:
    def __init__(
        self,
        clock: Clock | None = None,
        grace_ms: int | None = None,
        store: JsonSnapshotStore | None = None,
    ) -> None:
        self._clock = clock or FixedClock(0)
        self._registry = RuleRegistry()
        self._engine = CorrelationEngine(self._registry, self._clock, grace_ms)
        self._alerts = AlertManager(self._clock)
        self._engine.bind_alerts(self._alerts)
        self._store = store

    # ------------------------------------------------------------------
    # 规则
    def upsert_rule(self, rule: Rule) -> None:
        """登记规则；版本回退抛 RuleVersionError（HTTP 层映射为 409）。"""
        self._registry.upsert(rule)

    def list_rules(self) -> list[Rule]:
        return self._registry.all()

    # ------------------------------------------------------------------
    # 事件
    def ingest_event_dict(self, payload: Any) -> IngestionResult:
        """校验并摄入原始 dict 事件，任何异常都转成可区分的拒绝结论。"""
        if not isinstance(payload, dict):
            return self._reject(
                str(id(payload)),
                RejectReason.MALFORMED,
                f"事件载荷必须是 JSON 对象，实际为 {type(payload).__name__}",
            )

        event_id = payload.get("event_id")
        label = event_id if isinstance(event_id, str) and event_id else "<unknown>"

        for field_name in _REQUIRED_STR_FIELDS:
            value = payload.get(field_name)
            if not isinstance(value, str) or not value:
                return self._reject(
                    label,
                    RejectReason.MISSING_FIELD,
                    f"必填字符串字段 {field_name} 缺失或不是非空字符串",
                )

        ts = payload.get("timestamp_ms")
        if isinstance(ts, bool) or not isinstance(ts, int):
            return self._reject(
                label,
                RejectReason.BAD_TIMESTAMP,
                "timestamp_ms 必须是整数毫秒时间戳",
            )
        if ts < 0:
            return self._reject(
                label, RejectReason.BAD_TIMESTAMP, "timestamp_ms 不允许为负数"
            )

        attrs = payload.get("attrs", {})
        if attrs is None:
            attrs = {}
        if not isinstance(attrs, dict):
            return self._reject(
                label, RejectReason.MALFORMED, "attrs 必须是 JSON 对象"
            )

        try:
            event = Event(
                event_id=payload["event_id"],
                timestamp_ms=ts,
                source=payload["source"],
                event_type=payload["event_type"],
                attrs=dict(attrs),
            )
        except TypeError as exc:
            return self._reject(label, RejectReason.MALFORMED, f"事件构造失败: {exc}")

        return self.ingest_event(event)

    def ingest_event(self, event: Event) -> IngestionResult:
        return self._engine.ingest(event)

    @staticmethod
    def _reject(
        event_id: str, reason: RejectReason, detail: str
    ) -> IngestionResult:
        logger.info("入口拒绝 event_id=%s reason=%s detail=%s", event_id, reason, detail)
        return IngestionResult(
            event_id=event_id, accepted=False, reject_reason=reason, detail=detail
        )

    # ------------------------------------------------------------------
    # 告警
    def list_alerts(self) -> list[Alert]:
        return self._alerts.list()

    def get_alert(self, alert_id: str) -> Alert:
        return self._alerts.get(alert_id)

    def act_alert(
        self,
        alert_id: str,
        action: AlertAction,
        actor: str,
        reason: str,
        expected_version: int | None = None,
    ) -> AuditEntry:
        return self._alerts.act(
            alert_id, action, actor, reason, expected_version=expected_version
        )

    def audit_trail(self, alert_id: str) -> list[AuditEntry]:
        return self._alerts.audit_trail(alert_id)

    def all_audit(self) -> list[AuditEntry]:
        return self._alerts.all_audit()

    # ------------------------------------------------------------------
    # 持久化
    def save(self) -> None:
        if self._store is None:
            raise RuntimeError("未配置持久化存储")
        self._store.save(self._registry, self._engine, self._alerts)

    def load(self) -> bool:
        if self._store is None:
            raise RuntimeError("未配置持久化存储")
        return self._store.load(self._registry, self._engine, self._alerts)

    @property
    def alerts_manager(self) -> AlertManager:
        return self._alerts

    @property
    def registry(self) -> RuleRegistry:
        return self._registry
