"""告警状态机与审计：确认、关闭、重新打开的并发安全处置。

状态机：
    OPEN --ACK--> ACKED --CLOSE--> CLOSED
    OPEN --CLOSE--> CLOSED
    CLOSED --REOPEN--> OPEN
其余跃迁一律非法，且失败原因逐条可区分。

并发控制：
    每次成功处置使 alert.version + 1；调用方携带 expected_version 时，
    与当前版本不一致就抛 StaleVersionError（乐观锁），更新不会丢失。
    所有处置尝试（成功、非法跃迁、版本冲突）都追加一条审计记录。
"""

from __future__ import annotations

import threading
from dataclasses import replace

from siem.clock import Clock, FixedClock
from siem.models import (
    Alert,
    AlertAction,
    AlertState,
    ALLOWED_TRANSITIONS,
    NEXT_STATE,
    AuditEntry,
)


class IllegalTransitionError(Exception):
    """非法状态跃迁，message 携带可区分原因。"""


class StaleVersionError(Exception):
    """乐观锁冲突：expected_version 与当前版本不一致。"""


# 非法跃迁的逐条可区分原因
_ILLEGAL_REASONS: dict[tuple[AlertAction, AlertState], str] = {
    (AlertAction.ACK, AlertState.ACKED): "告警已处于 ACKED，重复确认被拒绝",
    (AlertAction.ACK, AlertState.CLOSED): "CLOSED 告警不能确认，须先 REOPEN",
    (AlertAction.CLOSE, AlertState.CLOSED): "告警已 CLOSED，重复关闭被拒绝；如需处理请 REOPEN",
    (AlertAction.REOPEN, AlertState.OPEN): "告警处于 OPEN，无需重新打开",
    (AlertAction.REOPEN, AlertState.ACKED): "ACKED 告警不能 REOPEN；须先 CLOSE 再 REOPEN",
}


class AlertManager:
    def __init__(self, clock: Clock | None = None) -> None:
        self._alerts: dict[str, Alert] = {}
        self._audit: list[AuditEntry] = []
        self._audit_seq = 0
        self._clock = clock or FixedClock(0)
        self._lock = threading.RLock()

    def add(self, alert: Alert) -> None:
        """登记引擎产生的新告警；alert_id 重复属于程序错误，直接拒绝。"""
        with self._lock:
            if alert.alert_id in self._alerts:
                raise ValueError(f"告警 ID 重复登记: {alert.alert_id}")
            self._alerts[alert.alert_id] = alert

    def get(self, alert_id: str) -> Alert:
        with self._lock:
            try:
                return replace(self._alerts[alert_id])
            except KeyError:
                raise KeyError(f"告警不存在: {alert_id}") from None

    def list(self) -> list[Alert]:
        with self._lock:
            return [replace(a) for a in self._alerts.values()]

    def attach_evidence(
        self, alert_id: str, event_id: str, *, suppressed: bool
    ) -> bool:
        """把抑制期/触发窗口内的事件挂到存储中的告警对象上。

        直接在锁内修改内部对象（get/list 返回的是副本，禁止经副本回写）。
        返回是否真的新增（重复 event_id 不重复计数）。
        """
        with self._lock:
            alert = self._alerts[alert_id]
            if event_id in alert.event_ids:
                return False
            alert.event_ids.append(event_id)
            alert.correlated_count = len(alert.event_ids)
            if suppressed:
                alert.suppressed_count += 1
            return True

    def act(
        self,
        alert_id: str,
        action: AlertAction,
        actor: str,
        reason: str,
        expected_version: int | None = None,
    ) -> AuditEntry:
        """执行处置动作并返回审计记录。

        非法跃迁抛 IllegalTransitionError，版本冲突抛 StaleVersionError；
        两种失败都会先写入一条 success=False 的审计记录。
        """
        if not actor or not actor.strip():
            raise ValueError("actor 不能为空，处置动作必须可追溯")
        if not reason or not reason.strip():
            raise ValueError("reason 不能为空，处置原因必须可区分可追溯")

        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise KeyError(f"告警不存在: {alert_id}")
            from_state = alert.state
            actual = alert.version

            def record(success: bool, to: AlertState | None, why: str) -> AuditEntry:
                self._audit_seq += 1
                entry = AuditEntry(
                    audit_id=self._audit_seq,
                    alert_id=alert_id,
                    action=action,
                    actor=actor,
                    reason=why,
                    success=success,
                    from_state=from_state,
                    to_state=to,
                    expected_version=expected_version,
                    actual_version=actual,
                    at_ms=self._clock.now_ms(),
                )
                self._audit.append(entry)
                return entry

            if expected_version is not None and expected_version != actual:
                why = (
                    f"乐观锁冲突：期望版本 {expected_version}，实际版本 {actual}，"
                    "该处置被拒绝以避免丢失更新"
                )
                record(False, None, why)
                raise StaleVersionError(why)

            if from_state not in ALLOWED_TRANSITIONS[action]:
                why = _ILLEGAL_REASONS.get(
                    (action, from_state),
                    f"非法跃迁：{action.value} 不允许从 {from_state.value} 发起",
                )
                record(False, None, why)
                raise IllegalTransitionError(why)

            to_state = NEXT_STATE[action]
            alert.state = to_state
            alert.version = actual + 1
            entry = record(True, to_state, reason)
            return entry

    def audit_trail(self, alert_id: str) -> list[AuditEntry]:
        with self._lock:
            return [e for e in self._audit if e.alert_id == alert_id]

    def all_audit(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._audit)

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "alerts": [
                    {
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
                        "event_ids": list(a.event_ids),
                        "suppressed_count": a.suppressed_count,
                        "correlated_count": a.correlated_count,
                    }
                    for a in self._alerts.values()
                ],
                "audit_seq": self._audit_seq,
                "audit": [
                    {
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
                    for e in self._audit
                ],
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            self._alerts = {}
            for item in state.get("alerts", []):
                data = dict(item)
                data["state"] = AlertState(data["state"])
                self._alerts[data["alert_id"]] = Alert(**data)
            self._audit = []
            for item in state.get("audit", []):
                data = dict(item)
                data["action"] = AlertAction(data["action"])
                data["from_state"] = (
                    AlertState(data["from_state"]) if data["from_state"] else None
                )
                data["to_state"] = (
                    AlertState(data["to_state"]) if data["to_state"] else None
                )
                self._audit.append(AuditEntry(**data))
            self._audit_seq = state.get("audit_seq", len(self._audit))
