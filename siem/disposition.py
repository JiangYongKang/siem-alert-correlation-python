"""告警处置：状态机流转与审计，线程安全。"""

from __future__ import annotations

import threading

from .models import Alert, AlertStatus, AuditAction, AuditRecord


class DispositionError(Exception):
    """非法状态跃迁或告警不存在，消息中携带可区分原因。"""


# 合法跃迁表：动作 -> 允许的源状态集合
_TRANSITIONS: dict[AuditAction, frozenset[AlertStatus]] = {
    AuditAction.ACKNOWLEDGE: frozenset({AlertStatus.OPEN}),
    AuditAction.CLOSE: frozenset({AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED}),
    AuditAction.REOPEN: frozenset({AlertStatus.CLOSED}),
}

_TARGET: dict[AuditAction, AlertStatus] = {
    AuditAction.ACKNOWLEDGE: AlertStatus.ACKNOWLEDGED,
    AuditAction.CLOSE: AlertStatus.CLOSED,
    AuditAction.REOPEN: AlertStatus.OPEN,
}


class AlertDispositionService:
    """对告警执行确认/关闭/重开。

    所有检查与修改在同一把锁内完成，并发处置同一告警时：
    - 不会出现非法跃迁（非法动作抛 DispositionError 并说明原因）；
    - 不会丢失更新（每次成功流转递增 alert.version 并追加审计记录）；
    - 状态与计数一致（status_counts 由同一锁内的告警状态派生）。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: dict[str, Alert] = {}
        self._audit: list[AuditRecord] = []

    def register(self, alert: Alert) -> None:
        with self._lock:
            self._alerts.setdefault(alert.alert_id, alert)

    def _transition(
        self, alert_id: str, action: AuditAction, actor: str, timestamp: float
    ) -> AuditRecord:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise DispositionError(f"告警不存在: {alert_id}")
            if alert.status not in _TRANSITIONS[action]:
                reason = (
                    f"非法跃迁: 告警 {alert_id} 当前状态 {alert.status.value}，"
                    f"不允许执行 {action.value}"
                )
                # 失败尝试同样留痕，原因可区分（detail 以 rejected: 前缀标识）
                self._audit.append(
                    AuditRecord(
                        alert_id=alert_id,
                        action=action,
                        actor=actor,
                        from_status=alert.status,
                        to_status=alert.status,
                        timestamp=timestamp,
                        detail=f"rejected: {reason}",
                    )
                )
                raise DispositionError(reason)
            record = AuditRecord(
                alert_id=alert_id,
                action=action,
                actor=actor,
                from_status=alert.status,
                to_status=_TARGET[action],
                timestamp=timestamp,
                detail=f"{actor} 将告警从 {alert.status.value} "
                f"流转为 {_TARGET[action].value}",
            )
            alert.status = record.to_status
            alert.updated_at = max(alert.updated_at, timestamp)
            alert.version += 1
            self._audit.append(record)
            return record

    def acknowledge(self, alert_id: str, actor: str, timestamp: float) -> AuditRecord:
        return self._transition(alert_id, AuditAction.ACKNOWLEDGE, actor, timestamp)

    def close(self, alert_id: str, actor: str, timestamp: float) -> AuditRecord:
        return self._transition(alert_id, AuditAction.CLOSE, actor, timestamp)

    def reopen(self, alert_id: str, actor: str, timestamp: float) -> AuditRecord:
        return self._transition(alert_id, AuditAction.REOPEN, actor, timestamp)

    def get(self, alert_id: str) -> Alert | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def audit_trail(self, alert_id: str | None = None) -> list[AuditRecord]:
        with self._lock:
            if alert_id is None:
                return list(self._audit)
            return [r for r in self._audit if r.alert_id == alert_id]

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            counts = {s.value: 0 for s in AlertStatus}
            for alert in self._alerts.values():
                counts[alert.status.value] += 1
            return counts
