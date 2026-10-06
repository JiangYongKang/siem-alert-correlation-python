"""告警处置：状态机流转与审计，线程安全。

新增能力（不改变既有判定）：
- 带前置校验的处置入口 try_transition：调用方携带其认为的当前修订
  （expected_version），对得上才允许流转；对不上作为可区分的冲突
  （TransitionOutcome.CONFLICT）被拒绝，与非法跃迁分开。
- 计数口径拆分：关联事件数 / 成功流转次数 / 累计尝试次数，各自独立。
- 被拒绝的尝试（含冲突）同样追加审计记录，可追溯到人与时间。
"""

from __future__ import annotations

import threading
from dataclasses import replace

from .models import (
    Alert,
    AlertStatus,
    AuditAction,
    AuditRecord,
    DispositionCounters,
    TransitionOutcome,
    TransitionResult,
)


class DispositionError(Exception):
    """非法状态跃迁或告警不存在，消息中携带可区分原因。"""


class ConflictError(DispositionError):
    """前置校验失败：调用方携带的修订与当前修订不一致。

    继承 DispositionError，旧的捕获方式仍然有效；
    需要区分冲突与非法跃迁时可单独捕获本类。
    """


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
    - 状态与计数一致（status_counts 由同一锁内的告警状态派生，
      counters 与审计/状态在同一临界区内更新）。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._alerts: dict[str, Alert] = {}
        self._audit: list[AuditRecord] = []
        self._counters: dict[str, DispositionCounters] = {}

    def register(self, alert: Alert) -> None:
        with self._lock:
            self._alerts.setdefault(alert.alert_id, alert)
            self._counters.setdefault(alert.alert_id, DispositionCounters())

    def note_correlated(self, alert_id: str) -> None:
        """记录一条事件被关联进告警（新建或抑制收编均计入）。"""
        with self._lock:
            c = self._counters.get(alert_id)
            if c is not None:
                self._counters[alert_id] = replace(
                    c, correlated_events=c.correlated_events + 1
                )

    def counters(self, alert_id: str) -> DispositionCounters | None:
        """告警的三类计数：关联事件数 / 成功流转次数 / 累计尝试次数。"""
        with self._lock:
            return self._counters.get(alert_id)

    def _bump_attempted(self, alert_id: str) -> None:
        c = self._counters[alert_id]
        self._counters[alert_id] = replace(
            c, transitions_attempted=c.transitions_attempted + 1
        )

    def _bump_applied(self, alert_id: str) -> None:
        c = self._counters[alert_id]
        self._counters[alert_id] = replace(
            c, transitions_applied=c.transitions_applied + 1
        )

    def _attempt(
        self,
        alert_id: str,
        action: AuditAction,
        actor: str,
        timestamp: float,
        expected_version: int | None,
    ) -> TransitionResult:
        """处置尝试的统一临界区：前置校验 -> 跃迁校验 -> 应用，全程持锁。"""
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                reason = f"告警不存在: {alert_id}"
                record = AuditRecord(
                    alert_id=alert_id,
                    action=action,
                    actor=actor,
                    from_status=AlertStatus.OPEN,
                    to_status=AlertStatus.OPEN,
                    timestamp=timestamp,
                    detail=f"rejected: {reason}",
                )
                self._audit.append(record)
                return TransitionResult(
                    TransitionOutcome.NOT_FOUND, alert_id, action, actor, reason, record
                )
            self._bump_attempted(alert_id)
            if expected_version is not None and expected_version != alert.version:
                reason = (
                    f"修订冲突: 告警 {alert_id} 当前修订 {alert.version}，"
                    f"调用方期望 {expected_version}"
                )
                record = AuditRecord(
                    alert_id=alert_id,
                    action=action,
                    actor=actor,
                    from_status=alert.status,
                    to_status=alert.status,
                    timestamp=timestamp,
                    detail=f"conflict: {reason}",
                )
                self._audit.append(record)
                return TransitionResult(
                    TransitionOutcome.CONFLICT, alert_id, action, actor, reason, record
                )
            if alert.status not in _TRANSITIONS[action]:
                reason = (
                    f"非法跃迁: 告警 {alert_id} 当前状态 {alert.status.value}，"
                    f"不允许执行 {action.value}"
                )
                # 失败尝试同样留痕，原因可区分（detail 以 rejected: 前缀标识）
                record = AuditRecord(
                    alert_id=alert_id,
                    action=action,
                    actor=actor,
                    from_status=alert.status,
                    to_status=alert.status,
                    timestamp=timestamp,
                    detail=f"rejected: {reason}",
                )
                self._audit.append(record)
                return TransitionResult(
                    TransitionOutcome.INVALID_TRANSITION,
                    alert_id,
                    action,
                    actor,
                    reason,
                    record,
                )
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
            self._bump_applied(alert_id)
            self._audit.append(record)
            return TransitionResult(
                TransitionOutcome.APPLIED, alert_id, action, actor, record.detail, record
            )

    def try_transition(
        self,
        alert_id: str,
        action: AuditAction,
        actor: str,
        timestamp: float,
        expected_version: int | None = None,
    ) -> TransitionResult:
        """带前置校验的处置入口。

        expected_version 不为 None 时，仅当它与告警当前修订一致才允许流转；
        不一致返回 CONFLICT（可区分于非法跃迁），被拒绝的尝试同样留痕。
        """
        return self._attempt(alert_id, action, actor, timestamp, expected_version)

    def _transition(
        self, alert_id: str, action: AuditAction, actor: str, timestamp: float
    ) -> AuditRecord:
        result = self._attempt(alert_id, action, actor, timestamp, None)
        if result.outcome is not TransitionOutcome.APPLIED:
            raise DispositionError(result.detail)
        return result.record

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

    def snapshot(
        self,
    ) -> tuple[list[Alert], list[AuditRecord], dict[str, DispositionCounters]]:
        """导出 (告警, 审计, 计数)，用于持久化。"""
        with self._lock:
            return list(self._alerts.values()), list(self._audit), dict(self._counters)

    def restore(
        self,
        alerts: list[Alert],
        audit: list[AuditRecord],
        counters: dict[str, DispositionCounters],
    ) -> None:
        """从持久化状态恢复。恢复后已处置状态、审计与计数全部保留。"""
        with self._lock:
            if self._alerts:
                raise ValueError("只能在未注册过告警的处置服务上恢复状态")
            for alert in alerts:
                self._alerts[alert.alert_id] = alert
            self._audit = list(audit)
            self._counters = dict(counters)
            for alert_id in self._alerts:
                self._counters.setdefault(alert_id, DispositionCounters())
