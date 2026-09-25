"""告警关联与抑制窗口去重。"""

from __future__ import annotations

import threading

from .models import Alert, DetectionRule, LogEvent


class AlertCorrelator:
    """把命中同一规则且关联键相同的事件聚合为一条告警。

    抑制窗口规则（确定且可复现）：
    - 每条告警的窗口为 [created_at, created_at + suppression_window)，
      以事件时间（而非到达时间）判定，与到达顺序无关。
    - 事件时间落在某条已有告警窗口内 -> 聚合进该告警，suppressed_count + 1，
      不产生新告警（窗口内去重）。
    - 事件时间早于该键所有告警窗口 -> 聚合进最早告警（同一攻击链的前序事件，
      乱序到达不另建告警）。
    - 事件时间不早于最新告警窗口末尾 -> 窗口解除抑制，创建新告警。
    - 关联键携带规则版本，规则变更后自然落入新键，判定不受旧状态影响。
    """

    def __init__(self, suppression_window: float = 600.0) -> None:
        self.suppression_window = suppression_window
        self._by_key: dict[tuple, list[Alert]] = {}
        self._seq = 0
        self._lock = threading.Lock()

    def correlate(self, event: LogEvent, rule: DetectionRule) -> tuple[Alert, bool]:
        """返回 (告警, 是否新建告警)。"""
        key = rule.correlation_key(event)
        with self._lock:
            alerts = self._by_key.setdefault(key, [])
            for alert in alerts:
                if alert.created_at <= event.timestamp < alert.created_at + self.suppression_window:
                    self._absorb(alert, event)
                    return alert, False
            if alerts and event.timestamp < alerts[-1].created_at + self.suppression_window:
                # 早于所有窗口的乱序前序事件，并入最早告警
                self._absorb(alerts[0], event)
                return alerts[0], False
            self._seq += 1
            alert = Alert(
                alert_id=f"alert-{self._seq:04d}",
                rule_id=rule.rule_id,
                rule_version=rule.version,
                severity=rule.severity,
                correlation_key=key,
                event_ids=[event.event_id],
                created_at=event.timestamp,
                updated_at=event.timestamp,
            )
            alerts.append(alert)
            return alert, True

    @staticmethod
    def _absorb(alert: Alert, event: LogEvent) -> None:
        if event.event_id not in alert.event_ids:
            alert.event_ids.append(event.event_id)
            alert.event_ids.sort()
        alert.suppressed_count += 1
        alert.updated_at = max(alert.updated_at, event.timestamp)
        alert.version += 1

    def alerts(self) -> list[Alert]:
        with self._lock:
            return [a for alerts in self._by_key.values() for a in alerts]
