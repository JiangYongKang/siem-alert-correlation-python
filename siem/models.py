"""核心数据模型：日志事件、检测规则、告警、审计记录。"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RejectReason(enum.Enum):
    """事件被拒绝或被忽略的可区分原因。"""

    MISSING_FIELD = "missing_field"
    INVALID_TIMESTAMP = "invalid_timestamp"
    DUPLICATE_DELIVERY = "duplicate_delivery"
    TOO_LATE = "too_late"


class AlertStatus(enum.Enum):
    """告警状态机：OPEN -> ACKNOWLEDGED -> CLOSED，CLOSED 可重新打开。"""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


class AuditAction(enum.Enum):
    """处置动作类型。"""

    ACKNOWLEDGE = "acknowledge"
    CLOSE = "close"
    REOPEN = "reopen"


@dataclass(frozen=True)
class LogEvent:
    """一条日志事件。event_id 用于重复投递去重，timestamp 为事件时间（秒）。"""

    event_id: str
    timestamp: float
    event_type: str
    source: str
    attributes: tuple[tuple[str, Any], ...] = ()

    def get(self, key: str, default: Any = None) -> Any:
        if key == "source":
            return self.source
        return dict(self.attributes).get(key, default)


@dataclass(frozen=True)
class DetectionRule:
    """检测规则：匹配 event_type 与必备属性，命中后给出关联键与严重度。"""

    rule_id: str
    event_type: str
    severity: str
    required_attributes: tuple[str, ...] = ()
    correlation_keys: tuple[str, ...] = ("source",)
    version: int = 1

    def matches(self, event: LogEvent) -> bool:
        if event.event_type != self.event_type:
            return False
        return all(event.get(attr) is not None for attr in self.required_attributes)

    def correlation_key(self, event: LogEvent) -> tuple[Any, ...]:
        return (self.rule_id, self.version) + tuple(
            event.get(k) for k in self.correlation_keys
        )


@dataclass
class Alert:
    """由同一攻击链上多条事件关联而成的告警。"""

    alert_id: str
    rule_id: str
    rule_version: int
    severity: str
    correlation_key: tuple[Any, ...]
    event_ids: list[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    created_at: float = 0.0
    updated_at: float = 0.0
    suppressed_count: int = 0
    version: int = 0


@dataclass(frozen=True)
class AuditRecord:
    """一次处置动作的审计记录。"""

    alert_id: str
    action: AuditAction
    actor: str
    from_status: AlertStatus
    to_status: AlertStatus
    timestamp: float
    detail: str = ""


@dataclass(frozen=True)
class IngestResult:
    """摄入结果：被接受或被拒绝，拒绝时给出可区分原因。"""

    accepted: bool
    event_id: str
    reason: RejectReason | None = None
    detail: str = ""
