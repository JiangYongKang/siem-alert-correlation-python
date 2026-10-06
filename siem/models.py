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


class OutcomeCategory(enum.Enum):
    """事件处理结论分类：只看类别与说明即可决定后续动作。

    - REJECTED_INVALID：数据本身有问题，被摄入校验挡掉（修正数据后重投）。
    - SKIPPED_DUPLICATE：重复投递被跳过（无需处理，不会重复计数）。
    - PROCESSED_NO_MATCH：数据没问题但未命中任何规则，未产生告警。
    - ALERT_CREATED：命中规则并创建了新告警。
    - ALERT_SUPPRESSED：命中规则但被已有告警的抑制窗口收编，未产生新告警。
    """

    REJECTED_INVALID = "rejected_invalid"
    SKIPPED_DUPLICATE = "skipped_duplicate"
    PROCESSED_NO_MATCH = "processed_no_match"
    ALERT_CREATED = "alert_created"
    ALERT_SUPPRESSED = "alert_suppressed"


@dataclass(frozen=True)
class RuleHit:
    """一次规则命中的可解释记录。"""

    rule_id: str
    rule_version: int
    alert_id: str
    created: bool  # True=新建告警；False=被已有告警抑制窗口收编
    window_start: float
    window_end: float


@dataclass(frozen=True)
class ProcessOutcome:
    """一条事件的完整处理结论。

    同样的输入必得到同样的分类，与到达顺序无关。
    原有 IngestResult 字段继续可用，本结构为新增的可解释视图。
    """

    category: OutcomeCategory
    event_id: str
    detail: str
    reason: RejectReason | None = None  # 仅 REJECTED_INVALID / SKIPPED_DUPLICATE 时有值
    hits: tuple[RuleHit, ...] = ()  # 命中的规则与规则版本（可多条）


class TransitionOutcome(enum.Enum):
    """处置尝试结论：成功、修订冲突、非法跃迁、告警不存在。"""

    APPLIED = "applied"
    CONFLICT = "conflict"
    INVALID_TRANSITION = "invalid_transition"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class TransitionResult:
    """一次带前置校验的处置尝试结果（不抛异常，结论可区分）。"""

    outcome: TransitionOutcome
    alert_id: str
    action: AuditAction
    actor: str
    detail: str
    record: AuditRecord | None = None  # 留痕的审计记录（含被拒绝的尝试）


@dataclass(frozen=True)
class DispositionCounters:
    """告警计数口径，三类各自独立：

    - correlated_events：关联进该告警的事件总数（含被抑制收编的）。
    - transitions_applied：成功流转次数（等于 alert.version 中处置贡献的部分）。
    - transitions_attempted：累计处置尝试次数（含冲突与非法跃迁的拒绝）。
    """

    correlated_events: int = 0
    transitions_applied: int = 0
    transitions_attempted: int = 0
