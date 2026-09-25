"""核心领域模型：事件、规则、关联结果、告警、审计记录。

本模块只定义类型，不包含持久化与编排逻辑，保证 HTTP、CLI、测试
各入口共享同一份结论结构（一致且可解释）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# 关联键模板中允许的占位符：{source}/{event_type}/{event_id} 与 {attr:名称}
_CORR_TOKEN_RE = re.compile(r"^\{([a-zA-Z_]+)(?::([^{}]+))?\}$")
# match_type=attr 时 match_value 的格式：名称=值
_ATTR_MATCH_RE = re.compile(r"^([^=]+)=(.*)$")


class RejectReason(str, Enum):
    """事件在入口即被拒绝（不进入匹配）的可区分原因。"""

    MALFORMED = "MALFORMED"              # 载荷不是合法对象/类型错误
    MISSING_FIELD = "MISSING_FIELD"      # 必填字段或关联键字段缺失
    BAD_TIMESTAMP = "BAD_TIMESTAMP"      # 时间戳非法
    DUPLICATE = "DUPLICATE"              # event_id 重复投递


class IgnoreReason(str, Enum):
    """事件被接收但不产生新结论的可区分原因。"""

    NO_RULE_MATCHED = "NO_RULE_MATCHED"          # 无任何启用规则命中
    LATE_BEYOND_GRACE = "LATE_BEYOND_GRACE"      # 超过乱序容忍宽限
    OUT_OF_WINDOW = "OUT_OF_WINDOW"              # 落不进任何关联窗口
    SUPPRESSED = "SUPPRESSED"                    # 处于告警抑制区间


class AlertState(str, Enum):
    """告警状态机：OPEN -> ACKED -> CLOSED，CLOSED 可 REOPEN 回 OPEN。"""

    OPEN = "OPEN"
    ACKED = "ACKED"
    CLOSED = "CLOSED"


class AlertAction(str, Enum):
    ACK = "ACK"
    CLOSE = "CLOSE"
    REOPEN = "REOPEN"


# 处置动作允许的来源状态；任何不在表内的跃迁都是非法跃迁
ALLOWED_TRANSITIONS: dict[AlertAction, frozenset[AlertState]] = {
    AlertAction.ACK: frozenset({AlertState.OPEN}),
    AlertAction.CLOSE: frozenset({AlertState.OPEN, AlertState.ACKED}),
    AlertAction.REOPEN: frozenset({AlertState.CLOSED}),
}

# 动作的目标状态
NEXT_STATE: dict[AlertAction, AlertState] = {
    AlertAction.ACK: AlertState.ACKED,
    AlertAction.CLOSE: AlertState.CLOSED,
    AlertAction.REOPEN: AlertState.OPEN,
}


@dataclass(frozen=True)
class Event:
    """一条日志事件。event_id 用于全局去重，timestamp_ms 为事件发生时间。"""

    event_id: str
    timestamp_ms: int
    source: str
    event_type: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """读取扩展字段；内置字段优先，其次查 attrs。"""
        if key == "event_id":
            return self.event_id
        if key == "timestamp_ms":
            return self.timestamp_ms
        if key == "source":
            return self.source
        if key == "event_type":
            return self.event_type
        return self.attrs.get(key, default)


@dataclass(frozen=True)
class Rule:
    """检测 + 关联 + 抑制规则。

    匹配方式 match_type：
      - "event_type"：event_type 与 match_value 完全相等；
      - "source"     ：source 与 match_value 完全相等；
      - "attr"       ：match_value 形如 "字段名=期望值"，取自 event.attrs。

    correlation_key 为占位符模板，例如 "{source}"、"{attr:src_ip}"、
    "{event_type}|{attr:src_ip}"；任一占位符取值缺失则该事件无法关联，
    由上层给出 MISSING_FIELD 判定。
    """

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

    def __post_init__(self) -> None:
        if self.match_type not in ("event_type", "source", "attr"):
            raise ValueError(f"不支持的 match_type: {self.match_type}")
        if self.threshold < 1 or self.window_ms < 1 or self.suppression_ms < 0:
            raise ValueError("threshold/window_ms 必须为正，suppression_ms 不可为负")
        if self.version < 1:
            raise ValueError("version 必须 >= 1")
        if self.match_type == "attr" and not _ATTR_MATCH_RE.match(self.match_value):
            raise ValueError('match_type=attr 时 match_value 必须是 "名称=值"')

    def matches(self, event: Event) -> bool:
        """判断事件是否命中规则（纯函数）。"""
        if not self.enabled:
            return False
        if self.match_type == "event_type":
            return event.event_type == self.match_value
        if self.match_type == "source":
            return event.source == self.match_value
        m = _ATTR_MATCH_RE.match(self.match_value)
        assert m is not None  # 构造期已校验
        name, expected = m.group(1), m.group(2)
        actual = event.attrs.get(name)
        return actual is not None and str(actual) == expected

    def correlation_value(self, event: Event) -> tuple[str | None, str | None]:
        """渲染关联键，返回 (取值, 缺失字段名)；无缺失时缺失字段名为 None。"""
        missing: str | None = None

        def repl(match: re.Match[str]) -> str:
            nonlocal missing
            kind, name = match.group(1), match.group(2)
            if kind == "attr":
                if not name:
                    missing = "attr:"
                    return ""
                if name not in event.attrs:
                    missing = f"attr:{name}"
                    return ""
                return str(event.attrs[name])
            if kind in ("source", "event_type", "event_id"):
                return str(event.get(kind))
            missing = kind
            return ""

        rendered = _CORR_TOKEN_RE  # 仅为类型检查器保留引用
        value = re.sub(
            r"\{(event_id|source|event_type|attr):?([^{}]*)\}", repl, self.correlation_key
        )
        if missing is not None:
            return None, missing
        return value, None


@dataclass
class MatchedRule:
    rule_id: str
    version: int
    correlation_value: str


@dataclass
class RuleDecision:
    """单条事件在单条命中规则上的判定依据（用于日志与排障）。"""

    rule_id: str
    version: int
    correlation_value: str
    status: str  # TRIGGERED / COUNTED / SUPPRESSED / WINDOW_RESET / MISSING_FIELD
    alert_id: str | None = None
    reason: str = ""


@dataclass
class IngestionResult:
    """单条事件摄入的确定结论，所有入口共用。

    accepted=False 时 reject_reason 必填；
    accepted=True 但没有任何新结论时 ignore_reason 给出区分原因。
    """

    event_id: str
    accepted: bool
    reject_reason: RejectReason | None = None
    ignore_reason: IgnoreReason | None = None
    matches: list[MatchedRule] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    rule_decisions: list[RuleDecision] = field(default_factory=list)
    detail: str = ""


@dataclass
class AuditEntry:
    """一次告警处置尝试的审计记录（成功/失败均记录，原因可区分）。"""

    audit_id: int
    alert_id: str
    action: AlertAction
    actor: str
    reason: str
    success: bool
    from_state: AlertState | None
    to_state: AlertState | None
    expected_version: int | None
    actual_version: int | None
    at_ms: int


@dataclass
class Alert:
    """一条聚合告警及其证据、抑制信息与状态版本。"""

    alert_id: str
    rule_id: str
    rule_version: int
    correlation_key: str
    correlation_value: str
    state: AlertState
    severity: str
    threshold: int
    window_ms: int
    suppression_ms: int
    anchor_ms: int
    triggered_ms: int
    suppress_until_ms: int
    version: int = 0
    event_ids: list[str] = field(default_factory=list)
    suppressed_count: int = 0
    correlated_count: int = 0
