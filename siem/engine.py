"""检测与关联引擎：规则匹配、攻击链聚合、抑制窗口判定。

确定性关联语义（全部基于事件时间 timestamp_ms，与到达顺序解耦判定）：

1. 全局去重：event_id 相同的重复投递一律拒绝 DUPLICATE，绝不重复计数；
   仅结构合法且被接收的事件登记去重。
2. 乱序宽限：维护已见最大事件时间 max_seen_ms，事件时间早于
   max_seen_ms - grace_ms 时显式忽略 LATE_BEYOND_GRACE（grace_ms
   默认取所有启用规则最大窗口长度）。
3. 关联窗口：同一 (rule_id, rule_version, 关联取值) 构成一条攻击链；
   窗口为半开区间 [anchor_ms, anchor_ms + window_ms)，anchor 为窗口内
   最早事件时间。晚到但在宽限内的事件可并入当前窗口并把锚点回退；
   晚于窗口右边界的事件关闭未达阈值的旧窗口（WINDOW_RESET）并开新窗；
   已关闭窗口不重开。
4. 触发：窗口内去重事件数首次达到 threshold 即产生一条 OPEN 告警，
   triggered_ms 取窗口内最大事件时间（只依赖数据，不依赖到达顺序）。
5. 抑制：半开区间 [triggered_ms, triggered_ms + suppression_ms) 内的
   事件全部附加到该告警（suppressed_count 增加），不产生新告警；
   时间到达右边界立即解除并开新窗（suppression_ms=0 时下一同刻事件
   即属新周期）。
6. 规则版本：链键含 rule_version，版本提升后新事件进入新链，旧链的
   抑制窗口不再影响新规则。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from siem.clock import Clock, FixedClock
from siem.models import (
    Alert,
    AlertState,
    Event,
    IgnoreReason,
    IngestionResult,
    MatchedRule,
    RejectReason,
    Rule,
    RuleDecision,
)
from siem.rules import RuleRegistry

if TYPE_CHECKING:
    from siem.alerts import AlertManager

logger = logging.getLogger("siem.engine")


@dataclass
class _Member:
    event_id: str
    ts: int


@dataclass
class _ChainState:
    """一条攻击链的运行态：当前关联窗口 + 可选的活动告警抑制期。"""

    rule_id: str
    rule_version: int
    correlation_value: str
    seq: int = 0
    members: list[_Member] = field(default_factory=list)
    anchor_ms: int | None = None
    active_alert_id: str | None = None
    triggered_ms: int | None = None
    suppress_until_ms: int | None = None


class CorrelationEngine:
    def __init__(
        self,
        registry: RuleRegistry,
        clock: Clock | None = None,
        grace_ms: int | None = None,
    ) -> None:
        self._registry = registry
        self._clock = clock or FixedClock(0)
        self._explicit_grace = grace_ms
        self._alerts: "AlertManager | None" = None
        self._seen_ids: set[str] = set()
        self._max_seen_ms: int | None = None
        self._chains: dict[tuple[str, int, str], _ChainState] = {}
        self._lock = threading.RLock()

    def bind_alerts(self, manager: "AlertManager") -> None:
        """绑定告警管理器；触发告警时登记到其中。"""
        with self._lock:
            self._alerts = manager

    # ------------------------------------------------------------------
    def _grace_ms(self) -> int:
        if self._explicit_grace is not None:
            return self._explicit_grace
        active = self._registry.list_active()
        return max((r.window_ms for r in active), default=0)

    def ingest(self, event: Event) -> IngestionResult:
        """处理一条事件，返回确定结论；按 event_id 幂等，线程安全。"""
        with self._lock:
            logger.info("摄入事件 event_id=%s ts=%s source=%s type=%s attrs=%s",
                        event.event_id, event.timestamp_ms, event.source,
                        event.event_type, event.attrs)

            if event.event_id in self._seen_ids:
                result = IngestionResult(
                    event_id=event.event_id,
                    accepted=False,
                    reject_reason=RejectReason.DUPLICATE,
                    detail="event_id 已处理过，重复投递不重复计数",
                )
                logger.info("判定 DUPLICATE event_id=%s", event.event_id)
                return result

            # 乱序宽限判定（全局，独立于规则）。
            # 注意必须在去重之后：重启/重放时历史事件即使早于当前水位，
            # 其身份仍是重复投递，优先返回 DUPLICATE 以保证幂等可复现。
            grace = self._grace_ms()
            watermark = None if self._max_seen_ms is None else self._max_seen_ms - grace
            if watermark is not None and event.timestamp_ms < watermark:
                self._seen_ids.add(event.event_id)
                result = IngestionResult(
                    event_id=event.event_id,
                    accepted=True,
                    ignore_reason=IgnoreReason.LATE_BEYOND_GRACE,
                    detail=(
                        f"事件时间 {event.timestamp_ms} 早于水位 {watermark}"
                        f"（max_seen={self._max_seen_ms} - grace={grace}），"
                        "超出乱序宽限，忽略"
                    ),
                )
                logger.info("判定 LATE_BEYOND_GRACE event_id=%s: %s",
                            event.event_id, result.detail)
                return result

            # 匹配 + 关联键解析（关联键缺字段 => 拒绝且不改状态）
            matched: list[tuple[Rule, str]] = []
            decisions: list[RuleDecision] = []
            for rule in self._registry.list_active():
                if not rule.matches(event):
                    continue
                value, missing = rule.correlation_value(event)
                if missing is not None:
                    result = IngestionResult(
                        event_id=event.event_id,
                        accepted=False,
                        reject_reason=RejectReason.MISSING_FIELD,
                        detail=(
                            f"命中规则 {rule.rule_id} v{rule.version} 但其关联键 "
                            f"{rule.correlation_key!r} 需要缺失字段 {missing}，拒绝"
                        ),
                    )
                    logger.info("判定 MISSING_FIELD event_id=%s: %s",
                                event.event_id, result.detail)
                    return result
                matched.append((rule, value))
                decisions.append(
                    RuleDecision(
                        rule_id=rule.rule_id,
                        version=rule.version,
                        correlation_value=value,
                        status="MATCHED",
                    )
                )

            if not matched:
                self._seen_ids.add(event.event_id)
                self._advance_watermark(event.timestamp_ms)
                result = IngestionResult(
                    event_id=event.event_id,
                    accepted=True,
                    ignore_reason=IgnoreReason.NO_RULE_MATCHED,
                    detail="没有任何启用规则命中该事件，忽略",
                )
                logger.info("判定 NO_RULE_MATCHED event_id=%s", event.event_id)
                return result

            # 事件正式计入：登记去重、推进水位
            self._seen_ids.add(event.event_id)
            self._advance_watermark(event.timestamp_ms)

            result = IngestionResult(
                event_id=event.event_id, accepted=True,
                matches=[MatchedRule(r.rule_id, r.version, v) for r, v in matched],
            )
            any_suppressed = True
            any_counted = False
            for (rule, value), dec in zip(matched, decisions):
                self._apply_chain(rule, value, event, dec)
                result.rule_decisions.append(dec)
                if dec.status == "TRIGGERED" and dec.alert_id:
                    result.alert_ids.append(dec.alert_id)
                if dec.status != "SUPPRESSED":
                    any_suppressed = False
                if dec.status in ("COUNTED", "WINDOW_RESET", "TRIGGERED"):
                    any_counted = True

            if result.alert_ids:
                result.detail = "命中关联规则并产生/关闭告警，见 rule_decisions"
            elif any_suppressed:
                result.ignore_reason = IgnoreReason.SUPPRESSED
                result.detail = "命中规则但处于抑制窗口内，已附加为抑制证据"
            elif any_counted:
                result.detail = "命中规则并计入关联窗口，尚未达到阈值"
            else:
                result.ignore_reason = IgnoreReason.OUT_OF_WINDOW
                result.detail = "命中规则但无法落入任何关联窗口"

            logger.info(
                "关联判定 event_id=%s -> %s | %s",
                event.event_id,
                [(d.rule_id, d.status, d.reason) for d in result.rule_decisions],
                result.detail,
            )
            return result

    # ------------------------------------------------------------------
    def _advance_watermark(self, ts: int) -> None:
        if self._max_seen_ms is None or ts > self._max_seen_ms:
            self._max_seen_ms = ts

    def _chain(self, rule: Rule, value: str) -> _ChainState:
        key = (rule.rule_id, rule.version, value)
        chain = self._chains.get(key)
        if chain is None:
            chain = _ChainState(rule.rule_id, rule.version, value)
            self._chains[key] = chain
        return chain

    def _apply_chain(
        self, rule: Rule, value: str, event: Event, dec: RuleDecision
    ) -> None:
        chain = self._chain(rule, value)
        ts = event.timestamp_ms

        # 抑制期（活动告警）
        if chain.active_alert_id is not None:
            triggered = chain.triggered_ms
            until = chain.suppress_until_ms
            assert triggered is not None and until is not None
            if ts < triggered:
                # 告警后的迟到补充事件：属于触发窗口的证据则补挂
                anchor = chain.anchor_ms
                if anchor is not None and ts >= anchor:
                    self._attach_evidence(chain.active_alert_id, event, suppressed=False)
                    dec.status = "COUNTED"
                    dec.reason = (
                        f"晚到事件 {ts} 属于触发窗口 [{anchor},{triggered})，"
                        "补挂为关联证据"
                    )
                else:
                    dec.status = "OUT_OF_WINDOW"
                    dec.reason = f"晚到事件 {ts} 早于触发窗口锚点 {anchor}，忽略"
                return
            if ts < until:
                self._attach_evidence(chain.active_alert_id, event, suppressed=True)
                dec.status = "SUPPRESSED"
                dec.reason = (
                    f"事件时间 {ts} 位于半开抑制区间 [{triggered},{until})，"
                    "不产生新告警"
                )
                return
            # 到达右边界：抑制解除，旧活动期归档，开新窗
            dec.reason = (
                f"事件时间 {ts} >= 抑制右边界 {until}，抑制解除并开启新窗口"
            )
            self._reset_chain_window(chain)

        # 关联窗口累积（半开 [anchor, anchor+window)）
        if chain.anchor_ms is not None and ts >= chain.anchor_ms + rule.window_ms:
            dec.status = "WINDOW_RESET"
            dec.reason = (
                f"事件时间 {ts} 不在半开窗口 "
                f"[{chain.anchor_ms},{chain.anchor_ms + rule.window_ms}) 内，"
                "旧窗口未达阈值关闭，本事件开启新窗口"
            )
            chain.members = []
            chain.anchor_ms = None

        # 并入窗口（晚到事件会把锚点回退，并裁剪掉落在新窗口外的旧成员）
        if chain.anchor_ms is None:
            chain.anchor_ms = ts
            chain.members = [_Member(event.event_id, ts)]
        else:
            chain.members.append(_Member(event.event_id, ts))
            new_anchor = min(chain.anchor_ms, ts)
            chain.anchor_ms = new_anchor
            chain.members = [
                m for m in chain.members
                if new_anchor <= m.ts < new_anchor + rule.window_ms
            ]

        if len(chain.members) >= rule.threshold:
            self._trigger(rule, value, chain, dec)
        else:
            dec.status = "WINDOW_RESET" if dec.status == "WINDOW_RESET" else "COUNTED"
            if not dec.reason:
                dec.reason = (
                    f"计入窗口 [{chain.anchor_ms},"
                    f"{chain.anchor_ms + rule.window_ms})，"
                    f"现有 {len(chain.members)}/{rule.threshold}"
                )

    def _trigger(
        self, rule: Rule, value: str, chain: _ChainState, dec: RuleDecision
    ) -> None:
        chain.seq += 1
        members = chain.members
        anchor = chain.anchor_ms
        assert anchor is not None
        triggered_ms = max(m.ts for m in members)
        until = triggered_ms + rule.suppression_ms
        alert_id = f"{rule.rule_id}:v{rule.version}:{value}#{chain.seq}"
        alert = Alert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            correlation_key=rule.correlation_key,
            correlation_value=value,
            state=AlertState.OPEN,
            severity=rule.severity,
            threshold=rule.threshold,
            window_ms=rule.window_ms,
            suppression_ms=rule.suppression_ms,
            anchor_ms=anchor,
            triggered_ms=triggered_ms,
            suppress_until_ms=until,
            event_ids=[m.event_id for m in members],
            suppressed_count=0,
            correlated_count=len(members),
        )
        if self._alerts is not None:
            self._alerts.add(alert)
        chain.active_alert_id = alert_id
        chain.triggered_ms = triggered_ms
        chain.suppress_until_ms = until
        dec.status = "TRIGGERED"
        dec.alert_id = alert_id
        dec.reason = (
            f"窗口 [{anchor},{anchor + rule.window_ms}) 内去重事件 "
            f"{len(members)}/{rule.threshold} 达到阈值；triggered_ms={triggered_ms}，"
            f"抑制半开区间 [{triggered_ms},{until})"
        )
        logger.info("触发告警 %s rule=%s v%s corr=%s 证据=%s",
                    alert_id, rule.rule_id, rule.version, value, alert.event_ids)

    def _attach_evidence(
        self, alert_id: str, event: Event, *, suppressed: bool
    ) -> None:
        if self._alerts is None:
            return
        # 必须经 AlertManager 在锁内修改存储对象，不能修改 get() 返回的副本
        self._alerts.attach_evidence(alert_id, event.event_id, suppressed=suppressed)

    @staticmethod
    def _reset_chain_window(chain: _ChainState) -> None:
        chain.active_alert_id = None
        chain.triggered_ms = None
        chain.suppress_until_ms = None
        chain.members = []
        chain.anchor_ms = None

    def reset(self) -> None:
        with self._lock:
            self._seen_ids.clear()
            self._max_seen_ms = None
            self._chains.clear()

    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            return {
                "seen_ids": sorted(self._seen_ids),
                "max_seen_ms": self._max_seen_ms,
                "chains": [
                    {
                        "rule_id": c.rule_id,
                        "rule_version": c.rule_version,
                        "correlation_value": c.correlation_value,
                        "seq": c.seq,
                        "anchor_ms": c.anchor_ms,
                        "active_alert_id": c.active_alert_id,
                        "triggered_ms": c.triggered_ms,
                        "suppress_until_ms": c.suppress_until_ms,
                        "members": [
                            {"event_id": m.event_id, "ts": m.ts} for m in c.members
                        ],
                    }
                    for c in self._chains.values()
                ],
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            self._seen_ids = set(state.get("seen_ids", []))
            self._max_seen_ms = state.get("max_seen_ms")
            self._chains = {}
            for item in state.get("chains", []):
                chain = _ChainState(
                    rule_id=item["rule_id"],
                    rule_version=item["rule_version"],
                    correlation_value=item["correlation_value"],
                    seq=item.get("seq", 0),
                    anchor_ms=item.get("anchor_ms"),
                    active_alert_id=item.get("active_alert_id"),
                    triggered_ms=item.get("triggered_ms"),
                    suppress_until_ms=item.get("suppress_until_ms"),
                    members=[
                        _Member(m["event_id"], m["ts"]) for m in item.get("members", [])
                    ],
                )
                self._chains[
                    (chain.rule_id, chain.rule_version, chain.correlation_value)
                ] = chain
