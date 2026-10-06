"""端到端流水线：摄入 -> 检测 -> 关联 -> 可处置告警。"""

from __future__ import annotations

import threading

from .correlation import AlertCorrelator
from .detection import DetectionEngine
from .disposition import AlertDispositionService
from .ingest import EventIngester
from .models import (
    Alert,
    DetectionRule,
    IngestResult,
    LogEvent,
    ProcessOutcome,
    ProcessResult,
    RejectReason,
    RuleHit,
)


class SiemPipeline:
    """组合各组件，对外提供一致的处理入口。

    process 的每个阶段结论可解释：摄入给出接受/拒绝原因，
    检测给出命中规则，关联返回 (告警, 是否新建)。
    """

    def __init__(
        self,
        rules: list[DetectionRule],
        suppression_window: float = 600.0,
        max_lateness: float = 300.0,
    ) -> None:
        self.ingester = EventIngester(max_lateness=max_lateness)
        self.engine = DetectionEngine(rules)
        self.correlator = AlertCorrelator(suppression_window=suppression_window)
        self._disposition = AlertDispositionService()
        self._lock = threading.Lock()
        self._correlated_events = 0

    def process(self, event: LogEvent) -> tuple[IngestResult, list[Alert]]:
        """处理一条事件，返回 (摄入结果, 本次关联到的告警列表)。"""
        result = self.ingester.ingest(event)
        if not result.accepted:
            return result, []
        alerts: list[Alert] = []
        with self._lock:
            for rule in self.engine.match(event):
                alert, _created = self.correlator.correlate(event, rule)
                self._disposition.register(alert)
                alerts.append(alert)
            if alerts:
                self._correlated_events += 1
        return result, alerts

    def process_event(self, event: LogEvent) -> ProcessResult:
        """处理一条事件并给出可分类、可解释的完整结论。

        分类规则（确定且与到达顺序无关）：
        - 摄入拒绝 -> REJECTED_INVALID（数据本身有问题）
        - 重复投递 -> SKIPPED_DUPLICATE（跳过，不重复计数）
        - 接受但未命中任何规则 -> ACCEPTED_NO_MATCH
        - 命中规则且全部落入已有告警抑制窗口 -> ALERT_SUPPRESSED
        - 命中规则且至少一条新建告警 -> ALERT_CREATED
        hits 中记录每条命中规则的 rule_id、规则版本与关联去向。
        """
        result = self.ingester.ingest(event)
        if not result.accepted:
            if result.reason is RejectReason.DUPLICATE_DELIVERY:
                return ProcessResult(
                    ProcessOutcome.SKIPPED_DUPLICATE,
                    event.event_id,
                    result,
                    detail=result.detail,
                )
            return ProcessResult(
                ProcessOutcome.REJECTED_INVALID,
                event.event_id or "<missing>",
                result,
                detail=result.detail,
            )
        hits: list[RuleHit] = []
        with self._lock:
            for rule in self.engine.match(event):
                alert, created = self.correlator.correlate(event, rule)
                self._disposition.register(alert)
                hits.append(
                    RuleHit(rule.rule_id, rule.version, alert.alert_id, created)
                )
            if hits:
                self._correlated_events += 1
        if not hits:
            return ProcessResult(
                ProcessOutcome.ACCEPTED_NO_MATCH,
                event.event_id,
                result,
                detail="事件合法但未命中任何规则，未产生告警",
            )
        if any(h.created for h in hits):
            outcome = ProcessOutcome.ALERT_CREATED
            detail = "命中规则并新建告警"
        else:
            outcome = ProcessOutcome.ALERT_SUPPRESSED
            detail = "命中规则，事件被已有告警的抑制窗口吸收"
        return ProcessResult(outcome, event.event_id, result, tuple(hits), detail)

    @property
    def disposition(self) -> AlertDispositionService:
        return self._disposition

    def counters(self) -> dict[str, int]:
        """三类独立计数：关联进来的事件数、成功流转次数、累计尝试流转次数。"""
        with self._lock:
            correlated = self._correlated_events
        transitions = self._disposition.transition_counts()
        return {
            "correlated_events": correlated,
            "successful_transitions": transitions["succeeded"],
            "attempted_transitions": transitions["attempted"],
        }

    def snapshot(self) -> dict:
        """导出整条流水线的可持久化状态（摄入/关联/处置/计数）。"""
        with self._lock:
            correlated = self._correlated_events
        return {
            "ingester": self.ingester.snapshot(),
            "correlator": self.correlator.snapshot(),
            "disposition": self._disposition.snapshot(),
            "correlated_events": correlated,
        }

    @classmethod
    def restore(
        cls,
        state: dict,
        rules: list[DetectionRule],
        suppression_window: float = 600.0,
        max_lateness: float = 300.0,
    ) -> SiemPipeline:
        """从快照恢复一条流水线。

        规则集由调用方按当前配置提供（规则是配置而非状态）；
        恢复后：已见事件再投递仍判重、抑制窗口起止与处置状态原样保留、
        告警 ID 序号接续分配，不会产生重复告警或漏告警。
        """
        pipe = cls(rules, suppression_window, max_lateness)
        pipe.ingester.restore(state["ingester"])
        pipe.correlator.restore(state["correlator"])
        pipe._disposition.restore(state["disposition"], pipe.correlator.alerts())
        pipe._correlated_events = state["correlated_events"]
        return pipe

    def save(self, path: str) -> None:
        """把当前状态原子写入本地文件（附带上一份完整状态备份）。"""
        from .persistence import SnapshotStore

        SnapshotStore(path).save(self.snapshot())

    @classmethod
    def load(
        cls,
        path: str,
        rules: list[DetectionRule],
        suppression_window: float = 600.0,
        max_lateness: float = 300.0,
    ) -> SiemPipeline:
        """从本地文件加载状态并恢复流水线。

        文件损坏时回退到上一份完整状态；两份都损坏抛 StateCorruptionError。
        """
        from .persistence import SnapshotStore

        state = SnapshotStore(path).load()
        return cls.restore(state, rules, suppression_window, max_lateness)
