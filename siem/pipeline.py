"""端到端流水线：摄入 -> 检测 -> 关联 -> 可处置告警。

新增能力（不改变既有判定与既有接口）：
- process_explain：给出可分类、可解释的处理结论 ProcessOutcome。
- save_state / restore：把检测、关联、处置状态整体落到本地文件并恢复。
"""

from __future__ import annotations

import threading
from typing import Any

from . import persistence
from .correlation import AlertCorrelator
from .detection import DetectionEngine
from .disposition import AlertDispositionService
from .ingest import EventIngester
from .models import (
    Alert,
    DetectionRule,
    IngestResult,
    LogEvent,
    OutcomeCategory,
    ProcessOutcome,
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
                self._disposition.note_correlated(alert.alert_id)
                alerts.append(alert)
        return result, alerts

    def process_explain(self, event: LogEvent) -> ProcessOutcome:
        """处理一条事件并给出分类结论（ProcessOutcome）。

        分类稳定且与到达顺序无关：同样的输入必得到同样的类别。
        """
        result = self.ingester.ingest(event)
        if not result.accepted:
            category = (
                OutcomeCategory.SKIPPED_DUPLICATE
                if result.reason is RejectReason.DUPLICATE_DELIVERY
                else OutcomeCategory.REJECTED_INVALID
            )
            return ProcessOutcome(
                category=category,
                event_id=result.event_id,
                reason=result.reason,
                detail=result.detail,
            )
        hits: list[RuleHit] = []
        with self._lock:
            for rule in self.engine.match(event):
                alert, created = self.correlator.correlate(event, rule)
                self._disposition.register(alert)
                self._disposition.note_correlated(alert.alert_id)
                start, end = self.correlator.window_of(alert)
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        rule_version=rule.version,
                        alert_id=alert.alert_id,
                        created=created,
                        window_start=start,
                        window_end=end,
                    )
                )
        if not hits:
            return ProcessOutcome(
                category=OutcomeCategory.PROCESSED_NO_MATCH,
                event_id=result.event_id,
                detail="事件合法但未命中任何规则，未产生告警",
            )
        if any(h.created for h in hits):
            category = OutcomeCategory.ALERT_CREATED
        else:
            category = OutcomeCategory.ALERT_SUPPRESSED
        detail = "; ".join(
            f"命中规则 {h.rule_id} v{h.rule_version} -> "
            f"{'新建告警' if h.created else '抑制窗口收编'} {h.alert_id} "
            f"(窗口 [{h.window_start}, {h.window_end}))"
            for h in hits
        )
        return ProcessOutcome(
            category=category, event_id=result.event_id, detail=detail, hits=tuple(hits)
        )

    @property
    def disposition(self) -> AlertDispositionService:
        return self._disposition

    # ---- 状态保存与恢复 ----

    def snapshot(self) -> dict[str, Any]:
        """导出整条流水线的可持久化状态（同一临界区，保证一致性）。"""
        with self._lock:
            seen_ids, watermark = self.ingester.snapshot()
            alerts = self.correlator.alerts()
            disp_alerts, audit, counters = self._disposition.snapshot()
            disp_by_id = {a.alert_id: a for a in disp_alerts}
            return {
                "suppression_window": self.correlator.suppression_window,
                "max_lateness": self.ingester.max_lateness,
                "ingester": {"seen_ids": seen_ids, "watermark": watermark},
                "correlator": {
                    "seq": self.correlator.seq,
                    "alerts": [
                        persistence.alert_to_dict(
                            # 处置服务里的告警与关联器共享同一对象，状态一致
                            disp_by_id.get(a.alert_id, a),
                            self.correlator.window_of(a),
                        )
                        for a in alerts
                    ],
                },
                "disposition": {
                    "audit": [persistence.audit_to_dict(r) for r in audit],
                    "counters": persistence.counters_to_dict(counters),
                },
            }

    def save_state(self, path: str) -> None:
        """把当前状态原子写入本地文件。"""
        persistence.save_state_file(path, self.snapshot())

    @classmethod
    def restore(
        cls,
        path: str,
        rules: list[DetectionRule],
        suppression_window: float = 600.0,
        max_lateness: float = 300.0,
    ) -> "SiemPipeline":
        """从状态文件恢复一条流水线。

        文件损坏或格式不兼容时抛 StateCorruptionError，绝不带着坏状态继续跑。
        恢复后：关联证据、抑制窗口起止、处置状态、计数全部保留；
        恢复前处理过的重复事件再投递仍被跳过，不产生重复告警。
        """
        state = persistence.load_state_file(path)
        pipe = cls(
            rules,
            suppression_window=state.get("suppression_window", suppression_window),
            max_lateness=state.get("max_lateness", max_lateness),
        )
        ing = state["ingester"]
        pipe.ingester.restore(ing["seen_ids"], ing["watermark"])
        alerts = [persistence.alert_from_dict(a) for a in state["correlator"]["alerts"]]
        pipe.correlator.restore(alerts, state["correlator"]["seq"])
        disp = state["disposition"]
        pipe._disposition.restore(
            alerts,
            [persistence.audit_from_dict(r) for r in disp["audit"]],
            persistence.counters_from_dict(disp["counters"]),
        )
        return pipe
