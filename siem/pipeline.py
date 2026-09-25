"""端到端流水线：摄入 -> 检测 -> 关联 -> 可处置告警。"""

from __future__ import annotations

import threading

from .correlation import AlertCorrelator
from .detection import DetectionEngine
from .disposition import AlertDispositionService
from .ingest import EventIngester
from .models import Alert, DetectionRule, IngestResult, LogEvent


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
                alerts.append(alert)
        return result, alerts

    @property
    def disposition(self) -> AlertDispositionService:
        return self._disposition
