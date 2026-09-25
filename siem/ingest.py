"""事件摄入：校验、去重、乱序控制。"""

from __future__ import annotations

import math
import threading

from .models import IngestResult, LogEvent, RejectReason


class EventIngester:
    """摄入日志事件。

    - 字段缺失 -> RejectReason.MISSING_FIELD
    - 时间戳非法 -> RejectReason.INVALID_TIMESTAMP
    - 重复投递（event_id 已见）-> RejectReason.DUPLICATE_DELIVERY，忽略且不计数
    - 乱序超过 max_lateness -> RejectReason.TOO_LATE
    乱序但在容忍窗口内的事件按事件时间正常参与后续关联，不被丢弃。
    """

    def __init__(self, max_lateness: float = 300.0) -> None:
        self.max_lateness = max_lateness
        self._seen_ids: set[str] = set()
        self._watermark: float | None = None
        self._accepted: list[LogEvent] = []
        self._lock = threading.Lock()

    def ingest(self, event: LogEvent) -> IngestResult:
        with self._lock:
            if not event.event_id or not event.event_type or not event.source:
                return IngestResult(
                    False,
                    event.event_id or "<missing>",
                    RejectReason.MISSING_FIELD,
                    "event_id/event_type/source 不能为空",
                )
            if (
                not isinstance(event.timestamp, (int, float))
                or isinstance(event.timestamp, bool)
                or math.isnan(event.timestamp)
                or math.isinf(event.timestamp)
                or event.timestamp < 0
            ):
                return IngestResult(
                    False,
                    event.event_id,
                    RejectReason.INVALID_TIMESTAMP,
                    f"非法时间戳: {event.timestamp!r}",
                )
            if event.event_id in self._seen_ids:
                return IngestResult(
                    False,
                    event.event_id,
                    RejectReason.DUPLICATE_DELIVERY,
                    "event_id 已处理，忽略重复投递",
                )
            if (
                self._watermark is not None
                and event.timestamp < self._watermark - self.max_lateness
            ):
                return IngestResult(
                    False,
                    event.event_id,
                    RejectReason.TOO_LATE,
                    f"事件时间 {event.timestamp} 早于水位线 {self._watermark} "
                    f"超过容忍窗口 {self.max_lateness}",
                )
            self._seen_ids.add(event.event_id)
            self._accepted.append(event)
            if self._watermark is None or event.timestamp > self._watermark:
                self._watermark = event.timestamp
            return IngestResult(True, event.event_id)

    def accepted_events(self) -> list[LogEvent]:
        with self._lock:
            return list(self._accepted)
