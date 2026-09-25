"""检测规则匹配引擎。"""

from __future__ import annotations

import threading

from .models import DetectionRule, LogEvent


class DetectionEngine:
    """按规则集匹配事件。

    规则以 (rule_id, version) 标识；update_rules 整体替换规则集，
    使规则变更后的判定确定且可复现（关联键中携带规则版本）。
    """

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self._lock = threading.Lock()
        self._rules: list[DetectionRule] = list(rules or [])

    def update_rules(self, rules: list[DetectionRule]) -> None:
        with self._lock:
            self._rules = list(rules)

    def current_rules(self) -> list[DetectionRule]:
        with self._lock:
            return list(self._rules)

    def match(self, event: LogEvent) -> list[DetectionRule]:
        with self._lock:
            rules = list(self._rules)
        return [r for r in rules if r.matches(event)]
