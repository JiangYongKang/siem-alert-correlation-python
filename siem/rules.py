"""规则注册表：规则的增改、版本化查询与禁用管理。

规则变更语义（确定可复现）：
- rule_id 相同、version 相同视为幂等重复写入，直接忽略；
- version 必须单调递增，回退版本被拒绝；
- 引擎按 (rule_id, version) 隔离关联链，因此版本提升后旧链的
  抑制窗口不再作用于新规则的事件。
"""

from __future__ import annotations

import threading

from siem.models import Rule


class RuleVersionError(ValueError):
    """规则版本非单调递增时抛出，原因可区分。"""


class RuleRegistry:
    """线程安全的规则注册表，按 rule_id 保存当前版本。"""

    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}
        self._lock = threading.RLock()

    def upsert(self, rule: Rule) -> None:
        """新增或替换规则；version 相同幂等，回退版本抛 RuleVersionError。"""
        with self._lock:
            current = self._rules.get(rule.rule_id)
            if current is not None:
                if rule.version < current.version:
                    raise RuleVersionError(
                        f"规则 {rule.rule_id} 版本回退: "
                        f"{rule.version} < 当前 {current.version}"
                    )
                if rule.version == current.version and rule == current:
                    return
                if rule.version == current.version and rule != current:
                    raise RuleVersionError(
                        f"规则 {rule.rule_id} 版本 {rule.version} 已存在且内容不同，"
                        "禁止同号改写"
                    )
            self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Rule | None:
        with self._lock:
            return self._rules.get(rule_id)

    def list_active(self) -> list[Rule]:
        """返回所有 enabled 规则（按 rule_id 排序，结论稳定）。"""
        with self._lock:
            return sorted(
                (r for r in self._rules.values() if r.enabled),
                key=lambda r: r.rule_id,
            )

    def all(self) -> list[Rule]:
        with self._lock:
            return sorted(self._rules.values(), key=lambda r: (r.rule_id, r.version))

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "rule_id": r.rule_id,
                    "version": r.version,
                    "match_type": r.match_type,
                    "match_value": r.match_value,
                    "severity": r.severity,
                    "correlation_key": r.correlation_key,
                    "threshold": r.threshold,
                    "window_ms": r.window_ms,
                    "suppression_ms": r.suppression_ms,
                    "enabled": r.enabled,
                }
                for r in sorted(self._rules.values(), key=lambda x: x.rule_id)
            ]

    def restore(self, rules: list[dict]) -> None:
        with self._lock:
            self._rules.clear()
            for item in rules:
                self.upsert(Rule(**item))
