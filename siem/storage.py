"""本地文件持久化：JSON 快照，保证重启/重复处理幂等。

写入采用同目录临时文件 + os.replace 原子替换，崩溃不会留下半截文件；
恢复后 event_id 去重表、关联链、告警与审计全部还原，因此重启后再喂
相同事件只会得到 DUPLICATE 而不会产生重复告警，漏喂的事件仍会正常
关联，不会错失应有告警。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from siem.alerts import AlertManager
from siem.engine import CorrelationEngine
from siem.rules import RuleRegistry

SNAPSHOT_VERSION = 1


class JsonSnapshotStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)

    def save(
        self,
        registry: RuleRegistry,
        engine: CorrelationEngine,
        alerts: AlertManager,
    ) -> None:
        """原子写入规则 + 引擎 + 告警的完整状态。"""
        payload = {
            "snapshot_version": SNAPSHOT_VERSION,
            "rules": registry.snapshot(),
            "engine": engine.snapshot(),
            "alerts": alerts.snapshot(),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self._path.name + ".", suffix=".tmp", dir=self._path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self._path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise

    def load(
        self,
        registry: RuleRegistry,
        engine: CorrelationEngine,
        alerts: AlertManager,
    ) -> bool:
        """恢复状态到三个组件；快照文件不存在时返回 False。"""
        if not self._path.exists():
            return False
        with self._path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        if payload.get("snapshot_version") != SNAPSHOT_VERSION:
            raise ValueError(
                f"不支持的快照版本: {payload.get('snapshot_version')!r}"
            )
        registry.restore(payload.get("rules", []))
        engine.restore(payload.get("engine", {}))
        alerts.restore(payload.get("alerts", {}))
        # 告警编号与链的对应关系在引擎恢复后仍然有效（alert_id 是确定性的）
        return True
