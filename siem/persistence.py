"""本地状态快照：原子写入、校验和校验、损坏回退。

只使用标准库与本地文件，离线可复现。

写入协议：
- 状态序列化为 JSON 信封 {"format": 1, "checksum": sha256(payload), "payload": ...}；
- 先写入 <path>.tmp 并 fsync，再 os.replace 原子替换 <path>，
  写一半崩溃不会留下截断的正式文件；
- 替换前把上一份完整状态保留为 <path>.bak。

读取协议：
- 校验 JSON 完整性与 payload 的 sha256；
- 正式文件损坏/截断时回退到 <path>.bak 的上一份完整状态；
- 两份都损坏时抛 StateCorruptionError，绝不悄悄读出坏状态继续跑。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any

from .models import Alert, AlertStatus, AuditAction, AuditRecord

FORMAT_VERSION = 1


class StateCorruptionError(Exception):
    """状态文件与其备份均损坏或无法校验，拒绝加载。"""


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _checksum(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


class SnapshotStore:
    """管理单个状态文件的读写。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self.tmp_path = path + ".tmp"
        self.bak_path = path + ".bak"

    def save(self, payload: dict[str, Any]) -> None:
        """原子写入一份完整状态，并把上一份完整状态保留为备份。"""
        envelope = {
            "format": FORMAT_VERSION,
            "checksum": _checksum(payload),
            "payload": payload,
        }
        data = json.dumps(envelope, sort_keys=True).encode("utf-8")
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if os.path.exists(self.path):
                # 上一份完整状态留作备份，供损坏时回退
                os.replace(self.path, self.bak_path)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def load(self) -> dict[str, Any]:
        """加载并校验状态；损坏时回退备份，备份也损坏则报错。"""
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"状态文件不存在: {self.path}")
        try:
            return self._read_verified(self.path)
        except StateCorruptionError as primary:
            if os.path.exists(self.bak_path):
                # 回到上一份完整状态
                return self._read_verified(self.bak_path)
            raise StateCorruptionError(
                f"状态文件损坏且无可用备份: {self.path}: {primary}"
            ) from primary

    @staticmethod
    def _read_verified(path: str) -> dict[str, Any]:
        try:
            with open(path, "rb") as fh:
                envelope = json.loads(fh.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise StateCorruptionError(f"无法解析状态文件 {path}: {exc}") from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("format") != FORMAT_VERSION
            or not isinstance(envelope.get("payload"), dict)
            or not isinstance(envelope.get("checksum"), str)
        ):
            raise StateCorruptionError(f"状态文件格式不符: {path}")
        if _checksum(envelope["payload"]) != envelope["checksum"]:
            raise StateCorruptionError(f"状态文件校验和不匹配（可能被截断或篡改）: {path}")
        return envelope["payload"]


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """告警 -> 可 JSON 序列化字典（关联键取值须为 JSON 标量）。"""
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "rule_version": alert.rule_version,
        "severity": alert.severity,
        "correlation_key": list(alert.correlation_key),
        "event_ids": list(alert.event_ids),
        "status": alert.status.value,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "suppressed_count": alert.suppressed_count,
        "version": alert.version,
    }


def alert_from_dict(data: dict[str, Any]) -> Alert:
    return Alert(
        alert_id=data["alert_id"],
        rule_id=data["rule_id"],
        rule_version=data["rule_version"],
        severity=data["severity"],
        correlation_key=tuple(data["correlation_key"]),
        event_ids=list(data["event_ids"]),
        status=AlertStatus(data["status"]),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
        suppressed_count=data["suppressed_count"],
        version=data["version"],
    )


def audit_to_dict(record: AuditRecord) -> dict[str, Any]:
    return {
        "alert_id": record.alert_id,
        "action": record.action.value,
        "actor": record.actor,
        "from_status": record.from_status.value,
        "to_status": record.to_status.value,
        "timestamp": record.timestamp,
        "detail": record.detail,
    }


def audit_from_dict(data: dict[str, Any]) -> AuditRecord:
    return AuditRecord(
        alert_id=data["alert_id"],
        action=AuditAction(data["action"]),
        actor=data["actor"],
        from_status=AlertStatus(data["from_status"]),
        to_status=AlertStatus(data["to_status"]),
        timestamp=data["timestamp"],
        detail=data["detail"],
    )
