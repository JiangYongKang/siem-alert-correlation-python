"""本地状态持久化：JSON 快照 + 校验和 + 原子写。

- 只用标准库与本地文件，离线可复现。
- 写入先落临时文件再 os.replace 原子替换，写一半崩溃不会留下半截状态文件。
- 文件携带格式版本与内容校验和；解析失败、校验和不符、格式版本不支持
  一律抛 StateCorruptionError，绝不悄悄读出一份坏状态继续跑。
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any

from .models import (
    Alert,
    AlertStatus,
    AuditAction,
    AuditRecord,
    DispositionCounters,
)

STATE_FORMAT = 1


class StateCorruptionError(Exception):
    """状态文件缺失、损坏、被截断或格式不兼容。"""


def alert_to_dict(alert: Alert, window: tuple[float, float]) -> dict[str, Any]:
    """告警序列化；window 为该告警抑制窗口 [start, end)，显式保存起止。"""
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
        "window_start": window[0],
        "window_end": window[1],
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


def counters_to_dict(counters: dict[str, DispositionCounters]) -> dict[str, Any]:
    return {
        alert_id: {
            "correlated_events": c.correlated_events,
            "transitions_applied": c.transitions_applied,
            "transitions_attempted": c.transitions_attempted,
        }
        for alert_id, c in counters.items()
    }


def counters_from_dict(data: dict[str, Any]) -> dict[str, DispositionCounters]:
    return {
        alert_id: DispositionCounters(
            correlated_events=c["correlated_events"],
            transitions_applied=c["transitions_applied"],
            transitions_attempted=c["transitions_attempted"],
        )
        for alert_id, c in data.items()
    }


def _checksum(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def save_state_file(path: str, state: dict[str, Any]) -> None:
    """原子写入状态文件：临时文件 + fsync + os.replace。"""
    payload = json.dumps(state, ensure_ascii=False, sort_keys=True)
    envelope = json.dumps(
        {"format": STATE_FORMAT, "checksum": _checksum(payload), "payload": payload},
        ensure_ascii=False,
    )
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".siem-state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(envelope)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_state_file(path: str) -> dict[str, Any]:
    """加载状态文件；任何损坏都抛 StateCorruptionError，不返回坏状态。"""
    try:
        with open(path, encoding="utf-8") as fh:
            envelope = json.load(fh)
    except FileNotFoundError as exc:
        raise StateCorruptionError(f"状态文件不存在: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise StateCorruptionError(f"状态文件无法解析（可能被截断或损坏）: {exc}") from exc
    if not isinstance(envelope, dict) or envelope.get("format") != STATE_FORMAT:
        raise StateCorruptionError(
            f"不支持的状态格式版本: {envelope.get('format')!r}"
            if isinstance(envelope, dict)
            else "状态文件结构非法"
        )
    payload = envelope.get("payload")
    checksum = envelope.get("checksum")
    if not isinstance(payload, str) or _checksum(payload) != checksum:
        raise StateCorruptionError("状态文件校验和不匹配，内容已被损坏")
    try:
        state = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise StateCorruptionError(f"状态内容无法解析: {exc}") from exc
    if not isinstance(state, dict):
        raise StateCorruptionError("状态内容结构非法")
    return state
