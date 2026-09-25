"""时钟抽象：所有时间获取都经此模块，保证测试结果确定可复现。

事件关联判定使用事件自带时间戳（与处理顺序解耦）；
审计动作时间使用注入的 Clock，测试时注入 FixedClock 即可完全确定。
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """可注入时钟协议，单位为毫秒 epoch 整数。"""

    def now_ms(self) -> int:
        ...


class SystemClock:
    """墙上时钟：审计动作时间使用。"""

    def now_ms(self) -> int:
        return int(time.time() * 1000)


class FixedClock:
    """固定时钟：测试与确定性回放使用，时间只能向前推进。"""

    def __init__(self, now_ms: int = 0) -> None:
        self._now = int(now_ms)

    def set(self, now_ms: int) -> None:
        now_ms = int(now_ms)
        if now_ms < self._now:
            raise ValueError("FixedClock 不允许时间倒退")
        self._now = now_ms

    def advance(self, delta_ms: int) -> int:
        if delta_ms < 0:
            raise ValueError("FixedClock 不允许推进负数时间")
        self._now += int(delta_ms)
        return self._now

    def now_ms(self) -> int:
        return self._now
