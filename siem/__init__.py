"""本地威胁检测与告警关联引擎。

仅依赖标准库与仓库已声明的 fastapi，可完全离线运行。
"""

__all__ = [
    "clock",
    "models",
    "rules",
    "engine",
    "alerts",
    "storage",
    "service",
    "api",
]

__version__ = "0.1.0"
