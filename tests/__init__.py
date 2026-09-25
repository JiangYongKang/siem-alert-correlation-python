"""测试包配置：让 siem.* 的 INFO 日志在 unittest 运行时直接打印。

这样单测日志中可看到每个事件的输入（event_id/时间戳/source/type/attrs）
与关联判定依据（窗口、阈值、抑制区间、拒绝/忽略原因）。
"""

import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("siem.engine").setLevel(logging.INFO)
logging.getLogger("siem.service").setLevel(logging.INFO)
