# 本地威胁检测与告警关联（Python）

一套**完全本地、内存状态、确定性可复现**的威胁检测与告警关联流程：
本地日志事件流 → 检测规则匹配 → 同一攻击链事件聚合为一条告警 →
抑制窗口内去重 → 告警确认/关闭/重开（带乐观锁与审计）。

仅依赖仓库已声明的 `fastapi[standard]`（含 pydantic / uvicorn / httpx），
测试使用 Python 标准库 `unittest`，**无需联网、无需额外安装依赖**。

## 快速开始

```bash
# 运行全部测试（标准库 unittest，离线可跑）
python -m unittest discover -s tests -v

# 启动 HTTP 服务
python main.py
# 或：uvicorn main:app --port 8000
```

运行单测时会直接打印每个事件的输入与关联判定依据，例如：

```
[INFO] siem.engine: 摄入事件 event_id=c ts=300 source=hostA type=LOGIN_FAIL attrs={'src_ip': '1.1.1.1'}
[INFO] siem.engine: 关联判定 event_id=c -> [('brute','TRIGGERED',
  '窗口 [100,1100) 内去重事件 3/3 达到阈值；triggered_ms=300，抑制半开区间 [300,5300)')]
```

## 60 秒体验（HTTP）

```bash
curl -s -X PUT localhost:8000/rules -H 'content-type: application/json' -d '{
  "rule_id":"brute","version":1,"match_type":"event_type","match_value":"LOGIN_FAIL",
  "severity":"HIGH","correlation_key":"{source}|{attr:src_ip}",
  "threshold":3,"window_ms":1000,"suppression_ms":5000}'

for ts in 100 200 300 400; do
  curl -s -X POST localhost:8000/events -H 'content-type: application/json' -d "{
    \"event_id\":\"e$ts\",\"timestamp_ms\":$ts,\"source\":\"hostA\",
    \"event_type\":\"LOGIN_FAIL\",\"attrs\":{\"src_ip\":\"1.1.1.1\"}}"
  echo
done
# 前三条聚合成一条 OPEN 告警；第 4 条返回 SUPPRESSED，挂为抑制证据

curl -s localhost:8000/alerts
curl -s "localhost:8000/alerts/brute%3Av1%3AhostA%7C1.1.1.1%231/audit"
```

> 告警 ID 含 `|`、`#` 等字符，URL 中需做百分号编码。

## 目录结构

| 路径 | 职责 |
| --- | --- |
| `siem/models.py` | 事件、规则、结论、告警、审计等领域模型与纯函数匹配 |
| `siem/rules.py` | 规则注册表：版本单调递增、同号禁改、禁用管理 |
| `siem/engine.py` | 检测匹配、乱序宽限、关联窗口、阈值触发、抑制窗口、幂等去重 |
| `siem/alerts.py` | 告警状态机、乐观版本锁、全量审计（含失败动作） |
| `siem/storage.py` | 原子 JSON 快照（临时文件 + `os.replace`） |
| `siem/service.py` | 门面服务：载荷校验、统一入口，HTTP/CLI/测试共用 |
| `siem/api.py` | FastAPI HTTP 入口，统一响应信封与错误码 |
| `main.py` | `uvicorn` 启动入口 |
| `tests/` | 48 个 `unittest` 用例（乱序/重复/边界/并发/重启） |
| `docs/DESIGN.md` | 详细设计：规则模型、聚合抑制规则、状态机、验证方法 |

## 结论一致性保证

- **统一结论结构**：HTTP、服务层、测试都返回同一个 `IngestionResult`；
  被拒绝的事件带 `reject_reason`，被接收但无新结论的带 `ignore_reason`，
  且 `detail` / `rule_decisions.reason` 给出可区分、可解释的原因。
- **确定性**：关联与抑制判定全部基于事件自带的 `timestamp_ms`，
  同一批事件无论正序还是乱序喂入，`anchor_ms`、`triggered_ms`、告警 ID
  都相同；审计时间走可注入时钟（`FixedClock`）。
- **幂等**：按 `event_id` 全局去重；重启加载快照后重放历史事件只会得到
  `DUPLICATE`，不产生重复告警；抑制边界后的新事件仍能产生新告警，不漏报。
- **并发安全**：告警处置在锁内完成状态跃迁并递增版本号；携带
  `expected_version` 的过期请求以 `STALE_VERSION` 被拒，更新不丢失；
  每次处置尝试（包括失败）都留一条审计记录。
