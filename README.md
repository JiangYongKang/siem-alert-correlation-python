# SIEM 本地威胁检测与告警关联

用本地日志事件流与内存状态模拟安全事件的检测、关联与处置全流程。
仅依赖仓库已有依赖（FastAPI + 标准库），全部流程可离线复现。

## 架构

```
日志事件 -> EventIngester -> DetectionEngine -> AlertCorrelator -> AlertDispositionService
            (校验/去重)      (规则匹配)          (聚合/抑制)          (状态机/审计)
```

- `siem/models.py` — 数据模型：`LogEvent`、`DetectionRule`、`Alert`、`AuditRecord`、
  `RejectReason` / `AlertStatus` / `AuditAction` 枚举。
- `siem/ingest.py` — 事件摄入：校验、重复投递去重、乱序容忍。
- `siem/detection.py` — 规则匹配引擎，支持规则集整体替换（版本化）。
- `siem/correlation.py` — 告警关联与抑制窗口去重。
- `siem/disposition.py` — 告警状态机与审计，线程安全。
- `siem/pipeline.py` — 端到端流水线 `SiemPipeline.process(event)`。
- `main.py` — FastAPI 入口（`/events`、`/alerts`、`/alerts/{id}/{action}`、`/audit`、`/stats`）。

## 检测规则模型

`DetectionRule` 字段：

| 字段 | 含义 |
| --- | --- |
| `rule_id` | 规则标识 |
| `event_type` | 匹配的事件类型 |
| `severity` | 命中后告警严重度 |
| `required_attributes` | 事件必须携带的属性，缺失则不命中（事件仍被接受，不计为异常） |
| `correlation_keys` | 关联键字段（`source` 或 attributes 中的键） |
| `version` | 规则版本，进入关联键，规则变更后判定不受旧状态影响 |

事件命中规则当且仅当 `event_type` 相等且所有 `required_attributes` 非空。

## 事件摄入规则

摄入结果必为「接受」或带可区分原因的拒绝，绝不静默丢弃：

| 情形 | 结论 |
| --- | --- |
| `event_id` / `event_type` / `source` 为空 | 拒绝 `missing_field` |
| 时间戳非数值 / NaN / Inf / 负数 | 拒绝 `invalid_timestamp` |
| `event_id` 已处理过 | 忽略 `duplicate_delivery`，不重复计数 |
| 事件时间早于水位线超过 `max_lateness` | 拒绝 `too_late` |
| 乱序但在容忍窗口内 | 接受，按事件时间参与关联 |

## 聚合与抑制规则

- 关联键 = `(rule_id, rule_version, *correlation_keys 取值)`；同键事件聚合为一条告警。
- 每条告警的抑制窗口为 `[created_at, created_at + suppression_window)`，
  以**事件时间**（而非到达时间）判定，与到达顺序无关，结论确定且可复现。
- 事件时间落入某条已有告警窗口内：聚合进该告警，`suppressed_count + 1`，不产生新告警。
- 乱序到达且早于该键所有窗口的前序事件：并入最早告警（同一攻击链），不另建告警。
- 事件时间不早于最新窗口末尾：抑制解除，创建新告警。窗口边界为左闭右开，
  即 `created_at + suppression_window` 恰好落在窗口外。
- 规则版本变更后关联键改变，自然生成新告警，旧告警状态不受污染。
- 告警 ID 按处理顺序单调分配（`alert-0001`…），同一输入流重放得到完全相同的告警集，
  重启/重复处理不产生重复告警或错失告警。

## 告警状态机

```
        acknowledge            close
OPEN  -------------> ACKNOWLEDGED -----> CLOSED
  |                                       |
  +---------------- close                 |
  |                                       |
  +<--------------- reopen ---------------+
```

- 合法跃迁：`acknowledge: OPEN→ACKNOWLEDGED`；`close: OPEN/ACKNOWLEDGED→CLOSED`；
  `reopen: CLOSED→OPEN`。
- 非法跃迁与操作不存在的告警均抛 `DispositionError`，消息中携带可区分原因。
- 所有检查与修改在同一把锁内完成：并发处置同一告警时恰好一个动作成功，
  无非法跃迁、无丢失更新；`alert.version` 与成功流转次数一致，
  `status_counts()` 与告警实际状态一致。
- 每次处置动作（含被拒绝的尝试）都追加 `AuditRecord`，
  被拒绝的记录以 `rejected:` 前缀标识原因，审计链中相邻成功记录的状态首尾相接。

## 本地验证

```bash
# 单元测试（仅标准库，覆盖乱序/重复、抑制窗口边界、并发处置；
# 日志打印事件输入与关联判定依据）
python3 -m unittest discover -s tests -v

# 启动 HTTP 服务
uv run python main.py   # 或 uv run uvicorn main:app --port 8000

# 示例：上报事件 -> 告警被抑制聚合 -> 处置 -> 查看审计
curl -X POST localhost:8000/events -H 'content-type: application/json' -d \
  '{"event_id":"e1","timestamp":1000.0,"event_type":"login_failed","source":"h1","attributes":{"user":"root"}}'
curl -X POST localhost:8000/alerts/alert-0001/acknowledge -H 'content-type: application/json' -d \
  '{"actor":"op","timestamp":2000.0}'
curl localhost:8000/audit
```
