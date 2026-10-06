# SIEM 本地威胁检测与告警关联

用本地日志事件流与内存状态模拟安全事件的检测、关联与处置全流程。
仅依赖仓库已有依赖（FastAPI + 标准库），全部流程可离线复现。

## 架构

```
日志事件 -> EventIngester -> DetectionEngine -> AlertCorrelator -> AlertDispositionService
            (校验/去重)      (规则匹配)          (聚合/抑制)          (状态机/审计)
```

- `siem/models.py` — 数据模型：`LogEvent`、`DetectionRule`、`Alert`、`AuditRecord`、
  `RejectReason` / `AlertStatus` / `AuditAction` 枚举；`ProcessOutcome` / `RuleHit` /
  `OutcomeCategory`（处理结论分类）；`TransitionResult` / `TransitionOutcome` /
  `DispositionCounters`（处置结论与计数）。
- `siem/ingest.py` — 事件摄入：校验、重复投递去重、乱序容忍；支持快照/恢复。
- `siem/detection.py` — 规则匹配引擎，支持规则集整体替换（版本化）。
- `siem/correlation.py` — 告警关联与抑制窗口去重；支持快照/恢复。
- `siem/disposition.py` — 告警状态机与审计，线程安全；带前置校验的处置入口与计数。
- `siem/persistence.py` — 本地状态文件：JSON 快照 + 校验和 + 原子写。
- `siem/pipeline.py` — 端到端流水线 `SiemPipeline.process(event)` /
  `process_explain(event)` / `save_state(path)` / `SiemPipeline.restore(path, rules)`。
- `main.py` — FastAPI 入口（`/events`、`/alerts`、`/alerts/{id}/{action}`、`/audit`、
  `/stats`、`/state/save`、`/state/reload`）。

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

## 处理结论分类

`SiemPipeline.process_explain(event)` 返回 `ProcessOutcome`，在原有
`process()` 接口之外提供稳定、可区分、可解释的分类结论（原有 `process()` 行为不变）：

| 类别 | 含义 | 后续动作 |
| --- | --- | --- |
| `rejected_invalid` | 数据本身有问题被挡掉（缺字段/非法时间戳/过迟） | 修正数据后重投，`reason` 给出具体原因 |
| `skipped_duplicate` | 重复投递被跳过 | 无需处理，不会重复计数 |
| `processed_no_match` | 数据合法但未命中任何规则 | 未产生告警，属正常 |
| `alert_created` | 命中规则并创建新告警 | `hits` 含规则 ID、规则版本、新告警 ID 与窗口起止 |
| `alert_suppressed` | 命中规则但被已有告警抑制窗口收编 | `hits` 含被收编进的告警 ID 与窗口起止 |

同样的输入必得到同样的分类，与到达顺序无关（窗口判定基于事件时间）。
HTTP 层 `POST /events` 响应在原有字段之外新增 `outcome` 字段承载上述结论。

## 状态保存与恢复

- `pipeline.save_state(path)` 把摄入去重集合与水位线、全部告警（含关联证据
  `event_ids`、每条抑制窗口起止、状态、修订号）、审计记录、三类计数整体写入
  本地 JSON 文件；`SiemPipeline.restore(path, rules)` 在新实例上恢复后继续跑。
- 恢复后：恢复前处理过的重复事件再投递仍被跳过（不重复计数、不出重复告警）；
  抑制窗口内的事件仍被同一条告警收编；窗口外事件照常产生新告警，
  告警序号从恢复点继续，不与历史冲突。
- 写入采用「临时文件 + fsync + 原子替换」：写到一半崩溃不会留下半截状态文件，
  上一份完整状态保持可用。
- 文件携带格式版本与 SHA-256 校验和：文件被截断、篡改或格式版本不支持时，
  `restore` 抛出 `StateCorruptionError` 明确报错，绝不悄悄读出坏状态继续跑。
- 兼容范围：仅保证同一 `STATE_FORMAT` 版本（当前为 1）的保存/恢复；
  规则集由调用方在恢复时传入，关联键中的规则版本保证规则变更后判定不受旧状态影响。
- 只使用标准库与本地文件，离线可复现。

## 前置校验处置与计数口径

- `disposition.try_transition(alert_id, action, actor, timestamp, expected_version)`
  为带前置校验的处置入口：调用方携带其认为的当前修订（`alert.version`），
  对得上才允许流转。结论四类可区分：`applied` / `conflict`（修订对不上）/
  `invalid_transition`（非法跃迁）/ `not_found`，不抛异常；
  被拒绝的尝试同样追加审计记录（冲突以 `conflict:` 前缀、非法跃迁以
  `rejected:` 前缀标识）。原有 `acknowledge/close/reopen` 接口行为不变
  （非法跃迁仍抛 `DispositionError`）。
- 计数口径三类各自独立，见 `disposition.counters(alert_id)`：
  - `correlated_events`：关联进该告警的事件总数（含被抑制收编的）；
  - `transitions_applied`：成功流转次数；
  - `transitions_attempted`：累计处置尝试次数（含冲突与非法跃迁的拒绝）。
- 多线程同时处置同一告警时，所有检查与修改在同一临界区内完成：
  带相同 `expected_version` 的并发尝试恰好一个成功、其余全部为 `conflict`，
  无非法跃迁、无丢失更新，状态与计数始终一致。
- HTTP 层 `POST /alerts/{id}/{action}` 请求体可携带 `expected_version`；
  409 响应体中的 `outcome` 字段区分 `conflict` 与 `invalid_transition`。
  `GET /stats` 在原有状态计数之外新增 `counters` 字段。

## 本地验证

```bash
# 单元测试（仅标准库，覆盖乱序/重复、抑制窗口边界、并发处置、
# 结论分类、保存后重启恢复、并发前置校验冲突；
# 日志打印事件输入、命中规则与窗口判定依据）
python3 -m unittest discover -s tests -v

# 启动 HTTP 服务
uv run python main.py   # 或 uv run uvicorn main:app --port 8000

# 示例：上报事件 -> 告警被抑制聚合 -> 处置 -> 查看审计
curl -X POST localhost:8000/events -H 'content-type: application/json' -d \
  '{"event_id":"e1","timestamp":1000.0,"event_type":"login_failed","source":"h1","attributes":{"user":"root"}}'
curl -X POST localhost:8000/alerts/alert-0001/acknowledge -H 'content-type: application/json' -d \
  '{"actor":"op","timestamp":2000.0,"expected_version":0}'
curl localhost:8000/audit

# 状态保存与恢复
curl -X POST localhost:8000/state/save -H 'content-type: application/json' -d '{"path":"siem-state.json"}'
curl -X POST localhost:8000/state/reload -H 'content-type: application/json' -d '{"path":"siem-state.json"}'
```
