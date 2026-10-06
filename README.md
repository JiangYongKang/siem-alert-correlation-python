# SIEM 本地威胁检测与告警关联

用本地日志事件流与内存状态模拟安全事件的检测、关联与处置全流程。
仅依赖仓库已有依赖（FastAPI + 标准库），全部流程可离线复现。

## 架构

```
日志事件 -> EventIngester -> DetectionEngine -> AlertCorrelator -> AlertDispositionService
            (校验/去重)      (规则匹配)          (聚合/抑制)          (状态机/审计)
```

- `siem/models.py` — 数据模型：`LogEvent`、`DetectionRule`、`Alert`、`AuditRecord`、
  `RejectReason` / `AlertStatus` / `AuditAction` / `ProcessOutcome` 枚举、
  `ProcessResult` / `RuleHit` 处理结论。
- `siem/ingest.py` — 事件摄入：校验、重复投递去重、乱序容忍。
- `siem/detection.py` — 规则匹配引擎，支持规则集整体替换（版本化）。
- `siem/correlation.py` — 告警关联与抑制窗口去重。
- `siem/disposition.py` — 告警状态机与审计，线程安全；带前置校验的处置入口。
- `siem/persistence.py` — 本地状态快照：原子写入、校验和校验、损坏回退。
- `siem/pipeline.py` — 端到端流水线 `SiemPipeline.process(event)` /
  `SiemPipeline.process_event(event)`。
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

## 处理结论分类

`SiemPipeline.process_event(event)` 返回 `ProcessResult`，
`outcome` 字段给出五类稳定、可区分、可解释的结论，
只看结论与说明就知道该怎么继续处理：

| outcome | 含义 | 后续处理 |
| --- | --- | --- |
| `rejected_invalid` | 数据本身有问题被挡掉（缺字段/非法时间戳/超出乱序容忍） | 检查上游数据，`ingest.reason` 给出具体原因 |
| `skipped_duplicate` | 重复投递被跳过，不重复计数 | 无需处理，投递方收到的是确定性结论 |
| `accepted_no_match` | 数据合法但未命中任何规则，未产生告警 | 正常现象；如需覆盖可补充规则 |
| `alert_created` | 命中规则并新建告警 | 进入处置流程 |
| `alert_suppressed` | 命中规则，但事件被已有告警的抑制窗口吸收 | 关注原告警即可，`suppressed_count` 已累计 |

- 命中规则时 `hits` 记录每条命中规则的 `rule_id`、`rule_version`、
  关联到的 `alert_id` 及是否新建，命中依据完全可解释。
- 同样的输入流必得到同样的分类序列：判定只依赖事件内容与事件时间，
  不依赖到达时刻或随机因素；窗口判定按事件时间，
  乱序到达（容忍窗口内）的事件仍按其事件时间落入正确窗口。
- 原 `process(event)` 接口签名与返回结构保持不变。

## 状态保存与恢复

`pipeline.save(path)` / `SiemPipeline.load(path, rules, ...)` 把检测、关联、
处置的全部运行状态保存到本地文件并恢复（仅标准库 + 本地文件，离线可复现）：

- 保存内容：已见 `event_id` 集合与水位线、全部告警（含证据 `event_ids`、
  每条抑制窗口的起点 `created_at`、窗口长度由 `suppression_window` 参数给出）、
  告警处置状态、审计轨迹、三类计数器、告警 ID 序号。
- 恢复效果：重启或换新实例后，之前关联的证据、抑制窗口起止、处置状态都在；
  恢复前处理过的事件再投递仍判 `skipped_duplicate`，不重复计数、不冒出重复告警；
  告警 ID 序号接续分配，窗口外事件照常产生新告警，不因恢复漏告警。
- 写入是原子的：先写临时文件并 fsync，再 `os.replace` 替换；
  写一半崩溃不会留下截断的正式文件。替换前上一份完整状态保留为 `<path>.bak`。
- 每份状态带 sha256 校验和。读取时正式文件损坏/被截断/被篡改，
  自动回退到 `<path>.bak` 的上一份完整状态；两份都损坏则抛
  `StateCorruptionError` 明确报错，绝不悄悄读出坏状态继续跑。
- 兼容范围：状态格式带 `format` 版本号（当前为 1），格式不符即报错而非猜测。
  检测规则属于配置而非状态，恢复时由调用方提供当前规则集；
  关联键中携带规则版本，用新规则集恢复不会污染旧告警。
  关联键取值须为 JSON 标量（字符串/数值/null）。
  `accepted_events()` 的内存历史列表不在持久化范围内。
- HTTP 服务模式：设置环境变量 `SIEM_STATE_PATH` 后，启动时自动恢复
  （文件不存在则全新启动），每次状态变更（含被拒绝的处置尝试）后自动落盘。

## 前置校验处置与计数口径

- `disposition.transition(alert_id, action, actor, timestamp, expected_version=...)`
  是带前置校验的处置入口：调用方声明它认为的当前修订（`alert.version`，
  可由 `/alerts` 的 `version` 字段获得），一致才允许流转。
- 修订对不上抛 `ConflictError`（HTTP 409 `error=conflict`），
  与非法状态跃迁的 `DispositionError`（HTTP 409 `error=illegal_transition`）
  是不同的异常类型，不会混为一谈；`expected_version=None` 时退化为无校验流转。
- 冲突与非法跃迁的尝试同样写入审计，分别以 `conflict:` / `rejected:` 前缀区分。
- 三类计数各自独立（`pipeline.counters()` 与 `/stats`）：
  - `correlated_events`：关联进告警的事件数（新建 + 被抑制吸收）；
  - `successful_transitions`：成功流转次数；
  - `attempted_transitions`：累计尝试次数（含冲突与非法跃迁）。
- 多线程同时处置同一条告警：检查与修改在同一把锁内完成，
  带相同 `expected_version` 的并发请求恰好一个成功、其余收到冲突，
  无非法跃迁、无丢失更新，状态与计数始终一致。

## 本地验证

```bash
# 单元测试（仅标准库，覆盖乱序/重复、抑制窗口边界、并发处置、
# 处理结论分类、保存后重启恢复、前置校验并发冲突；
# 日志打印事件输入、命中规则与窗口判定依据）
python3 -m unittest discover -s tests -v

# 启动 HTTP 服务（SIEM_STATE_PATH 可选，设置后启用状态保存/恢复）
uv run python main.py   # 或 SIEM_STATE_PATH=./state.json uv run uvicorn main:app --port 8000

# 示例：上报事件 -> 告警被抑制聚合 -> 带前置校验处置 -> 查看审计与计数
curl -X POST localhost:8000/events -H 'content-type: application/json' -d \
  '{"event_id":"e1","timestamp":1000.0,"event_type":"login_failed","source":"h1","attributes":{"user":"root"}}'
curl -X POST localhost:8000/alerts/alert-0001/acknowledge -H 'content-type: application/json' -d \
  '{"actor":"op","timestamp":2000.0,"expected_version":0}'
curl localhost:8000/audit
curl localhost:8000/stats
```
