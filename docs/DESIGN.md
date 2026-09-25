# 设计说明：本地威胁检测与告警关联

本文档说明检测规则模型、聚合与抑制规则、告警状态机，以及本地验证方法。
目标是让规则匹配、告警聚合与告警处置在 HTTP、服务层与测试各入口下
给出**一致、确定、可解释、可离线复现**的结论。

---

## 1. 总体架构

```
日志事件(dict)
   │  入口校验（MALFORMED / MISSING_FIELD / BAD_TIMESTAMP）
   ▼
SiemService.ingest_event_dict
   ▼
CorrelationEngine（全局 event_id 去重 → 乱序宽限 → 规则匹配 → 关联键）
   ▼                         每条规则一个 RuleDecision（判定依据）
攻击链 _ChainState（关联窗口 → 阈值触发 → 抑制区间）
   ▼ 触发
AlertManager（OPEN/ACKED/CLOSED 状态机 + 乐观版本锁 + 审计）
   ▼
JsonSnapshotStore（原子快照，重启恢复，重放幂等）
```

所有时间判定都使用**事件时间** `timestamp_ms`（毫秒，整数），与处理
到达顺序解耦；只有审计动作时间使用可注入时钟（生产 `SystemClock`，
测试 `FixedClock`），因此整套流程的输出可完全复现。

---

## 2. 检测规则模型（`siem/rules.py`, `siem/models.py`）

一条规则同时描述「检测 + 关联 + 抑制」：

| 字段 | 含义 |
| --- | --- |
| `rule_id` / `version` | 规则身份与版本。版本必须单调递增；同号不同内容与版本回退都被 `RuleVersionError` 拒绝；同号同内容为幂等写入 |
| `match_type` / `match_value` | 命中方式：`event_type` 全等、`source` 全等、`attr` 形式为 `字段名=期望值`（取 `event.attrs`） |
| `correlation_key` | 关联键模板，占位符 `{event_id}` `{source}` `{event_type}` `{attr:名称}`；多个占位符可与字面量混用，如 `{source}|{attr:src_ip}` |
| `threshold` | 窗口内去重事件数达到该值即触发告警（≥1） |
| `window_ms` | 关联窗口长度（毫秒，≥1） |
| `suppression_ms` | 触发后抑制长度（毫秒，≥0，0 表示空抑制区间） |
| `severity` | 告警严重级别，原样落到告警上 |
| `enabled` | 禁用规则不参与匹配；禁用属于变更，必须提升版本 |

**链身份** = `(rule_id, rule_version, correlation_value)`。因此规则
版本提升后，事件进入全新关联链，旧版本链的抑制窗口不再影响新规则。

### 2.1 关联键字段缺失

事件命中了规则但其 `correlation_key` 所需字段缺失时，事件在入口被
**拒绝**（`MISSING_FIELD`，detail 指明缺失字段，如 `attr:src_ip`），
且拒绝事件不登记去重、不推进水位——数据提供方补全字段后可用同一
`event_id` 重新投递并被正常计数。

---

## 3. 事件摄入结论（拒绝 / 忽略，原因可区分）

任何输入都不会被静默丢弃，结论统一为 `IngestionResult`：

| 类别 | 原因码 | 触发条件 |
| --- | --- | --- |
| 拒绝 `accepted=false` | `MALFORMED` | 载荷不是对象、`attrs` 不是对象等 |
| 拒绝 | `MISSING_FIELD` | 顶层必填字符串缺失，或命中规则的关联键字段缺失（detail 带字段名） |
| 拒绝 | `BAD_TIMESTAMP` | `timestamp_ms` 非整数或为负（布尔值也视为非法） |
| 拒绝 | `DUPLICATE` | `event_id` 已处理过（重复投递，不重复计数）。**去重检查先于乱序宽限**，保证重启重放永远得到 DUPLICATE |
| 忽略 `accepted=true` | `NO_RULE_MATCHED` | 无任何启用规则命中 |
| 忽略 | `LATE_BEYOND_GRACE` | 事件时间早于水位 `max_seen_ms - grace_ms` |
| 忽略 | `OUT_OF_WINDOW` | 命中规则但落不进任何关联窗口（如告警后的极晚补充事件） |
| 忽略 | `SUPPRESSED` | 命中规则且位于告警抑制半开区间内，已挂为抑制证据 |

此外 `rule_decisions[]` 给出每条命中规则上的状态（`COUNTED` /
`WINDOW_RESET` / `TRIGGERED` / `SUPPRESSED` 等）与人类可读 `reason`，
HTTP 响应中原样返回，并由 `siem.engine` logger 打印。

---

## 4. 聚合与抑制规则（`siem/engine.py`）

### 4.1 乱序到达与水位宽限

- 维护已接收事件的最大事件时间 `max_seen_ms`；
- `grace_ms` 显式可配，**默认等于所有启用规则的最大 `window_ms`**；
- 事件时间 `< max_seen_ms - grace_ms` → `LATE_BEYOND_GRACE`（仍登记
  去重，重放为 DUPLICATE）。
- 宽限检查是半开边界：事件时间**恰等**于水位线时不算迟到。

### 4.2 关联窗口（半开区间）

对每条攻击链，窗口为 **`[anchor_ms, anchor_ms + window_ms)`**，
其中 `anchor_ms` 为窗口内最早事件时间。

- 新事件落入右边界之后（`ts >= anchor + window`）：若窗口内计数未达
  阈值，旧窗口关闭（判定 `WINDOW_RESET`，reason 带具体区间），本事件
  以自己为锚点开启新窗口；
- 宽限内的晚到事件可并入当前窗口，锚点随之回退，并裁剪掉落在新窗口
  之外的旧成员。因为触发判定只取决于「窗口内去重事件集合」，所以
  `anchor_ms` / `triggered_ms` / 告警 ID **不依赖事件到达顺序**
  （见 `test_order_independent_trigger_result`）。

### 4.3 阈值触发

窗口内去重事件数首次 `>= threshold` 时产生一条 `OPEN` 告警：

- `triggered_ms = 窗口内最大事件时间`（只依赖数据）；
- 初始证据 = 窗口内全部事件，`correlated_count = len(event_ids)`；
- 告警 ID 确定性生成：`{rule_id}:v{version}:{corr_value}#{链内序号}`，
  同一状态重放不会变化，不同周期不会撞号。

### 4.4 抑制（半开区间，边界解除）

触发后抑制区间为 **`[triggered_ms, triggered_ms + suppression_ms)`**：

- 区间内事件**不产生新告警**，挂到活动告警：`event_ids` 追加、
  `correlated_count += 1`、`suppressed_count += 1`；
- 事件时间 `>= suppress_until_ms`（右边界）立即解除抑制并开启新窗口，
  新窗口达到阈值后产生 `#2` 告警；
- `suppression_ms = 0` 时空区间，与触发事件同刻的下一条事件即属新周期；
- 触发之后到达、但事件时间仍落在触发窗口 `[anchor, triggered]` 内的
  晚到补充事件会被补挂为关联证据（非抑制），更早的则 `OUT_OF_WINDOW`。

### 4.5 幂等与重启

- 引擎状态（去重表、水位、每条链的窗口/抑制期/序号）与规则、告警、
  审计一起写入单个 JSON 快照（`JsonSnapshotStore`，临时文件
  `fsync` + `os.replace` 原子替换）；
- 恢复后重放历史事件 → 全部 `DUPLICATE`，不产生重复告警；
- 恢复后抑制期仍生效（边界判定可复现），边界后的新事件照常产生
  新告警，不会错失应有告警。

---

## 5. 告警状态机与审计（`siem/alerts.py`）

### 5.1 合法跃迁

```
OPEN  ──ACK──▶  ACKED
OPEN  ──CLOSE─▶  CLOSED
ACKED ──CLOSE─▶  CLOSED
CLOSED──REOPEN─▶ OPEN
```

任何其他跃迁都是非法跃迁，每种非法组合都有**专属原因文案**，例如：

- `ACKED` 上再 ACK → “告警已处于 ACKED，重复确认被拒绝”
- `CLOSED` 上 ACK → “CLOSED 告警不能确认，须先 REOPEN”
- `ACKED` 上 REOPEN → “ACKED 告警不能 REOPEN；须先 CLOSE 再 REOPEN”

### 5.2 并发处置：乐观版本锁

- 告警带单调 `version`，每次**成功**处置 `version += 1`；
- 请求可携带 `expected_version`，与当前版本不一致 → 抛
  `StaleVersionError`（HTTP `409 STALE_VERSION`），状态不变、更新不丢；
- 全部读写在 `RLock` 内完成。并发 N 个 ACK 时恰好 1 个成功、其余
  失败，最终版本恰好为 1（见并发测试：10 线程 ACK 同一告警）；
- 每个处置尝试都校验非空 `actor` 与 `reason`，保证动作可追溯。

### 5.3 审计

成功与失败动作都追加 `AuditEntry`：`audit_id`（全局递增）、动作、
操作人、原因、`success`、`from_state`/`to_state`、期望/实际版本、
动作时间（注入时钟）。失败动作记 `to_state=null` 且不增加版本。
入口：`GET /alerts/{id}/audit`、`GET /audit`。

---

## 6. HTTP 接口

统一信封：成功 `{"ok": true, "data": ...}`；
失败 `{"ok": false, "error": {"code", "message"}}`。

| 方法/路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查 |
| `PUT /rules` | 新增/升级规则；版本冲突 `409 RULE_VERSION` |
| `GET /rules` | 列出全部规则 |
| `POST /events` | 摄入一条事件；业务结论（含 DUPLICATE 等）以 200 + 结构化原因返回 |
| `GET /alerts` / `GET /alerts/{id}` | 告警列表/详情 |
| `POST /alerts/{id}/actions` | `ACK` / `CLOSE` / `REOPEN`，可带 `expected_version`；非法跃迁 `409 ILLEGAL_TRANSITION`，版本冲突 `409 STALE_VERSION` |
| `GET /alerts/{id}/audit` / `GET /audit` | 审计记录 |
| `POST /snapshot` / `POST /snapshot/load` | 保存/加载本地 JSON 快照；未配置存储 `400 PERSISTENCE_DISABLED` |

> 提示：告警 ID 含 `|`、`#`、`:`，URL 中需百分号编码。

---

## 7. 本地验证方法

无需联网、无需额外依赖（测试只用标准库 `unittest`；TestClient 使用
`fastapi[standard]` 已携带的 httpx）：

```bash
# 全部 48 个用例
python -m unittest discover -s tests -v

# 分组运行
python -m unittest tests.test_models -v   # 规则匹配/关联键/跃迁表
python -m unittest tests.test_engine -v   # 乱序/重复/字段缺失/窗口与抑制边界/规则变更/重启
python -m unittest tests.test_alerts -v   # 状态机/非法跃迁/乐观锁/并发处置/审计
python -m unittest tests.test_api -v      # 端到端 HTTP + 10 线程并发处置 + 重启重放
```

关键场景与对应用例：

| 场景 | 用例 |
| --- | --- |
| 重复投递不重复计数 | `test_duplicate_event_is_rejected_not_double_counted` |
| 乱序到达结论一致 | `test_order_independent_trigger_result` |
| 宽限内晚到并入窗口 | `test_late_event_in_grace_joins_window_and_anchor_moves_back` |
| 超宽限可区分忽略 | `test_late_beyond_grace_is_ignored_with_distinct_reason` |
| 宽限/窗口/抑制半开边界 | `test_custom_grace_boundary_half_open`、`test_untriggered_window_closes...`、`test_suppression_released_at_right_boundary`、`test_zero_suppression_...` |
| 关联键缺字段拒绝 | `test_missing_correlation_field_is_rejected_with_field_name` |
| 规则版本变更隔离 | `test_rule_version_bump_starts_independent_chain` |
| 重启重放不重复、不漏报 | `test_restart_dedups_and_does_not_lose_due_alerts`、`test_replay_after_restart...` |
| 并发处置无非法跃迁/不丢更新 | `test_parallel_ack_only_one_succeeds`、`test_concurrent_mixed_actions...`、`test_concurrent_actions_over_http_exactly_one_ack` |
| 失败动作可追溯 | `test_every_failed_attempt_leaves_audit_with_flag_and_reason` |

程序化使用（不经 HTTP）：

```python
from siem.service import SiemService
from siem.models import Rule

svc = SiemService()  # 或传 store=JsonSnapshotStore("state.json")、clock=FixedClock(0)
svc.upsert_rule(Rule("brute", 1, "event_type", "LOGIN_FAIL", "HIGH",
                     "{source}|{attr:src_ip}", 3, 1000, 5000))
result = svc.ingest_event_dict({...})
print(result.reject_reason, result.ignore_reason, result.alert_ids, result.detail)
```
