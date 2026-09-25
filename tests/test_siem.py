"""本地威胁检测与告警关联流程测试。

日志中打印事件输入与关联判定依据，便于复核结论。
仅依赖标准库（unittest），可离线运行：python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import logging
import threading
import unittest

from siem import (
    Alert,
    AlertDispositionService,
    AlertStatus,
    DetectionRule,
    LogEvent,
    RejectReason,
    SiemPipeline,
)
from siem.disposition import DispositionError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("siem-test")

RULE = DetectionRule(
    "brute-force", "login_failed", "high",
    required_attributes=("user",), correlation_keys=("source", "user"),
)


def ev(eid, ts, source="h1", user="root", etype="login_failed"):
    attrs = (("user", user),) if user is not None else ()
    return LogEvent(eid, ts, etype, source, attrs)


def explain(result, alerts):
    if not result.accepted:
        return f"拒绝: {result.reason.value} ({result.detail})"
    if not alerts:
        return "接受: 未命中任何规则"
    return "关联: " + ", ".join(
        f"{a.alert_id}[事件数={len(a.event_ids)} 抑制={a.suppressed_count}]" for a in alerts
    )


class IngestTest(unittest.TestCase):
    def test_out_of_order_and_duplicate_events(self):
        pipe = SiemPipeline([RULE], suppression_window=100, max_lateness=50)
        # 乱序到达：e2 的事件时间早于已见的 e1，但在容忍窗口内
        cases = [
            ev("e1", 1000.0),
            ev("e2", 980.0),           # 乱序，窗口内 -> 接受
            ev("e1", 1000.0),          # 重复投递 -> DUPLICATE_DELIVERY
            ev("e3", 900.0),           # 超出容忍窗口 -> TOO_LATE
            ev("", 1000.0),            # 缺字段 -> MISSING_FIELD
            ev("e4", float("nan")),    # 非法时间戳 -> INVALID_TIMESTAMP
            ev("e5", 1010.0, user=None),  # 缺规则必备属性 -> 接受但不命中规则
        ]
        results = []
        for e in cases:
            r, alerts = pipe.process(e)
            log.info("输入事件 %s(ts=%s) -> %s", e.event_id or "<missing>", e.timestamp,
                     explain(r, alerts))
            results.append((r, alerts))

        self.assertTrue(results[0][0].accepted)
        self.assertTrue(results[1][0].accepted)
        self.assertEqual(results[2][0].reason, RejectReason.DUPLICATE_DELIVERY)
        self.assertEqual(results[3][0].reason, RejectReason.TOO_LATE)
        self.assertEqual(results[4][0].reason, RejectReason.MISSING_FIELD)
        self.assertEqual(results[5][0].reason, RejectReason.INVALID_TIMESTAMP)
        self.assertTrue(results[6][0].accepted)
        self.assertEqual(results[6][1], [])  # 缺 user 属性，不命中规则

        # 重复投递未被重复计数：告警只包含 e1、e2 两条事件
        alerts = pipe.correlator.alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_ids, ["e1", "e2"])
        self.assertEqual(alerts[0].suppressed_count, 1)

    def test_replay_is_reproducible(self):
        events = [ev("e1", 1000.0), ev("e2", 1050.0), ev("e3", 1100.0)]
        def run():
            pipe = SiemPipeline([RULE], suppression_window=100)
            for e in events:
                pipe.process(e)
            return [(a.alert_id, tuple(a.event_ids)) for a in pipe.correlator.alerts()]
        first, second = run(), run()
        log.info("首次重放: %s; 二次重放: %s", first, second)
        self.assertEqual(first, second)  # 重启/重复处理结论一致


class SuppressionWindowTest(unittest.TestCase):
    def test_window_boundary_is_deterministic(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        # 窗口 [1000, 1100)：1099.9 抑制，1100.0 解除抑制产生新告警
        boundaries = [(1000.0, True), (1099.9, False), (1100.0, True)]
        created = []
        for i, (ts, expect_new) in enumerate(boundaries):
            before = {a.alert_id for a in pipe.correlator.alerts()}
            _, alerts = pipe.process(ev(f"e{i}", ts))
            is_new = alerts[0].alert_id not in before
            created.append(alerts[0].alert_id)
            log.info("ts=%s -> %s (新建=%s, 期望新建=%s)", ts,
                     alerts[0].alert_id, is_new, expect_new)
            self.assertEqual(is_new, expect_new)
        alerts = {a.alert_id: a for a in pipe.correlator.alerts()}
        self.assertEqual(alerts[created[0]].suppressed_count, 1)
        self.assertEqual(alerts[created[2]].suppressed_count, 0)

    def test_rule_change_creates_new_alert(self):
        pipe = SiemPipeline([RULE], suppression_window=1000)
        pipe.process(ev("e1", 100.0))
        # 规则变更（版本升级）后，同一时间窗内的事件落入新关联键
        pipe.engine.update_rules([
            DetectionRule("brute-force", "login_failed", "high",
                          ("user",), ("source", "user"), version=2)
        ])
        _, alerts = pipe.process(ev("e2", 110.0))
        log.info("规则变更后事件 e2 -> %s (rule_version=%d)",
                 alerts[0].alert_id, alerts[0].rule_version)
        self.assertEqual(alerts[0].rule_version, 2)
        self.assertEqual(len(pipe.correlator.alerts()), 2)


class DispositionTest(unittest.TestCase):
    def test_state_machine_transitions(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        svc.acknowledge("a1", "alice", 1.0)
        svc.close("a1", "bob", 2.0)
        svc.reopen("a1", "carol", 3.0)
        self.assertEqual(svc.get("a1").status, AlertStatus.OPEN)
        with self.assertRaises(DispositionError):
            svc.reopen("a1", "dave", 4.0)  # OPEN 不能重开
        with self.assertRaises(DispositionError):
            svc.acknowledge("ghost", "dave", 4.0)  # 告警不存在
        trail = svc.audit_trail("a1")
        for r in trail:
            log.info("审计: %s %s %s->%s (%s)", r.actor, r.action.value,
                     r.from_status.value, r.to_status.value, r.detail)
        self.assertEqual(len(trail), 4)  # 3 成功 + 1 拒绝均留痕
        self.assertTrue(trail[-1].detail.startswith("rejected:"))

    def test_concurrent_disposition_no_lost_updates(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        successes, failures = [], []

        def work(i):
            try:
                svc.acknowledge("a1", f"user-{i}", 10.0)
                successes.append(i)
            except DispositionError as exc:
                failures.append(str(exc))

        threads = [threading.Thread(target=work, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        log.info("并发确认: 成功 %d 次, 拒绝 %d 次", len(successes), len(failures))
        self.assertEqual(len(successes), 1)          # 恰好一次成功，无丢失更新
        self.assertEqual(len(failures), 49)          # 其余均为可区分原因的拒绝
        self.assertEqual(svc.get("a1").status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(svc.get("a1").version, 1)
        # 审计与状态计数一致
        self.assertEqual(len(svc.audit_trail("a1")), 50)
        self.assertEqual(svc.status_counts(),
                         {"open": 0, "acknowledged": 1, "closed": 0})

    def test_concurrent_mixed_actions(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))

        def act(fn, i):
            try:
                fn("a1", f"user-{i}", 10.0)
            except DispositionError:
                pass

        threads = (
            [threading.Thread(target=act, args=(svc.acknowledge, i)) for i in range(20)]
            + [threading.Thread(target=act, args=(svc.close, i)) for i in range(20)]
            + [threading.Thread(target=act, args=(svc.reopen, i)) for i in range(20)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        alert = svc.get("a1")
        trail = svc.audit_trail("a1")
        applied = [r for r in trail if not r.detail.startswith("rejected:")]
        log.info("混合并发: 终态=%s version=%d 成功流转=%d 审计总数=%d",
                 alert.status.value, alert.version, len(applied), len(trail))
        # 终态合法、version 与成功流转数一致、每次动作均有审计
        self.assertIn(alert.status, set(AlertStatus))
        self.assertEqual(alert.version, len(applied))
        self.assertEqual(len(trail), 60)
        # 审计链连续：每条成功记录的起始状态等于上一条的结束状态
        for prev, cur in zip(applied, applied[1:]):
            self.assertEqual(prev.to_status, cur.from_status)


if __name__ == "__main__":
    unittest.main()
