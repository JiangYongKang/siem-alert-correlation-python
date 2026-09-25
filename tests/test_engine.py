"""检测/聚合/抑制引擎测试。

重点覆盖：乱序到达、重复投递、字段缺失、关联窗口与抑制窗口的半开
边界、抑制解除、规则版本变更、快照重启幂等。
每个用例都会通过 logging 打印事件输入与关联判定依据，并断言日志中
确实出现可解释的判定文字。
"""

from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from siem.alerts import AlertManager
from siem.clock import FixedClock
from siem.engine import CorrelationEngine
from siem.models import Event, IgnoreReason, RejectReason, Rule
from siem.rules import RuleRegistry
from siem.storage import JsonSnapshotStore


def brute_rule(version: int = 1, **over) -> Rule:
    base = dict(
        rule_id="brute",
        version=version,
        match_type="event_type",
        match_value="LOGIN_FAIL",
        severity="HIGH",
        correlation_key="{source}|{attr:src_ip}",
        threshold=3,
        window_ms=1000,
        suppression_ms=5000,
    )
    base.update(over)
    return Rule(**base)


def ev(eid: str, ts: int, src: str = "hostA", ip: str = "1.1.1.1",
       etype: str = "LOGIN_FAIL") -> Event:
    return Event(eid, ts, src, etype, {"src_ip": ip})


class _LogCapture(logging.Handler):
    """收集 siem.engine 的日志，便于断言“输入 + 判定依据”被打印。"""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


class EngineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = RuleRegistry()
        self.registry.upsert(brute_rule())
        self.alerts = AlertManager(FixedClock(0))
        self.engine = CorrelationEngine(self.registry)
        self.engine.bind_alerts(self.alerts)
        self.cap = _LogCapture()
        self.logger = logging.getLogger("siem.engine")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.cap)

    def tearDown(self) -> None:
        self.logger.removeHandler(self.cap)

    def assert_log_contains(self, fragment: str) -> None:
        self.assertTrue(
            any(fragment in line for line in self.cap.records),
            f"日志中未找到 {fragment!r}；实际日志: {self.cap.records}",
        )


class IngestionBasicsTest(EngineTestBase):
    def test_no_match_is_ignored_with_distinct_reason(self) -> None:
        r = self.engine.ingest(ev("e0", 0, etype="LOGIN_OK"))
        self.assertTrue(r.accepted)
        self.assertEqual(r.ignore_reason, IgnoreReason.NO_RULE_MATCHED)
        self.assert_log_contains("NO_RULE_MATCHED")

    def test_duplicate_event_is_rejected_not_double_counted(self) -> None:
        self.engine.ingest(ev("e1", 100))
        dup = self.engine.ingest(ev("e1", 999))  # 即便时间戳不同也按 id 去重
        self.assertFalse(dup.accepted)
        self.assertEqual(dup.reject_reason, RejectReason.DUPLICATE)
        self.assert_log_contains("判定 DUPLICATE")

    def test_missing_correlation_field_is_rejected_with_field_name(self) -> None:
        bad = Event("e2", 100, "hostA", "LOGIN_FAIL", attrs={})
        r = self.engine.ingest(bad)
        self.assertFalse(r.accepted)
        self.assertEqual(r.reject_reason, RejectReason.MISSING_FIELD)
        self.assertIn("attr:src_ip", r.detail)
        # 被拒绝事件不得进入去重表后的计数：修正后重新投递仍可被计数
        fixed = ev("e2", 100)
        r2 = self.engine.ingest(fixed)
        self.assertTrue(r2.accepted)
        self.assertIsNone(r2.reject_reason)

    def test_threshold_triggers_single_alert_and_evidence(self) -> None:
        r1 = self.engine.ingest(ev("a", 100))
        r2 = self.engine.ingest(ev("b", 200))
        r3 = self.engine.ingest(ev("c", 300))
        self.assertEqual(r1.alert_ids, [])
        self.assertEqual(r2.alert_ids, [])
        self.assertEqual(len(r3.alert_ids), 1)
        alert = self.alerts.get(r3.alert_ids[0])
        self.assertEqual(alert.correlated_count, 3)
        self.assertEqual(alert.triggered_ms, 300)
        self.assertEqual(alert.suppress_until_ms, 5300)
        self.assertEqual(alert.state.value, "OPEN")
        self.assert_log_contains("触发告警")
        self.assert_log_contains("达到阈值")

    def test_decision_log_records_event_input_and_basis(self) -> None:
        self.engine.ingest(ev("a", 100))
        self.assert_log_contains("event_id=a ts=100")
        self.assert_log_contains("1/3")


class OutOfOrderTest(EngineTestBase):
    def test_order_independent_trigger_result(self) -> None:
        """同一批事件正序/乱序喂入，触发结论必须一致。"""

        def run(order: tuple[int, ...], ids: tuple[str, ...]):
            reg = RuleRegistry()
            reg.upsert(brute_rule())
            mgr = AlertManager()
            eng = CorrelationEngine(reg)
            eng.bind_alerts(mgr)
            timestamps = (100, 600, 900)
            for idx in order:
                r = eng.ingest(ev(ids[idx], timestamps[idx]))
            return [
                (a.alert_id, a.anchor_ms, a.triggered_ms, sorted(a.event_ids))
                for a in mgr.list()
            ]

        ids = ("a", "b", "c")
        forward = run((0, 1, 2), ids)
        shuffled = run((2, 0, 1), ids)
        self.assertEqual(forward, shuffled)

    def test_late_event_in_grace_joins_window_and_anchor_moves_back(self) -> None:
        self.engine.ingest(ev("late1", 100))   # 先到一条早时间
        self.engine.ingest(ev("mid", 800))
        self.engine.ingest(ev("late2", 300))   # 乱序，在窗口内
        # 阈值已到（100/300/800 同在 [100,1100)），triggered_ms 取最大值 800
        alerts = self.alerts.list()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].triggered_ms, 800)
        self.assertEqual(alerts[0].anchor_ms, 100)

    def test_late_beyond_grace_is_ignored_with_distinct_reason(self) -> None:
        # grace 默认 = window_ms = 1000
        self.engine.ingest(ev("pivot", 5000))
        r = self.engine.ingest(ev("ancient", 3000))  # 3000 < 5000-1000=4000
        self.assertTrue(r.accepted)
        self.assertEqual(r.ignore_reason, IgnoreReason.LATE_BEYOND_GRACE)
        self.assertIn("4000", r.detail)
        self.assert_log_contains("LATE_BEYOND_GRACE")
        # 但它仍然被登记去重，重放不再计数
        dup = self.engine.ingest(ev("ancient", 3000))
        self.assertEqual(dup.reject_reason, RejectReason.DUPLICATE)

    def test_custom_grace_boundary_half_open(self) -> None:
        eng = CorrelationEngine(self.registry, grace_ms=1000)
        eng.bind_alerts(self.alerts)
        eng.ingest(ev("p", 5000))
        # ts == max_seen - grace = 4000：半开边界，不算迟到
        at_edge = eng.ingest(ev("edge", 4000))
        self.assertNotEqual(at_edge.ignore_reason, IgnoreReason.LATE_BEYOND_GRACE)
        # ts = 3999：迟到
        before = eng.ingest(ev("before", 3999))
        self.assertEqual(before.ignore_reason, IgnoreReason.LATE_BEYOND_GRACE)

    def test_untriggered_window_closes_then_new_window_triggers(self) -> None:
        # 阈值 3；窗口 [100,1100)
        self.engine.ingest(ev("a", 100))
        self.engine.ingest(ev("b", 200))
        # 1100 到达窗口右边界：旧窗关闭（仅2条未达阈值），开新窗
        r = self.engine.ingest(ev("c", 1100))
        dec = r.rule_decisions[0]
        self.assertEqual(dec.status, "WINDOW_RESET")
        self.assertIn("[100,1100)", dec.reason)
        self.assertEqual(self.alerts.list(), [])
        # 新窗再补两条 => 触发
        r2 = self.engine.ingest(ev("d", 1200))
        r3 = self.engine.ingest(ev("e", 1300))
        self.assertEqual(len(r3.alert_ids), 1)
        alert = self.alerts.get(r3.alert_ids[0])
        self.assertEqual(alert.anchor_ms, 1100)
        self.assertEqual(sorted(alert.event_ids), ["c", "d", "e"])


class SuppressionBoundaryTest(EngineTestBase):
    def _trigger_first(self) -> str:
        for eid, ts in (("a", 100), ("b", 200), ("c", 300)):
            r = self.engine.ingest(ev(eid, ts))
        return r.alert_ids[0]

    def test_events_inside_suppression_are_attached_not_new_alert(self) -> None:
        aid = self._trigger_first()
        s1 = self.engine.ingest(ev("s1", 400))
        s2 = self.engine.ingest(ev("s2", 5299))  # 5299 < until 5300
        self.assertEqual(s1.ignore_reason, IgnoreReason.SUPPRESSED)
        self.assertEqual(s2.ignore_reason, IgnoreReason.SUPPRESSED)
        alert = self.alerts.get(aid)
        self.assertEqual(alert.suppressed_count, 2)
        self.assertEqual(alert.correlated_count, 5)
        self.assertEqual(len(self.alerts.list()), 1)
        self.assert_log_contains("抑制区间")

    def test_suppression_released_at_right_boundary(self) -> None:
        aid = self._trigger_first()
        # until = 5300；边界事件解除抑制，开启新窗口（COUNTED 1/3）
        edge = self.engine.ingest(ev("edge", 5300))
        dec = edge.rule_decisions[0]
        self.assertEqual(dec.status, "COUNTED")
        self.assertIn("抑制解除", dec.reason)
        # 原告警仍只有第一次的 3 条证据
        self.assertEqual(self.alerts.get(aid).correlated_count, 3)
        # 新窗口继续累积后应产生序号 #2 的新告警
        self.engine.ingest(ev("f", 5400))
        r = self.engine.ingest(ev("g", 5500))
        self.assertEqual(len(r.alert_ids), 1)
        self.assertTrue(r.alert_ids[0].endswith("#2"))
        self.assertEqual(len(self.alerts.list()), 2)

    def test_zero_suppression_means_boundary_released_immediately(self) -> None:
        reg = RuleRegistry()
        reg.upsert(brute_rule(suppression_ms=0))
        mgr = AlertManager()
        eng = CorrelationEngine(reg)
        eng.bind_alerts(mgr)
        for eid, ts in (("a", 100), ("b", 200), ("c", 300)):
            eng.ingest(ev(eid, ts))
        # suppression 区间 [300,300) 为空：同刻的下一条事件即属新窗口
        r = eng.ingest(ev("d", 300))
        self.assertEqual(r.rule_decisions[0].status, "COUNTED")

    def test_distinct_correlation_values_are_independent_chains(self) -> None:
        for i, ip in enumerate(("1.1.1.1", "2.2.2.2")):
            for j in range(3):
                r = self.engine.ingest(ev(f"{ip}-{j}", 100 + j, ip=ip))
        self.assertEqual(len(self.alerts.list()), 2)


class RuleChangeTest(EngineTestBase):
    def test_rule_version_bump_starts_independent_chain(self) -> None:
        for eid, ts in (("a", 100), ("b", 200), ("c", 300)):
            self.engine.ingest(ev(eid, ts))
        self.assertEqual(len(self.alerts.list()), 1)
        # 新版本规则（阈值降到 2），事件进入新链，不受旧抑制影响
        self.registry.upsert(brute_rule(version=2, threshold=2))
        r1 = self.engine.ingest(ev("n1", 400))
        r2 = self.engine.ingest(ev("n2", 500))
        self.assertEqual(len(r2.alert_ids), 1)
        new_id = r2.alert_ids[0]
        self.assertIn("v2", new_id)
        self.assertEqual(len(self.alerts.list()), 2)
        self.assertNotEqual(new_id, self.alerts.list()[0].alert_id)

    def test_disabled_rule_matches_nothing(self) -> None:
        # 禁用属于规则变更，必须提升版本；同号改写会被注册表拒绝
        self.registry.upsert(brute_rule(version=2, enabled=False))
        r = self.engine.ingest(ev("a", 100))
        self.assertEqual(r.ignore_reason, IgnoreReason.NO_RULE_MATCHED)


class SnapshotRestartTest(EngineTestBase):
    def test_restart_dedups_and_does_not_lose_due_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = JsonSnapshotStore(str(Path(tmp) / "snap.json"))
            # 第一次运行：产生一条告警 + 一条抑制证据
            self.engine.ingest(ev("a", 100))
            self.engine.ingest(ev("b", 200))
            r = self.engine.ingest(ev("c", 300))
            aid = r.alert_ids[0]
            self.engine.ingest(ev("s1", 400))
            store.save(self.registry, self.engine, self.alerts)

            # 重启到全新组件并恢复
            reg2, mgr2 = RuleRegistry(), AlertManager()
            eng2 = CorrelationEngine(reg2)
            eng2.bind_alerts(mgr2)
            self.assertTrue(store.load(reg2, eng2, mgr2))

            # 重放已处理事件 => 全部 DUPLICATE，不产生第二条告警
            for eid, ts in (("a", 100), ("b", 200), ("c", 300), ("s1", 400)):
                dup = eng2.ingest(ev(eid, ts))
                self.assertEqual(dup.reject_reason, RejectReason.DUPLICATE)
            self.assertEqual(len(mgr2.list()), 1)
            self.assertEqual(mgr2.get(aid).suppressed_count, 1)

            # 抑制期内新事件仍被附加，边界后仍能产生第二条告警 => 不漏报
            sup = eng2.ingest(ev("s2", 500))
            self.assertEqual(sup.ignore_reason, IgnoreReason.SUPPRESSED)
            eng2.ingest(ev("x", 5300))
            eng2.ingest(ev("y", 5400))
            r2 = eng2.ingest(ev("z", 5500))
            self.assertEqual(len(r2.alert_ids), 1)
            self.assertEqual(len(mgr2.list()), 2)


if __name__ == "__main__":
    unittest.main()
