"""长期值守能力测试：结论分类、状态保存/恢复、带前置校验的并发处置。

日志打印输入事件、命中规则与窗口判定依据，便于复核。
仅依赖标准库：python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import unittest

from siem import (
    Alert,
    AlertDispositionService,
    AlertStatus,
    AuditAction,
    DetectionRule,
    LogEvent,
    OutcomeCategory,
    RejectReason,
    SiemPipeline,
    StateCorruptionError,
    TransitionOutcome,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("siem-service-test")

RULE = DetectionRule(
    "brute-force", "login_failed", "high",
    required_attributes=("user",), correlation_keys=("source", "user"),
)


def ev(eid, ts, source="h1", user="root", etype="login_failed"):
    attrs = (("user", user),) if user is not None else ()
    return LogEvent(eid, ts, etype, source, attrs)


def explain(outcome):
    hits = ", ".join(
        f"{h.rule_id} v{h.rule_version} -> {h.alert_id} "
        f"({'新建' if h.created else '抑制'} 窗口[{h.window_start}, {h.window_end}))"
        for h in outcome.hits
    )
    return f"{outcome.category.value}: {outcome.detail}" + (f" | 命中: {hits}" if hits else "")


class OutcomeClassificationTest(unittest.TestCase):
    """处理结论分类：五类结论稳定、可区分、可解释。"""

    def test_five_categories_are_distinguishable(self):
        pipe = SiemPipeline([RULE], suppression_window=100, max_lateness=50)
        cases = [
            ("e0", ev("e0", 1000.0, user=None), OutcomeCategory.PROCESSED_NO_MATCH),
            ("e1", ev("e1", 1000.0), OutcomeCategory.ALERT_CREATED),
            ("e2", ev("e2", 1050.0), OutcomeCategory.ALERT_SUPPRESSED),
            ("e1-dup", ev("e1", 1000.0), OutcomeCategory.SKIPPED_DUPLICATE),
            ("bad-ts", ev("e3", float("nan")), OutcomeCategory.REJECTED_INVALID),
            ("missing", ev("", 1000.0), OutcomeCategory.REJECTED_INVALID),
        ]
        for name, event, expected in cases:
            outcome = pipe.process_explain(event)
            log.info("用例 %s: 输入 %s(ts=%s) -> %s",
                     name, event.event_id or "<missing>", event.timestamp, explain(outcome))
            self.assertEqual(outcome.category, expected, name)

        # 命中结论能看出规则与规则版本
        created = pipe.process_explain(ev("e9", 1200.0))  # 窗口外 -> 新告警
        self.assertEqual(created.category, OutcomeCategory.ALERT_CREATED)
        self.assertEqual(created.hits[0].rule_id, "brute-force")
        self.assertEqual(created.hits[0].rule_version, 1)
        # 拒绝原因仍可区分
        dup = pipe.process_explain(ev("e1", 1000.0))
        self.assertEqual(dup.reason, RejectReason.DUPLICATE_DELIVERY)

    def test_classification_is_reproducible(self):
        events = [ev("e1", 1000.0), ev("e2", 1050.0), ev("e3", 1200.0), ev("e1", 1000.0)]

        def run():
            pipe = SiemPipeline([RULE], suppression_window=100)
            return [pipe.process_explain(e).category for e in events]

        first, second = run(), run()
        log.info("首次分类: %s; 重放分类: %s", [c.value for c in first],
                 [c.value for c in second])
        self.assertEqual(first, second)  # 同样输入得到同样分类

    def test_window_boundary_classification_matches_existing_semantics(self):
        # 与既有窗口判定一致：1099.9 抑制，1100.0 新建（左闭右开）
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_explain(ev("e1", 1000.0))
        inside = pipe.process_explain(ev("e2", 1099.9))
        outside = pipe.process_explain(ev("e3", 1100.0))
        log.info("窗口边界: 1099.9 -> %s; 1100.0 -> %s",
                 inside.category.value, outside.category.value)
        self.assertEqual(inside.category, OutcomeCategory.ALERT_SUPPRESSED)
        self.assertEqual(outside.category, OutcomeCategory.ALERT_CREATED)


class PersistenceTest(unittest.TestCase):
    """状态保存与恢复：重启后证据、窗口、处置状态都在，重放不产生重复。"""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "state.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_restart_inside_suppression_window_and_replay(self):
        pipe = SiemPipeline([RULE], suppression_window=100, max_lateness=50)
        pipe.process_explain(ev("e1", 1000.0))
        pipe.process_explain(ev("e2", 1030.0))  # 抑制窗口内
        pipe.disposition.acknowledge("alert-0001", "op", 1040.0)
        pipe.save_state(self.path)
        log.info("已保存状态到 %s", self.path)

        # 模拟重启：新实例从文件恢复
        restored = SiemPipeline.restore(self.path, [RULE])
        alert = restored.disposition.get("alert-0001")
        log.info("恢复后告警: 事件=%s 抑制=%d 状态=%s 窗口=%s",
                 alert.event_ids, alert.suppressed_count, alert.status.value,
                 restored.correlator.window_of(alert))
        # 关联证据、处置状态保留
        self.assertEqual(alert.event_ids, ["e1", "e2"])
        self.assertEqual(alert.suppressed_count, 1)
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(restored.correlator.window_of(alert), (1000.0, 1100.0))

        # 恢复前处理过的重复事件再投递：跳过、不重复计数、不出重复告警
        dup = restored.process_explain(ev("e1", 1000.0))
        log.info("重放 e1 -> %s", explain(dup))
        self.assertEqual(dup.category, OutcomeCategory.SKIPPED_DUPLICATE)
        self.assertEqual(len(restored.correlator.alerts()), 1)
        self.assertEqual(alert.event_ids, ["e1", "e2"])
        self.assertEqual(alert.suppressed_count, 1)

        # 重启后窗口内事件仍被同一条告警收编（窗口起止恢复正确）
        inside = restored.process_explain(ev("e3", 1060.0))
        log.info("重启后窗口内事件 e3 -> %s", explain(inside))
        self.assertEqual(inside.category, OutcomeCategory.ALERT_SUPPRESSED)
        self.assertEqual(inside.hits[0].alert_id, "alert-0001")

        # 不漏告警：窗口外事件产生新告警，且告警 ID 不与历史冲突
        outside = restored.process_explain(ev("e4", 1100.0))
        log.info("窗口外事件 e4 -> %s", explain(outside))
        self.assertEqual(outside.category, OutcomeCategory.ALERT_CREATED)
        self.assertEqual(outside.hits[0].alert_id, "alert-0002")
        self.assertEqual(len(restored.correlator.alerts()), 2)

    def test_restore_then_save_roundtrip_is_stable(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        for e in [ev("e1", 1000.0), ev("e2", 1010.0), ev("e3", 1200.0)]:
            pipe.process_explain(e)
        pipe.disposition.close("alert-0001", "op", 1300.0)
        pipe.save_state(self.path)
        restored = SiemPipeline.restore(self.path, [RULE])
        path2 = os.path.join(self.dir.name, "state2.json")
        restored.save_state(path2)
        with open(self.path, encoding="utf-8") as f1, open(path2, encoding="utf-8") as f2:
            self.assertEqual(f1.read(), f2.read())  # 保存-恢复-再保存，内容一致
        # 审计记录也完整恢复
        self.assertEqual(len(restored.disposition.audit_trail("alert-0001")), 1)

    def test_corrupted_state_is_rejected_loudly(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_explain(ev("e1", 1000.0))
        pipe.save_state(self.path)

        # 截断损坏
        with open(self.path, "rb") as fh:
            data = fh.read()
        with open(self.path, "wb") as fh:
            fh.write(data[: len(data) // 2])
        with self.assertRaises(StateCorruptionError):
            SiemPipeline.restore(self.path, [RULE])
        log.info("截断文件被明确拒绝")

        # 篡改内容（校验和不符）
        pipe.save_state(self.path)
        with open(self.path, encoding="utf-8") as fh:
            text = fh.read().replace("1000.0", "9999.0", 1)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(text)
        with self.assertRaises(StateCorruptionError):
            SiemPipeline.restore(self.path, [RULE])
        log.info("篡改文件被明确拒绝")

        # 状态文件不存在
        with self.assertRaises(StateCorruptionError):
            SiemPipeline.restore(os.path.join(self.dir.name, "ghost.json"), [RULE])

    def test_failed_save_keeps_previous_complete_state(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_explain(ev("e1", 1000.0))
        pipe.save_state(self.path)
        with open(self.path, encoding="utf-8") as fh:
            good = fh.read()
        # 模拟写到一半崩溃：目标路径不可写时失败，原文件应保持完整
        with self.assertRaises(OSError):
            pipe.save_state(os.path.join(self.dir.name, "no-such-dir", "state.json"))
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), good)
        restored = SiemPipeline.restore(self.path, [RULE])
        self.assertEqual(len(restored.correlator.alerts()), 1)
        log.info("失败保存未破坏上一份完整状态")


class GuardedDispositionTest(unittest.TestCase):
    """带前置校验的处置：冲突可区分、计数口径独立、并发安全。"""

    def test_conflict_is_distinguishable_from_invalid_transition(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        ok = svc.try_transition("a1", AuditAction.ACKNOWLEDGE, "alice", 1.0,
                                expected_version=0)
        self.assertEqual(ok.outcome, TransitionOutcome.APPLIED)
        # 修订对不上 -> 冲突（此时动作本身合法）
        conflict = svc.try_transition("a1", AuditAction.CLOSE, "bob", 2.0,
                                      expected_version=0)
        self.assertEqual(conflict.outcome, TransitionOutcome.CONFLICT)
        # 修订对得上但跃迁非法 -> 非法跃迁
        invalid = svc.try_transition("a1", AuditAction.ACKNOWLEDGE, "carol", 3.0,
                                     expected_version=1)
        self.assertEqual(invalid.outcome, TransitionOutcome.INVALID_TRANSITION)
        # 告警不存在
        missing = svc.try_transition("ghost", AuditAction.CLOSE, "dave", 4.0,
                                     expected_version=0)
        self.assertEqual(missing.outcome, TransitionOutcome.NOT_FOUND)
        for r in svc.audit_trail("a1"):
            log.info("审计: %s %s (%s)", r.actor, r.action.value, r.detail)
        # 被拒绝的尝试（含冲突）同样留痕
        self.assertTrue(conflict.record.detail.startswith("conflict:"))
        self.assertTrue(invalid.record.detail.startswith("rejected:"))
        self.assertEqual(len(svc.audit_trail("a1")), 3)

    def test_counters_are_independent_and_accurate(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_explain(ev("e1", 1000.0))  # 关联 1 条
        pipe.process_explain(ev("e2", 1010.0))  # 抑制收编，再关联 1 条
        svc = pipe.disposition
        svc.try_transition("alert-0001", AuditAction.ACKNOWLEDGE, "a", 1.0,
                           expected_version=1)   # 尝试+1，成功+1
        svc.try_transition("alert-0001", AuditAction.CLOSE, "b", 2.0,
                           expected_version=0)   # 尝试+1，冲突
        svc.try_transition("alert-0001", AuditAction.ACKNOWLEDGE, "c", 3.0)  # 尝试+1，非法
        c = svc.counters("alert-0001")
        log.info("计数: 关联=%d 成功流转=%d 累计尝试=%d",
                 c.correlated_events, c.transitions_applied, c.transitions_attempted)
        self.assertEqual(c.correlated_events, 2)
        self.assertEqual(c.transitions_applied, 1)
        self.assertEqual(c.transitions_attempted, 3)

    def test_concurrent_guarded_transitions_single_winner(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        outcomes = []
        lock = threading.Lock()

        def work(i):
            result = svc.try_transition("a1", AuditAction.ACKNOWLEDGE, f"user-{i}",
                                        10.0, expected_version=0)
            with lock:
                outcomes.append(result.outcome)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        applied = outcomes.count(TransitionOutcome.APPLIED)
        conflicts = outcomes.count(TransitionOutcome.CONFLICT)
        log.info("并发前置校验处置: 成功=%d 冲突=%d", applied, conflicts)
        self.assertEqual(applied, 1)            # 恰好一个赢家，无丢失更新
        self.assertEqual(conflicts, 49)         # 其余全是可区分的冲突，非非法跃迁
        self.assertEqual(svc.get("a1").status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(svc.get("a1").version, 1)
        c = svc.counters("a1")
        # 状态与计数对得上：尝试=50，成功=1，审计=50
        self.assertEqual(c.transitions_attempted, 50)
        self.assertEqual(c.transitions_applied, 1)
        self.assertEqual(len(svc.audit_trail("a1")), 50)
        self.assertEqual(svc.status_counts(),
                         {"open": 0, "acknowledged": 1, "closed": 0})

    def test_counters_survive_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            pipe = SiemPipeline([RULE], suppression_window=100)
            pipe.process_explain(ev("e1", 1000.0))
            pipe.process_explain(ev("e2", 1010.0))
            pipe.disposition.try_transition("alert-0001", AuditAction.ACKNOWLEDGE,
                                            "op", 1.0, expected_version=1)
            pipe.save_state(path)
            restored = SiemPipeline.restore(path, [RULE])
            c = restored.disposition.counters("alert-0001")
            log.info("恢复后计数: 关联=%d 成功=%d 尝试=%d",
                     c.correlated_events, c.transitions_applied, c.transitions_attempted)
            self.assertEqual(c.correlated_events, 2)
            self.assertEqual(c.transitions_applied, 1)
            self.assertEqual(c.transitions_attempted, 1)
            # 恢复后前置校验基于正确的修订号继续工作
            stale = restored.disposition.try_transition(
                "alert-0001", AuditAction.CLOSE, "op", 2.0, expected_version=1)
            self.assertEqual(stale.outcome, TransitionOutcome.CONFLICT)
            ok = restored.disposition.try_transition(
                "alert-0001", AuditAction.CLOSE, "op", 2.0, expected_version=2)
            self.assertEqual(ok.outcome, TransitionOutcome.APPLIED)


if __name__ == "__main__":
    unittest.main()
