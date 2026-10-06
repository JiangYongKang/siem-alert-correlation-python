"""处理结论分类、状态保存/恢复、前置校验并发处置的测试。

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
    ConflictError,
    DetectionRule,
    LogEvent,
    ProcessOutcome,
    SiemPipeline,
    SnapshotStore,
    StateCorruptionError,
)
from siem.disposition import DispositionError

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("siem-lifecycle-test")

RULE = DetectionRule(
    "brute-force", "login_failed", "high",
    required_attributes=("user",), correlation_keys=("source", "user"),
)


def ev(eid, ts, source="h1", user="root", etype="login_failed"):
    attrs = (("user", user),) if user is not None else ()
    return LogEvent(eid, ts, etype, source, attrs)


def explain(res):
    hits = ", ".join(
        f"{h.rule_id}@v{h.rule_version}->{h.alert_id}({'新建' if h.created else '抑制'})"
        for h in res.hits
    )
    return f"{res.outcome.value} [{hits}] {res.detail}"


class ProcessOutcomeTest(unittest.TestCase):
    def test_outcome_classification(self):
        pipe = SiemPipeline([RULE], suppression_window=100, max_lateness=50)
        cases = [
            (ev("e1", 1000.0), ProcessOutcome.ALERT_CREATED),
            (ev("e2", 1050.0), ProcessOutcome.ALERT_SUPPRESSED),   # 窗口 [1000,1100) 内
            (ev("e1", 1000.0), ProcessOutcome.SKIPPED_DUPLICATE),  # 重复投递
            (ev("e3", 900.0), ProcessOutcome.REJECTED_INVALID),    # 超过乱序容忍
            (ev("", 1000.0), ProcessOutcome.REJECTED_INVALID),     # 缺字段
            (ev("e4", float("nan")), ProcessOutcome.REJECTED_INVALID),  # 非法时间戳
            (ev("e5", 1060.0, user=None), ProcessOutcome.ACCEPTED_NO_MATCH),  # 不命中规则
            (ev("e6", 1100.0), ProcessOutcome.ALERT_CREATED),      # 窗口边界，解除抑制
        ]
        for event, expect in cases:
            res = pipe.process_event(event)
            log.info("事件 %s(ts=%s) -> %s", event.event_id or "<missing>",
                     event.timestamp, explain(res))
            self.assertEqual(res.outcome, expect)

    def test_hit_records_rule_and_version(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        res = pipe.process_event(ev("e1", 1000.0))
        self.assertEqual(len(res.hits), 1)
        hit = res.hits[0]
        log.info("命中: 规则=%s 版本=%d 告警=%s 新建=%s",
                 hit.rule_id, hit.rule_version, hit.alert_id, hit.created)
        self.assertEqual((hit.rule_id, hit.rule_version), ("brute-force", 1))
        self.assertTrue(hit.created)

    def test_classification_is_order_independent(self):
        # 同一输入流重放：逐事件分类完全一致（确定性）
        events = [ev("e1", 1000.0), ev("e2", 1050.0), ev("e3", 1200.0)]

        def run(seq):
            pipe = SiemPipeline([RULE], suppression_window=100)
            return [pipe.process_event(e).outcome for e in seq]

        first, second = run(events), run(events)
        log.info("首次: %s; 重放: %s",
                 [o.value for o in first], [o.value for o in second])
        self.assertEqual(first, second)
        self.assertEqual(
            first,
            [ProcessOutcome.ALERT_CREATED, ProcessOutcome.ALERT_SUPPRESSED,
             ProcessOutcome.ALERT_CREATED],
        )
        # 窗口判定按事件时间而非到达时间：e2 虽在 e3 之后到达，
        # 但其事件时间落在 alert-0001 的窗口 [1000,1100) 内，被该窗口抑制
        pipe = SiemPipeline([RULE], suppression_window=100, max_lateness=300)
        pipe.process_event(ev("e1", 1000.0))
        pipe.process_event(ev("e3", 1200.0))
        res = pipe.process_event(ev("e2", 1050.0))
        log.info("乱序事件 e2(ts=1050) -> %s", explain(res))
        self.assertEqual(res.outcome, ProcessOutcome.ALERT_SUPPRESSED)
        self.assertEqual(res.hits[0].alert_id, "alert-0001")
        alerts = {a.alert_id: a for a in pipe.correlator.alerts()}
        self.assertEqual(alerts["alert-0001"].event_ids, ["e1", "e2"])
        self.assertEqual(alerts["alert-0002"].event_ids, ["e3"])


class PersistenceTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "state.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_restart_inside_suppression_window(self):
        # 窗口 [1000, 1100) 内重启：恢复后窗口内事件仍被抑制，不新建告警
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_event(ev("e1", 1000.0))
        pipe.disposition.acknowledge("alert-0001", "op", 1001.0)
        pipe.save(self.path)
        log.info("已保存状态: %s", self.path)

        restored = SiemPipeline.load(self.path, [RULE], suppression_window=100)
        res = restored.process_event(ev("e2", 1050.0))
        log.info("恢复后窗口内事件 e2 -> %s", explain(res))
        self.assertEqual(res.outcome, ProcessOutcome.ALERT_SUPPRESSED)
        self.assertEqual(res.hits[0].alert_id, "alert-0001")

        alerts = restored.correlator.alerts()
        self.assertEqual(len(alerts), 1)  # 没有因恢复冒出重复告警
        self.assertEqual(alerts[0].event_ids, ["e1", "e2"])  # 证据保留
        self.assertEqual(alerts[0].created_at, 1000.0)  # 窗口起点保留
        self.assertEqual(alerts[0].status, AlertStatus.ACKNOWLEDGED)  # 处置状态保留
        # 窗口外事件仍正常产生新告警，不因恢复漏告警
        res = restored.process_event(ev("e3", 1100.0))
        self.assertEqual(res.outcome, ProcessOutcome.ALERT_CREATED)
        self.assertEqual(res.hits[0].alert_id, "alert-0002")  # 序号接续

    def test_duplicate_replay_after_restore(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_event(ev("e1", 1000.0))
        pipe.process_event(ev("e2", 1050.0))
        pipe.save(self.path)

        restored = SiemPipeline.load(self.path, [RULE], suppression_window=100)
        for e in (ev("e1", 1000.0), ev("e2", 1050.0)):
            res = restored.process_event(e)
            log.info("恢复后重放 %s -> %s", e.event_id, explain(res))
            self.assertEqual(res.outcome, ProcessOutcome.SKIPPED_DUPLICATE)
        alerts = restored.correlator.alerts()
        self.assertEqual(len(alerts), 1)  # 不重复计数、不重复告警
        self.assertEqual(alerts[0].event_ids, ["e1", "e2"])
        self.assertEqual(alerts[0].suppressed_count, 1)
        self.assertEqual(restored.counters()["correlated_events"], 2)

    def test_audit_and_counters_survive_restart(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_event(ev("e1", 1000.0))
        pipe.disposition.acknowledge("alert-0001", "op", 1001.0)
        with self.assertRaises(DispositionError):
            pipe.disposition.acknowledge("alert-0001", "op2", 1002.0)
        pipe.save(self.path)

        restored = SiemPipeline.load(self.path, [RULE], suppression_window=100)
        trail = restored.disposition.audit_trail("alert-0001")
        for r in trail:
            log.info("恢复后审计: %s %s %s->%s (%s)", r.actor, r.action.value,
                     r.from_status.value, r.to_status.value, r.detail)
        self.assertEqual(len(trail), 2)  # 1 成功 + 1 拒绝均保留
        self.assertEqual(
            restored.counters(),
            {"correlated_events": 1, "successful_transitions": 1,
             "attempted_transitions": 2},
        )

    def test_truncated_state_falls_back_to_backup(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_event(ev("e1", 1000.0))
        pipe.save(self.path)          # 第一份完整状态（进入备份）
        pipe.process_event(ev("e2", 1050.0))
        pipe.save(self.path)          # 第二份完整状态
        # 模拟写一半崩溃：正式文件被截断
        with open(self.path, "rb") as fh:
            data = fh.read()
        with open(self.path, "wb") as fh:
            fh.write(data[: len(data) // 2])

        restored = SiemPipeline.load(self.path, [RULE], suppression_window=100)
        ids = [a.alert_id for a in restored.correlator.alerts()]
        log.info("正式文件截断，回退备份，告警: %s", ids)
        self.assertEqual(ids, ["alert-0001"])  # 回到上一份完整状态
        res = restored.process_event(ev("e1", 1000.0))
        self.assertEqual(res.outcome, ProcessOutcome.SKIPPED_DUPLICATE)

    def test_fully_corrupted_state_raises(self):
        pipe = SiemPipeline([RULE], suppression_window=100)
        pipe.process_event(ev("e1", 1000.0))
        pipe.save(self.path)
        for p in (self.path, self.path + ".bak"):
            with open(p, "wb") as fh:
                fh.write(b"garbage-not-json")
        with self.assertRaises(StateCorruptionError):
            SiemPipeline.load(self.path, [RULE], suppression_window=100)
        log.info("正式与备份均损坏，明确报错 StateCorruptionError")

    def test_tampered_checksum_rejected(self):
        store = SnapshotStore(self.path)
        store.save({"ingester": {}, "n": 1})
        with open(self.path, "rb") as fh:
            raw = fh.read()
        # 篡改内容但保持合法 JSON：直接改 checksum 字段无效，改 payload 则校验和不符
        tampered = raw.replace(b'"n": 1', b'"n": 2')
        with open(self.path, "wb") as fh:
            fh.write(tampered)
        with self.assertRaises(StateCorruptionError):
            store.load()


class GuardedDispositionTest(unittest.TestCase):
    def test_expected_version_guard(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        svc.acknowledge("a1", "alice", 1.0)  # version 0 -> 1
        # 修订对得上：允许流转
        rec = svc.transition("a1", AuditAction.CLOSE, "bob", 2.0, expected_version=1)
        self.assertEqual(rec.to_status, AlertStatus.CLOSED)
        # 修订对不上：可区分的冲突，不是非法跃迁
        with self.assertRaises(ConflictError):
            svc.transition("a1", AuditAction.REOPEN, "carol", 3.0, expected_version=1)
        # 冲突与非法跃迁是不同异常
        with self.assertRaises(DispositionError):
            svc.transition("a1", AuditAction.ACKNOWLEDGE, "dave", 4.0)
        trail = svc.audit_trail("a1")
        for r in trail:
            log.info("审计: %s %s (%s)", r.actor, r.action.value, r.detail)
        self.assertTrue(trail[2].detail.startswith("conflict:"))
        self.assertTrue(trail[3].detail.startswith("rejected:"))
        self.assertEqual(svc.transition_counts(), {"attempted": 4, "succeeded": 2})

    def test_concurrent_guarded_disposition(self):
        svc = AlertDispositionService()
        svc.register(Alert("a1", "r1", 1, "high", ("k",)))
        results = {"ok": [], "conflict": [], "rejected": []}
        lock = threading.Lock()

        def work(i):
            try:
                # 所有线程都基于它们看到的修订 0 发起确认
                svc.transition("a1", AuditAction.ACKNOWLEDGE, f"user-{i}", 10.0,
                               expected_version=0)
                with lock:
                    results["ok"].append(i)
            except ConflictError:
                with lock:
                    results["conflict"].append(i)
            except DispositionError:
                with lock:
                    results["rejected"].append(i)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        log.info("并发前置校验处置: 成功=%d 冲突=%d 非法=%d",
                 len(results["ok"]), len(results["conflict"]), len(results["rejected"]))
        # 恰好一个成功，其余全部因修订冲突被拒（前置校验先于状态机检查）
        self.assertEqual(len(results["ok"]), 1)
        self.assertEqual(len(results["conflict"]), 49)
        self.assertEqual(len(results["rejected"]), 0)
        alert = svc.get("a1")
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(alert.version, 1)  # 无丢失更新
        # 状态与计数对得上：50 次尝试、1 次成功、50 条审计
        self.assertEqual(svc.transition_counts(), {"attempted": 50, "succeeded": 1})
        self.assertEqual(len(svc.audit_trail("a1")), 50)
        self.assertEqual(svc.status_counts(),
                         {"open": 0, "acknowledged": 1, "closed": 0})


if __name__ == "__main__":
    unittest.main()
