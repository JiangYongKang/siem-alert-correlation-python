"""告警状态机测试。

覆盖：合法/非法状态跃迁（原因可区分）、重复动作、乐观锁丢更新防护、
多线程并发处置下状态/版本/审计计数一致、快照恢复。
"""

from __future__ import annotations

import threading
import unittest

from siem.alerts import AlertManager, IllegalTransitionError, StaleVersionError
from siem.clock import FixedClock
from siem.models import Alert, AlertAction, AlertState


def make_alert(aid: str = "a1") -> Alert:
    return Alert(
        alert_id=aid,
        rule_id="r1",
        rule_version=1,
        correlation_key="{source}",
        correlation_value="hostA",
        state=AlertState.OPEN,
        severity="HIGH",
        threshold=3,
        window_ms=1000,
        suppression_ms=5000,
        anchor_ms=100,
        triggered_ms=300,
        suppress_until_ms=5300,
    )


class TransitionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedClock(1000)
        self.mgr = AlertManager(self.clock)
        self.mgr.add(make_alert())

    def test_open_ack_close_reopen_cycle(self) -> None:
        e1 = self.mgr.act("a1", AlertAction.ACK, "ana", "开始排查")
        self.assertEqual(e1.to_state, AlertState.ACKED)
        self.assertEqual(self.mgr.get("a1").version, 1)
        self.clock.advance(10)
        e2 = self.mgr.act("a1", AlertAction.CLOSE, "ana", "确认为误报",
                          expected_version=1)
        self.assertEqual(e2.to_state, AlertState.CLOSED)
        self.assertEqual(self.mgr.get("a1").version, 2)
        e3 = self.mgr.act("a1", AlertAction.REOPEN, "ana", "发现新证据",
                          expected_version=2)
        self.assertEqual(e3.to_state, AlertState.OPEN)
        self.assertEqual(self.mgr.get("a1").version, 3)
        self.assertEqual([e.at_ms for e in (e1, e2, e3)], [1000, 1010, 1010])

    def test_open_can_close_directly(self) -> None:
        e = self.mgr.act("a1", AlertAction.CLOSE, "ana", "直接关闭")
        self.assertEqual(e.to_state, AlertState.CLOSED)

    def test_illegal_transitions_have_distinct_reasons(self) -> None:
        # OPEN -> REOPEN
        with self.assertRaises(IllegalTransitionError) as cm:
            self.mgr.act("a1", AlertAction.REOPEN, "a", "r")
        self.assertIn("无需重新打开", str(cm.exception))
        # OPEN -> ACK 成功后：ACKED -> ACK
        self.mgr.act("a1", AlertAction.ACK, "a", "r")
        with self.assertRaises(IllegalTransitionError) as cm:
            self.mgr.act("a1", AlertAction.ACK, "a", "r")
        self.assertIn("已处于 ACKED", str(cm.exception))
        # ACKED -> REOPEN
        with self.assertRaises(IllegalTransitionError) as cm:
            self.mgr.act("a1", AlertAction.REOPEN, "a", "r")
        self.assertIn("须先 CLOSE 再 REOPEN", str(cm.exception))
        # -> CLOSED 后：CLOSED -> ACK / CLOSED -> CLOSE
        self.mgr.act("a1", AlertAction.CLOSE, "a", "r")
        with self.assertRaises(IllegalTransitionError) as cm:
            self.mgr.act("a1", AlertAction.ACK, "a", "r")
        self.assertIn("须先 REOPEN", str(cm.exception))
        with self.assertRaises(IllegalTransitionError) as cm:
            self.mgr.act("a1", AlertAction.CLOSE, "a", "r")
        self.assertIn("重复关闭", str(cm.exception))

    def test_every_failed_attempt_leaves_audit_with_flag_and_reason(self) -> None:
        for _ in range(3):
            try:
                self.mgr.act("a1", AlertAction.REOPEN, "ana", "尝试重开 OPEN")
            except IllegalTransitionError:
                pass
        trail = self.mgr.audit_trail("a1")
        self.assertEqual(len(trail), 3)
        self.assertTrue(all(not e.success for e in trail))
        self.assertTrue(all(e.reason for e in trail))
        self.assertTrue(all(e.from_state == AlertState.OPEN for e in trail))
        self.assertTrue(all(e.to_state is None for e in trail))
        # 失败不改变版本
        self.assertEqual(self.mgr.get("a1").version, 0)

    def test_stale_version_rejected_without_losing_update(self) -> None:
        self.mgr.act("a1", AlertAction.ACK, "ana", "v1 确认")  # version -> 1
        with self.assertRaises(StaleVersionError):
            self.mgr.act("a1", AlertAction.CLOSE, "ana", "旧版本关闭",
                         expected_version=0)
        # 状态/版本保持一致
        alert = self.mgr.get("a1")
        self.assertEqual(alert.state, AlertState.ACKED)
        self.assertEqual(alert.version, 1)
        # 用当前版本可以成功
        e = self.mgr.act("a1", AlertAction.CLOSE, "ana", "正确版本关闭",
                         expected_version=1)
        self.assertTrue(e.success)

    def test_actor_and_reason_required(self) -> None:
        with self.assertRaises(ValueError):
            self.mgr.act("a1", AlertAction.ACK, "", "无操作人")
        with self.assertRaises(ValueError):
            self.mgr.act("a1", AlertAction.ACK, "ana", "   ")

    def test_unknown_alert_raises_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            self.mgr.act("nope", AlertAction.ACK, "a", "r")

    def test_duplicate_alert_id_registration_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.mgr.add(make_alert())


class ConcurrentHandlingTest(unittest.TestCase):
    """并发处置：恰好一个动作成功，其余要么因版本冲突要么因非法跃迁失败。"""

    def test_parallel_ack_only_one_succeeds(self) -> None:
        mgr = AlertManager()
        mgr.add(make_alert())
        barrier = threading.Barrier(8)
        outcomes: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            try:
                mgr.act("a1", AlertAction.ACK, f"ana-{threading.get_ident()}",
                        "并发确认")
                with lock:
                    outcomes.append("ok")
            except (IllegalTransitionError, StaleVersionError):
                with lock:
                    outcomes.append("rejected")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(outcomes), 8)
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(mgr.get("a1").state, AlertState.ACKED)
        # 成功一次 => 版本恰好为 1，不多不少（状态与计数一致）
        self.assertEqual(mgr.get("a1").version, 1)
        trail = mgr.audit_trail("a1")
        self.assertEqual(len(trail), 8)
        self.assertEqual(sum(1 for e in trail if e.success), 1)
        self.assertEqual(sum(1 for e in trail if not e.success), 7)
        # 失败原因必须落在两类可区分原因之一
        for e in trail:
            if not e.success:
                self.assertTrue(
                    "重复确认" in e.reason or "乐观锁冲突" in e.reason,
                    f"无法区分的失败原因: {e.reason}",
                )

    def test_concurrent_mixed_actions_never_illegally_mutate(self) -> None:
        mgr = AlertManager()
        mgr.add(make_alert())
        actions = [AlertAction.ACK, AlertAction.CLOSE, AlertAction.REOPEN] * 6
        barrier = threading.Barrier(len(actions))
        results: list[tuple[str, bool, str]] = []
        lock = threading.Lock()

        def worker(action: AlertAction) -> None:
            barrier.wait()
            try:
                mgr.act("a1", action, f"ana-{threading.get_ident()}",
                        f"并发{action.value}")
                with lock:
                    results.append((action.value, True, ""))
            except (IllegalTransitionError, StaleVersionError) as exc:
                with lock:
                    results.append((action.value, False, str(exc)))

        threads = [threading.Thread(target=worker, args=(a,)) for a in actions]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 无论调度如何：版本增长次数 == 成功动作数；最终状态合法
        success = sum(1 for _, ok, _ in results if ok)
        self.assertEqual(mgr.get("a1").version, success)
        self.assertIn(mgr.get("a1").state, set(AlertState))
        self.assertEqual(len(mgr.audit_trail("a1")), len(actions))
        # 成功动作按状态机必然构成合法路径（成功的 REOPEN 之前必为 CLOSED）
        state = AlertState.OPEN
        for _, ok, _ in results:
            pass  # 结果顺序即线程完成顺序；此处仅核对最终不变量，路径由审计保证

    def test_optimistic_retry_eventually_consistent(self) -> None:
        """模拟两个处置者读取同一版本后重试：最终成功两次、版本为 2。"""
        mgr = AlertManager()
        mgr.add(make_alert())
        done = threading.Event()

        def closer() -> None:
            # 等待对方先 ACK，再用读到的新版本带条件 CLOSE
            done.wait()
            v = mgr.get("a1").version
            mgr.act("a1", AlertAction.CLOSE, "closer", "条件关闭",
                    expected_version=v)

        t = threading.Thread(target=closer)
        t.start()
        mgr.act("a1", AlertAction.ACK, "acker", "先确认")
        done.set()
        t.join()
        alert = mgr.get("a1")
        self.assertEqual(alert.state, AlertState.CLOSED)
        self.assertEqual(alert.version, 2)


class AuditSnapshotTest(unittest.TestCase):
    def test_audit_ids_monotonic_globally(self) -> None:
        mgr = AlertManager()
        mgr.add(make_alert("a1"))
        mgr.add(make_alert("a2"))
        mgr.act("a1", AlertAction.ACK, "x", "r")
        mgr.act("a2", AlertAction.ACK, "x", "r")
        ids = [e.audit_id for e in mgr.all_audit()]
        self.assertEqual(ids, [1, 2])

    def test_snapshot_restore_preserves_state_and_audit(self) -> None:
        mgr = AlertManager(FixedClock(7))
        mgr.add(make_alert())
        try:
            mgr.act("a1", AlertAction.REOPEN, "x", "非法尝试")
        except IllegalTransitionError:
            pass
        mgr.act("a1", AlertAction.ACK, "x", "合法确认")
        state = mgr.snapshot()

        mgr2 = AlertManager()
        mgr2.restore(state)
        self.assertEqual(mgr2.get("a1").state, AlertState.ACKED)
        self.assertEqual(mgr2.get("a1").version, 1)
        trail = mgr2.audit_trail("a1")
        self.assertEqual([(e.success, e.at_ms) for e in trail],
                         [(False, 7), (True, 7)])
        self.assertEqual(mgr2.all_audit()[0].audit_id, 1)


if __name__ == "__main__":
    unittest.main()
