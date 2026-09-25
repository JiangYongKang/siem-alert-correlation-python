"""端到端 HTTP 测试（FastAPI TestClient，httpx 随 fastapi[standard] 提供）。

覆盖：规则下发、乱序/重复事件在 HTTP 入口的一致结论、抑制边界、
告警查询、并发处置（多线程打同一接口）、审计可追溯、重启恢复后
重放不重复、服务层与 HTTP 入口结论一致。
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from siem.api import create_app
from siem.clock import FixedClock
from siem.service import SiemService
from siem.storage import JsonSnapshotStore

RULE = {
    "rule_id": "brute",
    "version": 1,
    "match_type": "event_type",
    "match_value": "LOGIN_FAIL",
    "severity": "HIGH",
    "correlation_key": "{source}|{attr:src_ip}",
    "threshold": 3,
    "window_ms": 1000,
    "suppression_ms": 5000,
}


def event(eid: str, ts: int, ip: str = "1.1.1.1") -> dict:
    return {
        "event_id": eid,
        "timestamp_ms": ts,
        "source": "hostA",
        "event_type": "LOGIN_FAIL",
        "attrs": {"src_ip": ip},
    }


class ApiEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FixedClock(0)
        self.svc = SiemService(clock=self.clock)
        self.client = TestClient(create_app(self.svc))
        self.assertEqual(self.client.put("/rules", json=RULE).status_code, 200)

    def _post(self, payload: dict) -> dict:
        resp = self.client.post("/events", json=payload)
        self.assertEqual(resp.status_code, 200)
        return resp.json()["data"]

    def test_health_and_root(self) -> None:
        self.assertTrue(self.client.get("/health").json()["ok"])
        self.assertEqual(self.client.get("/rules").json()["data"][0]["rule_id"],
                         "brute")

    def test_duplicate_and_malformed_have_distinct_reasons(self) -> None:
        self._post(event("e1", 100))
        dup = self._post(event("e1", 100))
        self.assertFalse(dup["accepted"])
        self.assertEqual(dup["reject_reason"], "DUPLICATE")

        missing = self.client.post("/events", json={"event_id": "x"}).json()["data"]
        self.assertEqual(missing["reject_reason"], "MISSING_FIELD")

        bad_ts = self.client.post(
            "/events",
            json={**event("x2", 1), "timestamp_ms": -5},
        ).json()["data"]
        self.assertEqual(bad_ts["reject_reason"], "BAD_TIMESTAMP")

    def test_trigger_suppress_boundary_and_retrigger_over_http(self) -> None:
        # 乱序到达：先 300 再 100/200，阈值结论仍一致
        r3 = self._post(event("c", 300))
        self.assertEqual(r3["alert_ids"], [])
        r1 = self._post(event("a", 100))
        r2 = self._post(event("b", 200))
        self.assertEqual(len(r2["alert_ids"]), 1)
        # 判定依据在响应中可见
        self.assertIn("达到阈值", r2["rule_decisions"][0]["reason"])
        aid = r2["alert_ids"][0]

        # 抑制
        sup = self._post(event("s1", 400))
        self.assertEqual(sup["ignore_reason"], "SUPPRESSED")
        alert = self.client.get(f"/alerts/{quote(aid, safe='')}").json()["data"]
        self.assertEqual(alert["suppressed_count"], 1)

        # 抑制右边界 5300：解除并最终产生第二条告警
        self._post(event("edge", 5300))
        self._post(event("d2", 5400))
        r_last = self._post(event("d3", 5500))
        self.assertTrue(r_last["alert_ids"][0].endswith("#2"))
        self.assertEqual(len(self.client.get("/alerts").json()["data"]), 2)

    def test_illegal_transition_and_stale_version_codes(self) -> None:
        self._post(event("a", 100))
        self._post(event("b", 200))
        aid = quote(self._post(event("c", 300))["alert_ids"][0], safe="")

        # OPEN -> REOPEN 非法
        r = self.client.post(
            f"/alerts/{aid}/actions",
            json={"action": "REOPEN", "actor": "a", "reason": "x"},
        )
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["error"]["code"], "ILLEGAL_TRANSITION")

        # 乐观锁版本不符
        r = self.client.post(
            f"/alerts/{aid}/actions",
            json={"action": "ACK", "actor": "a", "reason": "x",
                  "expected_version": 42},
        )
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["error"]["code"], "STALE_VERSION")

        # 合法 ACK，随后审计里成功失败都在
        ok = self.client.post(
            f"/alerts/{aid}/actions",
            json={"action": "ACK", "actor": "ana", "reason": "开始排查"},
        )
        self.assertEqual(ok.json()["data"]["to_state"], "ACKED")
        audit = self.client.get(f"/alerts/{aid}/audit").json()["data"]
        self.assertEqual([(e["action"], e["success"]) for e in audit],
                         [("REOPEN", False), ("ACK", False), ("ACK", True)])

    def test_rule_version_conflict_and_not_found(self) -> None:
        conflict = self.client.put("/rules", json={**RULE, "severity": "LOW"})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "RULE_VERSION")
        self.assertEqual(self.client.get("/alerts/missing").status_code, 404)

    def test_concurrent_actions_over_http_exactly_one_ack(self) -> None:
        self._post(event("a", 100))
        self._post(event("b", 200))
        aid = quote(self._post(event("c", 300))["alert_ids"][0], safe="")
        barrier = threading.Barrier(10)
        statuses: list[int] = []
        lock = threading.Lock()

        def fire() -> None:
            barrier.wait()
            resp = self.client.post(
                f"/alerts/{aid}/actions",
                json={"action": "ACK", "actor": f"t{threading.get_ident()}",
                      "reason": "并发确认"},
            )
            with lock:
                statuses.append(resp.status_code)

        threads = [threading.Thread(target=fire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(statuses), 10)
        # TestClient 调用同一进程内的真实服务（带锁）：恰好一个 200
        self.assertEqual(statuses.count(200), 1)
        self.assertEqual(statuses.count(409), 9)
        alert = self.client.get(f"/alerts/{aid}").json()["data"]
        self.assertEqual(alert["state"], "ACKED")
        self.assertEqual(alert["version"], 1)
        audit = self.client.get(f"/alerts/{aid}/audit").json()["data"]
        self.assertEqual(len(audit), 10)
        self.assertEqual(sum(1 for e in audit if e["success"]), 1)


class RestartConsistencyTest(unittest.TestCase):
    def test_replay_after_restart_is_duplicate_not_new_alert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "state.json"

            svc1 = SiemService(store=JsonSnapshotStore(snap))
            c1 = TestClient(create_app(svc1))
            c1.put("/rules", json=RULE)
            for eid, ts in (("a", 100), ("b", 200), ("c", 300)):
                c1.post("/events", json=event(eid, ts))
            before = c1.get("/alerts").json()["data"]
            self.assertEqual(len(before), 1)
            save = c1.post("/snapshot")
            self.assertEqual(save.status_code, 200)
            aid = before[0]["alert_id"]

            # 全新服务实例加载同一快照
            svc2 = SiemService(store=JsonSnapshotStore(snap))
            c2 = TestClient(create_app(svc2))
            loaded = c2.post("/snapshot/load").json()["data"]["loaded"]
            self.assertTrue(loaded)
            self.assertEqual(c2.get("/health").status_code, 200)
            for eid, ts in (("a", 100), ("b", 200), ("c", 300)):
                body = c2.post("/events", json=event(eid, ts)).json()["data"]
                self.assertEqual(body["reject_reason"], "DUPLICATE")
            after = c2.get("/alerts").json()["data"]
            self.assertEqual(len(after), 1)
            self.assertEqual(after[0]["alert_id"], aid)

    def test_snapshot_endpoint_without_store_is_400(self) -> None:
        c = TestClient(create_app(SiemService()))
        resp = c.post("/snapshot")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["code"], "PERSISTENCE_DISABLED")


if __name__ == "__main__":
    unittest.main()
