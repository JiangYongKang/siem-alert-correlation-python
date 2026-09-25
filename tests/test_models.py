"""领域模型测试：事件取值、规则匹配、关联键模板、状态跃迁表。"""

import unittest

from siem.models import (
    ALLOWED_TRANSITIONS,
    NEXT_STATE,
    AlertAction,
    AlertState,
    Event,
    Rule,
)


def make_rule(**overrides) -> Rule:
    base = dict(
        rule_id="r1",
        version=1,
        match_type="event_type",
        match_value="LOGIN_FAIL",
        severity="HIGH",
        correlation_key="{source}|{attr:src_ip}",
        threshold=3,
        window_ms=1000,
        suppression_ms=5000,
    )
    base.update(overrides)
    return Rule(**base)


class EventModelTest(unittest.TestCase):
    def test_event_get_builtin_then_attrs(self) -> None:
        e = Event("e1", 100, "hostA", "LOGIN_FAIL", {"src_ip": "1.1.1.1"})
        self.assertEqual(e.get("event_id"), "e1")
        self.assertEqual(e.get("source"), "hostA")
        self.assertEqual(e.get("src_ip"), "1.1.1.1")
        self.assertIsNone(e.get("missing"))
        self.assertEqual(e.get("missing", "def"), "def")

    def test_rule_match_event_type(self) -> None:
        r = make_rule()
        hit = Event("e", 1, "h", "LOGIN_FAIL", {"src_ip": "1.1.1.1"})
        miss = Event("e", 1, "h", "LOGIN_OK", {"src_ip": "1.1.1.1"})
        self.assertTrue(r.matches(hit))
        self.assertFalse(r.matches(miss))

    def test_rule_match_source(self) -> None:
        r = make_rule(match_type="source", match_value="hostA")
        self.assertTrue(r.matches(Event("e", 1, "hostA", "X")))
        self.assertFalse(r.matches(Event("e", 1, "hostB", "X")))

    def test_rule_match_attr_equality(self) -> None:
        r = make_rule(match_type="attr", match_value="action=delete")
        self.assertTrue(r.matches(Event("e", 1, "h", "X", {"action": "delete"})))
        self.assertFalse(r.matches(Event("e", 1, "h", "X", {"action": "create"})))
        self.assertFalse(r.matches(Event("e", 1, "h", "X", {})))

    def test_disabled_rule_never_matches(self) -> None:
        r = make_rule(enabled=False)
        self.assertFalse(r.matches(Event("e", 1, "h", "LOGIN_FAIL", {"src_ip": "x"})))

    def test_correlation_value_renders_template(self) -> None:
        r = make_rule(correlation_key="{event_type}@{attr:src_ip}")
        e = Event("e", 1, "h", "LOGIN_FAIL", {"src_ip": "1.1.1.1"})
        self.assertEqual(r.correlation_value(e), ("LOGIN_FAIL@1.1.1.1", None))

    def test_correlation_value_missing_attr_reports_field(self) -> None:
        r = make_rule()
        value, missing = r.correlation_value(Event("e", 1, "hostA", "LOGIN_FAIL"))
        self.assertIsNone(value)
        self.assertEqual(missing, "attr:src_ip")

    def test_invalid_rule_construction_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_rule(threshold=0)
        with self.assertRaises(ValueError):
            make_rule(suppression_ms=-1)
        with self.assertRaises(ValueError):
            make_rule(match_type="regex")
        with self.assertRaises(ValueError):
            make_rule(match_type="attr", match_value="no-equal-sign")
        with self.assertRaises(ValueError):
            make_rule(version=0)


class TransitionTableTest(unittest.TestCase):
    def test_transition_table_is_total_for_actions(self) -> None:
        for action in AlertAction:
            self.assertIn(action, ALLOWED_TRANSITIONS)
            self.assertIn(action, NEXT_STATE)

    def test_legal_and_illegal_matrix(self) -> None:
        # 合法
        self.assertIn(AlertState.OPEN, ALLOWED_TRANSITIONS[AlertAction.ACK])
        self.assertIn(AlertState.OPEN, ALLOWED_TRANSITIONS[AlertAction.CLOSE])
        self.assertIn(AlertState.ACKED, ALLOWED_TRANSITIONS[AlertAction.CLOSE])
        self.assertIn(AlertState.CLOSED, ALLOWED_TRANSITIONS[AlertAction.REOPEN])
        # 非法
        self.assertNotIn(AlertState.ACKED, ALLOWED_TRANSITIONS[AlertAction.ACK])
        self.assertNotIn(AlertState.CLOSED, ALLOWED_TRANSITIONS[AlertAction.ACK])
        self.assertNotIn(AlertState.CLOSED, ALLOWED_TRANSITIONS[AlertAction.CLOSE])
        self.assertNotIn(AlertState.OPEN, ALLOWED_TRANSITIONS[AlertAction.REOPEN])
        self.assertNotIn(AlertState.ACKED, ALLOWED_TRANSITIONS[AlertAction.REOPEN])


if __name__ == "__main__":
    unittest.main()
