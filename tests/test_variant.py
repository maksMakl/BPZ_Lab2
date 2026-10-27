import pytest
from accesscontrol.monitor import Permission, ReferenceMonitor, AuditLog
from mypolicy import create_populated_policy
from mydetector import VariantDetector


@pytest.fixture
def populated_policy():
    """Fixture to provide a pre-populated VariantPolicy (7 subjects, 20 objects)."""
    policy, subjects, objects = create_populated_policy()
    return policy


def test_hierarchy(populated_policy):
    # Alice is manager -> editor -> viewer (depth 2 hierarchy)
    # Inherits READ on doc_1 from viewer
    decision = populated_policy.evaluate("alice", "doc_1", Permission.READ)
    assert decision.allowed is True

    # Inherits WRITE on doc_1 from editor
    decision_write = populated_policy.evaluate("alice", "doc_1", Permission.WRITE)
    assert decision_write.allowed is True

def test_multiple_roles(populated_policy):
    # Bob has multiple roles (editor + auditor)
    # WRITE on doc_1 from editor
    assert populated_policy.evaluate("bob", "doc_1", Permission.WRITE).allowed is True
    # READ on system_1 from auditor
    assert populated_policy.evaluate("bob", "system_1", Permission.READ).allowed is True

def test_safe_default_deny(populated_policy):
    # Charlie is viewer (no WRITE permissions)
    decision = populated_policy.evaluate("charlie", "doc_1", Permission.WRITE)
    assert decision.allowed is False
    assert "safe default" in decision.reason.lower()

    # Dave (auditor) has no permission on doc_1
    assert populated_policy.evaluate("dave", "doc_1", Permission.READ).allowed is False


def test_delegation_flow(populated_policy):
    # Alice (manager) delegates READ on report_1 to Charlie with depth=2
    populated_policy.delegate("alice", "charlie", "report_1", Permission.READ, requested_depth=2)
    assert populated_policy.evaluate("charlie", "report_1", Permission.READ).allowed is True

    # Charlie re-delegates READ to Frank with depth=1 (1 < 2 OK)
    populated_policy.delegate("charlie", "frank", "report_1", Permission.READ, requested_depth=1)
    assert populated_policy.evaluate("frank", "report_1", Permission.READ).allowed is True

    # Frank re-delegates to Grace with depth=0 (0 < 1 OK)
    populated_policy.delegate("frank", "grace", "report_1", Permission.READ, requested_depth=0)
    assert populated_policy.evaluate("grace", "report_1", Permission.READ).allowed is True

    # Grace attempts to re-delegate with depth=0 (Blocked: Grace has depth=0)
    with pytest.raises(Exception, match="Delegation not allowed"):
        populated_policy.delegate("grace", "dave", "report_1", Permission.READ, requested_depth=0)


def test_delegation_depth_exceeded(populated_policy):
    populated_policy.delegate("alice", "charlie", "report_1", Permission.READ, requested_depth=1)

    # Charlie attempts to re-delegate with depth=1 (Blocked: 1 >= 1)
    with pytest.raises(Exception, match="Delegation not allowed"):
        populated_policy.delegate("charlie", "frank", "report_1", Permission.READ, requested_depth=1)


def test_reference_monitor(populated_policy):
    mon = ReferenceMonitor(populated_policy)

    decision = mon.check("alice", "doc_1", Permission.READ)
    assert decision.allowed is True

    mon.enforce("alice", "doc_1", Permission.READ)

    with pytest.raises(PermissionError):
        mon.enforce("charlie", "doc_1", Permission.DELETE)

    entries = mon.audit.entries()
    assert len(entries) == 3


def test_detector_clean_log():
    detector = VariantDetector(start_hour=8, end_hour=18, scan_threshold=3)
    clean_log = AuditLog()
    clean_log._records = [
        {"ts": "2026-10-27T10:00:00", "subject": "alice", "object": "doc_1", "action": Permission.READ, "allowed": True,
         "reason": "надано"},
        {"ts": "2026-10-27T11:00:00", "subject": "alice", "object": "doc_5", "action": Permission.READ, "allowed": True,
         "reason": "надано"},
    ]
    assert len(detector.scan(clean_log)) == 0


def test_variant_detector_anomalies():
    detector = VariantDetector(start_hour=8, end_hour=18, scan_threshold=3)
    anomaly_log = AuditLog()
    anomaly_log._records = [
        # Off-hours access (02:00)
        {"ts": "2026-10-27T02:00:00", "subject": "eve", "object": "system_1", "action": Permission.READ,
         "allowed": True, "reason": "надано"},
        # Sequential scan doc_1 -> doc_2 -> doc_3
        {"ts": "2026-10-27T10:00:00", "subject": "frank", "object": "doc_1", "action": Permission.READ, "allowed": True,
         "reason": "надано"},
        {"ts": "2026-10-27T10:01:00", "subject": "frank", "object": "doc_2", "action": Permission.READ, "allowed": True,
         "reason": "надано"},
        {"ts": "2026-10-27T10:02:00", "subject": "frank", "object": "doc_3", "action": Permission.READ, "allowed": True,
         "reason": "надано"},
    ]

    alerts = detector.scan(anomaly_log)
    assert len(alerts) == 2
    assert any("Доступ поза часовим вікном" in a for a in alerts)
    assert any("Послідовний перебір об'єктів" in a for a in alerts)