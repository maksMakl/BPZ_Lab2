from accesscontrol.monitor import Permission, ReferenceMonitor
from mypolicy import create_populated_policy


policy, _, _ = create_populated_policy()
mon = ReferenceMonitor(policy)

print("=== Before Delegation ===")
d1 = mon.check("alice", "doc_1", Permission.READ)
print(f"1. Alice READ doc_1: {d1.allowed} ({d1.reason})")
d2 = mon.check("bob", "system_1", Permission.READ)
print(f"2. Bob READ system_1: {d2.allowed} ({d2.reason})")
d3_before = mon.check("charlie", "report_1", Permission.READ)
print(f"3. Charlie READ report_1 (ДО): {d3_before.allowed} ({d3_before.reason})")
d4 = mon.check("dave", "doc_1", Permission.WRITE)
print(f"4. Dave WRITE doc_1: {d4.allowed} ({d4.reason})")

print("\n=== After Delegation ===")
policy.delegate("alice", "charlie", "report_1", Permission.READ, requested_depth=2)
d3_after = mon.check("charlie", "report_1", Permission.READ)
print(f"3. Charlie READ report_1 (ПІСЛЯ): {d3_after.allowed} ({d3_after.reason})")

print("\n=== Using mon.enforce ===")
try:
    mon.enforce("charlie", "report_1", Permission.READ)
    print("Enforce PASS: Charlie READ report_1")
except PermissionError as e:
    print("Enforce FAIL:", e)

try:
    mon.enforce("dave", "doc_1", Permission.WRITE)
    print("Enforce PASS: Dave WRITE doc_1")
except PermissionError as e:
    print("Enforce FAIL (successfully cathced PermissionError):", e)

print("\n=== Verify AuditLog ===")
entries = mon.audit.entries()
print(f"Total monitor calls: 7 (5 check + 2 enforce)")
print(f"Total AuditLog entries: {len(entries)}")
print(mon.audit.dump())