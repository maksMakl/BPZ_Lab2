from accesscontrol.monitor import Permission
from mypolicy import create_populated_policy

if __name__ == '__main__':
    policy, _, _ = create_populated_policy()

    # Before using delegation
    print("=== Before Delegation ===")
    res1 = policy.evaluate("alice", "doc_1", Permission.READ)
    print("1. Alice (manager) READ doc_1:", res1)
    res2 = policy.evaluate("bob", "system_1", Permission.READ)
    print("2. Bob (editor+auditor) READ system_1:", res2)
    res3_before = policy.evaluate("charlie", "report_1", Permission.READ)
    print("3. Charlie (viewer) READ report_1 (ДО):", res3_before)
    res4 = policy.evaluate("dave", "doc_1", Permission.WRITE)
    print("4. Dave (auditor) WRITE doc_1:", res4)

    # After using delegation
    print("\n=== After Delegation ===")
    policy.delegate("alice", "charlie", "report_1", Permission.READ, requested_depth=2)
    res1 = policy.evaluate("alice", "doc_1", Permission.READ)
    print("1. Alice (manager) READ doc_1:", res1)
    res2 = policy.evaluate("bob", "system_1", Permission.READ)
    print("2. Bob (editor+auditor) READ system_1:", res2)
    res3_before = policy.evaluate("charlie", "report_1", Permission.READ)
    print("3. Charlie (viewer) READ report_1 (ДО):", res3_before)
    res4 = policy.evaluate("dave", "doc_1", Permission.WRITE)
    print("4. Dave (auditor) WRITE doc_1:", res4)