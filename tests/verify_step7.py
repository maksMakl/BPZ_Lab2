from accesscontrol.monitor import Permission
from mypolicy import create_populated_policy

policy, subjects, objects = create_populated_policy()
policy.delegate("alice", "charlie", "report_1", Permission.READ, requested_depth=2)

print("=== objects_accessible_by ===")
charlie_read_objs = policy.objects_accessible_by("charlie", Permission.READ)
print(f"Charlie READ objects ({len(charlie_read_objs)}):", sorted(list(charlie_read_objs)))
alice_delete_objs = policy.objects_accessible_by("alice", Permission.DELETE)
print(f"Alice DELETE objects ({len(alice_delete_objs)}):", sorted(list(alice_delete_objs)))


print("\n=== subjects_with_access ===")
report1_readers = policy.subjects_with_access("report_1", Permission.READ)
print("Subjects with READ on 'report_1':", sorted(list(report1_readers)))
doc1_writers = policy.subjects_with_access("doc_1", Permission.WRITE)
print("Subjects with WRITE on 'doc_1':", sorted(list(doc1_writers)))