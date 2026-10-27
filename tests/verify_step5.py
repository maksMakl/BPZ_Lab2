from accesscontrol.monitor import AuditLog, Permission
from mydetector import VariantDetector

detector = VariantDetector(start_hour=8, end_hour=18, scan_threshold=3)

# Verification on Clean Audit Log
clean_log = AuditLog()
clean_log._records = [
    {
        "ts": "2026-10-27T10:00:00",
        "subject": "alice",
        "object": "doc_1",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
    {
        "ts": "2026-10-27T11:30:00",
        "subject": "alice",
        "object": "doc_5",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
    {
        "ts": "2026-10-27T14:00:00",
        "subject": "bob",
        "object": "report_1",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
]

clean_alerts = detector.scan(clean_log)
print("=== Clean Log ===")
print("Alerts found:", len(clean_alerts))
print("Alert details:", clean_alerts)

# Log with 2 Anomalies
anomalous_log = AuditLog()
anomalous_log._records = [
    # --- Anomaly A2: Access outside working window (03:15 AM) ---
    {
        "ts": "2026-10-27T03:15:00",
        "subject": "eve",
        "object": "system_1",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
    # --- Anomaly A3: Sequential object scanning (doc_1 -> doc_2 -> doc_3) ---
    {
        "ts": "2026-10-27T10:00:00",
        "subject": "frank",
        "object": "doc_1",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
    {
        "ts": "2026-10-27T10:01:00",
        "subject": "frank",
        "object": "doc_2",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
    {
        "ts": "2026-10-27T10:02:00",
        "subject": "frank",
        "object": "doc_3",
        "action": Permission.READ,
        "allowed": True,
        "reason": "надано",
    },
]

anomalous_alerts = detector.scan(anomalous_log)
print("\n=== Anomalous Log ===")
print("Alerts found:", len(anomalous_alerts))
for alert in anomalous_alerts:
    print(" -", alert)