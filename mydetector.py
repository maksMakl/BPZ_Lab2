import collections
from datetime import datetime
import re
from accesscontrol.monitor import AnomalyDetector, AuditLog


class VariantDetector(AnomalyDetector):
    def __init__(
        self,
        start_hour: int = 8,
        end_hour: int = 18,
        scan_threshold: int = 3,
    ) -> None:
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.scan_threshold = scan_threshold

    def scan(self, log: AuditLog) -> list[str]:
        alerts: list[str] = []
        entries = log.entries()

        # Access outside of time window
        for entry in entries:
            dt = datetime.fromisoformat(entry["ts"])
            if dt.hour < self.start_hour or dt.hour >= self.end_hour:
                alerts.append(
                    f"Доступ поза часовим вікном від {entry['subject']} "
                    f"о {dt.strftime('%H:%M:%S')} до {entry['object']}"
                )

        # Sequential ID scanning
        # Group entries by subject
        subject_entries: dict[str, list[dict]] = collections.defaultdict(list)
        for entry in entries:
            subject_entries[entry["subject"]].append(entry)

        for subject, sub_entries in subject_entries.items():
            # Sort chronologically by timestamp
            sorted_entries = sorted(sub_entries, key=lambda x: x["ts"])

            current_prefix: str | None = None
            last_num: int | None = None
            run_length = 0

            for entry in sorted_entries:
                match = re.match(r"^([a-zA-Z_]+)_(\d+)$", entry["object"])
                if not match:
                    current_prefix = None
                    last_num = None
                    run_length = 0
                    continue

                prefix, num_str = match.group(1), match.group(2)
                num = int(num_str)

                if prefix == current_prefix and last_num is not None and num == last_num + 1:
                    run_length += 1
                else:
                    current_prefix = prefix
                    run_length = 1

                last_num = num

                if run_length == self.scan_threshold:
                    alerts.append(
                        f"Послідовний перебір об'єктів від {subject} "
                        f"(серія з {self.scan_threshold} об'єктів типу '{prefix}')"
                    )

        return alerts