from collections import Counter
from datetime import datetime

LOG_FILE = "security_events.log"
REPORT_FILE = "automation_report.txt"

events = []

with open(LOG_FILE, "r") as file:
    for line in file:
        line = line.strip()
        if line:
            events.append(line)
failed_logins = []
role_changes = []
suspicious_access = []

for event in events:
    if "LOGIN_FAILED" in event:
        failed_logins.append(event)

    if "ROLE_CHANGED" in event:
        role_changes.append(event)

    if "SUSPICIOUS_ACCESS" in event:
        suspicious_access.append(event)
ip_counter = Counter()

for event in failed_logins:
    for part in event.split():
        if part.startswith("ip="):
            ip = part.split("=", 1)[1]
            ip_counter[ip] += 1

alerts = []

for ip, count in ip_counter.items():
    if count >= 3:
        alerts.append(
            f"[HIGH] Brute-force activity detected from {ip} ({count} failed logins)"
        )
for event in role_changes:
    alerts.append(f"[HIGH] Privilege change detected: {event}")

for event in suspicious_access:
    alerts.append(f"[MEDIUM] Suspicious access detected: {event}")
report = [
    "SECURITY AUTOMATION REPORT",
    "=" * 40,
    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "",
    f"Events analyzed: {len(events)}",
    f"Failed logins: {len(failed_logins)}",
    f"Privilege changes: {len(role_changes)}",
    f"Suspicious access events: {len(suspicious_access)}",
    f"Security alerts: {len(alerts)}",
    "",
    "ALERTS",
    "-" * 40
]

if alerts:
    report.extend(alerts)
else:
    report.append("No security alerts detected.")

with open(REPORT_FILE, "w") as file:
    file.write("\n".join(report))

print("\n".join(report))
print(f"\nReport saved to: {REPORT_FILE}")
