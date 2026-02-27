import re
import csv
from collections import defaultdict

log_file = "sample_logs/auth.log"
output_file = "alerts.csv"

failed_attempts = defaultdict(int)
successful_logins = defaultdict(int)

# -------------------------
# Parse Log File
# -------------------------
with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                failed_attempts[ip_match.group(1)] += 1

        if "Accepted password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                successful_logins[ip_match.group(1)] += 1

# -------------------------
# Analyze & Classify Risk
# -------------------------
alerts = []

print("\n========== SOC ALERT REPORT ==========\n")

for ip in set(list(failed_attempts.keys()) + list(successful_logins.keys())):

    fails = failed_attempts[ip]
    success = successful_logins[ip]

    risk = "LOW"

    if fails >= 3 and success >= 1:
        risk = "CRITICAL"
    elif fails >= 3:
        risk = "HIGH"
    elif fails == 2:
        risk = "MEDIUM"

    print(f"IP Address: {ip}")
    print(f"Failed Attempts: {fails}")
    print(f"Successful Logins: {success}")
    print(f"Risk Level: {risk}")

    if risk in ["HIGH", "CRITICAL"]:
        print("🚨 ALERT: Potential brute-force attack detected!")

        alerts.append({
            "IP Address": ip,
            "Failed Attempts": fails,
            "Successful Logins": success,
            "Risk Level": risk
        })

    print("-------------------------------------")

# -------------------------
# Export Alerts to CSV
# -------------------------
if alerts:
    with open(output_file, mode="w", newline="") as csv_file:
        fieldnames = ["IP Address", "Failed Attempts", "Successful Logins", "Risk Level"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert)

    print(f"\n📁 Alerts exported to {output_file}")
else:
    print("\nNo high-risk alerts detected.")