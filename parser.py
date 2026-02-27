import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict, deque

log_file = "sample_logs/auth.log"
output_file = "alerts.csv"

# Detection thresholds
FAIL_THRESHOLD = 3
WINDOW_MINUTES = 2  # "3 failures within 2 minutes" => brute-force pattern

# Example log format:
# Jul 10 10:12:01 server sshd[1234]: Failed password ...
# We'll assume current year for parsing.
CURRENT_YEAR = datetime.now().year

failed_times = defaultdict(deque)      # ip -> deque of datetimes (failed attempts)
successful_logins = defaultdict(int)   # ip -> count

def parse_timestamp(line: str) -> datetime | None:
    """
    Parse 'Mon DD HH:MM:SS' at the start of auth.log lines.
    """
    ts_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
    if not ts_match:
        return None
    ts_str = ts_match.group(1)
    try:
        return datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def extract_ip(line: str) -> str | None:
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    return ip_match.group(1) if ip_match else None

# -------------------------
# Parse logs
# -------------------------
with open(log_file, "r") as file:
    for line in file:
        ts = parse_timestamp(line)
        ip = extract_ip(line)

        if not ts or not ip:
            continue

        if "Failed password" in line:
            failed_times[ip].append(ts)

        if "Accepted password" in line:
            successful_logins[ip] += 1

# -------------------------
# Analyze time-window failures
# -------------------------
alerts = []

print("\n========== SOC ALERT REPORT (Time-Window Detection) ==========\n")

for ip in set(list(failed_times.keys()) + list(successful_logins.keys())):
    fails_total = len(failed_times[ip])
    success = successful_logins[ip]

    # Sliding window check
    window = list(failed_times[ip])
    brute_force_detected = False
    max_fails_in_window = 0

    if window:
        # Ensure sorted (deques are in order based on file order)
        for i in range(len(window)):
            start = window[i]
            end_limit = start + timedelta(minutes=WINDOW_MINUTES)

            # Count how many timestamps fall within [start, end_limit]
            count = 0
            for t in window[i:]:
                if t <= end_limit:
                    count += 1
                else:
                    break

            max_fails_in_window = max(max_fails_in_window, count)
            if count >= FAIL_THRESHOLD:
                brute_force_detected = True

    # Risk classification
    risk = "LOW"
    if brute_force_detected and success >= 1:
        risk = "CRITICAL"
    elif brute_force_detected:
        risk = "HIGH"
    elif fails_total == 2:
        risk = "MEDIUM"

    print(f"IP Address: {ip}")
    print(f"Total Failed Attempts: {fails_total}")
    print(f"Max Failed Attempts in {WINDOW_MINUTES} min window: {max_fails_in_window}")
    print(f"Successful Logins: {success}")
    print(f"Risk Level: {risk}")

    if risk in ["HIGH", "CRITICAL"]:
        print("🚨 ALERT: Brute-force pattern detected within time window!")

        alerts.append({
            "IP Address": ip,
            "Total Failed Attempts": fails_total,
            f"Max Fails in {WINDOW_MINUTES} min": max_fails_in_window,
            "Successful Logins": success,
            "Risk Level": risk
        })

    print("-------------------------------------")

# -------------------------
# Export alerts
# -------------------------
if alerts:
    with open(output_file, mode="w", newline="") as csv_file:
        fieldnames = list(alerts[0].keys())
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\n📁 Alerts exported to {output_file}")
else:
    print("\nNo high-risk alerts detected.")