import re
import csv
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, deque


def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC Lab: SSH brute-force time-window detection with CSV + SIEM-style JSONL output"
    )
    parser.add_argument("--logfile", default="sample_logs/auth.log", help="Path to auth.log file")
    parser.add_argument("--threshold", type=int, default=3, help="Failed attempts threshold within the time window")
    parser.add_argument("--window", type=int, default=2, help="Time window in minutes")
    parser.add_argument("--output", default="alerts.csv", help="Output CSV file for high-risk alerts")
    parser.add_argument("--json", default="alerts.jsonl", help="Output JSONL file for SIEM-style alerts")
    return parser.parse_args()


def parse_timestamp(line: str, year: int):
    """
    Parse 'Mon DD HH:MM:SS' at the start of auth.log lines.
    Example: 'Jul 10 10:12:01 ...'
    """
    ts_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
    if not ts_match:
        return None

    ts_str = ts_match.group(1)
    try:
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def extract_ip(line: str):
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
    return ip_match.group(1) if ip_match else None


def main():
    args = parse_args()

    log_file = args.logfile
    FAIL_THRESHOLD = args.threshold
    WINDOW_MINUTES = args.window
    csv_output = args.output
    json_output = args.json

    CURRENT_YEAR = datetime.now().year

    failed_times = defaultdict(deque)      # ip -> deque of datetimes (failed attempts)
    successful_logins = defaultdict(int)   # ip -> count

    # -------------------------
    # Parse logs
    # -------------------------
    with open(log_file, "r") as file:
        for line in file:
            ts = parse_timestamp(line, CURRENT_YEAR)
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
    alerts_csv = []
    alerts_jsonl = []

    print("\n========== SOC ALERT REPORT (Time-Window Detection) ==========\n")
    print(f"Logfile: {log_file}")
    print(f"Threshold: {FAIL_THRESHOLD} failures within {WINDOW_MINUTES} minutes\n")

    for ip in set(list(failed_times.keys()) + list(successful_logins.keys())):
        window = list(failed_times[ip])  # convert deque -> list so we can slice
        fails_total = len(window)
        success = successful_logins[ip]

        brute_force_detected = False
        max_fails_in_window = 0

        if window:
            for i in range(len(window)):
                start = window[i]
                end_limit = start + timedelta(minutes=WINDOW_MINUTES)

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

        # Print console report
        print(f"IP Address: {ip}")
        print(f"Total Failed Attempts: {fails_total}")
        print(f"Max Failed Attempts in {WINDOW_MINUTES} min window: {max_fails_in_window}")
        print(f"Successful Logins: {success}")
        print(f"Risk Level: {risk}")

        # High-risk alerts only
        if risk in ["HIGH", "CRITICAL"]:
            print("🚨 ALERT: Brute-force pattern detected within time window!")

            # CSV alert (human friendly)
            alerts_csv.append({
                "IP Address": ip,
                "Total Failed Attempts": fails_total,
                f"Max Fails in {WINDOW_MINUTES} min": max_fails_in_window,
                "Successful Logins": success,
                "Risk Level": risk
            })

            # JSONL alert (SIEM/pipeline friendly)
            alerts_jsonl.append({
                "@timestamp": datetime.now().isoformat(),
                "event": {
                    "kind": "alert",
                    "category": ["authentication"],
                    "type": ["start"],
                    "dataset": "soc_lab.ssh"
                },
                "rule": {
                    "name": "SSH Brute Force (Time Window)",
                    "threshold": FAIL_THRESHOLD,
                    "window_minutes": WINDOW_MINUTES
                },
                "source": {
                    "ip": ip
                },
                "ssh": {
                    "failed_attempts_total": fails_total,
                    "max_failed_attempts_in_window": max_fails_in_window,
                    "successful_logins": success
                },
                "severity": risk,
                "message": "Brute-force pattern detected within time window"
            })

        print("-------------------------------------")

    # -------------------------
    # Export alerts to CSV
    # -------------------------
    if alerts_csv:
        with open(csv_output, mode="w", newline="") as csv_file:
            fieldnames = list(alerts_csv[0].keys())
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(alerts_csv)

        print(f"\n📁 Alerts exported to {csv_output}")
    else:
        print("\nNo high-risk alerts detected (CSV not generated).")

    # -------------------------
    # Export alerts to JSONL (SIEM-style)
    # -------------------------
    if alerts_jsonl:
        with open(json_output, "w") as f:
            for alert in alerts_jsonl:
                f.write(json.dumps(alert) + "\n")

        print(f"📄 Alerts exported to {json_output} (JSONL)")
    else:
        print("No high-risk alerts detected (JSONL not generated).")


if __name__ == "__main__":
    main()