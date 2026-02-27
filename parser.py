import re
from collections import defaultdict

log_file = "sample_logs/auth.log"

failed_attempts = defaultdict(int)
successful_logins = defaultdict(int)

with open(log_file, "r") as file:
    for line in file:
        # Detect failed login attempts
        if "Failed password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                failed_attempts[ip] += 1

        # Detect successful login attempts
        if "Accepted password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                successful_logins[ip] += 1


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

    print("-------------------------------------")