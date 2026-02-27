import re
from collections import defaultdict

log_file = "sample_logs/auth.log"

failed_attempts = defaultdict(int)
successful_logins = []

with open(log_file, "r") as file:
    for line in file:
        # Detect failed login attempts
        if "Failed password" in line:
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                failed_attempts[ip.group(1)] += 1

        # Detect successful login
        if "Accepted password" in line:
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                successful_logins.append(ip.group(1))

print("Failed Login Attempts:")
for ip, count in failed_attempts.items():
    print(f"{ip} → {count} failed attempts")

print("\nSuccessful Logins:")
for ip in successful_logins:
    print(ip)

print("\n⚠ Suspicious IPs (more than 2 failed attempts):")
for ip, count in failed_attempts.items():
    if count > 2:
        print(ip)