# Incident Report – SSH Brute Force Attempt

## Summary
Multiple failed login attempts were detected from IP 192.168.1.50 followed by a successful login to root account.

## Timeline
10:12:01 – Failed login attempt
10:12:05 – Failed login attempt
10:12:10 – Failed login attempt
10:12:15 – Successful login

## Risk Assessment
Possible brute force attack leading to account compromise.

## MITRE Mapping
T1110 – Brute Force

## Recommended Actions
- Disable password authentication
- Enable SSH key authentication
- Implement fail2ban
- Monitor for lateral movement