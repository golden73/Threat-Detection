# INC-002  (HIGH)

## Summary
Source 172.16.0.1 showed 1 detected activity burst(s) (5,879 flows) between 2017-07-04T14:09:00 and 2017-07-04T15:11:00, covering the tactics: Credential Access. Target(s): 192.168.10.50.

## Timeline
- 2017-07-04T14:09:00 to 2017-07-04T15:11:00: SSH-Patator (5,879 flows, 1 target ports, avg confidence 1.00)

## ATT&CK mapping
- **T1110.001 Brute Force: Password Guessing** (tactic: Credential Access): Many login attempts against a service (here FTP or SSH) to guess valid credentials. If one succeeds, the attacker gains access to the system.

## Immediate actions
- Block the source and check authentication logs for any SUCCESSFUL login from it.
- If a login succeeded, treat the account as compromised: reset the password, end sessions, and review what the account did.

## Longer-term fixes
- Enforce strong passwords and account lockout / fail2ban.
- Use SSH keys and multi-factor authentication; avoid plain FTP (use SFTP).
- Do not expose SSH/FTP to the internet unless necessary; restrict by IP or VPN.

## ATT&CK mitigations
- M1036 Account Use Policies; M1032 Multi-factor Authentication; M1027 Password Policies; M1018 User Account Management

## Caveats
- Detections come from an ML model on network flow data; confirm with firewall, server and authentication logs before concluding compromise.
- Source IPs may be NAT or shared addresses; attribution is not implied.