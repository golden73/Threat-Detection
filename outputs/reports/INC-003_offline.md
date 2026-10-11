# INC-003  (CRITICAL)

## Summary
Source 172.16.0.1 showed 3 detected activity burst(s) (86,033 flows) between 2017-07-07T13:55:00 and 2017-07-07T16:16:00, covering the tactics: Discovery -> Impact. Target(s): 192.168.10.50.
Multiple stages from one source suggest a deliberate, staged attack rather than a one-off event.

## Timeline
- 2017-07-07T13:55:00 to 2017-07-07T14:16:00: PortScan (109 flows, 5 target ports, avg confidence 1.00)
- 2017-07-07T14:51:00 to 2017-07-07T15:23:00: PortScan (47,526 flows, 999 target ports, avg confidence 1.00)
- 2017-07-07T15:56:00 to 2017-07-07T16:16:00: DDoS (38,398 flows, 1 target ports, avg confidence 1.00)

## ATT&CK mapping
- **T1046 Network Service Discovery** (tactic: Discovery): The source probed many ports/services to learn what is running on the target. This is usually reconnaissance that comes before an exploit or attack.
- **T1498 Network Denial of Service** (tactic: Impact): A flood of traffic aimed at the target to exhaust bandwidth or server resources and make a service unavailable.

## Immediate actions
- Block or rate-limit the scanning source at the firewall.
- Check which ports and services the scan touched and whether any should not be exposed.
- Confirm service impact (is the site or system actually slow or down?).
- Contact your ISP/upstream provider to filter or rate-limit the flood.
- Apply rate limiting or a temporary block on the source at the edge firewall.

## Longer-term fixes
- Close unused ports and disable unneeded services.
- Segment the network so one exposed host does not reveal everything.
- Enable port-scan detection on the firewall/IDS (e.g. Suricata, Snort).
- Put public services behind a CDN or DDoS-protection service.
- Configure rate limits, SYN-flood protection and connection limits.
- Prepare a written DoS runbook with the ISP's contact details.

## ATT&CK mitigations
- M1031 Network Intrusion Prevention; M1030 Network Segmentation; M1042 Disable or Remove Feature or Program; M1037 Filter Network Traffic

## Caveats
- Detections come from an ML model on network flow data; confirm with firewall, server and authentication logs before concluding compromise.
- Source IPs may be NAT or shared addresses; attribution is not implied.