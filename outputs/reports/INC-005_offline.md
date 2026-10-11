# INC-005  (HIGH)

## Summary
Source 192.168.10.5 showed 1 detected activity burst(s) (5 flows) between 2017-07-07T16:54:00 and 2017-07-07T16:55:00, covering the tactics: Impact. Target(s): 122.225.115.212.

## Timeline
- 2017-07-07T16:54:00 to 2017-07-07T16:55:00: DDoS (5 flows, 1 target ports, avg confidence 0.94)

## ATT&CK mapping
- **T1498 Network Denial of Service** (tactic: Impact): A flood of traffic aimed at the target to exhaust bandwidth or server resources and make a service unavailable.

## Immediate actions
- Confirm service impact (is the site or system actually slow or down?).
- Contact your ISP/upstream provider to filter or rate-limit the flood.
- Apply rate limiting or a temporary block on the source at the edge firewall.

## Longer-term fixes
- Put public services behind a CDN or DDoS-protection service.
- Configure rate limits, SYN-flood protection and connection limits.
- Prepare a written DoS runbook with the ISP's contact details.

## ATT&CK mitigations
- M1037 Filter Network Traffic

## Caveats
- Detections come from an ML model on network flow data; confirm with firewall, server and authentication logs before concluding compromise.
- Source IPs may be NAT or shared addresses; attribution is not implied.