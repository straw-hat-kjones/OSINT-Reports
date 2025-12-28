---
title: "Scattered Spider"
created: 2025-12-28
date: 2025-12-28
category: "[[Threat Actor]]"
type: eCrime
origin: United States / United Kingdom
motivation: Financial
status: Active
first_seen: 2022-05

aliases:
  - UNC3944
  - Octo Tempest
  - Muddled Libra
  - Storm-0875
  - 0ktapus
  - Scatter Swine
  - Star Fraud
  - LUCR-3
  - Scattered Lapsus$ Hunters

affiliated_groups:
  - "[[Threat Actors/Lapsus$]]"
  - "[[Threat Actors/ShinyHunters]]"
  - "[[Threat Actors/ALPHV BlackCat]]"

tools:
  - "[[Malware/Cobalt Strike]]"
  - "[[Malware/Brute Ratel C4]]"
  - ngrok
  - Tailscale
  - AnyDesk
  - Splashtop
  - TeamViewer
  - FleetDeck

ransomware_affiliations:
  - "[[Malware/Ransomware/ALPHV BlackCat]]"
  - "[[Malware/Ransomware/DragonForce]]"
  - "[[Malware/Ransomware/RansomHub]]"

techniques:
  - T1566
  - T1566.001
  - T1566.004
  - T1078
  - T1078.002
  - T1078.004
  - T1133
  - T1219
  - T1059.001
  - T1003.003
  - T1562.001
  - T1114
  - T1136
  - T1585.001
  - T1090
  - T1656
  - T1660

targets:
  sectors:
    - Telecommunications
    - Hospitality
    - Retail
    - Gaming
    - Financial Services
    - Manufacturing
    - Automotive
  geography:
    - United States
    - United Kingdom
    - Global

tags:
  - "#threat-actor"
  - "#ransomware"
  - "#social-engineering"
  - "#sim-swapping"
  - "#help-desk-impersonation"
---

# Scattered Spider

## Overview

Scattered Spider is a financially motivated, native English-speaking cybercriminal group that has been active since at least May 2022. The group is renowned for its sophisticated social engineering capabilities, particularly help desk impersonation and SIM swapping attacks. Members are believed to be primarily young individuals (ages 19-22) based in the United States and United Kingdom.

## Key Characteristics

| Attribute | Details |
|-----------|---------|
| **First Observed** | May 2022 |
| **Type** | Cybercrime Collective |
| **Motivation** | Financial |
| **Status** | Active (despite arrests) |
| **Demographics** | Young adults (19-22), US/UK-based |
| **Language** | Native English speakers |

## Aliases

| Alias | Attributed By |
|-------|---------------|
| Scattered Spider | CrowdStrike |
| UNC3944 | Mandiant |
| Octo Tempest | Microsoft |
| Muddled Libra | Unit 42 |
| Storm-0875 | Microsoft |
| 0ktapus | Group-IB |
| Scatter Swine | Okta |
| Star Fraud | Industry |
| LUCR-3 | Industry |
| Scattered Lapsus$ Hunters | Self-attributed (2025) |

## Notable Campaigns

| Date | Victim | Impact |
|------|--------|--------|
| August 2023 | Caesars Entertainment | $15 million ransom paid |
| September 2023 | [[Campaigns/MGM Resorts Attack 2023\|MGM Resorts]] | $100+ million in losses |
| May 2025 | Marks & Spencer | £300+ million impact; weeks of disruption |
| May 2025 | Co-op | Operational disruption |
| May 2025 | Harrods | Targeted attack |
| September 2025 | [[Campaigns/JLR September 2025 Production Shutdown\|Jaguar Land Rover]] | £1.9 billion estimated damage |

## Tactics, Techniques, and Procedures

### Initial Access - Social Engineering Excellence

Scattered Spider's primary differentiator is its mastery of social engineering:

1. **Help Desk Impersonation**: Native English speakers call IT help desks, impersonating employees to reset passwords and MFA tokens
2. **SIM Swapping** (T1656): Convinces mobile carriers to transfer victim phone numbers to attacker-controlled SIMs
3. **Vishing** (T1566.004): Voice phishing calls to obtain credentials directly from employees
4. **Push Bombing**: Overwhelms users with MFA push notifications until they approve

### Persistence

- Deploys multiple legitimate RMM tools (AnyDesk, Splashtop, TeamViewer, FleetDeck)
- Creates backdoor accounts in victim environments
- Enrolls attacker devices for MFA on compromised accounts
- Uses tunneling tools (ngrok, Tailscale) for persistent access

### Credential Access

- Targets NTDS.dit files from domain controllers
- Uses Mimikatz, secretsdump, and DCSync techniques
- Searches password managers (particularly CyberArk)
- Harvests credentials from Slack, Teams, and email

### Defense Evasion

- **BYOVD** (Bring Your Own Vulnerable Driver): Loads vulnerable kernel drivers to kill EDR processes
- Disables security tools and logging
- Uses legitimate tools to blend with normal activity
- Leverages commercial VPNs (Mullvad, NordVPN, ExpressVPN) to mask location

### Counter-IR Capabilities

Scattered Spider is known for monitoring incident response activities:
- Joins victim Slack channels and Microsoft Teams
- Listens to incident response calls
- Searches email for security alerts and hunting activities
- Creates new identities when detected
- Proactively develops new access vectors in response to detection

## Ransomware Operations

Scattered Spider operates as affiliates for multiple RaaS operations:

| Ransomware | Period | Notable Attacks |
|------------|--------|-----------------|
| ALPHV/BlackCat | 2023-2024 | MGM Resorts, Caesars |
| DragonForce | 2025 | UK Retailers, JLR |
| RansomHub | 2024-Present | Various |

## Collaboration Networks

In 2025, Scattered Spider began operating under the "Scattered Lapsus$ Hunters" identity, suggesting formal or informal collaboration with:
- **Lapsus$**: Known for 2021-2022 attacks on Nvidia, Samsung, Microsoft
- **ShinyHunters**: Prolific data breach operators responsible for AT&T Wireless breaches

## Arrests and Disruptions

| Date | Event |
|------|-------|
| July 2025 | Four arrests in UK (including three teenagers) related to retail attacks |
| Various | Multiple US arrests of suspected members |

Despite arrests, the group's loose structure allows continued operations.

## Detection Opportunities

1. **Authentication Anomalies**: Monitor for password resets followed by MFA token registrations
2. **Help Desk Patterns**: Implement callback verification for all credential reset requests
3. **RMM Tool Detection**: Alert on installation of unauthorized remote access tools
4. **VPN Usage**: Detect logins from known VPN exit nodes
5. **NTDS.dit Access**: Monitor for access to Active Directory database files

## Recommendations

### Technical Controls

- Implement phishing-resistant MFA (FIDO2/WebAuthn)
- Disable SMS-based MFA
- Restrict RMM tool installation via application allowlisting
- Segment networks to limit lateral movement
- Monitor Active Directory for suspicious queries

### Process Controls

- Implement callback verification for all help desk requests
- Require video verification for high-risk credential operations
- Train help desk staff on social engineering tactics
- Establish out-of-band verification procedures

### Detection Priorities

| Priority | Detection Focus |
|----------|-----------------|
| Critical | Help desk impersonation patterns |
| Critical | NTDS.dit access attempts |
| High | Unauthorized RMM tool installation |
| High | MFA push bombing (>5 prompts in short period) |
| Medium | VPN exit node authentication |

## References

- CISA. (2023, November 16). Scattered Spider Advisory AA23-320A
- MITRE ATT&CK. Group G1015 - Scattered Spider
- CrowdStrike. (2025, July 2). Scattered Spider Escalates Attacks Across Industries
- Mandiant. (2025, May 6). Defending Against UNC3944: Cybercrime Hardening Guidance
- GuidePoint Security. (2024, October 25). Worldwide Web: Analysis of Scattered Spider Tactics

---

## Related Intelligence

```dataview
TABLE created, report_type, confidence
FROM "Reports"
WHERE contains(threat_actors, "[[Threat Actors/Scattered Spider]]")
SORT created DESC
```
