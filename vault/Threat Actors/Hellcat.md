---
title: "HELLCAT Ransomware Group"
created: 2025-12-28
date: 2025-12-28
category: "[[Threat Actor]]"
type: eCrime
origin: Unknown
motivation: Financial
status: Active
first_seen: 2024-06

aliases:
  - HELLCAT
  - HellCat

affiliated_groups:
  - "[[Threat Actors/Morpheus]]"

tools:
  - "[[Malware/Infostealer/Lumma Stealer]]"
  - "[[Malware/Cobalt Strike]]"
  - "[[Malware/SliverC2]]"
  - Netcat
  - Netscan

techniques:
  - T1566.001
  - T1190
  - T1059.001
  - T1562.001
  - T1620
  - T1046
  - T1021
  - T1486

targets:
  sectors:
    - Government
    - Energy
    - Telecommunications
    - Education
    - Automotive
  geography:
    - Global

tags:
  - "#threat-actor"
  - "#ransomware"
  - "#raas"
  - "#infostealer"
  - "#jira-exploitation"
---

# HELLCAT Ransomware Group

## Overview

HELLCAT is a Ransomware-as-a-Service (RaaS) operation that emerged in mid-2024 and has rapidly established itself as a sophisticated threat actor. The group is distinguished by its consistent exploitation of Atlassian Jira credentials harvested via infostealer malware, a technique that has proven highly effective against enterprise targets.

## Key Characteristics

| Attribute | Details |
|-----------|---------|
| **First Observed** | Mid-2024 |
| **Type** | Ransomware-as-a-Service (RaaS) |
| **Motivation** | Financial |
| **Status** | Active |
| **Key Members** | "Pryx" (founder), "Rey", "Grep" |

## Aliases

- HELLCAT
- HellCat

## Notable Campaigns

| Date | Victim | Impact |
|------|--------|--------|
| Q4 2024 | Schneider Electric | 400,000 rows of user data; 40GB exfiltrated |
| Q4 2024 | Telefonica | Jira exploitation; data exfiltration |
| Q4 2024 | Orange | AI-amplified data leak |
| Q4 2024 | Pinger | Corporate data breach |
| March 2025 | [[Campaigns/JLR March 2025 Data Breach\|Jaguar Land Rover]] | 700+ internal documents; 350GB data |

## Tactics, Techniques, and Procedures

### Initial Access

HELLCAT primarily gains initial access through two vectors:

1. **Infostealer Credential Harvesting**: The group leverages credentials stolen by infostealer malware (particularly Lumma Stealer) to access corporate Atlassian Jira instances. These credentials are often years old but remain valid due to poor credential hygiene.

2. **Exploit Public-Facing Applications** (T1190): Targets vulnerabilities in exposed systems, including zero-day exploits in enterprise tools like Jira.

### Execution

The group employs multi-stage PowerShell infection chains:
- Stage 1: Initial PowerShell script establishes foothold
- Stage 2: Downloads additional payloads including AMSI bypass scripts
- Stage 3: Retrieves final payload for in-memory execution

### Defense Evasion

- **AMSI Bypass** (T1562.001): Dedicated scripts to disable Windows Antimalware Scan Interface
- **Reflective Code Loading** (T1620): Executes payloads directly in memory to evade file-based detection

### Lateral Movement

Uses legitimate tools to blend with normal IT activity:
- Netcat for establishing communication channels
- Netscan for network discovery
- Standard Windows utilities (living-off-the-land)

## Infrastructure

HELLCAT operates open directories for payload staging and uses reflective loading techniques to minimize file-based artifacts. The group's infrastructure often overlaps with Morpheus ransomware, suggesting shared tooling or affiliate relationships.

## Detection Opportunities

1. Monitor for unauthorized access to Atlassian Jira instances, especially from unusual IP addresses
2. Detect encoded PowerShell commands and AMSI bypass attempts
3. Alert on network scanning activity using common tools
4. Track credential usage patterns for dormant or third-party accounts

## Recommendations

- Implement MFA on all Atlassian products
- Rotate credentials regularly, especially for third-party access
- Monitor for infostealer infections and treat compromised credentials as persistent threats
- Restrict network access to Jira instances

## References

- Picus Security. (2025, March 13). HellCat Ransomware: Exposing the TTPs of a Rising Ransomware Threat
- Bridewell. (2025, February 28). Who are Hellcat Ransomware Group?
- Cato Networks. (2025, June 15). Unmasking Hellcat: Not Your Average Ransomware Gang
- Halcyon. (2025, April 10). Emerging Threat Actor Hellcat Exemplifies Continued Innovation

---

## Related Intelligence

```dataview
TABLE created, report_type, confidence
FROM "Reports"
WHERE contains(threat_actors, "[[Threat Actors/HELLCAT]]")
SORT created DESC
```
