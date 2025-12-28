---
title: "Scattered Spider - Threat Actor Profile"
created: 2025-12-26
date: 2025-12-26
category: "[[Threat Report]]"
report_id: CTID-001-2025
report_type: threat_actor_profile
tlp: TLP:CLEAR
criticality: high
rating: 7

# Threat metadata
threat_actors:
  - "[[Threat Actors/Scattered Spider]]"
  - "[[Threat Actors/ALPHV-BlackCat]]"
  - "[[Threat Actors/RansomHub]]"
  - "[[Threat Actors/DragonForce]]"
  - "[[Threat Actors/ShinyHunters]]"
  - "[[Threat Actors/LAPSUS$]]"
malware:
  - "[[Malware/EIGHTBAIT]]"
  - "[[Malware/Spectre RAT]]"
  - "[[Malware/RattyRAT]]"
  - "[[Malware/LummaC2]]"
  - "[[Malware/ALPHV Ransomware]]"
  - "[[Malware/DragonForce Ransomware]]"
techniques:
  - T1566.004
  - T1621
  - T1656
  - T1078.004
  - T1219
  - T1562.001
  - T1003.003
  - T1003.006
  - T1486
  - T1098.005
  - T1068
campaigns:
  - "[[Campaigns/0ktapus Campaign 2022]]"
  - "[[Campaigns/MGM Resorts Attack 2023]]"
  - "[[Campaigns/Caesars Entertainment Attack 2023]]"
  - "[[Campaigns/UK Retail Campaign 2025]]"

# Intelligence metadata
confidence: high
sources:
  - CISA
  - MITRE ATT&CK
  - Mandiant/Google Cloud
  - CrowdStrike
  - Microsoft Security
  - Unit 42
  - Okta
  - ReliaQuest
ioc_count:
  hashes: 0
  domains: 10
  ips: 3

# Obsidian tags
tags:
  - "#threat-intel"
  - "#threat-actor-profile"
  - "#scattered-spider"
  - "#ransomware"
  - "#social-engineering"
  - "#active-threat"
---

# Scattered Spider - Threat Actor Profile

| **Report ID** | CTID-001-2025 |
|---------------|---------------|
| **Date** | 2025-12-26 |
| **TLP** | TLP:CLEAR |
| **Criticality** | HIGH |

## Executive Summary

Scattered Spider (UNC3944, Octo Tempest, 0ktapus) is a financially motivated cybercriminal collective comprising primarily young, native English-speaking individuals from the United States and United Kingdom. Active since May 2022, the group evolved from credential harvesting into one of the most dangerous ransomware affiliates.

**Key Assessment:**
- **Status**: ACTIVE with high operational tempo
- **Threat Level**: HIGH
- **Primary Capability**: Social engineering (vishing) against IT help desks
- **Current RaaS Partner**: DragonForce (April 2025-present)

Despite multiple arrests in 2024-2025, the group remains operationally active with recent UK retail attacks causing $270-440M in damages.

## Key Points

- ACTIVE HIGH-SEVERITY THREAT despite member arrests
- Social engineering specialists - native English speakers conducting convincing vishing
- Rapid RaaS transitions: ALPHV → RansomHub → DragonForce
- Attack timelines compressed from ~80 hours (2023) to <24 hours (2025)
- Installs 6+ RMM tools for persistence

## Notable Campaigns

| Campaign | Date | Impact |
|----------|------|--------|
| 0ktapus | August 2022 | 130+ organizations targeted |
| MGM Resorts | September 2023 | $100M loss; 10-day disruption |
| Caesars Entertainment | September 2023 | $15M ransom paid |
| UK Retailers (M&S, Co-op, Harrods) | April-May 2025 | $270-440M combined impact |

## MITRE ATT&CK Highlights

- T1566.004 - Spearphishing Voice
- T1621 - MFA Request Generation
- T1656 - Impersonation
- T1219 - Remote Access Software
- T1562.001 - Impair Defenses
- T1486 - Data Encrypted for Impact

See full report: [[Reports/CTID-001-2025_Scattered_Spider_Threat_Actor_Profile]]

---
*Report Generated: 2025-12-26 | TLP:CLEAR*
