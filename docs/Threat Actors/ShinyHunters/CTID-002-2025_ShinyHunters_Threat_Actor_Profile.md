---
title: "ShinyHunters - Threat Actor Profile"
created: 2025-12-26
date: 2025-12-26
category: "[[Threat Report]]"
report_id: CTID-002-2025
report_type: threat_actor_profile
tlp: TLP:CLEAR
criticality: high
rating: 7

threat_actors:
  - "[[Threat Actors/ShinyHunters]]"
  - "[[Threat Actors/Scattered Spider]]"
  - "[[Threat Actors/LAPSUS$]]"
malware:
  - "[[Malware/ShinySp1d3r Ransomware]]"
techniques:
  - T1566.004
  - T1528
  - T1530
  - T1078
campaigns:
  - "[[Campaigns/Snowflake Data Breach 2024]]"
  - "[[Campaigns/Salesforce Vishing Campaign 2025]]"
confidence: high

tags:
  - "#threat-intel"
  - "#threat-actor-profile"
  - "#shinyhunters"
  - "#data-breach"
  - "#extortion"
  - "#active-threat"
---

# ShinyHunters - Threat Actor Profile

| **Report ID** | CTID-002-2025 |
|---------------|---------------|
| **Date** | 2025-12-26 |
| **TLP** | TLP:CLEAR |
| **Criticality** | HIGH |

## Executive Summary

ShinyHunters (Bling Libra, UNC6040) is a financially motivated cybercriminal collective that emerged in May 2020 and has evolved into one of the most prolific data theft and extortion groups of the decade. The group has compromised 1+ billion records across hundreds of organizations.

**Key Assessment:**
- **Status**: ACTIVE (despite multiple arrests)
- **Threat Level**: HIGH
- **Primary Capability**: Cloud data theft (AWS, Snowflake, Salesforce)
- **2025 Evolution**: Merged with Scattered Spider, launched ShinySp1d3r RaaS

## Key Points

- 1+ billion records compromised across hundreds of organizations
- Tactical evolution from database sales to vishing + OAuth token abuse
- Confirmed Scattered Spider alliance under "Scattered LAPSUS$ Hunters" brand
- 160+ Snowflake instances compromised in 2024 campaign
- 285+ Salesforce instances via Gainsight supply chain (2025)

## Notable Breaches

| Year | Victim | Records |
|------|--------|---------|
| 2020 | Tokopedia | 91M |
| 2020 | Wattpad | 270M |
| 2024 | Ticketmaster | 560M |
| 2024 | AT&T | 110M+ |
| 2024 | Santander | 28M cards |

## MITRE ATT&CK Highlights

- T1566.004 - Spearphishing Voice (PRIMARY 2025)
- T1528 - Steal Application Access Token
- T1530 - Data from Cloud Storage
- T1078 - Valid Accounts

See full report: [CTID-002-2025_ShinyHunters_Threat_Actor_Profile](Reports/CTID-002-2025_ShinyHunters_Threat_Actor_Profile.md)

---
*Report Generated: 2025-12-26 | TLP:CLEAR*
