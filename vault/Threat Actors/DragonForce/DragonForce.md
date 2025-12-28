---
aliases:
  - DragonForce Ransomware
  - DragonForce Cartel
created: 2025-12-27
type: threat-actor
status: active
motivation: financial
origin: Malaysia
tags:
  - "#threat-actor"
  - "#ransomware"
  - "#raas"
  - "#active-threat"
---

# DragonForce

## Overview

DragonForce is a Ransomware-as-a-Service (RaaS) operation that emerged in August 2023. Originally associated with a Malaysian hacktivist collective, the group evolved into a profit-driven ransomware cartel responsible for 170+ victims worldwide.

## Quick Facts

| Attribute | Value |
|-----------|-------|
| **First Observed** | August 2023 |
| **Status** | ACTIVE |
| **Motivation** | Financial |
| **Actor Type** | RaaS Operator / Cartel |
| **Origin** | Malaysia (hacktivist) / International |

## Key Affiliations

- [[Threat Actors/Scattered Spider]] - Primary initial access broker
- RansomHub - Absorbed affiliates (April 2025)
- Qilin - Coalition partner (September 2025)
- LockBit - Coalition partner (September 2025)

## Notable Operations

- **UK Retail Campaign (2025)**: M&S, Co-op, Harrods - $600M+ damages
- **Ohio State Lottery (2023)**: 600+ GB data exfiltrated
- **Coca-Cola Singapore (2024)**: Data breach
- **Government of Palau (2024)**: Systems compromised

## Reports

- [[Reports/CTID-047-2025_DragonForce_Threat_Actor_Profile]]

## Related Intelligence

```dataview
TABLE created, report_type
FROM "Reports"
WHERE contains(threat_actors, this.file.link)
SORT created DESC
```