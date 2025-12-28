---
aliases:
  - HellCat
  - HELLCAT
  - ICA Group
type: threat-actor
classification: eCrime
origin: Jordan, UAE
status: active
first_seen: 2024-10
motivation:
  - financial
  - ideological
tags:
  - "#threat-actor"
  - "#ransomware"
  - "#raas"
  - "#active-threat"
---

# Hellcat

Hellcat is an emerging Ransomware-as-a-Service (RaaS) threat group that surfaced in Q4 2024. The group combines ideological motivations—targeting U.S. and Israeli organizations—with financially-driven extortion operations.

## Quick Reference

| Attribute | Details |
|-----------|---------|
| **Type** | eCrime / RaaS |
| **Origin** | Jordan, UAE |
| **Motivation** | Financial, Ideological |
| **Status** | Active |
| **First Seen** | October 2024 |

## Key Operators

- **Pryx (HolyPryx)** - Founding leader
- **Rey (Hikki-Chan)** - Administrator
- **Grep** - Operator

## Signature TTPs

- Jira credential exploitation via infostealer logs
- Multi-stage PowerShell infection chains
- SliverC2 for command and control
- Custom ransomware (AES-CBC + RSA)

## Associated Malware

- [[Malware/Hellcat Ransomware]]
- [[Malware/SliverC2]]
- [[Malware/Cobalt Strike]]
- [[Malware/LummaStealer]]

## Related Reports

- [[Reports/CTID-002-2025_Hellcat_Threat_Actor_Profile]]

## Notable Victims

- Schneider Electric (November 2024)
- Telefonica (January 2025)
- Jaguar Land Rover (March 2025)
- Orange Romania (February 2025)
- Israel's Knesset (October 2024)
---
title: "Hellcat Ransomware"
created: 2025-12-27
date: 2025-12-27
category: "[[Threat Report]]"
report_type: threat_actor_profile
tlp: TLP:AMBER
criticality: high
rating: 5

threat_actors:
  - "[[Threat Actors/Hellcat]]"
  - "[[Threat Actors/Morpheus]]"
  - "[[Threat Actors/Scattered Spider]]"
malware:
  - "[[Malware/Ransomware/Hellcat Ransomware]]"
  - "[[Malware/Ransomware/Morpheus Ransomware]]"
  - "[[Malware/SliverC2]]"
  - "[[Malware/LummaStealer]]"
techniques:
  - T1566.001
  - T1190
  - T1078
  - T1059.001
  - T1486

confidence: high
sources:
  - SentinelOne
  - KELA Cyber

tags:
  - "#threat-intel"
  - "#threat-actor-profile"
  - "#ransomware"
  - "#raas"
  - "#hellcat"
  - "#jira-exploitation"
---

# Hellcat Ransomware

> [!info] Related Profile
> Hellcat shares an identical codebase with [[Threat Actors/Morpheus]]. See the comprehensive profile at [[Threat Actors/Morpheus]] for full technical analysis.

## Overview

Hellcat is a Ransomware-as-a-Service (RaaS) operation that emerged in mid-2024, originally branded as "ICA Group." The group operates transparently with active affiliate recruitment and has been confirmed to share an identical codebase with [[Threat Actors/Morpheus]].

## Leadership (Unmasked)

| **Persona** | **Real Identity** | **Origin** |
|-------------|-------------------|------------|
| Rey (Hikki-Chan, ggyaf) | Saif Khader | Amman, Jordan |
| Pryx (HolyPryx, Sp1d3r) | "Adem" (partial) | UAE |
| Grep | Unknown | Unknown |
| IntelBroker | Unknown | BreachForums |

## Signature TTPs

- **Jira Credential Exploitation**: Primary initial access via infostealer-harvested Jira credentials
- **PowerShell Infection Chain**: S1.ps1 → Payload.ps1 → Isma.ps1 → Shellcode.ps1 → Stager.woff
- **SliverC2**: Primary command-and-control framework
- **SFTP Exfiltration**: Data exfiltrated via SFTP, sometimes to waifu[.]cat

## Key IOCs

| **Type** | **Value** |
|----------|-----------|
| SHA1 | `b834d9dbe2aed69e0b1545890f0be6f89b2a53c7` |
| Tor DLS | `hellcakbszllztlyqbjzwcbdhfrodx55wq77kmftp4bhnhsnn5r3odad[.]onion` |
| Email | `h3llr4ns[@]onionmail[.]com` |

## Notable Victims

- Schneider Electric (Nov 2024) - 40GB
- Telefónica (Jan 2025, May 2025) - 342GB total
- Jaguar Land Rover (Mar 2025) - 350GB+
- Orange Romania (Feb 2025) - 6.5GB

---

*See [[Threat Actors/Morpheus]] for complete technical analysis, MITRE ATT&CK mapping, and detection guidance.*
