---
title: "Morpheus Ransomware - Threat Actor Profile"
created: 2025-12-27
date: 2025-12-27
category: "[[Threat Report]]"
report_id: CTID-MORPHEUS-2025-001
report_type: threat_actor_profile
tlp: TLP:AMBER
criticality: high
rating: 5

threat_actors:
  - "[[Threat Actors/Morpheus]]"
  - "[[Threat Actors/Hellcat]]"
  - "[[Threat Actors/Scattered Spider]]"
malware:
  - "[[Malware/Ransomware/Morpheus Ransomware]]"
  - "[[Malware/Ransomware/Hellcat Ransomware]]"
  - "[[Malware/SliverC2]]"
  - "[[Malware/Cobalt Strike]]"
  - "[[Malware/LummaStealer]]"
techniques:
  - T1566.001
  - T1190
  - T1078
  - T1059.001
  - T1547.001
  - T1098.004
  - T1068
  - T1562.001
  - T1620
  - T1070.004
  - T1036
  - T1046
  - T1021.004
  - T1555
  - T1048
  - T1567
  - T1486
  - T1657
campaigns:
  - "[[Campaigns/Schneider Electric Breach 2024]]"
  - "[[Campaigns/Telefonica Breach 2025]]"
  - "[[Campaigns/Jaguar Land Rover Breach 2025]]"

confidence: high
sources:
  - SentinelOne
  - KELA Cyber
  - Picus Security
  - Bridewell
  - SOC Prime
  - Splunk
ioc_count:
  hashes: 3
  domains: 4
  ips: 4

tags:
  - "#threat-intel"
  - "#threat-actor-profile"
  - "#ransomware"
  - "#raas"
  - "#morpheus"
  - "#hellcat"
  - "#jira-exploitation"
  - "#active-threat"
---

# Morpheus Ransomware - Threat Actor Profile

| **Report ID** | CTID-MORPHEUS-2025-001 |
|---------------|------------------------|
| **Date** | 2025-12-27 |
| **TLP** | TLP:AMBER |
| **Criticality** | HIGH |
| **Confidence** | HIGH |

> [!note] Primary Profile
> The primary threat actor profile is maintained at [Morpheus](Threat%20Actors/Morpheus.md)

---

## Executive Summary

[Morpheus](Threat%20Actors/Morpheus.md) is a ransomware operation that emerged in December 2024, operating on an identical technical foundation to [Hellcat](Threat%20Actors/Hellcat.md)—a confirmed shared codebase discovered by SentinelOne researchers in January 2025. This connection represents a significant threat intelligence finding: organizations defending against one operation must account for TTPs from both groups.

The groups have collectively compromised telecommunications giants (Telefónica, Orange Romania), critical infrastructure (Schneider Electric), and automotive manufacturers (Jaguar Land Rover) through a signature attack methodology exploiting stolen Atlassian Jira credentials harvested via infostealer malware.

---

## Key Findings

- **Shared Codebase**: Morpheus and Hellcat ransomware payloads share identical code (~18KB 64-bit PE files)
- **Jira Exploitation Specialty**: Both groups primarily leverage stolen Atlassian Jira credentials from infostealer malware
- **High-Value Targeting**: Victims include Schneider Electric (40GB), Jaguar Land Rover (350GB+), Telefónica (342GB total)
- **Leadership Unmasked**: Hellcat operator "Rey" identified as Saif Khader from Amman, Jordan
- **No Extension Modification**: Distinctive detection opportunity - neither operation modifies file extensions

---

## Quick Reference

| **Attribute** | **Details** |
|---------------|-------------|
| **Primary Name** | Morpheus |
| **Associated Groups** | Hellcat, Scattered LAPSUS$ Hunters |
| **Origin** | Unknown (Hellcat: Jordan, UAE) |
| **Motivation** | Financial (double extortion) |
| **First Observed** | December 2024 |
| **Status** | Active |

---

## Critical IOCs

| **Type** | **Value** | **Context** |
|----------|-----------|-------------|
| SHA1 | `f86324f889d078c00c2d071d6035072a0abb1f73` | Morpheus payload |
| SHA1 | `b834d9dbe2aed69e0b1545890f0be6f89b2a53c7` | Hellcat payload |
| Domain | `izsp6ipui4ctgxfugbgtu65kzefrucltyfpbxplmfybl5swiadpljmyd[.]onion` | Morpheus DLS |
| Email | `morpheus[@]onionmail[.]com` | Morpheus contact |

---

## Priority Mitigations

1. Patch Atlassian Jira and Palo Alto PAN-OS immediately
2. Enable PowerShell Script Block Logging (Event ID 4104)
3. Monitor registry Run keys for "maintenance" value
4. Implement MFA for all Jira instances
5. Block known IOCs at network perimeter

---

*Full report: [Morpheus](Threat%20Actors/Morpheus.md)*

*Report generated: 2025-12-27 | Classification: TLP:AMBER*
