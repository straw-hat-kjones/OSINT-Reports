# Hellcat Ransomware Group

**Aliases:** HellCat, HELLCAT, ICA Group (original name)
**Type:** Ransomware-as-a-Service (RaaS)
**Status:** Active
**First Observed:** October 2024
**Attribution:** eCrime with ideological component (anti-Israel/anti-US)
**Confidence:** High

---

## Overview

Hellcat is an emerging RaaS threat group that surfaced in Q4 2024, operated by high-ranking BreachForums members. The group combines sophisticated technical capabilities with ideological targeting, focusing on U.S. and Israeli organizations while maintaining financial motivations.

## Key Members

| Alias | Role | Attribution |
|-------|------|-------------|
| **Pryx** (HolyPryx) | Founding leader | "Adem" - UAE-based |
| **Rey** (Hikki-Chan) | Administrator | Saif Khader, Amman, Jordan |
| **Grep** | Operator | Dell/CapGemini breaches |
| **IntelBroker** | Associated | BreachForums owner (arrested Feb 2025) |

## Target Profile

**Primary Sectors:**
- Critical Infrastructure (Schneider Electric, Telefonica, Orange)
- Government (Israel Knesset, Jordan Ministry of Education)
- Telecommunications
- Automotive (Jaguar Land Rover)
- Technology/IT

**Geographic Focus:** United States, Israel, Europe

## Notable Campaigns

| Date | Victim | Data Stolen |
|------|--------|-------------|
| Oct 2024 | Israel's Knesset | 64GB |
| Nov 2024 | Schneider Electric | 40GB+ |
| Jan 2025 | Telefonica | 2.3GB |
| Feb 2025 | Orange Romania | 6.5GB |
| Mar 2025 | Jaguar Land Rover | 350GB+ |
| Mar 2025 | Ascom | 44GB |

## MITRE ATT&CK Techniques

### Initial Access
- [T1566.001](T1566.001.md) - Spearphishing Attachment
- [T1190](T1190.md) - Exploit Public-Facing Application (Jira, Palo Alto PAN-OS)
- [T1078](T1078.md) - Valid Accounts (infostealer-harvested credentials)

### Execution
- [T1059.001](T1059.001.md) - PowerShell

### Persistence
- [T1547.001](T1547.001.md) - Registry Run Keys

### Defense Evasion
- [T1562.001](T1562.001.md) - AMSI Bypass
- [T1620](T1620.md) - Reflective Code Loading
- [T1036](T1036.md) - Masquerading
- [T1027](T1027.md) - Obfuscated Files

### Credential Access
- [T1555.003](T1555.003.md) - Credentials from Web Browsers

### Discovery
- [T1046](T1046.md) - Network Service Discovery
- [T1083](T1083.md) - File and Directory Discovery

### Lateral Movement
- [T1021](T1021.md) - Remote Services

### Command and Control
- [T1071](T1071.md) - Application Layer Protocol
- [T1219](T1219.md) - Remote Access Software (SliverC2)

### Exfiltration
- [T1020](T1020.md) - Automated Exfiltration
- [T1567](T1567.md) - Exfiltration Over Web Service

### Impact
- [T1486](T1486.md) - Data Encrypted for Impact
- [T1490](T1490.md) - Inhibit System Recovery

## Tools and Malware

- **SliverC2** - Primary C2 framework
- **Cobalt Strike** - Secondary C2
- **Custom Ransomware** - AES-CBC encryption with RSA key protection
- **LummaStealer** - Credential harvesting
- **Netcat/Netscan** - Lateral movement

## Infrastructure

### C2 Domains
- `pryx[.]pw`
- `waifu[.]cat` (exfiltration)
- `hellcat[.]locker`

### Tor Hidden Services
- `hellcakbszllztlyqbjzwcbdhfrodx55wq77kmftp4bhnhsnn5r3odad[.]onion`

### IP Addresses
- `45[.]200[.]148[.]157`
- `185[.]247[.]224[.]8`
- `185[.]10[.]68[.]159`

## Relationships

- **[Morpheus Ransomware](Morpheus%20Ransomware.md)** - Shared codebase/builder
- **[Underground Team](Underground%20Team.md)** - Ransom note template similarity
- **[BreachForums](BreachForums.md)** - Operational ecosystem
- **[ShinyHunters](ShinyHunters.md)** - Personnel overlap via BreachForums

## Detection

### Key Indicators
- PowerShell scripts with AMSI bypass attempts
- Registry modifications to Run keys
- SliverC2 network traffic patterns
- SFTP to unknown external hosts
- Ransom note: `_README_.txt` in `C:\Users\Public`

### Splunk Detections
- Windows Service Create SliverC2
- High Process Termination Frequency
- Ransomware Notes Bulk Creation

## References

- [Bridewell - Hellcat Ransomware Group](https://www.bridewell.com/insights/blogs/detail/who-are-hellcat-ransomware-group)
- [SentinelOne - HellCat and Morpheus Analysis](https://www.sentinelone.com/blog/hellcat-and-morpheus-two-brands-one-payload-as-ransomware-affiliates-drop-identical-code/)
- [KELA - Hellcat Unmasked](https://www.kelacyber.com/blog/hellcat-hacking-group-unmasked-rey-and-pryx/)
- [Splunk - Hellcat Analytics](https://research.splunk.com/stories/hellcat_ransomware/)

---

**Tags:** #threat-actor #ransomware #RaaS #hellcat #ecrime
**Last Updated:** 2025-12-27
