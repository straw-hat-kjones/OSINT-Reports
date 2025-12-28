# ShinyHunters Threat Actor Profile

```
============================================================
         THREAT INTELLIGENCE REPORT
         Classification: TLP:CLEAR
         Report Type: Threat Actor Profile
         Date: 2025-12-26
         Confidence: HIGH
============================================================
```

---

## Executive Summary

ShinyHunters is a financially motivated cybercriminal collective that emerged in May 2020 and has evolved into one of the most prolific and dangerous data theft and extortion groups of the decade. Originally known for selling stolen databases on dark web forums, the group has undergone significant tactical evolution, transitioning from data brokerage to direct extortion operations targeting cloud environments, particularly AWS and Salesforce instances.

The group has been linked to breaches affecting over 1 billion user records across hundreds of organizations globally. Notable victims include Tokopedia (91M records), Ticketmaster (560M records), AT&T (110M+ records), Microsoft GitHub, Santander Bank, Snowflake customers, and numerous enterprise Salesforce instances.

In 2025, ShinyHunters has reportedly merged operations with Scattered Spider (UNC3944) and LAPSUS$ affiliates, forming an alliance called "Scattered LAPSUS$ Hunters" (SLH) that operates an emerging Ransomware-as-a-Service platform called ShinySp1d3r. Despite multiple arrests of alleged members in France and the United States, the group remains operationally active and continues to conduct sophisticated vishing-based campaigns.

---

## Threat Actor Overview

| Attribute | Details |
|-----------|---------|
| **Primary Name** | ShinyHunters |
| **Aliases** | Bling Libra (Palo Alto Unit 42), UNC6040/UNC6240 (Google/Mandiant), ShinyCorp, Sp1d3rHunters |
| **Type** | eCrime / Financially Motivated Threat Actor |
| **Origin** | Primarily French nationals; suspected international membership |
| **Active Period** | May 2020 - Present |
| **Current Status** | ACTIVE (despite arrests) |
| **Motivation** | Financial Gain (Data Theft, Extortion, Ransomware) |
| **Associated Groups** | [[Scattered Spider]] (UNC3944), LAPSUS$, GnosticPlayers (historical), The Com |
| **Tracked By** | FBI, CISA, Mandiant/Google (UNC6040), Unit 42 (Bling Libra), CrowdStrike |

---

## Background and Evolution

### Origins (2020)

ShinyHunters first gained public attention in May 2020, emerging shortly after the disappearance of the GnosticPlayers collective. The group's name derives from "Shiny Pokemon" - rare alternate-color variants in the Pokemon franchise that collectors actively hunt. This nomenclature reflects their methodology of seeking out and collecting valuable data vulnerabilities.

Security researchers have noted tactical similarities between ShinyHunters and GnosticPlayers, including:
- Staggered release of data dumps
- Direct media outreach to claim responsibility
- Targeting of similar organization types
- Use of identical underground forums

### Tactical Evolution (2021-2024)

In April 2021, ShinyHunters publicly revealed a shift to extortion tactics, moving beyond pure data brokerage. The group began:
- Directly extorting victims before selling data
- Operating BreachForums following Pompompurin's arrest (March 2023)
- Targeting cloud environments (AWS) with increasingly sophisticated techniques

### Current Operations (2024-2025)

The group has evolved to:
- Conduct sophisticated voice phishing (vishing) campaigns
- Target enterprise Salesforce instances via OAuth abuse
- Operate Extortion-as-a-Service (EaaS) infrastructure
- Collaborate with Scattered Spider and LAPSUS$ affiliates
- Develop proprietary ransomware (ShinySp1d3r RaaS)

---

## Target Profile

### Industries Targeted

| Industry | Targeting Intensity | Notable Victims |
|----------|---------------------|-----------------|
| Technology/SaaS | HIGH | Microsoft, GitHub, Snowflake, Salesforce customers |
| E-commerce/Retail | HIGH | Tokopedia, Minted, Bonobos, Marks & Spencer |
| Telecommunications | HIGH | AT&T (110M+ records), SFR |
| Financial Services | HIGH | Santander Bank (28M cards), Allianz Life |
| Entertainment/Media | HIGH | Ticketmaster (560M records), Wattpad |
| Healthcare | MODERATE | BigBasket, various Snowflake customers |
| Luxury/Fashion | MODERATE | LVMH, Chanel, Tiffany, Dior, Adidas |
| Travel/Hospitality | MODERATE | Qantas, RedDoorz |

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | ShinyHunters Usage |
|--------|--------------|----------------|-------------------|
| **Reconnaissance** | T1593 | Search Open Websites/Domains | Scanning GitHub for exposed credentials |
| **Initial Access** | T1566.002 | Phishing: Spearphishing Link | Credential harvesting via fake login pages |
| **Initial Access** | T1566.004 | Phishing: Spearphishing Voice | Vishing calls impersonating IT support |
| **Initial Access** | T1078 | Valid Accounts | Using stolen credentials from infostealers |
| **Credential Access** | T1528 | Steal Application Access Token | OAuth token theft from Salesforce |
| **Discovery** | T1580 | Cloud Infrastructure Discovery | AWS S3 bucket enumeration |
| **Collection** | T1530 | Data from Cloud Storage | S3 bucket data theft |
| **Collection** | T1213 | Data from Information Repositories | Salesforce CRM data export |
| **Exfiltration** | T1048 | Exfiltration Over Alternative Protocol | Data transfer via S3 Browser, WinSCP |
| **Impact** | T1657 | Financial Theft | Extortion demands, data sales |
| **Impact** | T1485 | Data Destruction | S3 bucket deletion post-exfiltration |

---

## Notable Campaigns and Breaches

### 2024 Snowflake Campaign (UNC5537 Collaboration)

| Date | Victim | Records Affected | Method |
|------|--------|------------------|--------|
| May 2024 | Ticketmaster | 560M users | Snowflake credential theft |
| May 2024 | Santander Bank | 28M credit cards | Snowflake credential theft |
| Jul 2024 | AT&T | 110M+ records | Snowflake credential theft |

### 2025 Salesforce Vishing Campaign (UNC6040)

| Date | Victim | Data Type | Method |
|------|--------|-----------|--------|
| May-Aug 2025 | Google | SMB contact data | Vishing + OAuth abuse |
| 2025 | Qantas | CRM data | Vishing + OAuth abuse |
| 2025 | Allianz Life | Customer data | Vishing + OAuth abuse |
| 2025 | LVMH/Chanel | CRM data | Vishing + OAuth abuse |

---

## Known Members and Arrests

| Name | Alias | Arrest Date | Outcome |
|------|-------|-------------|---------|
| Sebastien Raoult | Sezyo Kaizen | May 2022 | 3 years, $5M restitution |
| Kai West | IntelBroker | Feb 2025 | Pending US extradition |
| Unknown | ShinyHunters | Jun 2025 | Arrested (France) |
| Unknown | Hollow | Jun 2025 | Arrested (France) |
| Unknown | Noct | Jun 2025 | Arrested (France) |
| Unknown | Depressed | Jun 2025 | Arrested (France) |

---

## Detection Opportunities

### Network Indicators
- VPN/TOR traffic: `185[.]220[.]101[.]0/24` (TOR), `193[.]138[.]218[.]0/24` (Mullvad)
- S3 bucket naming: `contact-shinycorp-tutanota-com-#`

### Behavioral Indicators
- Unsolicited IT support calls requesting OAuth app installation
- Bulk Salesforce Data Loader exports
- New Connected App installations from external sources
- S3 Browser/WinSCP tool execution

---

## Defensive Recommendations

1. Enforce MFA on all cloud services (hardware keys preferred)
2. Audit OAuth Connected Apps regularly
3. Implement strict IT helpdesk identity verification
4. Enable CloudTrail S3 data logging
5. Train employees on vishing tactics

---

## Tags

#threat-actor #ecrime #shinyhunters #bling-libra #unc6040 #data-theft #extortion #salesforce #aws #vishing

---

## Related Notes

- [[Scattered Spider]]
- [[LAPSUS$]]
- [[The Com]]
- [[Snowflake Data Breach]]
- [[BreachForums]]

---

*Report generated: 2025-12-26*
