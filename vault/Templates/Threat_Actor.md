---
created: {{date}}
category: "[[Threat Actors]]"
aliases: []
tags:
  - "#ThreatActor"
attribution_country:
motivation:
first_seen:
last_seen:
active: true
rating:
confidence:
---

# {{title}}

## Aliases

-

## Overview

## Goal

[[Goal_Name]]

## Attribution

**Country:** [[Country_Name]]
**Confidence:**

## Targeted Sectors

- [[Sector_Name]]

## Targeted Countries

- [[Country_Name]]

## TTPs

### Initial Access

- [[Attack_Vector_Name]]

### Execution

### Persistence

### Defense Evasion

## Associated Malware

- [[Malware/Malware_Name]]

## Associated Campaigns

- [[Campaigns/Campaign_Name]]

## Infrastructure Patterns

## Notable Incidents

- [[Incident_Number]] -

## MITRE ATT&CK

| Tactic | Technique | Procedure |
|--------|-----------|-----------|
|        |           |           |

## IOCs

<details>
<summary>Network Indicators</summary>

| Type | Indicator | Context | First Seen |
|------|-----------|---------|------------|
|      |           |         |            |

</details>

## Intelligence Gaps

-

## References

-

---

## Related Intelligence

```dataview
TABLE created, report_type, confidence
FROM "Reports"
WHERE contains(threat_actors, this.file.link)
SORT created DESC
LIMIT 10
```
