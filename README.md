# OSINT Reports - Threat Intelligence Vault

Automatically convert Obsidian vault to GitHub-compatible Markdown using GitHub Actions.

## Overview

| Directory | Format | Purpose |
|-----------|--------|--------|
| `vault/` | Obsidian-native | Source of truth, full features |
| `docs/` | GitHub-compatible | Auto-generated, readable on GitHub |

## Features Converted

| Obsidian Syntax | Conversion |
|-----------------|------------|
| `[[Note]]` | `[Note](Note.md)` |
| `[[path/Note]]` | `[Note](path/Note.md)` |
| `[[Note\|Alias]]` | `[Alias](Note.md)` |
| `![[image.png]]` | `![image](image.png)` |
| Dataview blocks | Removed |

## Local Usage

```bash
python scripts/obsidian_to_github.py vault/ docs/ --verbose
```

## Workflow Permissions

Go to Repository Settings → Actions → General → Set "Read and write permissions"
