---
status: active
updated: 2026-07-22
related: [[architecture/current-state]], [[CLAUDE]], [[index]]
---

# SOC Automation Project Vault

Documentation vault for an n8n-based SOC automation lab. Organized for both human reading and fresh Claude instances.

## Quick start (humans)

- **What is this project?** → [[architecture/current-state]]
- **What's being worked on?** → look in `subprojects/` for the latest dated folder
- **Why was a choice made?** → check `decisions/`
- **How do I do an operation?** → look in `runbooks/`

## Quick start (fresh Claude instances)

Open [[CLAUDE]]. It is the schema for this vault and tells you everything you need.

## Vault layout

```
vault/
├── CLAUDE.md                    # Schema — fresh-instance entry
├── README.md                    # This file
├── index.md                     # Catalog of all pages
├── log.md                       # Append-only chronological record
├── architecture/                # System docs
│   ├── current-state.md
│   ├── target-state.md
│   └── components/              # One file per major component
├── subprojects/                 # One folder per sub-project (YYYY-MM-DD-<topic>/)
├── decisions/                   # Numbered ADRs, immutable
├── runbooks/                    # Operational how-tos
├── workflows/                   # n8n workflow documentation
└── sources/                     # Session notes, raw artifacts
```

## Conventions in one paragraph

Sub-projects live in dated folders. Each has its own README, spec, plan, runbook, and notes. Decisions are numbered and immutable. The log is append-only. Secrets never enter this vault — they live in a gitignored file at the project root.
