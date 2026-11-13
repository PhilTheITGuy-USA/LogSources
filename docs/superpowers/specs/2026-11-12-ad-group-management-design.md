# AD group management: LogSource

Date: 2026-11-12, revised 2026-11-13 to what shipped. Status: shipped; portal-imported and tested
on a live domain controller (see `docs/verification.md`).

## Goal

Make sure Active Directory security-group changes from every domain controller reach LM Logs.

| Module | Type | Job |
|---|---|---|
| `Microsoft_AD_GroupManagement_Events` | LogSource (`wineventlog`) | Ingest the 16 security-group Security events |

Out of scope:

- Distribution groups (4744-4753, 4759-4763). They grant no permissions (user, 2026-11-13).
- 4662 (an operation was performed on an object). It needs Directory Service Access auditing and
  SACLs, it can be very high volume, and the correlation it serves belongs in a SIEM.
- LM Logs alert rules (for example "member added to Domain Admins"). They are portal
  configuration, not part of a module.
- Checking or changing the audit policy. The technical notes say how to check it by hand.

## Why the stock module is not enough

LM's core `Windows Event Logs` LogSource excludes `Level = Security Audit Success`. Every event below
is logged as Security Audit Success, so the stock module drops all of them. Because of that
exclusion, running both modules does not ingest these events twice, unless someone has removed the
stock module's filter.

## Events (single source: `Microsoft_AD_GroupManagement/events.py`)

Produced by *Audit Security Group Management*:

| Scope | Created | Changed | Member added | Member removed | Deleted |
|---|---|---|---|---|---|
| Global | 4727 | 4737 | 4728 | 4729 | 4730 |
| Domain Local / Builtin Local | 4731 | 4735 | 4732 | 4733 | 4734 |
| Universal | 4754 | 4755 | 4756 | 4757 | 4758 |

Plus 4764, a group's type or scope changed. That is 16 IDs. There is no event 4736. The build
writes this list into the LogSource filter and its `technicalNotes`, so the two cannot disagree.

## The module

Shape from lab-portal exports of LogSources that import (2026-11-13):

- `type: 10`, `collectionMethod: "wineventlog"`, `collectionInterval: 60`
- `collectionAttrs`: `{"resourceMappingOp": "OR", "useWrittenTime": false, "filterOp": "AND"}`
- `searchKeywords: ""`, `group: ""`, and a `comment` on every filter and `resourceMapping` entry
- `resourceMapping`: `system.deviceId`, method `Token`, value `##system.deviceId##`, index `"0"`
- `logFields`: `channel` ← `LogName`, `source` ← `SourceName`, `log_level` ← `Level`,
  `event_id` ← `EventId` (all `Attribute`); `_resource.type` ← `##predef.externalResourceType##`
  (`Token`)
- `registryMetadata: {}`. Without the block the portal refuses the import with code 1500; an
  exported block names the exporting portal, so the empty object ships.
- No `version`, `integrationMetadata` or `originId`: the portal assigns them.

Specific to this module:

- `appliesTo`: empty, so it ingests nothing until the user sets it. The technical notes suggest
  `hasCategory("MicrosoftDomainController")`.
- `filters`, both Include, combined by `filterOp: AND`:
  1. `{"op": "Equal", "name": "LogName", "value": "Security"}`
  2. `{"op": "In", "name": "EventId", "value": "<16 IDs, pipe-separated>"}`
- `logFields` gains a static field `ad_event_category` = `group_management`, so a single LM Logs
  query finds every event this module ingests.
- `technicalNotes`: the event table; the audit-policy prerequisite and the `auditpol` command that
  shows it; that the Collector's WMI account (service account, or `wmi.user`/`wmi.pass`) needs
  Security-log read access (SeSecurityPrivilege), because LM reads events through
  `Win32_NTLogEvent`; that the stock LogSource excludes Audit Success and so does not duplicate these
  events; and that `lmlogs.winevent.channels` is the first thing to check if no events arrive.

## Repository layout

```
build/build.py                       builds every set into dist/<set>/ and runs the cross-checks
Microsoft_AD_GroupManagement/
  events.py                          the 16 IDs with their meanings
  Microsoft_AD_GroupManagement_Events.json   LogSource template
tests/test_build.py                  build cross-checks
docs/verification.md                 which layer proved what, the one record of it
dist/                                gitignored
```

`build.py` fails the build when the event IDs differ from the approved 16, the template has no
`@@EVENT_IDS@@` filter or `@@EVENT_TABLE@@`, or a placeholder survives. Then the skill's
`lm_lint_module.py dist` must be clean.

## Verification

Recorded in `docs/verification.md`, one row per layer and claim: local (build, tests, lint), the
lab-portal round trip (import, export, diff against the build), and a live lab DC (group changes
reach LM Logs mapped to the DC with `ad_event_category = group_management`, and nothing else gets
in). Lab names and addresses stay in `CLAUDE.local.md`. Run `../lab-scrub/check.py` before every
push.
