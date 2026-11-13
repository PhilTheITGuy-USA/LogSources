# Verification

What each module has been verified against, and by which layer: **local** (build, tests, lint),
**portal import** (imported into a lab portal and exported again), **live target** (running against a
real resource). This file is the one record of it. A clean lint is not a portal import.

## `Microsoft_AD_GroupManagement_Events` (LogSource)

The first round-trip import (2026-11-13) was refused: "Invalid File, cannot import into LogicModule",
code 1500. That template's key set came from the spec's notes, not an export. The key set now
matches a lab-portal export of a `Windows Event Logs` clone that imports: top-level
`searchKeywords` and `group`, and a `comment` on every filter and `resourceMapping` entry, which the
first template lacked. That export does not vouch for filter `op: "In"`, a `LogName` filter, the
`Static` log-field method or `filterOp: "AND"`: only the round trip confirms those.

| Claim | Layer | Result | Date |
|---|---|---|---|
| Exactly the 31 approved event IDs, no 4736, no overlap between the groups | local (`tests/test_build.py`) | pass | 2026-11-13 |
| The EventId filter and the technicalNotes table come from the same `events.py` | local (`tests/test_build.py`) | pass | 2026-11-13 |
| No placeholder survives the build; no `version`, `registryMetadata`, `integrationMetadata` or `originId` | local (`tests/test_build.py`) | pass | 2026-11-13 |
| Every key set (top level, `collectionAttrs`, filters, logFields, resourceMapping) matches the working export's, minus portal-owned keys | local (`tests/test_build.py`) | pass | 2026-11-13 |
| `lm_lint_module.py dist`: 0 errors (1 expected WARN: shared checks only for LogSources) | local | pass | 2026-11-13 |
| Import of the first template (no `searchKeywords`, `group`, filter/mapping `comment`) | portal import | refused, code 1500 | 2026-11-13 |
| Candidates A and B (key set fixed, `appliesTo: false()`) | portal import | refused | 2026-11-13 |
| A module built in the portal UI (a `Windows Event Logs` clone) exports and re-imports | portal import | pass | 2026-11-13 |
| The UI offers `op` `In`, filter `LogName` and an AND/OR `filterOp` | portal UI | pass | 2026-11-13 |
| Import accepted with an empty AppliesTo and no portal metadata | portal import | pending | |
| Import accepted without `originId` | portal import | pending | |
| `LogName` filter (`Equal` `Security`) survives | portal import | pending | |
| `EventId` filter (`In`, 31 pipe-separated IDs) survives | portal import | pending | |
| `Static` log field `ad_event_category` survives | portal import | pending | |
| `resourceMapping` (`Token` `##system.deviceId##`, index `"0"`) survives | portal import | pending | |
| Top-level key set unchanged by the round trip | portal import | pending | |
| Group add/remove events reach LM Logs mapped to the DC, with `ad_event_category = group_management` | live target | pending | |

## Deferred

`Microsoft_AD_GroupManagement_AuditPolicy` (the DataSource that alerts when the audit policy is
off) is designed in `docs/superpowers/specs/2026-11-12-ad-group-management-design.md` and not
built (user, 2026-11-13). Finding kept for it: `auditpol /get ... /r` has no numeric Setting Value
column, only localized text; `auditpol /backup /file:` has one (0 none, 1 Success, ...).
