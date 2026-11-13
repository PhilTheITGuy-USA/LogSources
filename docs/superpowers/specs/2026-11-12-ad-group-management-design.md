# AD group management: LogSource and audit-policy DataSource

Date: 2026-11-12. Status: design approved in conversation, awaiting spec review.

> **Changed during implementation (2026-11-13).** What shipped differs from this design:
> - Only the LogSource was built; the AuditPolicy DataSource is deferred (user).
> - 16 security-group event IDs, not 31: the distribution-group IDs were dropped (user).
> - AppliesTo ships empty, opt-in; the technical notes say what to set (user).
> - The JSON shape below was a guess. The portal refused it until it carried `searchKeywords`,
>   `group`, filter and mapping `comment`s and a `registryMetadata` block (`{}` is enough).
>
> The template, `events.py` and `docs/verification.md` are the current record.

## Goal

Make sure Active Directory group-management events from every domain controller reach LM Logs,
and alert when they stop being produced.

Two modules ship together as the set `Microsoft_AD_GroupManagement`:

| Module | Type | Job |
|---|---|---|
| `Microsoft_AD_GroupManagement_Events` | LogSource (`wineventlog`) | Ingest the 31 group-management Security events |
| `Microsoft_AD_GroupManagement_AuditPolicy` | DataSource (PowerShell script) | Alert when the audit policy that produces them is off, or when the Collector cannot read the Security log |

Both apply to `hasCategory("MicrosoftDomainController")`.

Out of scope:

- 4662 (an operation was performed on an object). It needs Directory Service Access auditing and
  SACLs, it can be very high volume, and the correlation it serves belongs in a SIEM.
- LM Logs alert rules (for example "member added to Domain Admins"). They are portal
  configuration, not part of a module.
- Changing the audit policy. The DataSource reports it and never changes it.

## Why the stock module is not enough

LM's core `Windows Event Logs` LogSource excludes `Level = Security Audit Success`. Every event below
is logged as Security Audit Success, so the stock module drops all of them. Because of that
exclusion, running both modules does not ingest these events twice, unless someone has removed the
stock module's filter.

## Events (single source: `Microsoft_AD_GroupManagement/events.py`)

Security groups, produced by *Audit Security Group Management*:

| Scope | Created | Changed | Member added | Member removed | Deleted |
|---|---|---|---|---|---|
| Global | 4727 | 4737 | 4728 | 4729 | 4730 |
| Domain Local / Builtin Local | 4731 | 4735 | 4732 | 4733 | 4734 |
| Universal | 4754 | 4755 | 4756 | 4757 | 4758 |

Plus 4764, a group's type or scope changed. That is 16 IDs. There is no event 4736.

Distribution groups, produced by *Audit Distribution Group Management*:

| Scope | Created | Changed | Member added | Member removed | Deleted |
|---|---|---|---|---|---|
| Domain Local | 4744 | 4745 | 4746 | 4747 | 4748 |
| Global | 4749 | 4750 | 4751 | 4752 | 4753 |
| Universal | 4759 | 4760 | 4761 | 4762 | 4763 |

That is 15 IDs, 31 in total. The build writes this list into the LogSource filter and its
`technicalNotes`, so the two cannot disagree.

## Module 1: `Microsoft_AD_GroupManagement_Events` (LogSource)

Copied unchanged from LM's `Windows Event Logs` export:

- `type: 10`, `collectionMethod: "wineventlog"`, `collectionInterval: 60`
- `collectionAttrs`: `{"resourceMappingOp": "OR", "useWrittenTime": false, "filterOp": "AND"}`.
  LM's docs do not define `useWrittenTime`, so the reference value is kept.
- `resourceMapping`: `system.deviceId`, method `Token`, value `##system.deviceId##`, index `"0"`
- `logFields`: `channel` ← `LogName`, `source` ← `SourceName`, `log_level` ← `Level`,
  `event_id` ← `EventId` (all `Attribute`); `_resource.type` ← `##predef.externalResourceType##`
  (`Token`)

Not copied: `version`, `registryMetadata`, `integrationMetadata`, or any `originId`. The portal
assigns `originId`; the round trip confirms that an import without one is accepted.

New in this module:

- `appliesTo`: `hasCategory("MicrosoftDomainController")`
- `filters`, both Include, combined by `filterOp: AND`:
  1. `{"op": "Equal", "include": "y", "name": "LogName", "index": "1", "value": "Security"}`
  2. `{"op": "In", "include": "y", "name": "EventId", "index": "2", "value": "<31 IDs, pipe-separated>"}`
- `logFields` gains a static field `ad_event_category` = `group_management`, so a single LM Logs
  query finds every event this module ingests. The `Static` method name comes from LM's docs and is
  checked by the round trip.
- `technicalNotes`: the event table above; the audit-policy prerequisite and the companion
  DataSource; that the Collector's WMI account (service account, or `wmi.user`/`wmi.pass`) needs
  Security-log read access (SeSecurityPrivilege), because LM reads events through
  `Win32_NTLogEvent`; that the stock LogSource excludes Audit Success and so does not duplicate these
  events; and that `lmlogs.winevent.channels` is the first thing to check if no events arrive.

Each filter field and its source:

| Fact | Source |
|---|---|
| `include: "y"` / `"n"`, `op: "Equal"`, `op: "In"` with a pipe-separated value, `name: "EventId"`, string `index` counting from `"1"` | Lab-portal exports of a cloned LogSource, 2026-11-12 |
| `name: "LogName"` in a filter | LM's docs; the same attribute name appears in the reference's `channel` log field |
| `originId` is portal-assigned | Lab-portal exports: every `originId` changed on clone and stayed the same across edits |

## Module 2: `Microsoft_AD_GroupManagement_AuditPolicy` (DataSource)

Shape taken from LM's `Citrix_XenApp_DatastoreStatus` export, a single-instance PowerShell
WinRM DataSource:

- `collectionMethod: "script"`, `multiInstance: false`, no `activeDiscovery` key,
  `dataSourceType: 1`, `type: 0`
- `collectionAttrs`: `{"type": "powershell", "content": <AuditPolicy.ps1>}`
- `collectionInterval: "60m"`. The format is a string, as in `"5m"`. If the import refuses `60m`,
  use the nearest value it accepts and record which.
- `appliesTo`: `hasCategory("MicrosoftDomainController")`
- Datapoint and graph key sets: from the skill's portal-verified fixtures and LM's
  `Win_HyperV_VirtualMachines` export. `interpretMethod: "namevalue"` with the bare datapoint name
  as `interpretExpr` (Script, not BatchScript).

### Script flow (`AuditPolicy.ps1`)

Connection handling follows LM's `Microsoft_Powershell_Info` and `Citrix_XenApp_DatastoreStatus`:

1. Read `##SYSTEM.HOSTNAME##` and resolve it to an FQDN if it is an IP address.
2. If `##AUTO.WINRM##` is `disabled`, write the reason to stderr and stop (see Failure handling).
3. Credentials: `##WMI.USER##` / `##WMI.PASS##`. A value that is blank or still holds the literal
   token (`-like '*wmi.user*'`) counts as unset, and the Collector's service account is used.
4. WinRM options: `usessl`, `port`, `skipcacheck`, `skipcncheck` and `skiprevocationcheck`, read
   from `auto.winrm.*` first and then `winrm.*`. LM's own modules use both forms: Hyper-V reads
   `##AUTO.WINRM##`, Citrix reads `##WINRM.USESSL##`.
5. If the target is the Collector itself (hostname, `localhost` or the Collector's FQDN), run
   locally with no session.
6. Otherwise `New-PSSession`, then `Invoke-Command`, with `Remove-PSSession` in a `finally`.
7. On the DC, run `auditpol /get /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030},{0CCE9238-69AE-11D9-BED3-505054503030} /r`
   (Security Group Management, Distribution Group Management) and return the CSV.
8. Separately, from the Collector over WMI with the same credentials as LM's LogSource, query
   `Win32_NTEventlogFile` where `LogfileName='Security'`. A returned row means readable.
9. Parse (in `ConvertFrom-AuditPolCsv`, a pure function) and print `Name=value` lines with
   `Write-Output`.

Parsing matches rows on **Subcategory GUID** and decodes the numeric **Setting Value** column:
0 none, 1 Success, 2 Failure, 3 both. Subcategory names and the Inclusion Setting text are
translated on non-English systems and are never read. The meaning of Setting Value is inferred
and is confirmed on a lab DC.

### Datapoints

| Datapoint | Kind | Values | Alert |
|---|---|---|---|
| `SecurityGroupMgmtSuccess` | namevalue gauge | 1 / 0 | error at 0 |
| `DistributionGroupMgmtSuccess` | namevalue gauge | 1 / 0 | warn at 0 |
| `SecurityGroupMgmtFailure` | namevalue gauge | 1 / 0 | none |
| `DistributionGroupMgmtFailure` | namevalue gauge | 1 / 0 | none |
| `SecurityLogReadable` | namevalue gauge | 1 / 0 | error at 0 |
| `CollectionFailure` | expression | 1 when all five above are empty, else 0 | error at 1 |

`CollectionFailure` follows LM's Citrix pattern: `if(un(A) && un(B) && ..., 1, 0)`. Threshold
strings and alert-body tokens follow `references/module-export-schema.md` in the skill. Each
alert body says what to fix: the GPO setting (Computer Configuration > Policies > Windows Settings
> Security Settings > Advanced Audit Policy Configuration > Account Management), the `auditpol`
command that shows the effective value, and, for `SecurityLogReadable`, the Collector account's
Security-log right.

One graph, `Audit Policy Status`, shows the five status datapoints in far-apart colours, with
min 0 and max 1.

### Failure handling

- WinRM, authentication or `auditpol` failure: write the reason to stderr, print nothing, and exit
  non-zero. The five status datapoints read No Data, never a false 0.
- A subcategory missing from the CSV: its datapoints are not printed. The other subcategory's are.
- The WMI Security-log query fails with access denied: print `SecurityLogReadable=0`. Any other
  WMI failure (host unreachable): do not print it.
- **Unconfirmed:** whether LM computes the `CollectionFailure` expression after a run that exits
  non-zero. The lab test breaks the credential and watches it. If it stays empty, the fallback
  is: on connection failure, print `CollectionFailure=1` as a namevalue datapoint and exit 0. The
  observed behaviour is recorded in `docs/verification.md`.

## Repository layout

```
build/build.py                       builds every set into dist/<set>/ and runs the cross-checks
Microsoft_AD_GroupManagement/
  events.py                          the 31 IDs with their meanings
  Microsoft_AD_GroupManagement_Events.json      LogSource template
  Microsoft_AD_GroupManagement_AuditPolicy.json DataSource template, no script inside
  AuditPolicy.ps1
  tests/fixtures/                    auditpol /r CSV samples
  tests/run_tests.ps1
docs/verification.md                 which layer proved what, the one record of it
dist/                                gitignored
```

`build.py` fails the build when:

- an event ID is duplicated or not in the approved set of 31
- a datapoint printed by `AuditPolicy.ps1` is not declared in the DataSource, or a declared
  namevalue datapoint is never printed
- an expression datapoint names a datapoint that does not exist

Then the skill's `lm_lint_module.py dist` must be clean.

## Testing

`tests/run_tests.ps1` runs in Windows PowerShell 5.1 (the Collector's runtime). It prints one
`PASSED`/`FAILED` line per case and exits 1 on any failure. Cases:

- Fixtures for each policy state: Success only, Failure only, both, none, for each subcategory.
- A subcategory missing from the CSV: its datapoints are absent, not 0.
- A non-English CSV (translated names and setting text): parsed by GUID and value alone.
- Connection failure with a stubbed session: no datapoint output, non-zero exit.
- Unset-token detection for `wmi.user` / `wmi.pass` and the `auto.winrm.*` / `winrm.*` fallback.

## Verification

Recorded in `docs/verification.md`, one row per layer and claim:

1. **Local:** build, lint and `run_tests.ps1` all clean.
2. **Lab-portal round trip:** import both modules with AppliesTo `false()`, export, and diff against
   what was imported. This confirms the import accepts no `originId`, `LogName`, the `Static` log
   field and `60m`. The export replaces the template as the format reference.
3. **Live lab DC**, with the real AppliesTo:
   - Add and remove a test user in a test security group and a test distribution group. The
     events reach LM Logs mapped to the DC, with `ad_event_category = group_management`.
   - Turn off Audit Security Group Management in the GPO and run `gpupdate /force`.
     `SecurityGroupMgmtSuccess` reaches 0 and alerts. Turn it back on.
   - Break the credential. Record whether `CollectionFailure` fires; apply the fallback if it
     does not.
   - Record the `auditpol /r` Setting Value meanings as observed.

Lab names and addresses from these tests stay in `CLAUDE.local.md`. Run `../lab-scrub/check.py`
before every push.
