# AD Group Management Modules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `Microsoft_AD_GroupManagement_Events` (a `wineventlog` LogSource for the 31 AD group-management Security events) and `Microsoft_AD_GroupManagement_AuditPolicy` (a PowerShell DataSource that alerts when the audit policy behind them is off), then prove both in the lab portal and on a lab DC.

**Architecture:** Each module is a JSON template in `Microsoft_AD_GroupManagement/` with `@@…@@` placeholders. `build/build.py` fills them in: the event list comes from `events.py`, and the script from `AuditPolicy.ps1`. The build cross-checks the result and writes it to `dist/Microsoft_AD_GroupManagement/`. The PowerShell script keeps every decision in pure functions, which tests load with a test-mode switch, and does its I/O through two injectable script blocks.

**Tech Stack:** Python 3 stdlib (build and `unittest`); Windows PowerShell 5.1 (`powershell.exe`, the Collector's runtime) for the script and its tests; the `logicmonitor-modules` skill's `lm_lint_module.py`.

**Spec:** `docs/superpowers/specs/2026-11-12-ad-group-management-design.md`

## Global Constraints

- AppliesTo for both modules: `hasCategory("MicrosoftDomainController")`. The round-trip import (Task 6) temporarily uses `false()`.
- Event IDs: exactly the 31 in the spec's two tables; 4736 is not one of them.
- Never invent an export key or value. Shapes come from: `Windows Event Logs` and its lab clones (LogSource), `Citrix_XenApp_DatastoreStatus` (single-instance PowerShell DataSource), and the skill's `references/module-export-schema.md` §2 (datapoints, graphs). Never copy `version`, `registryMetadata`, `integrationMetadata` or any `originId`.
- Thresholds follow `"<op> warn error critical"`: warn-only is `"< 1"`, error is `"< 1 1"`, and for `CollectionFailure` error is `"> 0 0"`.
- Datapoint names, exactly: `SecurityGroupMgmtSuccess`, `DistributionGroupMgmtSuccess`, `SecurityGroupMgmtFailure`, `DistributionGroupMgmtFailure`, `SecurityLogReadable`, `CollectionFailure`.
- Subcategory GUIDs: Security Group Management `{0CCE9237-69AE-11D9-BED3-505054503030}`; Distribution Group Management `{0CCE9238-69AE-11D9-BED3-505054503030}`.
- The script prints with `Write-Output` and errors with `[Console]::Error.WriteLine`. It exits 0 on success and 2 on connection or `auditpol` failure, and never prints a 0 that means "unknown".
- No LM copyright header in our scripts.
- Lab names, addresses and DC output stay in `CLAUDE.local.md` or the scratchpad. Fixtures use `DC-A` / `example.test`. `python ../lab-scrub/check.py` before every push.
- Commit at the end of every task; push only when the user asks.

## Review Focus

1. **`auditpol` prints extra lines or a blank header** (some builds emit a blank first line or a trailing newline): the parser must skip non-data rows, not fail or misread them. Covered by a test in Task 2.
2. **The CSV has a row for an unknown GUID** (a future `auditpol` returning more rows than asked): ignored. Covered by a test in Task 2.
3. **The WinRM property holds an unexpected value** (`winrm.port` = `abc` or `70000`, `usessl` = `TRUE` or `yes`): port falls back to the default for the scheme; booleans accept `true/yes/on/1` in any case. Covered by tests in Task 3.
4. **`##SYSTEM.HOSTNAME##` is an IP with no reverse DNS:** the IP is kept and the connection is attempted, not abandoned. Covered by a test in Task 3.
5. **The Security-log probe throws a non-access error** (RPC unavailable): `SecurityLogReadable` is withheld, not reported as 0. Covered by a test in Task 4.

---

### Task 1: Record a real `auditpol /r` sample (user-assisted)

The parser's column layout must come from real output, not memory.

**Files:**
- Create: `Microsoft_AD_GroupManagement/tests/fixtures/auditpol_lab_raw.csv` (scrubbed)

- [ ] **Step 1: Ask the user** to run this in an **elevated** PowerShell on a lab DC (or any Windows machine, for the format), and to give back the output file path:
  `auditpol /get /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030},{0CCE9238-69AE-11D9-BED3-505054503030}" /r | Out-File $env:TEMP\auditpol.csv -Encoding utf8`
- [ ] **Step 2: Scrub it.** Replace the machine name with `DC-A`. Save as the fixture. Record the header line, the column count, and what the `Setting Value` column (or whatever holds the numeric value) contains for the current state, in the task report.
- [ ] **Step 3: Decide column access from the sample.** If the header names a numeric setting column, the parser reads by **column position** (headers may be translated), and the positions go into `$AuditPolColumns` in Task 2. If no numeric column exists, stop and report to the user. The spec's no-translated-text rule then needs a decision.
- [ ] **Step 4: Run `python ../lab-scrub/check.py`** (expect `clean`), then commit:
  `git add Microsoft_AD_GroupManagement/tests/fixtures && git commit -m "Add a recorded auditpol /r sample"`

### Task 2: CSV parser and its tests

**Files:**
- Create: `Microsoft_AD_GroupManagement/AuditPolicy.ps1`
- Create: `Microsoft_AD_GroupManagement/tests/run_tests.ps1`
- Create: `Microsoft_AD_GroupManagement/tests/fixtures/auditpol_{success,failure,both,none,security_only,fr,noise}.csv`

**Interfaces:**
- Consumes: the column layout from Task 1.
- Produces:
  - `ConvertFrom-AuditPolCsv -Lines [string[]] -> [hashtable]` with keys among `SecurityGroupMgmtSuccess`, `SecurityGroupMgmtFailure`, `DistributionGroupMgmtSuccess`, `DistributionGroupMgmtFailure` and values `[int]` 0/1. A subcategory with no row has no keys.
  - `$DatapointOrder` (the six names, in the Global Constraints order) on one line: `$DatapointOrder = @('…', …)`. `build.py` reads this exact line.
  - `Format-Datapoints -Values [hashtable] -> [string[]]`, giving `Name=value` in `$DatapointOrder` order, skipping absent keys.
  - Test-mode switch: when `$AuditPolicyTestMode` is `$true` before the script is dot-sourced, the script defines its functions and does not run.
  - `run_tests.ps1` helper `Assert-Equal($Name, $Expected, $Actual)` prints `PASSED <name>` or `FAILED <name>: expected … got …`. The script exits 1 if any case failed.

- [ ] **Step 1: Build the fixtures** from the Task 1 sample by editing only the numeric setting cell (1 Success, 2 Failure, 3 both, 0 none):
  - `success`, `failure`, `both` and `none` set both rows to that value
  - `security_only` drops the distribution row
  - `fr` translates the subcategory and inclusion-text cells to French and keeps the GUID and value
  - `noise` adds a blank first line, a trailing blank line and an extra row with GUID `{0CCE9999-0000-0000-0000-000000000000}`
- [ ] **Step 2: Write the failing tests** in `run_tests.ps1`. It sets `$AuditPolicyTestMode = $true`, dot-sources `..\AuditPolicy.ps1`, and asserts:
  - `success` → SecurityGroupMgmtSuccess 1, SecurityGroupMgmtFailure 0, DistributionGroupMgmtSuccess 1, DistributionGroupMgmtFailure 0
  - `failure` → Success 0 / Failure 1 for both
  - `both` → all four 1
  - `none` → all four 0
  - `security_only` → the hashtable has no `DistributionGroupMgmt*` keys and both Security keys are present
  - `fr` gives the same result as `success`
  - `noise` gives the same result as `success`, and the result has exactly 4 keys
  - `Format-Datapoints @{SecurityLogReadable=1; SecurityGroupMgmtSuccess=1}` → `@('SecurityGroupMgmtSuccess=1','SecurityLogReadable=1')`
- [ ] **Step 3: Run** `powershell.exe -NoProfile -File Microsoft_AD_GroupManagement\tests\run_tests.ps1`. Expect `FAILED` lines (functions not defined) and exit 1.
- [ ] **Step 4: Implement** `ConvertFrom-AuditPolCsv`, `Format-Datapoints`, `$DatapointOrder` and the test-mode guard in `AuditPolicy.ps1`. Parse with `ConvertFrom-Csv -Header` using positional names, so translated headers don't matter. Match GUIDs case-insensitively. Ignore rows whose value column isn't an integer from 0 to 3. Success = `value -band 1`, Failure = `(value -band 2) / 2`.
- [ ] **Step 5: Run the tests again.** Expect all `PASSED` and exit 0.
- [ ] **Step 6: Commit**, with message "Parse auditpol /r output by GUID and setting value".

### Task 3: Property handling and connection options

**Files:**
- Modify: `Microsoft_AD_GroupManagement/AuditPolicy.ps1`
- Modify: `Microsoft_AD_GroupManagement/tests/run_tests.ps1`

**Interfaces:**
- Produces:
  - `Get-LmProperty -Value [string] -> [string] or $null`. Returns `$null` when the value is blank or still a literal `##…##` token. Otherwise returns it trimmed.
  - `Get-WinRmOptions -Props [hashtable] -> [hashtable]` with keys `UseSSL` [bool], `Port` [int], `SkipCACheck`, `SkipCNCheck`, `SkipRevocationCheck` [bool]. For each setting, `auto.winrm.<x>` is used if set, otherwise `winrm.<x>`. Booleans match `^(?i:true|yes|on|1)$`. A port outside 1–65535 or non-numeric becomes 5986 if UseSSL, otherwise 5985.
  - `Resolve-TargetName -Hostname [string] -Resolver [scriptblock] -> [string]`. If the hostname is an IPv4 address, it returns `& $Resolver $ip`, or the IP itself when the resolver throws. Otherwise it returns the hostname lowercased.
  - `Test-IsLocalTarget -Hostname [string] -LocalNames [string[]] -> [bool]`. Case-insensitive match against `LocalNames` plus `localhost` and `127.0.0.1`.
  - `$Props` is a hashtable built at the top of the script from tokens: `system.hostname`, `wmi.user`, `wmi.pass`, `auto.winrm` and, for each of `usessl`, `port`, `skipcacheck`, `skipcncheck` and `skiprevocationcheck`, both the `auto.winrm.<x>` and `winrm.<x>` forms. The tokens are in the form `'##AUTO.WINRM.USESSL##'`. Passwords use the here-string form, as in LM's `Microsoft_Powershell_Info`.

- [ ] **Step 1: Write the failing tests:**
  - `Get-LmProperty '##WMI.USER##'` → `$null`; `'  '` → `$null`; `' svc_lm '` → `'svc_lm'`
  - `Get-WinRmOptions @{'auto.winrm.usessl'='TRUE'; 'winrm.usessl'='false'}` → `UseSSL $true`, `Port 5986`
  - `@{'winrm.usessl'='yes'; 'winrm.port'='abc'}` → `UseSSL $true`, `Port 5986`
  - `@{'winrm.port'='70000'}` → `Port 5985`
  - `@{}` → all false, `Port 5985`
  - `@{'winrm.skiprevocationcheck'='1'}` → `SkipRevocationCheck $true`
  - `Resolve-TargetName '192.0.2.10' {throw 'no PTR'}` → `'192.0.2.10'`
  - `Resolve-TargetName '192.0.2.10' {'dc-a.example.test'}` → `'dc-a.example.test'`
  - `Resolve-TargetName 'DC-A.example.test' {throw}` → `'dc-a.example.test'`
  - `Test-IsLocalTarget 'COLLECTOR1' @('collector1','collector1.example.test')` → `$true`
  - `Test-IsLocalTarget 'dc-a.example.test' @('collector1')` → `$false`
- [ ] **Step 2: Run the tests.** Expect the new cases to fail.
- [ ] **Step 3: Implement** the four functions and the `$Props` block.
- [ ] **Step 4: Run the tests.** Expect all `PASSED`.
- [ ] **Step 5: Commit**, with message "Read WinRM options and credentials as LM's modules do".

### Task 4: The collection run

**Files:**
- Modify: `Microsoft_AD_GroupManagement/AuditPolicy.ps1`
- Modify: `Microsoft_AD_GroupManagement/tests/run_tests.ps1`

**Interfaces:**
- Consumes: Tasks 2 and 3.
- Produces:
  - `Invoke-AuditPolicyCheck -Props [hashtable] -RemoteRunner [scriptblock] -LogProbe [scriptblock] -> [hashtable]` returning `@{ Lines = [string[]]; Error = [string] or $null; ExitCode = [int] }`.
    - `RemoteRunner` takes a target name and a WinRM options hashtable, and returns CSV lines or throws.
    - `LogProbe` takes a target name, returning `1` if readable or `0` on access denied, or throws for anything else.
  - Real implementations `New-RemoteRunner -Credential` and `New-LogProbe -Credential`:
    - The runner runs `auditpol` locally when `Test-IsLocalTarget`. Otherwise it uses `New-PSSession` (with `New-PSSessionOption` for the skip flags), then `Invoke-Command`, then `Remove-PSSession` in `finally`.
    - The probe uses `Get-WmiObject Win32_NTEventlogFile -Filter "LogfileName='Security'" -ComputerName … [-Credential …]`. An `UnauthorizedAccessException` or `Access denied`/`0x80070005` means 0.
  - The script's main block, outside test mode, calls `Invoke-AuditPolicyCheck` with the real runners. It writes each line with `Write-Output`, writes `Error` to stderr, and exits with `ExitCode`.

- [ ] **Step 1: Write the failing tests**, with stub script blocks:
  - The runner returns the `success` fixture and the probe returns 1. Lines are the four `*Mgmt*` lines plus `SecurityLogReadable=1`, in `$DatapointOrder` order. `ExitCode` is 0 and `Error` is `$null`.
  - The probe returns 0: `SecurityLogReadable=0` is present.
  - The probe throws `'The RPC server is unavailable'`: no `SecurityLogReadable` line, and `ExitCode` is 0.
  - The runner throws `'WinRM cannot complete the operation'`: `Lines` is empty, `ExitCode` is 2, and `Error` contains `WinRM cannot complete the operation`.
  - `Props['auto.winrm'] = 'disabled'`: the runner is never called (the stub sets a flag), `Lines` is empty, `ExitCode` is 2, and `Error` contains `auto.winrm`.
  - The runner returns only blank lines: `ExitCode` is 2, and `Error` contains `auditpol`.
  - No line in any case ends in `CollectionFailure=…`. It is an expression datapoint, never printed.
- [ ] **Step 2: Run the tests.** Expect the new cases to fail.
- [ ] **Step 3: Implement** `Invoke-AuditPolicyCheck`, `New-RemoteRunner`, `New-LogProbe` and the main block. Credentials come from `Get-LmProperty` on `wmi.user`/`wmi.pass`. Both must be set to build a `PSCredential`; otherwise pass none.
- [ ] **Step 4: Run the tests.** Expect all `PASSED`.
- [ ] **Step 5: Run the script once outside test mode on this workstation:** `powershell.exe -NoProfile -File Microsoft_AD_GroupManagement\AuditPolicy.ps1`. Its tokens are unreplaced, so the hostname is the literal token. Expect a non-zero exit and one stderr line, with no stack trace and no datapoint lines.
- [ ] **Step 6: Commit**, with message "Run the audit-policy check with injectable I/O".

### Task 5: Templates, build and cross-checks

**Files:**
- Create: `Microsoft_AD_GroupManagement/events.py`
- Create: `Microsoft_AD_GroupManagement/Microsoft_AD_GroupManagement_Events.json`
- Create: `Microsoft_AD_GroupManagement/Microsoft_AD_GroupManagement_AuditPolicy.json`
- Create: `build/build.py`
- Create: `tests/test_build.py`

**Interfaces:**
- Consumes: the `$DatapointOrder` line in `AuditPolicy.ps1` (Task 2).
- Produces:
  - `events.py`: `SECURITY_GROUP_EVENTS: dict[int, str]` (16) and `DISTRIBUTION_GROUP_EVENTS: dict[int, str]` (15), each mapping ID to a description such as `"Global group: member added"`.
  - `build.py`:
    - `class BuildError(Exception)`
    - `event_ids(module) -> list[int]` returns the sorted union. It raises `BuildError` if the two dicts overlap, or if the union differs from the 31 IDs hard-coded in `build.py` as `APPROVED_EVENT_IDS`.
    - `event_table(module) -> str` returns plain-text `technicalNotes` lines, one per ID: `4728  Global group: member added`, grouped under `Security groups:` / `Distribution groups:`.
    - `render_logsource(template: dict, module) -> dict` replaces the filter value `@@EVENT_IDS@@` with a pipe-joined list and `@@EVENT_TABLE@@` in `technicalNotes`.
    - `printed_datapoints(script: str) -> list[str]` parses the `$DatapointOrder = @(...)` line.
    - `render_datasource(template: dict, script: str) -> dict` replaces `@@SCRIPT@@` in `collectionAttrs.content`. It raises `BuildError` if:
      - the set of `namevalue` datapoints ≠ `printed_datapoints` minus the `expression` datapoints
      - an `un(X)` in an expression names no datapoint
      - any `interpretExpr` contains `##WILDVALUE##`
    - `build_set(set_dir: Path, out_dir: Path) -> list[Path]` also raises `BuildError` if any output string still contains `@@`.
    - `main() -> int` builds every folder with an `events.py` or `*.json` template into `dist/<folder>/`, prints `ERROR …` and returns 1 on a `BuildError`, and prints `built N modules` on success.
- Template content:
  - **LogSource:** keys and values per spec Module 1, in the reference's key order. The `ad_event_category` log field is `{"method": "Static", "comment": "", "value": "group_management", "key": "ad_event_category"}`. The description says what it ingests and names the companion DataSource.
  - **DataSource:** top-level keys per `Citrix_XenApp_DatastoreStatus` (`name`, `displayedAs` = `AD Group Management Audit Policy`, `description`, `appliesTo`, `technicalNotes`, `searchKeywords`, `group: ""`, `collectionInterval: "60m"`, `collectionMethod: "script"`, `multiInstance: false`, `useWildValueAsUniqueIdentifier: false`, `dataSourceType: 1`, `type: 0`, `collectionAttrs`, `datapoints`, `graphs`).
    - Datapoint keys per schema §2: `type` `gauge`, `dataType` 7, `useValue` `output`, `noData` `Do not trigger an alert`, `triggerInterval` 0, `clearInterval` 0.
    - Thresholds per Global Constraints: `SecurityGroupMgmtSuccess` and `SecurityLogReadable` `"< 1 1"`; `DistributionGroupMgmtSuccess` `"< 1"`; the two `*Failure` datapoints `""`.
    - `CollectionFailure`: `interpretMethod` `expression`, `interpretExpr` `if(un(SecurityGroupMgmtSuccess) && un(DistributionGroupMgmtSuccess) && un(SecurityGroupMgmtFailure) && un(DistributionGroupMgmtFailure) && un(SecurityLogReadable), 1, 0)`, `threshold` `"> 0 0"`, no `useValue`, matching Citrix.
    - `statusDisplayNames` on the five 0/1 datapoints: `Off`/`On` for the four audit datapoints and `Denied`/`Readable` for `SecurityLogReadable`, each `{"statusDisplayName", "metricValue", "operator": "EQ"}`. The alert bodies use `##ALERTVALUEDISPLAYSTATUSNAME##` and the spec's fix text.
    - One graph `Audit Policy Status`: `max` 1, `rigid` true, `min` 0, `timeScale` `1day`, `displayPriority` 1. Five `line` lines in `blue`, `green`, `orange`, `fuchsia` and `teal`; alias = datapoint name.

- [ ] **Step 1: Write the failing tests** in `tests/test_build.py` (stdlib `unittest`, importing `build/build.py` through `importlib`):
  - `event_ids` returns 31 IDs, includes 4764, excludes 4736, and is sorted
  - adding 4736 to a copy of the module raises `BuildError`
  - an overlap between the two dicts raises `BuildError`
  - `render_logsource` on the real template: the filter with `name == "EventId"` has `op == "In"`, `include == "y"`, and a value that splits on `|` into the 31 IDs as strings; `technicalNotes` contains `4728` and `Distribution groups:`
  - `printed_datapoints` on the real script returns the six names in order
  - `render_datasource` with a template that drops `SecurityLogReadable` raises `BuildError` naming it; one whose expression reads `un(Nope)` raises `BuildError`
  - `build_set` on the real folder writes two files, and neither contains `@@`
- [ ] **Step 2: Run** `python -m unittest discover -s tests -v`. Expect errors, since `build.py` is missing.
- [ ] **Step 3: Implement** `events.py`, both templates and `build.py`.
- [ ] **Step 4: Run the tests again.** Expect `OK`.
- [ ] **Step 5: Build and lint:**
  - `python build/build.py` should print `built 2 modules`.
  - `python ../logicmonitor-modules-skill/skill/scripts/lm_lint_module.py dist` should show no `ERROR`. The LogSource gets the shared-checks-only `WARN`. Note any other `WARN` in the task report and judge it.
- [ ] **Step 6: Commit**, with message "Build both modules from templates with cross-checks".

### Task 6: Docs and lab-portal round trip (user-assisted)

**Files:**
- Create: `docs/verification.md`
- Modify: `CLAUDE.md` (Commands section), `README.md`
- Create (gitignored scratch, not committed): round-trip exports go in the session scratchpad

**Interfaces:**
- Consumes: `dist/Microsoft_AD_GroupManagement/*.json` from Task 5.

- [ ] **Step 1: Write `docs/verification.md`.** It has one table per module with columns *Claim / Layer (local, portal import, live target) / Result / Date*. Pre-fill the local rows from Tasks 2–5, and add pending rows for every spec Verification item.
- [ ] **Step 2: Add a Commands section to `CLAUDE.md`:** build, `python -m unittest discover -s tests`, `powershell.exe -NoProfile -File Microsoft_AD_GroupManagement\tests\run_tests.ps1`, lint. Note that there's no single-test filter for the PowerShell tests; read their `FAILED` lines. Add a module list and import steps to `README.md`.
- [ ] **Step 3: Build a round-trip copy** with both AppliesTo values set to `false()`, written to the scratchpad. Ask the user to import both into the lab portal and export them again. The DataSource is imported first; order doesn't matter, as nothing references the other.
- [ ] **Step 4: Diff each export against its import** (key by key, ignoring `version`, `registryMetadata`, `integrationMetadata`, `originId`). Record in `verification.md` whether each of these survived: missing `originId`, the `LogName` filter, the `Static` log field, `"60m"`, `statusDisplayNames`, the `CollectionFailure` expression and the graph. If anything was dropped or renamed, fix the template to the exported form, re-run Task 5 Steps 4–5, and record it.
- [ ] **Step 5: Commit**, with message "Record the lab-portal round trip". If the portal taught something new, add it to the skill per the workspace `CLAUDE.md` ("Lessons go back into the skill") in a separate commit in the skill repo.

### Task 7: Live lab DC verification (user-assisted)

**Files:**
- Modify: `docs/verification.md`, and possibly `AuditPolicy.ps1` plus the DataSource template and tests (fallback only)

- [ ] **Step 1:** The user imports the real `dist/` modules (real AppliesTo). Confirm the DataSource appears on the lab DC and reports `SecurityGroupMgmtSuccess`, `DistributionGroupMgmtSuccess` and `SecurityLogReadable` with the values that `auditpol` shows on that DC. Record the observed `Setting Value` meaning.
- [ ] **Step 2:** The user adds and removes a test user in a test security group and a test distribution group. In LM Logs, query `ad_event_category="group_management"` and confirm 4728/4729 (or the matching scope) and 4751/4752 (or the matching scope) appear, mapped to the DC. If nothing arrives within 10 minutes, check `lmlogs.winevent.channels` first and record the finding.
- [ ] **Step 3:** The user turns off Audit Security Group Management in the GPO and runs `gpupdate /force`. Within one poll, `SecurityGroupMgmtSuccess` reads `Off (0)` and an error alert opens. Turn it back on and confirm the alert clears.
- [ ] **Step 4:** The user sets a wrong `wmi.pass` on the DC. Record whether `CollectionFailure` reaches 1 and alerts.
  - **If it does not**, apply the spec's fallback with TDD in `run_tests.ps1`: change the "runner throws" test to expect `Lines = @('CollectionFailure=1')`, `ExitCode` 0 and `Error` still set. Change `CollectionFailure` in the template to `namevalue` / `CollectionFailure`, add it to the printed set, print `CollectionFailure=0` on success, update `test_build.py`, and rebuild and re-verify.
  - Restore the credential.
- [ ] **Step 5:** Record every result and date in `verification.md`. Put lab names only in `CLAUDE.local.md`. Run `python ../lab-scrub/check.py` and commit, with message "Record live lab verification". Feed any new platform lesson back into the skill as in Task 6 Step 5.
