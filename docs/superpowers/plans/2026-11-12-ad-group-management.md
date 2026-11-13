# AD Group Management LogSource Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** complete (2026-11-13). Revised to what shipped: LogSource only, 16 security-group IDs, AppliesTo empty.

**Goal:** Build `Microsoft_AD_GroupManagement_Events`, a `wineventlog` LogSource for the 16 AD security-group Security events, then prove it in the lab portal and on a lab DC.

**Architecture:** The module is a JSON template in `Microsoft_AD_GroupManagement/` with `@@…@@` placeholders. `build/build.py` fills them in from `events.py`, cross-checks the result and writes it to `dist/Microsoft_AD_GroupManagement/`.

**Tech Stack:** Python 3 stdlib (build and `unittest`); the `logicmonitor-modules` skill's `lm_lint_module.py`.

**Spec:** `docs/superpowers/specs/2026-11-12-ad-group-management-design.md`

## Global Constraints

- AppliesTo ships empty (user, 2026-11-13); the technical notes suggest `hasCategory("MicrosoftDomainController")`.
- Event IDs: exactly the 16 in the spec's table; 4736 is not one of them.
- Never invent an export key or value. Shapes come from lab-portal exports of LogSources that import. Ship `registryMetadata` as `{}`; never copy `version`, `integrationMetadata`, any `originId` or an exported `registryMetadata`.
- Lab names, addresses and portal ids stay in `CLAUDE.local.md` or the scratchpad. `python ../lab-scrub/check.py` before every push.
- Commit at the end of every task; push only when the user asks.

---

### Task 1: Template, build and cross-checks

**Files:**
- Create: `Microsoft_AD_GroupManagement/events.py`
- Create: `Microsoft_AD_GroupManagement/Microsoft_AD_GroupManagement_Events.json`
- Create: `build/build.py`
- Create: `tests/test_build.py`

**Interfaces:**
- `events.py`: `SECURITY_GROUP_EVENTS: dict[int, str]` (16), mapping ID to a description such as `"Global group: member added"`.
- `build.py`:
  - `class BuildError(Exception)`
  - `event_ids(module) -> list[int]` returns the sorted IDs and raises `BuildError` if they differ from `APPROVED_EVENT_IDS`.
  - `event_table(module) -> str` returns one `technicalNotes` line per ID: `4728  Global group: member added`.
  - `render_logsource(template: dict, module) -> dict` replaces the filter value `@@EVENT_IDS@@` with a pipe-joined list and `@@EVENT_TABLE@@` in `technicalNotes`.
  - `build_set(set_dir: Path, out_dir: Path) -> list[Path]` raises `BuildError` if any output still contains `@@`.
  - `main() -> int` builds every folder with an `events.py` into `dist/<folder>/`.

- [x] **Step 1: Write the failing tests** in `tests/test_build.py`: the 16 IDs, sorted, without 4736; an unapproved or missing ID raises `BuildError`; the `In` `EventId` filter and the `LogName` filter; the `Static` `ad_event_category` field; key sets equal to a working export's; `registryMetadata == {}`; AppliesTo empty; no placeholder left.
- [x] **Step 2: Run** `python -m unittest discover -s tests -v`. Expect failures.
- [x] **Step 3: Implement** `events.py`, the template and `build.py`.
- [x] **Step 4: Run the tests again.** Expect `OK`.
- [x] **Step 5: Build and lint:** `python build/build.py` prints `built 1 modules`; `lm_lint_module.py dist` shows no `ERROR`, and two expected `WARN`s (shared checks only; empty AppliesTo).
- [x] **Step 6: Commit.**

### Task 2: Docs and lab-portal round trip (user-assisted)

**Files:**
- Create: `docs/verification.md`
- Modify: `CLAUDE.md` (Commands section), `README.md`

- [x] **Step 1: Write `docs/verification.md`:** columns *Claim / Layer (local, portal import, live target) / Result / Date*, local rows filled, pending rows for every spec Verification item.
- [x] **Step 2:** Add the commands to `CLAUDE.md`, and a module list and import steps to `README.md`.
- [x] **Step 3:** The user imports `dist/` into the lab portal and exports it again.
- [x] **Step 4: Diff the export against the build**, ignoring `version`, `originId` and the portal-filled `registryMetadata`. Record in `verification.md` that the `LogName` filter, the `In` filter and the `Static` field survived.
- [x] **Step 5: Commit**, and feed each portal lesson back into the skill (workspace `CLAUDE.md`, "Lessons go back into the skill") in the skill repo.

### Task 3: Live lab DC verification (user-assisted)

**Files:**
- Modify: `docs/verification.md`

- [x] **Step 1:** The user sets AppliesTo to the lab DC, then creates a test security group, adds and removes a member, and deletes it.
- [x] **Step 2:** In LM Logs, query `ad_event_category="group_management"`. Confirm the events arrive with their IDs, mapped to the DC, and that no other Security events get in. If nothing arrives within 10 minutes, check `lmlogs.winevent.channels` first.
- [x] **Step 3:** Record the results in `verification.md`, keeping lab names in `CLAUDE.local.md`. Run `python ../lab-scrub/check.py` and commit.
