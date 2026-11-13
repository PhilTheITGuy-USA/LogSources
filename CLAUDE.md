# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

The home for new LogicMonitor LogSource modules (user, 2026-11-12). Unlike the `<Product>-LogicModule`
suites, it groups modules by type, not by product. The repo is **public**.

The workspace `../CLAUDE.md` applies here too: use the `logicmonitor-modules` skill, lint before
calling anything done, scrub lab data and run `python ../lab-scrub/check.py` before every push, and
feed portal lessons back into the skill. Lab names, addresses and portal details go in the
gitignored `CLAUDE.local.md`.

## Commands

```sh
python build/build.py                  # templates + events.py -> dist/<set>/ (gitignored)
python -m unittest discover -s tests   # build cross-checks
python ../logicmonitor-modules-skill/skill/scripts/lm_lint_module.py dist
```

Rebuild before linting: the lint reads `dist/`. It recurses and skips non-module JSON. A LogSource
gets the shared checks only, plus one expected `WARN` that says so, and a second for an empty
AppliesTo: modules here ship it empty, opt-in, with what to set in technicalNotes (user, 2026-11-13).

A set is a folder (`Microsoft_AD_GroupManagement/`) with `events.py` and JSON templates holding
`@@EVENT_IDS@@` / `@@EVENT_TABLE@@`. Never edit `dist/`.

A clean lint is not a portal import. `docs/verification.md` is the one record of what each module
has been verified against (local checks / portal import / live target).
