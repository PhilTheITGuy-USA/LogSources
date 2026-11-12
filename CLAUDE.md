# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

The home for new LogicMonitor LogSource modules (user, 2026-11-12). Unlike the `<Product>-LogicModule`
suites, it groups modules by type, not by product. The repo is **public**.

The workspace `../CLAUDE.md` applies here too: use the `logicmonitor-modules` skill, lint before
calling anything done, scrub lab data and run `python ../lab-scrub/check.py` before every push, and
feed portal lessons back into the skill. Lab names, addresses and portal details go in the
gitignored `CLAUDE.local.md`.

## Checks

```sh
python ../logicmonitor-modules-skill/skill/scripts/lm_lint_module.py .
```

The lint recurses and skips non-module JSON. A clean lint is not a portal import. Record what each
module has been verified against (local checks / portal import / live target) in one place in
this repo once the first module lands.
