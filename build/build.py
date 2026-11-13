"""Build every module set into dist/<set>/ and cross-check the result.

    python build/build.py

A set is a folder at the repo root holding an events.py and *.json templates with @@...@@
placeholders. Output under dist/ is generated: never edit it, never commit it.
"""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

# The 16 security-group IDs. events.py must match this set exactly; there is no event 4736.
# The design spec's 15 distribution-group IDs were dropped (user, 2026-11-13).
APPROVED_EVENT_IDS = sorted(
    list(range(4727, 4736)) + [4737] + list(range(4754, 4759)) + [4764]
)


class BuildError(Exception):
    pass


def event_ids(module):
    ids = sorted(module.SECURITY_GROUP_EVENTS)
    if ids != APPROVED_EVENT_IDS:
        extra = sorted(set(ids) - set(APPROVED_EVENT_IDS))
        missing = sorted(set(APPROVED_EVENT_IDS) - set(ids))
        raise BuildError(f"event IDs differ from the approved 16: extra {extra}, missing {missing}")
    return ids


def event_table(module):
    events = module.SECURITY_GROUP_EVENTS
    return "\n".join(f"{i}  {events[i]}" for i in sorted(events))


def render_logsource(template, module):
    ids = event_ids(module)
    hits = [f for f in template.get("filters", []) if f.get("value") == "@@EVENT_IDS@@"]
    if len(hits) != 1:
        raise BuildError(f"expected one filter with value @@EVENT_IDS@@, found {len(hits)}")
    hits[0]["value"] = "|".join(str(i) for i in ids)
    notes = template.get("technicalNotes", "")
    if "@@EVENT_TABLE@@" not in notes:
        raise BuildError("technicalNotes has no @@EVENT_TABLE@@")
    template["technicalNotes"] = notes.replace("@@EVENT_TABLE@@", event_table(module))
    return template


def _load_events(set_dir):
    spec = importlib.util.spec_from_file_location(f"{set_dir.name}_events", set_dir / "events.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_set(set_dir, out_dir):
    set_dir, out_dir = Path(set_dir), Path(out_dir)
    module = _load_events(set_dir)
    written = []
    for tpl_path in sorted(set_dir.glob("*.json")):
        template = json.loads(tpl_path.read_text(encoding="utf-8"))
        method = template.get("collectionMethod")
        if method != "wineventlog":
            raise BuildError(f"{tpl_path.name}: no renderer for collectionMethod {method!r}")
        text = json.dumps(render_logsource(template, module), indent=4, ensure_ascii=False) + "\n"
        if "@@" in text:
            raise BuildError(f"{tpl_path.name}: placeholder left in output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / tpl_path.name
        out.write_text(text, encoding="utf-8", newline="\n")
        written.append(out)
    return written


def main():
    sets = sorted(p for p in ROOT.iterdir() if p.is_dir() and (p / "events.py").is_file())
    count = 0
    try:
        for s in sets:
            count += len(build_set(s, DIST / s.name))
    except BuildError as e:
        print(f"ERROR {e}")
        return 1
    print(f"built {count} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
