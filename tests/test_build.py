"""Tests for build/build.py. Run: python -m unittest discover -s tests -v"""
import copy
import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SET_DIR = ROOT / "Microsoft_AD_GroupManagement"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build = _load("build", ROOT / "build" / "build.py")
events = _load("events", SET_DIR / "events.py")
TEMPLATE = json.loads((SET_DIR / "Microsoft_AD_GroupManagement_Events.json").read_text(encoding="utf-8"))


def _clone(module):
    return types.SimpleNamespace(SECURITY_GROUP_EVENTS=dict(module.SECURITY_GROUP_EVENTS))


class EventIds(unittest.TestCase):
    def test_16_security_group_ids_sorted(self):
        # Security groups only; the 15 distribution-group IDs were dropped (user, 2026-11-13).
        ids = build.event_ids(events)
        self.assertEqual(ids, [4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737,
                               4754, 4755, 4756, 4757, 4758, 4764])
        self.assertFalse(hasattr(events, "DISTRIBUTION_GROUP_EVENTS"))

    def test_unapproved_id_fails(self):
        m = _clone(events)
        m.SECURITY_GROUP_EVENTS[4736] = "not a real event"
        with self.assertRaises(build.BuildError):
            build.event_ids(m)

    def test_missing_id_fails(self):
        m = _clone(events)
        del m.SECURITY_GROUP_EVENTS[4764]
        with self.assertRaises(build.BuildError):
            build.event_ids(m)


class EventTable(unittest.TestCase):
    def test_one_line_per_event(self):
        lines = build.event_table(events).splitlines()
        self.assertEqual(len(lines), 16)
        self.assertIn("4728  Global group: member added", lines)


class RenderLogSource(unittest.TestCase):
    def setUp(self):
        self.out = build.render_logsource(copy.deepcopy(TEMPLATE), events)

    def test_event_id_filter(self):
        f = [x for x in self.out["filters"] if x["name"] == "EventId"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["op"], "In")
        self.assertEqual(f[0]["include"], "y")
        self.assertEqual(f[0]["value"].split("|"), [str(i) for i in build.APPROVED_EVENT_IDS])

    def test_logname_filter(self):
        f = [x for x in self.out["filters"] if x["name"] == "LogName"]
        self.assertEqual(f, [{"op": "Equal", "include": "y", "name": "LogName", "index": "1", "comment": "Security log only", "value": "Security"}])

    def test_technical_notes_hold_table(self):
        self.assertIn("4728", self.out["technicalNotes"])
        notes = self.out["technicalNotes"]
        self.assertNotIn("Audit Distribution Group Management", notes)
        for dropped in list(range(4744, 4754)) + list(range(4759, 4764)):
            self.assertNotIn(str(dropped), notes)
        self.assertNotIn("31", self.out["description"])

    def test_static_field(self):
        self.assertIn(
            {"method": "Static", "comment": "", "value": "group_management", "key": "ad_event_category"},
            self.out["logFields"],
        )

    def test_reference_values(self):
        o = self.out
        self.assertEqual((o["type"], o["collectionMethod"], o["collectionInterval"]), (10, "wineventlog", 60))
        self.assertEqual(o["collectionAttrs"], {"resourceMappingOp": "OR", "useWrittenTime": False, "filterOp": "AND"})
        self.assertEqual(o["appliesTo"], "")  # empty: the user sets it (user, 2026-11-13)
        self.assertIn('hasCategory("MicrosoftDomainController")', o["technicalNotes"])
        for k in ("version", "registryMetadata", "integrationMetadata", "originId"):
            self.assertNotIn(k, o)

    def test_key_sets_match_a_working_export(self):
        # Key sets of a lab-portal export of a Windows Event Logs clone that imports (2026-11-13),
        # minus the portal-owned version, registryMetadata, integrationMetadata and originId.
        # The first import, without searchKeywords, group and the filter/mapping comments,
        # was refused with code 1500.
        o = self.out
        self.assertEqual(set(o), {
            "name", "description", "appliesTo", "technicalNotes", "searchKeywords", "group",
            "type", "collectionMethod", "collectionInterval", "collectionAttrs",
            "filters", "logFields", "resourceMapping",
        })
        self.assertEqual(set(o["collectionAttrs"]), {"resourceMappingOp", "useWrittenTime", "filterOp"})
        for f in o["filters"]:
            self.assertEqual(set(f), {"op", "include", "name", "index", "comment", "value"})
        for f in o["logFields"]:
            self.assertEqual(set(f), {"method", "comment", "value", "key"})
        for f in o["resourceMapping"]:
            self.assertEqual(set(f), {"method", "index", "comment", "value", "key"})

    def test_template_without_placeholder_fails(self):
        t = copy.deepcopy(TEMPLATE)
        t["filters"] = [x for x in t["filters"] if x["name"] != "EventId"]
        with self.assertRaises(build.BuildError):
            build.render_logsource(t, events)


class BuildSet(unittest.TestCase):
    def test_writes_logsource_without_placeholders(self):
        with tempfile.TemporaryDirectory() as d:
            paths = build.build_set(SET_DIR, Path(d))
            self.assertEqual([p.name for p in paths], ["Microsoft_AD_GroupManagement_Events.json"])
            text = paths[0].read_text(encoding="utf-8")
            self.assertNotIn("@@", text)
            json.loads(text)


if __name__ == "__main__":
    unittest.main()
