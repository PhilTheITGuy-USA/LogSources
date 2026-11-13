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
    return types.SimpleNamespace(
        SECURITY_GROUP_EVENTS=dict(module.SECURITY_GROUP_EVENTS),
        DISTRIBUTION_GROUP_EVENTS=dict(module.DISTRIBUTION_GROUP_EVENTS),
    )


class EventIds(unittest.TestCase):
    def test_31_sorted_with_4764_without_4736(self):
        ids = build.event_ids(events)
        self.assertEqual(len(ids), 31)
        self.assertEqual(ids, sorted(ids))
        self.assertIn(4764, ids)
        self.assertNotIn(4736, ids)

    def test_unapproved_id_fails(self):
        m = _clone(events)
        m.SECURITY_GROUP_EVENTS[4736] = "not a real event"
        with self.assertRaises(build.BuildError):
            build.event_ids(m)

    def test_overlap_fails(self):
        m = _clone(events)
        m.DISTRIBUTION_GROUP_EVENTS[4728] = "duplicate"
        with self.assertRaises(build.BuildError):
            build.event_ids(m)

    def test_missing_id_fails(self):
        m = _clone(events)
        del m.DISTRIBUTION_GROUP_EVENTS[4763]
        with self.assertRaises(build.BuildError):
            build.event_ids(m)


class EventTable(unittest.TestCase):
    def test_grouped_lines(self):
        table = build.event_table(events)
        self.assertIn("Security groups:", table)
        self.assertIn("Distribution groups:", table)
        self.assertLess(table.index("Security groups:"), table.index("Distribution groups:"))
        self.assertIn("4728  Global group: member added", table)


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
        self.assertEqual(f, [{"op": "Equal", "include": "y", "name": "LogName", "index": "1", "value": "Security"}])

    def test_technical_notes_hold_table(self):
        self.assertIn("4728", self.out["technicalNotes"])
        self.assertIn("Distribution groups:", self.out["technicalNotes"])

    def test_static_field(self):
        self.assertIn(
            {"method": "Static", "comment": "", "value": "group_management", "key": "ad_event_category"},
            self.out["logFields"],
        )

    def test_reference_values(self):
        o = self.out
        self.assertEqual((o["type"], o["collectionMethod"], o["collectionInterval"]), (10, "wineventlog", 60))
        self.assertEqual(o["collectionAttrs"], {"resourceMappingOp": "OR", "useWrittenTime": False, "filterOp": "AND"})
        self.assertEqual(o["appliesTo"], 'hasCategory("MicrosoftDomainController")')
        for k in ("version", "registryMetadata", "integrationMetadata", "originId"):
            self.assertNotIn(k, o)

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
