"""The AD security-group events this set ingests -- the single source. Distribution groups
(4744-4753, 4759-4763) are left out: they grant no permissions (user, 2026-11-13).

build/build.py writes these into the LogSource's EventId filter and its technicalNotes.
"""

# Produced by Audit Security Group Management.
SECURITY_GROUP_EVENTS = {
    4727: "Global group: created",
    4737: "Global group: changed",
    4728: "Global group: member added",
    4729: "Global group: member removed",
    4730: "Global group: deleted",
    4731: "Local group: created",
    4735: "Local group: changed",
    4732: "Local group: member added",
    4733: "Local group: member removed",
    4734: "Local group: deleted",
    4754: "Universal group: created",
    4755: "Universal group: changed",
    4756: "Universal group: member added",
    4757: "Universal group: member removed",
    4758: "Universal group: deleted",
    4764: "Group type or scope changed",
}

