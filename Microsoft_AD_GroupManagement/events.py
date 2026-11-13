"""The AD group-management Security events this set ingests -- the single source.

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

# Produced by Audit Distribution Group Management.
DISTRIBUTION_GROUP_EVENTS = {
    4744: "Domain Local distribution group: created",
    4745: "Domain Local distribution group: changed",
    4746: "Domain Local distribution group: member added",
    4747: "Domain Local distribution group: member removed",
    4748: "Domain Local distribution group: deleted",
    4749: "Global distribution group: created",
    4750: "Global distribution group: changed",
    4751: "Global distribution group: member added",
    4752: "Global distribution group: member removed",
    4753: "Global distribution group: deleted",
    4759: "Universal distribution group: created",
    4760: "Universal distribution group: changed",
    4761: "Universal distribution group: member added",
    4762: "Universal distribution group: member removed",
    4763: "Universal distribution group: deleted",
}
