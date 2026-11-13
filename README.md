# LogSources

LogicMonitor LogSource modules, each importable as JSON into a LogicMonitor portal.

## Modules

| Module | Collects | Applies to |
|---|---|---|
| `Microsoft_AD_GroupManagement_Events` | The 16 Active Directory security-group Security events (groups created, changed, deleted, members added or removed, type changed; distribution groups left out), tagged `ad_event_category=group_management` | Empty: set it after import, e.g. `hasCategory("MicrosoftDomainController")` |

Prerequisites and the event list are in each module's technical notes. What each module has been
verified against is in [docs/verification.md](docs/verification.md).

## Import

1. Build: `python build/build.py`. The importable JSON is written to `dist/<set>/`.
2. In the portal, go to **Modules > My Module Toolbox > Add > From File** and pick the JSON from `dist/`.

`Microsoft_AD_GroupManagement_Events` needs the domain controllers' advanced audit policy to log
*Audit Security Group Management* successes, and the
Collector's WMI account needs read access to the Security log.
