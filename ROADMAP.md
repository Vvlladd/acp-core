# ACP Core roadmap

Updated 2026-10-12. The accepted direction is a complete MIT local core and MIT host plugin,
with the optional Mac app kept private. The core includes the matching Swift analyzer. Commercial
work remains paused. This file does not claim future capabilities or pending acceptance as shipped.

| Priority | Outcome | Acceptance |
|---|---|---|
| Now | Independent MIT core and contributor build | Fresh public history, no app/internal files, locked build and fake-provider tests |
| Now | Easy free runtime + skill installation | Pinned compiled download, matching helper, honest Doctor/provider limits |
| Next | Trusted distribution | Developer ID signing/notarization, clean/second-machine and fresh-host checks |
| Next | Reliable first and second useful task | Observed setup, review evidence and safe recovery without losing context |
| Planned | Automatic Swift checks in builder workflows | Separately designed team/protocol and policy changes |
| Research | Codebase continuity | Source-linked maps, confirmed decisions, visible stale/conflicting assumptions and return briefs |
| Later | Optional paid continuity automation through skill and app | Measured benefit and recurring demand; no current billing or entitlement |

MCP interoperability and mixed-agent orchestration already exist in the market. Compare
[Superset](https://docs.superset.sh/orchestration), [Intent](https://intentapp.dev/),
[Entire](https://github.com/entireio/cli) and [HumanLayer](https://www.humanlayer.com/).
ACP must earn adoption through useful local execution, inspectable controls and retained
understanding. No unique moat or productivity multiplier has been demonstrated. Users' own
evidence should remain accessible. A paid app-only dashboard is not an established business case.

```mermaid
flowchart LR
    source[MIT core and skill] --> install[Independent installation]
    install --> repeat[Second useful task and recovery]
    repeat --> evidence[Measure understanding and return time]
    evidence -. validate .-> context[Confirmed decisions and current maps]
    context -. later .-> paid[Optional continuity automation]
```
