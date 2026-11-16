---
name: veh
description: Debug Windows user-mode processes with the built-in VEH DLL through VEH Debugger MCP. Use for local launch/attach, breakpoints, exceptions, memory inspection and traces; excludes external-backend, guest, kernel and VM control.
---

# VEH

Use the built-in VEH DLL for the user's next unresolved process-level question. This skill is self-contained; read only relevant sections of [references/field-guide.md](references/field-guide.md) for examples and less common pitfalls.

## Establish and connect

- Restore the active goal, allowed dependencies, prohibited solutions and prior authorization. A reference program used in a test is not automatically an allowed product dependency.
- Choose one question, observation address/value, expected result, time/hit/step budget and stopping condition before adding tooling. Separate task-launched targets from borrowed live processes; track owned stops, breakpoints and temporary changes.
- Use directly exposed VEH MCP tools. Discover only missing schemas through `veh_toolbox`, using one filtered manifest for several tools; prefer native search/batch/trace to per-address loops or a new bridge. Report a disconnected MCP rather than silently starting another server.
- Separate saved configuration, loaded project overrides, live profile, client filters/approvals and actual bindings. Preserve global defaults. Confirm the current PID/TID, bitness, module bases and supported operations; exposure alone proves no support.

## Observe and control

- State-dependent inspection needs a confirmed current stop. Process survival, an old event and `unknown` are not proof of stopped state or UI responsiveness.
- For selected-thread work use the actual current stop's OS thread ID. To deliberately forward an exception, use that nonzero ID with `pass_exception=true`. Decide forwarding versus consumption first; `ignore_exceptions` automatically forwards, not merely hides. Distinguish application INT3 from owned breakpoints.
- `veh_continue` is not wait-only. Do not append `continue(wait=true)` just to wait after `continue(wait=false)`: it may return a cached stop or resume execution. Use supported notifications/state or run-to. Timeout alone does not establish running state.
- Correlate session generation/sequence, PID/TID, stop reason, current RIP and hit counters; preserve exact string IDs. A new stop after resume can be a new exception.
- Use this execution's module base + RVA and current object/BP IDs. Decode from a verified instruction boundary, follow split function ranges and use stopped-code width. Interpret arguments from ABI and consuming instructions; DL does not make all of RDX a pointer.
- Confirm register/frame context before dereferencing. Bound memory reads by page, terminator and maximum length; preserve partial success. Read/decode failure is not proof of object absence.
- Preserve the user's specified mutation method. Code writes, assembly patches, software breakpoints and register edits have different effects; do not silently substitute one for another. An unavailable required method is a boundary to report.
- Check the original error and operation prerequisites before repeating a failed mutation or blaming hooks. Do not change execution state broadly just to bypass a refusal.

## Prove, clean up and improve

- Separate static candidates, received events, hit counters, later memory and executed steps. Check actual reachability and downstream behavior; dialog removal or command acceptance is not completion. Export success does not make incomplete capture complete.
- Remove only owned instrumentation/settings, restore intended execution state, release owned stops/freezes and verify cleanup. Preserve borrowed targets and user breakpoints. Use real nonblocking timeouts and finally-cleanup for test processes; verify executable identity and parent chain before terminating leftovers. Do not kill active agent/server trees to refresh configuration.
- Keep minimal evidence; remove disposable artifacts. Classify usage errors, unmet prerequisites, explicit unsupported operations, unresolved causes and reproduced defects separately. Verify the original reproduction before retiring a defect.
- Evolve from verified feedback: trigger | wrong decision | correction | evidence | applicability/invalidation. Amend the smallest rule, retire stale workarounds and exclude private targets, credentials, source locations and session narratives.
