---
name: veh-backend
description: Debug through a connected external VEH MCP backend, including guest-process, kernel or VM scopes when advertised. Use for backend qualification, execution hooks and backend-specific state/cleanup; excludes ordinary built-in VEH DLL sessions.
---

# VEH Backend

Use this self-contained skill for an explicitly selected external backend. Its implementation may be private: use public tool contracts, current capability replies and observed results. Read only relevant sections of [references/field-guide.md](references/field-guide.md); no other skill is required.

## Qualify the connection

- Restore the user's goal, prohibited methods, allowed dependencies and authorization. Choose one observation, expected result, bounded time/hit/step budget and stopping condition. Track task-launched versus borrowed targets and owned instrumentation.
- Separate configuration on disk, client-loaded overrides, live server profile, client filters/approvals and actual tool bindings. Preserve global defaults. Confirm backend registration before attach; unknown backend is not evidence of guest failure.
- Use directly exposed VEH MCP tools; discover only missing schemas with a filtered `veh_toolbox` manifest. Prefer native backend search/batch/trace over per-address reads or a new bridge. Do not start another server or kill an active agent tree to fix a connection.
- Confirm current backend, target scope, PID/TID, address width, module bases and capabilities. Requalify after reconnect; profile exposure, tool count and schema parameters do not establish support. Do not carry old workarounds forward without checking invalidation.

## Control the correct scope and method

- Process/thread stops, whole-process stops and VM/vCPU pause are distinct. A paused VM does not prove a selected thread has a debugger stop. Read operation-specific prerequisites: inspection may work where native allocation/protection or breakpoint installation is refused. Do not resume everything merely to bypass a refusal.
- Preserve the requested method: **EPT execution hooks and direct code modification are different and must never be substituted silently.** Qualify actual hook semantics/support on the connected backend; a tool name or hypervisor presence alone does not prove EPT implementation. If EPT-only or original-code-preserving operation is required and unavailable, report the boundary; do not fall back to memory/assembly/physical writes or software INT3.
- For selected-thread exception forwarding, use the current exception event's actual nonzero OS thread ID with `pass_exception=true`. Distinguish forwarding from consumption, application INT3 from owned breakpoints and automatic forwarding filters from display filters. Check record-only observation's exception-stop policy too.
- `veh_continue` is not wait-only: a follow-up `wait=true` call may return cached state or resume again. Use supported notifications/state or qualified run-to. Neither timeout nor `unknown` establishes running/stopped state.
- Correlate current session generation/sequence, PID/TID, reason, RIP and hits; preserve exact string IDs. Reacquire identities after restart. A new stop after resume can be a different exception; frontend sequence/queue loss is not guest capture time/completeness.
- Resolve current module base + RVA; decode verified instruction boundaries/split ranges using stopped-code width. Confirm ABI argument width and register/frame context. Prefer native memory view to a manual walker; bound page/string reads and preserve partial results.

## Verify effects and cleanup

- Separate static decode, actual execution, recovered semantics and equivalence. A branch's existence, changed flag, exported file or command acknowledgement does not prove downstream success. Preserve incomplete/fatal capture facts and original errors; do not infer hook causality or recovery-required state from generic wording.
- Remove only owned hooks/breakpoints/settings, restore intended execution state and verify backend cleanup. Session deletion, job count zero and detach success do not override `backendCleanupConfirmed=false`. Preserve borrowed processes, stops and instrumentation.
- Keep minimal evidence and clean disposable artifacts; use bounded nonblocking harnesses with finally-cleanup and verify executable/parent identity for task-started leftovers. Do not kill active MCP/agent trees or disturb a live login for deployment.
- Classify usage/precondition errors, explicit unsupported capabilities, unresolved causes and reproduced defects separately; retire a defect only after its original reproduction passes.
- Update the smallest applicable rule from verified feedback: trigger | wrong decision | correction | evidence | applicability/invalidation. Keep private implementation, registration names, target details and credentials out of distributed material.
