---
name: veh-debugging
description: Debug Windows processes or VM guests through VEH Debugger MCP, including live control-flow observation, exception disposition, tracing, and session cleanup. Use when an agent must select and interpret VEH tools across backend capabilities; not for unrelated debugger implementation work.
---

# VEH Debugging

Prove the user's next unresolved execution boundary with the connected VEH MCP tools. This skill describes public frontend usage and requires neither proprietary backend source nor private profiles.

## Establish the operation

- Restore the active goal, prohibited solutions, allowed dependencies and existing authorization. Separate a reference program used for testing from dependencies allowed in the delivered product. Auxiliary analysis earns its place by resolving that goal.
- Pick one question, the observation address/value, the expected result, a bounded time/hit/step budget and the stopping condition before adding tooling.
- Distinguish a target launched for this task from a borrowed live process. Record ownership of sessions, stops, breakpoints, hooks and temporary changes; cleanup must preserve pre-existing user state.

## Connect and qualify

- Separate configuration on disk, client-loaded configuration, live server profile, client tool filtering/approval and actual session bindings. Saved configuration is not a reconnected server. Preserve global defaults when only a project override is needed.
- Use directly exposed VEH tools. Discover only missing tools through `veh_toolbox`; one filtered manifest serves multiple schemas. Prefer native search/batch/trace over per-address loops or a new bridge. If VEH MCP is disconnected, report that boundary rather than silently starting another server.
- Confirm target scope, current PID/thread identity, bitness, current module bases and attach capabilities. Tool exposure and schema parameters do not establish backend support. Backend-name lookup failure is configuration evidence, not a guest crash.
- Backend-specific conditions come from current capabilities, public contracts and actual replies. Do not freeze tool counts, private backend names or old workarounds into instructions.

## Observe and control

- Query state before state-dependent work. A whole-VM pause, a live process, an old event or `unknown` does not prove a selected thread is stopped or responsive.
- Use the current stop's OS thread ID for selected-thread operations. For deliberate exception forwarding, pass that actual nonzero ID with `pass_exception=true`; never substitute all-thread ID 0. Decide forwarding versus consumption before resuming. `ignore_exceptions` changes disposition by automatically forwarding; it is not a display filter. Distinguish application INT3 from owned breakpoints.
- `veh_continue` is a control operation, not a wait-only API. Do not append `continue(wait=true)` merely to wait after `continue(wait=false)`: a cached stop may be returned, otherwise execution can resume. Use supported notifications/state or a capability-qualified run-to. A timeout does not prove current running state.
- Correlate session generation, stop sequence, PID/TID, reason, current RIP and hit counters. Preserve exact string IDs. A new stop after a successful resume may be a new exception; an old event is not current state.
- Resolve runtime addresses from the current module base plus RVA. Reacquire object addresses and breakpoint IDs after restart. Decode from a verified instruction boundary, check split function ranges, and use the stopped code's address width.
- Interpret arguments from the ABI and consuming instruction: a byte argument in DL does not make all of RDX a pointer. Confirm the selected register/frame context before dereferencing.
- Start with the backend's native memory view. Bound reads by page, terminator and length; distinguish partial availability from total absence. A manual walk's non-present result or a decoding failure is not proof that the object vanished.
- Check operation-specific stop requirements: a backend may permit reads while stopped as a whole but refuse native allocation/protection or software-breakpoint installation there. Read the original status before blaming hooks or declaring unsupported functionality; do not automatically resume everything to bypass a refusal.

For concrete calls, uncommon boundary cases and execution-environment pitfalls, read [references/field-guide.md](references/field-guide.md) only as needed.

## Prove and finish

- Report static hypotheses, received events, hit counters, later memory observations and executed steps separately. Neither a removed dialog nor a command acknowledgement proves the user's downstream operation succeeded.
- Treat incomplete capture as incomplete even when export succeeded. Preserve fatal errors and partial evidence; never invent missing values, events, hashes or successful cleanup.
- Remove only owned instrumentation and temporary settings. Restore the intended execution state, release owned stops/freezes as appropriate, and verify detach/cleanup receipts. `backendCleanupConfirmed=false` leaves backend cleanup unconfirmed. Never terminate a borrowed application just because a harness normally kills its own target.
- Retain the minimal useful evidence, remove disposable artifacts, and verify task-started processes are gone by executable identity and parent chain. Do not kill active agent/server trees to reload configuration or unlock files.
- Classify failures only after checking arguments, prerequisites and capability: usage error, explicit unsupported operation, unresolved cause, or reproducible product defect. Keep only reproduced unresolved defects in the defect list; remove them after the same reproduction passes.
- Improve this skill from verified session feedback: preserve the trigger, mistaken inference, correct decision, evidence and invalidation condition. Add the smallest general rule or conditional example, replace stale advice, and keep target details, credentials and private implementation out of the distributed skill.
