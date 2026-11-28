# VEH user-mode field guide

Read the relevant section for the current operation. Examples use synthetic IDs and addresses. Replace them with current observations and validate the connected tool schema; they are not commands to replay blindly.

## Connection and bounded discovery

| Input condition | Action | Expected evidence / stop condition |
|---|---|---|
| Tool bindings differ from saved configuration | Compare live profile, actual exposed bindings, client filters and loaded project configuration. Check cwd/trust requirements in the client's documented configuration contract. | Project-local scope is applied without changing unrelated global defaults; otherwise report saved versus active separately. |
| A needed tool is absent from current bindings | Use `veh_toolbox({"operation":"describe","tool":"veh_execution"})`. For several missing schemas use one `manifest` with exact `tools`. | Schema or an explicit discovery failure; do not dump the whole registry. |
| A session is already attached | Establish ownership before replacing/detaching it. Qualify conditional breakpoints and other optional features from this attach, not a prior session. | Current target/capability evidence. No forced agent/server termination to refresh configuration. |
| Every injection method fails (`LoadLibrary returned NULL`) on a target whose static DLL hooks thread start or file open | Relaunch with `veh_launch` `injectionMethod="importTable"`; add `restoreImports=true` only if the target may check its PE headers. Attach cannot use it. | Launch success with the DLL loaded before the static DLL; otherwise report the launch error unchanged. |
| High-cardinality inspection | Estimate scope; use native search, filters and supported batch/trace paths with bounded result fields/output. | Small counts, selected matches and artifact receipts. Do not serialize shell object metadata as plain text. |

## Selected-thread execution

Call `veh_continue` for an existing exception stop on synthetic OS thread 77 only when the intended next action is delivery to the application handler:

```json
{"threadId":77,"pass_exception":true,"wait":true,"timeout":10}
```

Require a current exception event and supported forwarding; use its actual nonzero thread ID. Expect a confirmed next stop, timeout or error, not necessarily application success. If refused, check arguments, current state and the original operation status before labeling the feature unsupported. On a successful resume, correlate the next event/state before issuing another resume.

For supported state inspection, including after a timeout:

```json
{"operation":"state","threadId":77}
```

Call this as `veh_execution`. Expect `stopped`, `running` or `unknown` with available identity fields. Preserve `unknown`; compare current registers and hits when available. Notifications are opt-in and bounded; queue loss is not proof of complete observation, and frontend sequence is not capture time.

| Situation | Correct decision |
|---|---|
| Observation is intended to be record-only | Check exception-stop and auto-forward policies first. Recording intent does not guarantee execution cannot stop. |
| First-chance exception | Identify its code, origin and intended handler before selecting forwarding/consumption. Do not assign one policy to all exception codes. |
| Application INT3 versus debugger breakpoint | Identify ownership and reason before forwarding; blindly forwarding all INT3 can create an unhandled exception. |
| Run-to or breakpoint actions | Verify advertised support, automatic continuation and temporary ownership. Observe batch/action lifecycle exclusions; do not nest session replacement. |
| Cancel or detach | Cancellation is not execution rollback. Preserve borrowed breakpoints; unconfirmed removal/cleanup remains unconfirmed even if the frontend session disappears or job count becomes zero. |

## Memory, frames and code evidence

| Trap | Required check |
|---|---|
| File VA reused after launch | Identify the binary/build and use current module base + RVA; never reuse another execution's PID/TID/object/BP IDs. |
| Disassembly starts inside an instruction | Use a verified function start, instruction address or stopped IP; follow split ranges. Exclude unaligned garbage from patch evidence. |
| Large register resembles a pointer | Check prototype/ABI and actual consuming instruction. `movzx ...,dl` consumes one byte. |
| Unwound frame output differs from expression context | Validate selected context and nonvolatile restoration; read a small range using explicit verified frame addresses. |
| Dump stack has wrong symbols | Use system/module images matching the captured target; repeat unwind before attributing a cause. |
| One range read fails | Retry only the necessary page-bounded slices; preserve partial success and identity/counter observations around the read. |
| String read/decode fails | Respect page boundaries, terminators, maximum length and UTF-16 surrogate boundaries; do not blame the target string from decoder failure alone. |
| Same vtable slot offset | Verify owning object/table, actual function and return ABI; inspect the original configuration path before patching. |
| Memory/trace export file exists | Inspect capture completeness, fatal gaps and exact execution counters. Static decoded bytes, executed trace, recovered semantics and native equivalence are distinct claims. |
| Suspected protection/virtualization scheme | Keep identity/version unknown without evidence; use generic observed occurrences instead of guessing a specialized plugin. |

Record branch/patch evidence as a compact table: binary identity, RVA, original bytes, nearby verified instructions, observed result and limit of the claim. Keep raw target-specific evidence private; publish synthetic examples.

## Reach the user's actual boundary

| Tempting inference | Required separation |
|---|---|
| Reference program works, so it is an acceptable product dependency | Preserve the user's allowed dependency set and forbidden solutions. Embedded browser permission does not imply permission to require an external browser. |
| Local check result changed, so downstream service access works | Trace actual check → stored result → UI/control branch → subsequent dependencies. Dialog removal, login entry, title screen, download and server operation need separate evidence. |
| Pipe exists or environment variable arrived | Distinguish transport/session availability from a successful protocol response; distinguish process environment from actual engine option consumption and effect. |
| String/export/branch exists | Find its caller, initialization/configuration condition and runtime reachability. Missing export-name matches do not exclude indirect calls, encoded names or other modules. |
| A static candidate should be tested repeatedly | First establish that the observed run reaches the decision point. No hits before that point is neither patch success nor failure. |
| Diagnostic launcher is equivalent to normal launch | Suspended launch, job wrapping, changed permissions and session context can alter behavior; use the original execution path when it can answer the question. |
| Process alive or Responding=true means UI works | Require actual input-driven change/hits; correlate crash records with the current PID/thread before calling them a new failure. |
| Launch/resume command succeeded | Separately observe actual process, title, download and downstream completion; an asynchronous acknowledgement is not completion. |
| Progress/file size/resume marker matches | Verify loaded identity, target identity, classification set, deletion/update ordering and hashes. Byte preservation, a static resume path and demonstrated reuse differ. |

## Windows and environment boundaries

| Boundary | Decision |
|---|---|
| Startup fails with an elevation error | Check the executable's required privilege and parent context before guessing URI/cache problems; preserve the actual OS error. |
| URI/argument delivery | Verify original handler contract and Windows quoting before adding wrappers. Never log authentication URIs, cookies, tokens or account arguments. |
| GUI invisible from remote/service session | Check session and desktop first; use the existing interactive UI/IPC path. A service-session window query does not prove user-session GUI absence. |
| Keyboard/mouse automation | Confirm foreground window before typing. Check intermediate hover overlays, then verify the actual resulting screen. |
| GUI layout change | Verify header and body on the affected screen and dock/layout ordering. A running-status panel is not a login-screen regression check. |
| Embedded web runtime | Distinguish engine, profile/session, web login, start authorization and native handoff; do not claim equivalence to an external browser from JavaScript execution alone. |
| CLI/helper update during active login | Preserve the live GUI/session and coordinate deployment with a natural restart. Do not attribute account/security actions to a cause without service evidence. |
| Compiler/shell output | Reuse verified compiler arguments, cwd and encoding. Keep noisy logs in OS temp, return bounded diagnostics, and remove the logs once no longer needed. |
| Harness cleanup | Use real nonblocking timeouts and finally-cleanup for every started process, including helpers outside a job. Verify path/parent identity before terminating leftovers. |

## Mutation method

Honor the requested mutation mechanism and original-code constraints. Software INT3 changes instruction bytes; a register edit or a different patch is not an equivalent replacement. If the required method is unavailable, report it instead of selecting another method implicitly.

## Feedback and defect triage

Keep a compact feedback row: trigger | wrong decision | corrected call/invariant | observed evidence | applicability/invalidation.

- Incorrect arguments, unmet preconditions and explicit unsupported capability are not automatically product defects. After correction, require a minimal reproducer, expected/actual response, affected version/environment and impact before filing.
- Do not attribute a crash to the debugger, application or protection layer from temporal proximity alone. Correlate current PID/TID, crash phase, code and matching images.
- Retest the original failure boundary before declaring a defect fixed; one healthy run elsewhere is insufficient. Retire fixed entries and obsolete workarounds instead of accumulating success history in an unresolved-defect list.
- Separate observation time from record-write time; keep unknown time unknown. Preserve required source/evidence and remove disposable hooks, settings, copies and test outputs.
- Feedback extends or corrects the smallest applicable rule. Keep session narratives, private source locations, real program names and one-off helper scripts out of this skill.
