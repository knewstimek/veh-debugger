# Bounded KD basic-block capture

Use the existing `veh_trace_basic_blocks` tool with `execution_context: "kd"`
after `veh_kd_connect` and an explicit whole-machine halt. Supply hexadecimal
`start`/`end` addresses and optionally `cpu`, `max_steps`, `collect_code`,
`collect_events` and `collect_snapshots`. Omit `threadId` or use 0.

The selected CPU can start in user or kernel mode and cross SYSCALL/SYSRET;
all other CPUs remain stopped. This observes a CPU, not a guaranteed OS thread.
This mode never attaches to a PID or changes a normal process trace into a global
halt. Ordinary process IPC trace still omits kernel execution. KD capture is
direct-call only: batch, breakpoint actions and capture setup refuse it because
they must not unexpectedly control the whole machine.

## Versioned backend contract

The optional RSP extension does not change process IPC layouts/capabilities.
It advertises `TraceBB:1` in qSupported; `qTraceBB:cap` returns `1,1000`.
`vTraceBB:1,<maxSteps>,<rangeStart>,<rangeEnd>,<flags>` takes strict hexadecimal
fields. MaxSteps is 1..4096, the half-open range must contain the current PC,
and only flags bit0 (register snapshots) is defined.
The command runs asynchronously like an RSP step and ends with a normal stop
reply. Invalid/unsupported requests have no target execution effects.
No concurrent process trace or pending guest exception/debug delivery is admitted.

Range exit stops before the first out-of-range instruction. Budget counts
completed instructions, including instructions emulated by the backend.
The backend isolates a step from guest IRQ/NMI delivery, retains queued debt,
and intercepts synchronous faults before guest delivery. Exception completion
is not inferred from arrival in a handler. Pending delivery remains owned by the
original stopped context; another capture is refused until it is handled.
REP-prefixed instructions (conservatively including F2/F3-prefixed SSE/ENDBR) and
privileged monitor-call instructions and TF-bearing contexts are refused before that instruction executes. They are not
counted as completed. This avoids treating an intermediate repeat iteration as
a whole instruction. A normal self-loop branch remains a completed instruction.

After the stop, `qTraceBB:status` returns a hex-encoded Header from
`src/common/kd_trace_protocol.h`.
`qTraceBB:read,<generation>,<offset>,<count>` returns immutable hex-encoded
records; each page must fit the negotiated packet capacity.
Offsets/counts are record counts. Generation is uint64; consumers retain it as
a decimal string in JSON and require an exact generation match for pages.
Active captures cannot be read, and a new capture invalidates the old generation.
Header and record byte sizes are fixed at48 and200. No packed native sizeof
from a later contract version may be substituted.

Each completed instruction carries observed before/after PC, CR3, code width,
CPL, bounded actual code bytes and optional before registers. PID/TID zero
means unknown; CPU number is never used as a thread identity.
Code is sampled before execution and published only after verified completion.
Header end values:1 budget,2 range exit,3 interrupted,4 exception,
5 code unavailable,6 another debug stop,7 unsupported instruction.
Missing code, faults and unsupported instructions are explicitly incomplete.
The target remains halted at its actual final PC. Cancellation uses an RSP
interrupt. Failed page reads retain the backend capture for a generation-bound
retry; they do not imply rollback of target effects.

Consumers validate record size, count/steps, selected CPU, generation, exact
budget/range termination, address chain and code bounds before reporting success.
Blocks, edges and code versions are pure decoding/grouping of captured bytes.
There is no frontend loop over target single-step or memory-read operations.

## Output and current limits

The KD result uses the usual blocks/edges/snapshots/events/code_versions keys,
plus `execution_context`, `capture_scope: "selected_cpu"`, `cpu`,
`generation`, `halted`, `backend_records` and explicit incomplete indicators.
Edges come from observed destinations; no unobserved path is invented.
Events contain both observed block entries and transitions. Register snapshots
use the documented18-slot CPU order with per-snapshot code width.
Unknown process/thread identities are JSON null.

Register snapshots default on; stack_bytes defaults to0 in KD and any positive
value is refused. Snapshot suppression skips register capture in the backend.
max_blocks/max_edges must cover max_steps. Advanced process conditions/windows,
dependency sources, operand/register-delta collection, compressed paths, return
scope and streamed code/event files are refused before execution. Pure result
export through output_file remains available.
Exceptions stop before delivery; follow_exceptions=true is explicitly refused.
Process-only policy capability bits are not reused to advertise this extension.

Tests: `py -3 test/test_kernel_trace.py` exercises backend collection, block
shaping, pre-effect refusal, selected-CPU and malformed terminal/page receipts.
It uses a synthetic RSP backend and is not a hardware qualification.
