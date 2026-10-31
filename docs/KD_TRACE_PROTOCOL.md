# Bounded KD basic-block capture

Use the existing `veh_trace_basic_blocks` tool with `execution_context: "kd"`
after `veh_kd_connect` and an explicit whole-machine halt. Supply hexadecimal
`start`/`end` addresses and optionally `cpu`, `max_steps`, `collect_code`,
`collect_events` and `collect_snapshots`. Omit `threadId` or use 0.

The selected CPU can start in user or kernel mode and cross SYSCALL/SYSRET;
all other CPUs remain stopped by default. The optional `run_peer_cpus=true`
policy below allows peers to run during each selected-CPU instruction. This
observes one CPU, not a guaranteed OS thread or a migrating thread.
This mode never attaches to a PID or changes a normal process trace into a global
halt. Ordinary process IPC trace still omits kernel execution. KD capture is
direct-call only: batch, breakpoint actions and capture setup refuse it because
they must not unexpectedly control the whole machine. Pure saved-artifact reads
use the same tool with `operation="read_capture"`; they require no KD connection
and are allowed in an attached process batch or breakpoint action.

## Version 1 compatibility contract

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

## Optional version 2 streaming contract

The version 1 negotiation and packed layouts remain unchanged. The frontend
additionally queries `qTraceBB:cap2`; the supported reply is
`2,1000,4c4b40` (version 2, 4,096 records per chunk, 5,000,000 logical steps).
An unsupported reply keeps version 1 and its 4,096-step limit; no frontend loop
over single-step or memory-read commands is used as a fallback.

Start with `vTraceBB:2,<maxSteps>,<rangeStart>,<rangeEnd>,<flags>`. Fields remain
hexadecimal. A full 4,096-record buffer ends the current execution slice with a
normal RSP stop and end reason 8 (`BufferFull`). The VM stays halted while the
frontend copies and validates that immutable chunk. The logical generation and
step budget span every chunk.

- `qTraceBB:status2` returns the 72-byte `HeaderV2`: the existing 48-byte header,
  global `recordOffset` and `maxSteps` as u64, then u32 `paused` and `reserved`.
  `paused=1` is required only for end reason 8.
- `qTraceBB:read2,<generation>,<globalOffset>,<count>` reads the current chunk.
  A compact record is 56 bytes; with snapshot flag bit0 it is followed by
  eighteen u64 registers, for 200 bytes. This layout differs from version 1's
  200-byte record, so consumers must convert explicitly.
- `vTraceBB:resume2,<generation>,<nextGlobalOffset>` resumes only after the
  frontend has validated and stored the entire preceding chunk. The generation
  and next offset must match exactly; draining never resets the step budget.
- `qTraceBB:cancel2,<generation>` cancels a paused full-buffer capture and
  returns `OK`. A subsequent status must report interrupted with unchanged
  generation, final PC, record offset/count and total steps, and `paused=0`.

The frontend checks the logical deadline again after chunk I/O and before
resuming. While execution is in flight it retains the ordinary RSP stop query
and interrupt recovery. Offset, CPU, generation, count/steps, chain, code bounds
and final PC are checked before a chunk is accepted. A page/checksum/storage
failure preserves any acknowledged disk prefix and the halted backend buffer;
it does not claim rollback of instructions already executed. RSP checksums
include the trailing payload NUL, which is removed only after validation.
Corrupt packets are never promoted to observations.

## Optional peer-CPU execution policy

MCP `run_peer_cpus` is a strict boolean, defaults to false and is accepted only
for KD capture. Default requests do not query the policy extension or set bit1.
For an explicit true request, require version 2 streaming and query
`qTraceBB:policies2`. Reply `2,3` contains two prefix-free hexadecimal fields:
policy version 2 and supported flags mask (bit0 snapshots, bit1 run_peer_cpus).
Empty replies, errors, unknown versions, malformed fields or missing requested
bits refuse the request before capture execution; never silently fall back.
Keep `qTraceBB:cap2` and its exact `2,1000,4c4b40` reply unchanged.

Use bit1 (`0x2`) in the existing v2 start flags: 2 without snapshots, 3 with
snapshots. Version 1 never receives bit1. Unsupported flags/version combinations
are refused by the backend with E22 before execution. Every status must echo
the exact applied flags across start, resume and cancellation; they are retained
as `applied_flags` and `run_peer_cpus` in results and raw-file metadata.

The backend runs peer CPUs while completing one selected-CPU instruction,
then confirms all CPUs stopped, repeating automatically. Buffer reads, chunk
replacement and final status require confirmed all-CPU halt. A peer breakpoint
ends capture; Header.cpu remains the selected capture CPU while the RSP stop
reply may name the peer that stopped. Pending interrupts end with Interrupted=3,
synchronous exceptions with Exception=4, and other confirmed debug stops with
OtherStop=6. The frontend cannot independently prove backend all-CPU or
code/mapping protection from a synthetic protocol test.

Existing end values 1–8 and header/record sizes remain unchanged. Two additional
terminal reasons are allowed only for v2 captures with bit1 applied:

| End | Meaning and accounting |
|---|---|
| 9 CodeUncertain | Completion confirmed, but unchanged execution code/mapping cannot be proved. Preserve exactly one final unknown-code record; increment count and steps once. |
| 10 CompletionUncertain | Last attempted instruction completion cannot be confirmed. Add no record or step for that attempt; steps is a lower bound. |

For 9, only the last record of the terminal chunk may carry `reserved=1`,
`codeSize=0` and sixteen zero code bytes. Its address/nextAddress are observed
before/after PCs. All other records still require reserved=0 and codeSize 1–15.
The final nextAddress must equal actual finalAddress. Preserve the marker in raw
storage and pages (`code_uncertain=true`, `execution_code_verified=false`);
never invent an instruction, block or branch from that record.

For 10, retain all ordinary prefix and cross-chunk chain checks. Only its final
nextAddress-to-finalAddress equality check is omitted, including a zero-record
first attempt: actual finalAddress is the selected CPU RIP after all CPUs stop.
Results set `execution_gap=true`, `execution_count_incomplete=true`,
`steps_executed_lower_bound=Header.steps` and `lost_records=null`. This is an
explicit unrecorded execution gap, not permission to fabricate a connecting edge.
Both 9 and 10 set capture_incomplete/decode_incomplete and retain their raw files
with capture_file.complete=false. If actual RIP or all-CPU halt cannot be
confirmed, status/read must return E23 instead of a normal header. The frontend
reports halt unconfirmed, retains any acknowledged prefix and never substitutes
a previous PC. None of these outcomes implies rollback of target execution.

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
For legacy version 1, max_blocks/max_edges must cover max_steps. Version 2
uses bounded output aggregates and refuses custom block/edge execution-stop
budgets. Its default `max_steps` is 100,000 (maximum 5,000,000); the legacy default is 4,096.
KD `timeout_ms` defaults to 10,000 and accepts 1–600,000 ms. Advanced process conditions/windows,
dependency sources, operand/register-delta collection, compressed paths, return
scope and streamed code/event files are refused before execution. Pure result
export through output_file remains available, preserving its object response:
`output_file={path,format,size,sha256}` for JSON or JSONL. Existing destinations
are never overwritten. NUL/control characters and malformed UTF-8 paths are
refused before target execution or filesystem effects.

Large captures (requested steps above 4,096 or shaped JSON above 8 KiB), and explicit
exports, retain a portable raw artifact and return a bounded summary instead of
full arrays. Incomplete captures always retain raw artifacts; short results keep
the existing arrays when the full response including artifact metadata fits 8 KiB.
The artifact uses the 64-byte `CaptureFileHeader` followed by
canonical 200-byte version 1 layout records, regardless of wire snapshot mode.
At 5,000,000 records this requires 1,000,000,064 bytes; the temporary storage path
checks for the requested raw size plus 16 MiB free before starting. An explicit
export keeps raw data beside it as `<output_file>.records`; generated paths use
the host temporary directory. Callers own retention and cleanup.

Summary analysis is bounded independently of raw capture: 16,384 blocks,
32,768 edges, 8,192 ordered block/edge events, a 4,096-entry decode cache and
bounded code/key bytes. `capture_incomplete` describes acquisition termination;
`analysis_incomplete`, omitted-step counts, event drops and code truncation
describe bounded decoding. A structurally complete raw artifact does not imply
a complete execution or full analysis. Artifact receipts separate
`storage_complete` (intact header, size, flush and hash) from `capture_complete`
(acquisition completion); legacy `complete` requires both. A false complete does
not prevent reading an intact prefix. All raw records remain available for
later inspection. Short writes retain only the acknowledged prefix; failed
header repair exposes an explicit recovery descriptor instead of claiming a
valid header or complete file.

For offline inspection call:

```json
{"execution_context":"kd","operation":"read_capture","capture_file":"<artifact path>","offset":"0","limit":16}
```

Offsets and generations remain exact decimal strings. Pages contain at most 100
records and 8 KiB of serialized JSON; optional `include_registers` includes
recorded registers, while missing snapshots remain explicit. Hexadecimal
`address_start`/`address_end` filters examine at most 65,536 raw records per call.
Use the returned `next_offset`, including for empty filtered pages. Reads report
`integrity="not_checked"`: they validate layout/record fields but do not hash
the entire artifact on each page. A caller can verify the retained prefix hash
separately. A failed-header `recovery` descriptor is explicit and never silently
replaces on-disk metadata.
Exceptions stop before delivery; follow_exceptions=true is explicitly refused.
Process-only policy capability bits are not reused to advertise this extension.

Tests: `py -3 test/test_kernel_trace.py` exercises backend collection, block
shaping, pre-effect refusal, selected-CPU and malformed terminal/page receipts.
`test/test_kernel_trace_stream.py` covers 100,000 logical records, compact/full
wire modes, explicit JSON/JSONL receipts, exact offsets, timeout and malformed
continuations, checksum failure retention, policy negotiation, exact applied flags,
9/10 terminal markers and accounting, E23 prefix retention, path validation and direct/batch/action
artifact reads. `kd_capture_store_tests` covers native short-body/header writes
and persistent header-repair recovery. These use synthetic RSP/storage fixtures;
they do not qualify a live VM.
