# KD hardware instruction trace: separate transport v1

This is the wire contract for adding hardware events to selected-CPU KD
capture. It shares CR/MSR/I/O observations with process hardware trace v1,
but has its own RSP negotiation, commands and status. Process IPC command
0x0077 must never be sent over KD. Ordinary process IPC, TraceBB v1/v2,
qTraceBB:cap2/policies2, flags, reasons9/10 and existing ACK behavior are
unchanged.

The definitions in `src/common/kd_hardware_trace_protocol.h` are authoritative
for byte order, sizes and offsets. All binary structures are little endian,
pack1, independent of host/guest pointer width. The wire contract is defined
here; the current MCP runtime does not yet send these new KD commands.
Do not treat the existing process hardware option as implemented KD support.

## Admission and negotiation

Use the existing MCP tool with execution_context=kd and the same strict
collect_hardware_events/hardware_kinds options when the KD frontend is wired.
The hardware option defaults false; false must use exactly the existing KD
path without new queries. True never falls back to TraceBB or process IPC.

Hardware capture requires an already connected, explicitly halted machine.
Select/verify the CPU through the existing KD selection and qC receipt.
CPU is zero based in this extension; existing RSP thread IDs remain CPU+1.
It observes that selected vCPU, not an OS thread and not a migrating thread.
CR3/CPL/thread transitions are observations, not implicit process-scope
bindings. The collector must use a selected-CPU scope rather than inherit
process tracing's automatic address-space/CPL/thread exit policy.

Query `qTraceHW:cap1` immediately before every capture. The response is exactly
128 hexadecimal characters encoding CapabilitiesV1 (64bytes), optionally
followed by the stub's ordinary single trailing NUL. qSupported may advertise
`TraceHW:1`; this alone does not establish support. Empty, error, malformed,
unknown-version/size, reserved-bit and supportedKinds=0 responses prohibit
capture. Do not reuse capabilities across reconnection/backend generations.

Capabilities contain supportedKinds (CR1/MSR2/port4), supportedFlags
(snapshots1/run_peer_cpus2), instructionCapacity and hardwareCapacity
(1..4096 each, hardware capacity at least maxPerInstruction), maxPerInstruction
(1..16), maxSteps (1..5000000), maxTimeoutMs (1..600000),
eventRecordBytes=80, fileSchema=3, maxFileBytes (1912..4294967296),
maxReplyBytes (529..4096) and zero reserved. Requested kinds/policies must all
be supported; never reduce them silently. Hardware support does not follow
from qTraceBB capabilities or GetCapabilities command bits.

Start requires cpu0..63, steps1..the negotiated maximum, timeoutMs1..the
negotiated maximum, start<end containing the observed current RIP, and a raw
file budget1912..the negotiated maximum. Frontend defaults are100000 steps,
10000ms and4GiB; unsupported budgets are refused rather than clamped.

Snapshots default true. Peer CPUs default stopped; run_peer_cpus=true is
strictly opt-in and must be supported by this capability reply. Its numeric
bits are1/2 here as well, but never add a hardware bit to old TraceBB flags.

## Commands and exact fields

All textual numbers below are unsigned, prefix-free hexadecimal, parsed with
overflow checks and no extra/missing fields. RSP checksum/framing rules remain
unchanged. Validate checksum including any trailing NUL before removing it;
accept at most one such NUL and no other trailing bytes.

| Command | Meaning |
|---|---|
| qTraceHW:cap1 | Query the independent64-byte capabilities. No execution, fault-in, restore or write effects. |
| vTraceHW:1,cpu,maxSteps,start,end,flags,kinds,timeoutMs,maxFileBytes,requestId | Start one logical capture; asynchronous normal RSP stop receipt. |
| qTraceHW:status1,requestId | Return hex HeaderV1 (192bytes), only after all CPUs are halted and actual selected-CPU RIP is known. |
| qTraceHW:read1,generation,requestId,chunk,stream,offset,count | Return hex PageV1 (64bytes) followed by exactly count records from the immutable current chunk. |
| vTraceHW:resume1,generation,requestId,chunk,nextInstructionOffset,nextHardwareOffset | Acknowledge BOTH persisted streams of a paused chunk and continue the logical capture; asynchronous stop receipt. |
| qTraceHW:cancel1,generation,requestId,chunk | Cancel a paused capture without executing anything; OK, then status reports Interrupted/paused0 with unchanged counters and actual PC. |
| qTraceHW:release1,generation,requestId,chunk,nextInstructionOffset,nextHardwareOffset | Release a terminal capture only after exact final offsets match; OK, idempotent. |

requestId is a strictly increasing nonzero64-bit operation ID within a KD
connection (an initial random seed is allowed; wrapping is not). generation is
a backend nonzero64-bit capture identity. Header/page receipts echo both.
Remember the admitted request-ID high-water mark until disconnect; released
IDs cannot start a new capture. E24 rejects an older non-current request ID. The same
requestId with identical start arguments must never execute a second capture:
return the existing stopped receipt, or E21 if still running. Reuse with
different arguments is E22. An identical resume ACK must never execute twice;
for the most recently admitted ACK, return current stopped state or E21 without
repeating continuation. Older acknowledged chunks may return E24. Retain the
last ACK tuple and the last release tuple; repeating the most recent release
returns OK. This bounded replay state and the request-ID high-water mark last
until disconnect, so releasing buffers cannot turn a delayed start into execution.

A new start while an unreleased capture exists is E21 and preserves its data.
Status lookup by requestId supports recovery after a lost start/stop receipt.
A running capture is interrupted through the ordinary RSP interrupt, then
queried through status1; never retry a start to recover an uncertain outcome.
Paused cancellation cannot be used as a shortcut for running cancellation.

Errors: E21 busy/running/pending delivery; E22 invalid or unsupported
arguments/kinds/policy; E23 all-CPU halt or actual selected RIP unconfirmed;
E24 stale/mismatched generation, requestId, chunk or offsets; E25 storage or
buffer admission failure. Rejected admission must not execute instructions.
E23 never returns a successful header with an invented/stale/zero replacement
PC. No error implies target rollback.

## Two immutable streams and continuation

stream1 is instruction facts, stream2 is hardware events. Offsets/counts are
record counts in their respective global streams. Both start at0. Hardware
events are NOT inserted into old KD instruction records.

Instruction wire records reuse the layout of CompactRecord (56bytes) or
FullRecordV2 (200bytes with snapshots), exactly as declared in the existing
KD header. Implicit instruction sequence is instructionOffset+index+1.
Do not reinterpret compact/full records as the differently ordered canonical
200-byte v1 storage record.

Hardware wire records are exactly the common80-byte EventV1, without the
8-byte .vte record prefix. Confirmed events join instruction facts by sequence;
multiple events use attempt/event_index. Attempts start at1, sequence0/Step
unknown denotes uncertain completion. Keep full CR3 values including PCID,
actual MSR/I/O facts and known-bit/null semantics. Do not re-read hardware to
supplement observations. Uncertain events appear only at the final tail and
are not retried or counted as completed instructions.

PageV1 echoes version/headerBytes/recordBytes, generation, requestId,
chunkIndex, stream, global offset and count. Its payloadHash covers the
following raw record bytes using the existing TraceEventPayloadHash:
seed1469598103934665603, xor each byte then multiply1099511628211 with uint64
wrap. Reserved is0. Check exact size, hash, identities and bounds before use.
For a reply budget B and record size R, count must be at most
floor((floor((B-1)/2)-64)/R); reserve one payload byte for a possible NUL.
RSP framing characters are outside B. Never split a record or cross a chunk.

Reserve capacity for one instruction and the negotiated maximum hardware
events BEFORE executing it. Either stream filling pauses the logical capture;
BufferFull need not contain4096 instruction records. The next instruction
has not been attempted. No allocations, file/network work, symbol lookup,
waiting or dropping records belongs in the EMT/collector callback.

After each stop, validate status, both streams and cross-chunk address/sequence
chains, then durably store BOTH streams before resume. ACK uses
nextInstructionOffset=instructionOffset+instructionCount and
nextHardwareOffset=hardwareOffset+hardwareCount. The backend must not replace
either buffer until this exact paired ACK is accepted. Page/storage failures
retain the current halted buffers for retry and any acknowledged host prefix.
Never resume automatically through an explicit peer-CPU stop or uncertain
stop CPU identity. Recheck the monotonic logical timeout after I/O and before
resume; a chunk does not reset maxSteps or timeoutMs.

## HeaderV1 and termination

The192-byte header has these fixed offsets:

| Offset | Fields |
|---:|---|
|0|u32 version1/status0/headerBytes192/instructionRecordBytes56 or200|
|16/24|u64 generation/requestId|
|32/36/40/44|u32 cpu/appliedFlags/appliedKinds/end|
|48/56/64/72/80|u64 chunkIndex/instructionOffset/instructionCount/hardwareOffset/hardwareCount|
|88/96/104/112|u64 steps/attempts/maxSteps/finalAddress|
|120/128/136/144|u64 retainedHardware/droppedHardware/unknownValueFields/uncertainRecords|
|152/156/160/164|u32 resultFlags/scopeExit/paused/haltFlags|
|168|three zero u64 reserved values|

Exact applied flags/kinds must equal the request. steps equals
instructionOffset+instructionCount; retainedHardware equals
hardwareOffset+hardwareCount. All counts are cumulative or chunk-local exactly
as named. attempts counts attempted selected-CPU instructions, including one
uncertain terminal attempt. All normal status/page/ACK/cancel boundaries
require haltFlags=1 (all CPUs halted) and resultFlags FINAL_PC_VALID.
Final PC is observed selected-CPU RIP, never the disassembler's predicted PC.

End values1..10 retain their meanings in this NEW namespace: Budget, Range,
Interrupted, Exception, CodeUnavailable, OtherStop, UnsupportedInstruction,
BufferFull, CodeUncertain, CompletionUncertain. Add11 ScopeExit and12 FileBudget.
These do not extend which reasons/flags old TraceBB commands accept.
Only BufferFull has paused1; all terminal statuses have paused0.

Common resultFlags/scope_exit semantics are shared with process hardware v1,
including offset-independent flag bit5=SCOPE_EXIT, values1..5 and unknown loss
UINT64_MAX. CodeUncertain carries a final confirmed instruction with reserved1,
codeSize0 and zero code bytes; it must not produce a decoded instruction/block/
branch. CompletionUncertain has no completed instruction record for that
attempt, Step unknown/sequence0 for its hardware side effects, and a verified
actual final PC; do not fabricate a connecting edge. These outcomes need no
run_peer_cpus flag in this new namespace.

A backend limitation that forces an address-space/CPL/thread exit must stop
before the next instruction, preserve the completed boundary instruction and
report explicit ScopeExit, never pretend it followed the requested CPU path.
The frontend reports such scope-limitation/identity-unavailable exits incomplete.
The CR/MSR/I/O collector can be shared; its admission/scope policy and transport
must remain distinct between process and selected-CPU tracing.

## Host artifacts and MCP results

File-only hardware output keeps summaries and read pages within8KiB. Store
hardware as schema3 .vte records (type4,80bytes plus8-byte record headers);
its other three counts may be0. Store instruction facts with the new
216-byte CaptureFileV1 (magic VEHKDHW1, version1, headerBytes216,
recordBytes200, reserved0 and the exact terminal HeaderV1) plus canonical
200-byte instruction records. This is a NEW artifact, not VEHKDTR2.
Partial/header-repair failures retain an explicit recovery descriptor.
Unknown-code markers are preserved. No old reader may silently decode this
artifact as an existing KD capture.

maxFileBytes limits the combined216-byte instruction header,88-byte event
header and both record bodies. Reserve200+16*88 bytes before an instruction;
the minimum request is1912 bytes. Do not preallocate a4GiB file. FileBudget
stops before the next instruction with a valid prefix, zero invented loss and
capture_complete=false. Timeout/budget/interruption/uncertainty/unsupported
termination also remains incomplete even if the prefix is stored intact.

Return hardware_collection protocol_version1 plus transport=kd-rsp-hardware-v1,
requested/applied kinds, exact count strings, unknowns and scope_exit. Include
execution_context=kd, capture_scope=selected_cpu, cpu, exact generation and
request_id strings, actual final_address, capture_file/event_file references,
and separate storage_complete/capture_complete/complete. COUNT_LOWER_BOUND
returns steps_executed=null, steps_executed_lower_bound as a decimal string,
execution_count_incomplete=true and lost_records=null. Use stop precedence
completion_uncertain, code_uncertain, unsupported_hardware, left_scope, base.
Hex strings preserve addresses and hardware values; unknown values are null.

Whole-machine capture stays direct-only, excluded from batch/actions/capture
setup. Immutable offline hardware reads/analysis can share the existing
process schema3 reader. A new instruction-artifact reader must explicitly
recognize VEHKDHW1; existing read_capture remains unchanged.

## Required frontend contract tests

The native contract checks in trace_path_regression verify independent sizes,
offsets, little-endian generation/request IDs, reserved-bit rejection and
buffer/uncertainty accounting. They test definitions, not an enabled KD runtime.
When wiring the runtime, add synthetic RSP coverage for both streams, paired
ACK/replay safety, rejected/stale pages, hash/NUL/EOF boundaries, halted-PC
refusal, selected versus peer CPU stops, lower bounds and file-budget prefixes.
Keep the existing KD v2 streaming tests as the compatibility boundary.
