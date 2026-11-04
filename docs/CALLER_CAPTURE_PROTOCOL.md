# Detailed caller capture, version 1

This is the agreed additive frontend/backend contract. Canonical packed
little-endian definitions and size assertions are in
`src/common/caller_capture_protocol.h`. Existing TraceCallers (0x0050),
SystemEvent, and Instrumentation v1 remain unchanged. This protocol captures
raw facts; it does not promise a complete call stack or interpret argument types.

## Discovery and commands

Advertise commands only when implemented in GetCapabilities.commands:

| Command | ID | Request bytes | Successful response |
|---|---|---:|---|
| QueryCallerCapture | 0x0055 | 4 | QueryResponse: 216 |
| StartCallerCapture | 0x0056 | 240 | Response: 336 |
| StopCallerCapture | 0x0057 | 16 | Response: 336 |
| ReadCallerCapture | 0x0058 | 32 | 336 + payloadBytes, at most maxBytes |

Every request/response carries version 1. Reserved fields and unused filters
must be zero. Error responses may contain only IpcStatus. A version mismatch
must be rejected before effects; never reinterpret a legacy request or fall
back to basic tracing. Struct sizes and offsets are identical on x86/x64.

Query reports the available collector, architecture/features, limits, provider,
reason, clock kind/frequency, and current retained trace ID (zero if none).
A usable collector implements all four commands and guarantees unchanged target
data-read bytes and omission of transactional hits before admission. These
are fixed Original/Omit policies in v1. Unsupported policies require a future
version; no automatic weakening. No guest code patching method is required.

Limits: stack <=4096 bytes, <=65536 retained records, <=64 MiB retained record
bytes, <=8 register predicates, reply <=65536 bytes including its header.
Advertised page capacity must hold a largest supported record plus Response.
All limits may be lower; explicit user requests are rejected, never clamped.
Only defaults adapt to provider limits. MCP status.available additionally requires
support for the attached target address width, not merely some other supported
architecture. Limits concern retained payload;
providers must separately bound bookkeeping and preallocate safely.

## Collection semantics

Capture one exact function-entry address in the attached process's user mode.
The backend binds the process lifetime and resolves the execution architecture;
never broaden to another process or kernel mode. Validate the requested entry
before installing. Preserve the prior running/paused state: start, stop, query,
and read do not resume, pause, or emit user-visible debugger stops. Instrumentation
still adds execution latency. Report limited/remapping coverage in the provider
reason; do not imply guaranteed capture of every attempted call.

Only one capture per connection is retained. Start refuses while active, never
replaces it. A successful new start invalidates the previous stopped capture;
failed admission leaves it intact. IDs are nonzero, connection-scoped, strictly
non-reused. Query exposes currentTraceId to recover an unconfirmed start result.
Never retry uncertain state-changing requests automatically.

Start uses address, stackBytes, bufferRecords, bufferBytes, durationMs, maxHits,
and filterCount + eight Filter slots. At least one of durationMs/maxHits must
be nonzero. durationMs is 0..60000. Filters AND together
`(register & mask) == expected`; expected has no bits outside mask.
Filter registers must be valid in each returned hit snapshot and satisfy every
accepted predicate. Integer register indices are defined in Register. No pointer dereferences or
expression evaluation. If the register/filter/architecture cannot be observed
truthfully, reject admission instead of treating the condition as false.

Each nontransactional, in-scope entry is filtered at the hit using that hit's
registers. Rejected predicates increment filteredHits (UINT64_MAX means unknown).
Accepted hits atomically consume maxHits and receive sequence 1,2,..., even on
multiple CPUs. Filtered/transactional hits consume neither sequence nor maxHits.
Never admit more than maxHits. A storage failure after admission increments
lostRecords; partial/unreadable stack copies retain a record and consume one hit.
matchedHits counts admitted hits, totalRecords retained records.
Retained records are an ordered prefix: record.sequence = retained index + 1.

Stop when the first boundary occurs: manual stop, maxHits, monotonic collection
duration, record/byte capacity, detach, or collection error. Buffer exhaustion
ends admission without overwriting the prefix; set Overflow|Incomplete and
stopReason=Buffer. Lost records are counted exactly or UINT64_MAX/JSON null.
Unknown must not be represented as zero. Duration uses one backend monotonic
operation clock; it is independent from the hit timestamp clock.

Stop removes the collector and waits for in-flight record publication before
returning, then retains immutable facts. Stop is idempotent; preserve an already
reached MaxHits/Duration/Buffer reason. Detach/target exit must release hooks and
invalidate connection-scoped IDs. An error must not claim successful cleanup.

## Hit records and consistency

Read appends count variable records with no padding. Each is a 216-byte Record
followed by stackCaptured raw bytes. recordBytes=216+stackCaptured.
Each includes sequence, timestamp, PID/TID/CPU, addressBits (32 or64), register
validity mask, function/caller addresses and full integer register slots:
rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags.
RIP and RSP must be valid. Other unavailable slots are zero on wire and JSON null.
x86 valid values and addresses are zero-extended. No XMM/FP/SIMD argument capture.
Caller is the captured return address, not a CALL instruction address.

Registers and stack must come from the same intercepted hit before its thread
resumes. This is not an atomic snapshot of memory shared with other running
threads; providers must not claim whole-process simultaneity. Never read target
memory after drain to reconstruct the historical snapshot.

Stack starts at captured RSP. stackRequested equals the accepted stackBytes:
NotRequested requires requested=captured=0; Complete requires both equal and
nonzero; Partial is a nonempty prefix shorter than requested; Unreadable is
requested>0,captured=0. Stop reading at the first unavailable byte; do not fill
holes with zeroes, force page-ins, or read a different address space.
Partial/Unreadable makes the capture Incomplete. This remains usable data, not
a failed capture. Frame reconstruction requires sufficient bytes, valid
nonvolatile registers and matching module/unwind information. This version
does not freeze module images or promise complete offline unwinding.

Clock None/Tsc/MonotonicNs is explicit. timestamp is a uint64 raw value, not UTC.
Frequency zero means unknown; MonotonicNs frequency is exactly1000000000.
TimestampValid=0 requires timestamp=0; otherwise JSON uses an exact decimal
string. SynchronizedClock is a separate assertion permitting cross-CPU timestamp
comparison; otherwise sequence orders collection only, not real-world causality.
No frontend inference from host time, TSC frequency, or source receipt time.

## Receipts and paging

Response echoes the immutable accepted StartRequest exactly and reports
traceId, flags, stopReason, cursor/nextCursor, totalRecords, matchedHits,
filteredHits, lostRecords, count/payloadBytes, clock/frequency.
Active iff stopReason=Active. Incomplete is sticky.
max_hits reason requires matchedHits=maxHits. All counters/IDs stay uint64
on wire and exact decimal strings in JSON, with null for unknown counters.

Read(maxRecords=0) returns summary even while active. Detail pages require a
stopped immutable capture. maxRecords<=256; maxBytes bounds the entire IPC response payload (Response
plus records), excluding the outer eight-byte IpcHeader.
Return as many whole records as fit; never split a stack record across pages.
If data remains and maxRecords>0 but no record fits, return InvalidArgs.
nextCursor=cursor+count; cursor may equal totalRecords for an empty last page.
All stopped summary/config/counter/clock facts stay identical between pages.
Use stable offsets: no ring-buffer overwrite, drain removal or speculative pages.

## MCP

Existing calls keep their behavior. New selector:
`veh_trace_callers(mode="detailed", operation="status|start|stop|read|export")`.

Start options: address; stack_bytes (default min(256,limit)); buffer_records
(default min(4096,limit)); buffer_bytes (default min(4 MiB,limit));
duration_ms (default5000); max_hits (exact decimal string, default"1000");
filters=[{register,mask:"0x...",equals:"0x..."}].
Status defaults without starting. Stop/read/export require trace_id string.
Read accepts cursor string, max0..256 (default0 summary), and optional
output_file={path,format:"json|jsonl"}.

Export reads every immutable page into a host artifact, bounded by a single
60-second monotonic deadline and256 MiB serialized record budget. It never loops
over live target memory. Optional output_file chooses a new, non-overwriting
path; otherwise generate a temporary artifact. Large read JSON above64KiB also
returns an artifact. Receipts distinguish storage_completed from capture
incomplete; file creation does not make an incomplete capture complete.
The caller owns returned artifacts and their retention.

Direct calls, veh_batch and breakpoint actions dispatch identically, including
trace ID references. These commands do not implicitly resume a paused target,
so an action start collects only once execution is resumed normally.
The frontend exposes raw registers/stack and their validity. Automatic unwind
and typed argument decoding are not implemented by this interface.

## Verification boundary

Host fixture tests qualify MCP validation, exact values, paging, files,
old-backend refusal and direct/batch/action parity. They do not qualify the real
provider's hit-time consistency, timing impact, SMP admission or remap coverage.
Backend acceptance must test actual x64/WoW64 entries, partial/unreadable stacks,
filters, simultaneous CPUs reaching a hit limit, byte/record exhaustion,
detach cleanup, and old frontend interoperability before declaring live support.
