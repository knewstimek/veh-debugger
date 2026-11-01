# Hardware instruction trace v1 frontend

The existing `veh_trace_basic_blocks` tool supports hardware events through the
process IPC path, including ordinary hypervisor process connections with
host target scope. Support is determined by TraceHardwareCapabilities, not by
requiring target_scope=guest. No extra MCP tool is added. Process kernel-range
capture uses the existing attach path when the backend advertises the required
mode. Whole-machine selected-CPU capture instead uses execution_context=kd and
the implemented, independent [KD hardware v1 transport](KD_HARDWARE_TRACE_PROTOCOL.md).
Process IPC is never sent over KD; existing KD v2 remains compatible.

```json
{
  "threadId": 77,
  "start": "0x1000",
  "end": "0x2000",
  "follow_exceptions": false,
  "collect_hardware_events": true,
  "hardware_kinds": ["control_register", "msr", "io_port"],
  "max_steps": 100000,
  "timeout_ms": 120000
}
```

`collect_hardware_events` is a strict boolean, default false. False uses the
existing trace command and schema1/2 without hardware negotiation.
`hardware_kinds` requires true; omission selects all three. Empty, duplicate and
unknown kinds fail before capture. Selected kinds must all be supported.

Hardware capture implies `collect_events=true` and defaults to
`events_output=file`. Explicit event inline output is rejected. Keep
`collect_snapshots=true`, `compress_paths=false` and `output_mode=file`.
The result is a bounded receipt; raw events live in the separate artifact.
Target windows and remote file pipes cannot be combined with this mode.
Hardware timeout is100–1800000ms, steps1–5000000, file budget88–4294967296bytes;
ordinary guest file event capture also accepts100–1800000ms without hardware.
Native host and inline process capture retain their60000ms limit; no request is clamped.
Negotiated smaller limits also apply. Explicit artifact paths are limited
to1024 UTF-8 bytes so receipts stay within8KiB. Files are never overwritten.

## IPC and compatibility

The exact packed layouts and validation helpers are in
`src/common/trace_hardware_protocol.h`.

| Command | Number | Request | Response |
|---|---|---|---|
| TraceHardwareCapabilities |0x0076|empty|CapabilitiesV1,64bytes|
| TraceBasicBlocksHardware |0x0077|RequestV1,32bytes + wire10 base|ResponseV1,64bytes + base response|

All fields are little endian, pack1. The base request ends at
`kTraceBasicBlocksRequestV10Size`, has wireVersion10, and excludes wire11
collectionFlags. Existing0x0074/0x0075 and ordinary wire10/11 paths are unchanged.
Capabilities use the existing IPC status values. Empty/status-only replies,
unknown layouts, reserved bits, missing kinds/modes, or incompatible budgets
fail without sending capture. No GetCapabilities bit implies hardware support.

Kinds cover MOV CR0/2/3/4/8, RDMSR/WRMSR and scalar IN/OUT. CLI/STI remain
ordinary register observations. Values describe guest vCPU and virtual devices.
The frontend never reads hardware to supplement observations and never infers
a write's installed value from its input. CR3 retains all bits, including PCID.

## Schema3 artifact and exact values

The88-byte file header,8-byte record header and existing48/84/320-byte payloads
are unchanged. Schema3 requires HAS_HARDWARE bit2 and uses the final header
uint32 as hardwareEventCount; schema1/2 keep it zero.
Record type4 has the80-byte EventV1 payload. Stream frames remain48bytes;
schema3 Complete appends uint64 hardware_events to the existing56bytes.

The receiver checks frame token/index/offset/hash, whole-record chunk
boundaries, reserved fields, all four counts, event semantics, the negotiated
per-instruction record limit and stream EOF. Drain cancellation is an error,
not EOF; the complete header is written only after EOF is confirmed. Native
artifact reads validate basic path payloads using the same rules as compressed
paths, with repeat records limited to schema2.
Known-zero values remain zero; unknown values are null. New uint64
sequence/attempt/count values are decimal strings and hardware values/addresses
are hexadecimal strings. A confirmed event has a known completed sequence and
value. Uncertain events retain side effects with sequence null at the tail,
without retrying or counting them as completed instructions.

`storage_complete` describes file storage, `capture_complete` describes capture,
and `complete` requires both. Budget stops may produce a fully stored prefix
with capture_complete=false. COUNT_LOWER_BOUND returns steps_executed=null,
steps_executed_lower_bound as an exact decimal string, and
execution_count_incomplete=true. Unknown loss is null. CODE_UNCERTAIN marks
decode/capture incomplete and suppresses inferred blocks/edges/code versions.
The final PC comes from a valid envelope; errors never substitute a prior PC.

ResponseV1 offset52 is uint32 scope_exit (not reserved); offset48 result_flags
bit5 is SCOPE_EXIT. Reasons1–5 are address_space, cpl, thread, rip_range and
identity_unavailable. The flag requires one of those values; without the flag
the field must be0. A scope exit accompanies base LeftRange and returns
stop_reason=left_scope plus scope_exit. The completed scope-changing instruction
and its true before/after values remain in the prefix; no next-scope execution
is inferred. Stop priority is completion_uncertain, code_uncertain,
unsupported_hardware, left_scope, then the base reason.

Normal/partial hardware results include hardware_collection with
protocol_version=1, requested=true, requested_kinds, applied_kinds, complete,
events, dropped_records, unknown_value_fields, uncertain_records and scope_exit.
Scope_exit is null without a scope exit; all new64-bit counts are exact decimal
strings (unknown dropped_records is null). Callers should check this receipt
rather than assuming that accepting an argument means an older frontend used it.
Capabilities are negotiated immediately before each capture without reusing a
previous backend generation's response.

If JSON export fails after raw-file storage, the error retains the raw file
path, counts and SHA-256. A failed stream/control completion may preserve a
`.vte.prefix` raw file with raw_prefix=true; it is not a complete readable .vte.

## Offline queries and analysis

Use the same tool without an attached session:

```json
{"operation":"read_events","event_file":"trace.vte","offset":"0","limit":16}
{"operation":"analyze_events","event_file":"trace.vte"}
```

Read pages contain hardware records only. Offset is a zero-based decimal
string within the hardware records matching optional `hardware_kind`.
Use returned next_offset until null. Limit is1–100 with a separate8KiB
response cap. Optional sha256 checks the artifact against its capture receipt.
Both operations validate schema1/2/3 structure, counts and EOF; schema1/2 have
no hardware records. Analysis returns kind/read/write counts, unknown fields,
uncertain records and code uncertainty without inventing device state.
Rejected stream frames disconnect the data pipe immediately so a peer draining
its writes can return the control error without waiting for capture expiry.
A raw file alone cannot establish the control envelope's capture completion,
so offline capture_complete is null; use the original receipt for that fact.

Capture, reads and analysis share direct/batch/breakpoint-action handlers.
Flat batches containing only offline event reads/analysis work without a
session. Whole-machine KD capture retains its direct-only restriction.

The portable converter also supports schema3:

```text
py -3 tools/read_trace_event_stream.py trace.vte --output trace-events.jsonl
```

## Frontend verification

`test/test_trace_hardware.py` uses the existing owned synthetic guest fixture
to exercise negotiation, wire10 envelopes, exact values, malformed
frames/records/responses, partial/raw results, no-overwrite export failures,
bounded pages and direct/batch/action parity. Existing event-stream, output
default, policy and IPC compatibility regressions protect ordinary tracing.
