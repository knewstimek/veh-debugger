# Instrumentation interface, version 1

This is an additive frontend/backend contract. Existing `TraceCallers (0x0050)`
and `veh_branch_trace(kind="full")` retain their wire format and behavior.
The built-in VEH DLL does not implement the new collector; hardware/agent
backends must adopt this contract before advertising its commands.
Frontend fixture tests do not qualify real detours, Intel PT hardware or RTM.

## MCP

No new tools or eager profile entries are added. Existing lazy tools accept:

- `veh_trace_callers(mode="standard", address=..., duration_ms=...)`: existing
  caller hit-count profile, including its original resume/pause rules and result.
  `standard` remains the default.
- `veh_trace_callers(mode="detour", operation=...)`: explicit backend function
  entry instrumentation. It never falls back to standard tracing.
- `veh_branch_trace(kind="ptwrite", operation=...)`: passive collection of
  PTWRITE payloads; it does not inject PTWRITE instructions or patch an address.
  `last` and `full` remain the LBR/ordinary PT paths.

Both new paths use `operation="status"` by default. Neither resumes or pauses
a target implicitly. Duration/thread/buffer_kb options of other trace modes are
rejected rather than silently ignored.

`status` distinguishes exposed Intel PT/PTWRITE support from an available
collector, reports reasons, and lists per-kind policy support and limits.
If the query command is absent, hardware support is unknown (`null`) and
`protocolSupported=false, available=false`. No backend-name/CPU guess is made.
Availability requires reported query/start/stop/read commands and a usable
collector. Query policy bits/limits belong to the requested kind. Collection must
respect the negotiated target scope: process captures must not silently become
VM-wide captures when process filtering is unavailable.

`start` accepts:

| Option | Contract |
|---|---|
| `address` | Required function entry for detour; forbidden for passive PTWRITE |
| `buffer_records` | 1..backend limit (maximum65536); default min(4096, backend limit) |
| `data_policy` | `original` default; `patched` explicit |
| `transaction_policy` | `omit` default; `rollback` explicit |
| `include_ip` | Boolean, default true; requires reported IP collection support |

`original` means target data reads of instrumentation-modified code pages
observe the original bytes. A provider unable to guarantee this must refuse
before installing anything. `patched` allows E9 and other detour patch bytes to
be read: integrity checks and self-code reads can change. This is a target
read policy, not a promise that a hook is invisible by every other means.
It does not change the existing global `veh_read_memory` protocol.

`omit` excludes every record inside RTM/HLE transactions, including committed
ones. `rollback` stages transactional records until commit and discards them
on abort. A backend that cannot guarantee the requested policy rejects it;
there is no silent downgrade or speculative record publication. Policy names
describe the observable contract, not a claim that hardware applies it without
backend processing.

Start returns an exact string `trace_id`. One active collector per kind is
allowed; a second start fails instead of replacing it. ID values are nonzero,
connection-scoped and never reassigned on that connection. IDs/cursors/counters
are strings in JSON to preserve 64-bit values. A timeout/malformed start receipt
means an unknown outcome: do not blindly retry installation. Reconnect/detach
ends the old backend ownership.

`read(trace_id="...", max=0)` returns a small summary by default, including
`active`, `totalRecords`, `lostRecords`, `incomplete`, `bufferOverflow`,
effective data/transaction policies, `omittedTransactionalRecords` and
`abortedTransactions`. Unknown counters are `null`, never inferred as zero.
Summary reads do not drain records. No raw PT packets are returned.

`stop(trace_id="...")` confirms collector shutdown and returns the same summary.
It is idempotent; the stopped capture remains until the next successful start
of that kind or session detach. Stop must finish restoring owned hooks before
acknowledging success. Failed/unconfirmed cleanup must remain an error.

Detailed `read(trace_id="...", cursor="0", max=32)` requires a stopped immutable
capture. `max` is 1..256, additionally bounded by the backend's advertised page
limit. It returns only that page, `nextCursor` and `hasMore`; pass the exact
returned cursor to continue. No frontend history cache, automatic drain,
unbounded list, automatic pagination or result notification is added.

PTWRITE records contain exact hexadecimal `value`, `instructionAddress`,
and `threadId`. Unknown IP/thread is `null`; an unavailable instruction
address makes the capture incomplete. No adjacent decoded instruction is
substituted for the actual IP. IP can be unavailable in PT decoding; see
[Intel libipt decoding guidance](https://github.com/intel/libipt/blob/master/doc/howto_libipt.md).
Detour records instead contain `functionAddress`, `instructionAddress`,
`callerAddress` (the captured return address, not the call instruction) and
`threadId`.

On buffer exhaustion, retain the already published prefix and discard new
records; set overflow/incomplete and report lost count or unknown. Retained
cursor offsets never move. Uncertain synchronization/transaction boundaries,
missing requested IP and decoder gaps also require incomplete. Omitted
transactional records are reported separately from accidental loss.
`totalRecords` counts retained committed records, not every attempted event.

Direct calls, `veh_batch` and breakpoint actions use the same dispatch and result
contract. Actions can use `as="$capture"`/`$capture.trace_id` references across start,
stop and read. All collection and transaction processing belongs to the backend;
the frontend does not sample target memory in a client loop.

## Wire

Canonical definitions: `src/common/ipc_protocol.h`. All fields are packed
little-endian, identical for x86/x64.

| Command | ID | Request bytes | Successful response |
|---|---|---:|---|
| QueryInstrumentation | 0x0051 | 8 | QueryInstrumentationResponse,440bytes |
| StartInstrumentation | 0x0052 | 32 | InstrumentationResponse,88bytes |
| StopInstrumentation | 0x0053 | 16 | InstrumentationResponse,88bytes |
| ReadInstrumentation | 0x0054 | 28 | 88bytes + count*32byte InstrumentationRecord |

Every request carries version1 and kind (1=detour,2=PTWRITE). Start carries
entry/buffer/data policy/transaction policy/include-IP. Read/stop carry the
capture ID; read additionally carries cursor and maxRecords (zero for summary).
The fixed header echoes kind/ID/effective policies, flags, buffer capacity,
cursor/nextCursor, counts and quality counters. Start/stop have count=0;
only read appends records. A successful reply must match exact size, version,
identity, policy, bounds and cursor progress; malformed success is an error,
including extra bytes. A refusal may be status-only; use existing IpcStatus
values (Unsupported/InvalidState/LimitReached/etc.).

Feature bits are defined by `InstrumentationFeatures`; never advertise CPU
support as collector availability. Policies/limits must describe the requested
kind. Record IP/caller validity bits are independent. Quality flags cover active,
overflow and incomplete. UINT64_MAX is reserved for unknown quality counters.
A detailed page must not be returned while active. Retained records never
contain records later removed by transaction abort.

Advertise GetCapabilities bits0x51..0x54 only for implemented commands. A start
must validate all options and target state before any instrumentation effect,
clean up failed installation, and reject conflicts. Stop/detach must not silently
leave hooks active. Since MCP owns no automatic-retry ID for start, unknown
outcomes need explicit old-session cleanup rather than duplicate installation.

Run `py -3 tools/run_tests.py test_instrumentation.py --jobs 1` and repeat with
`--build-dir build32`. The synthetic fixture covers malformed receipts,
policies/availability, paging, exact values, loss/unknown IP and batch/action
parity. Real backend qualification must additionally prove actual original and
patched target self-reads, omit/commit/abort behavior, buffer overflow, hook
cleanup and true PTWRITE IP association before advertising support.
