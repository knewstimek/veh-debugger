# MCP trace development tools

These bounded command-line helpers are the preferred way to reproduce and validate MCP trace changes. Run them from the repository root. Examples use only synthetic build targets; do not commit local machine paths, credentials, private target names, trace artifacts, or details that identify a real analyzed program.

## Tool catalog

| Tool | Purpose |
|---|---|
| `tools/run_tests.py` | Runs every `test/test_*.py` file in parallel (`--jobs`, longest first from `test/.test_durations.json`) with a per-file timeout, prints durations, flags exit-0 runs that report FAIL, skips `# requires: x64` files on an x86 build and `# slow` files with `--quick`, and cleans up exactly the processes each file started (parent chain + creation time, so reused pids are never adopted). |
| `test/test_remote_transport.py` | Exercises resident TCP/TLS authentication, IPC routing, late/missing detach replies, dead-agent recovery, startup exit/Win32 and structured common error diagnostics (including invalid-record fallback), launch width/initial-thread metadata and retry recovery, and real DLL lifecycle reply draining; removes its owned certificate, secret and processes. See [remote transport](REMOTE_TRANSPORT.md). |
| `test/test_dap_deferred_loader_stop.py` | Uses the guest fixture without dwell sleeps: binding requires a hold and the DLL disappears on explicit continuation. Covers reload, failed-install retry, shared BP IDs, query failures, historical versus new holds delivered inside a Continue exchange, known stop reasons and termination/exit with TID reuse. |
| `test/test_local_backend_recovery.py` | Kills only exact test-owned agent handles and checks same-MCP reattachment, death during detach, live pipe loss without agent termination, and stale-agent isolation from native DLL cleanup. |
| `test/test_session_operations.py`, `test/test_operation_lifetime.py` | VM-free run-until ownership, fast/stale/other-thread events, exit/reconnect, CALL step-over, bounded value-write leases, receipt loss, action parity, and input/output control-loss checks. Uses the existing guest fixture and owned MCP process job. |
| `test/test_session_receipts.py`, `test/test_system_receipts.py` | Target pointer width, exact breakpoint-removal/stopped-state and system event/hook receipts; direct/batch parity with synthetic malformed/refused responses. |
| `test/test_code_patch.py` | Exercises real DLL instruction-aware patches in x64/x86: automatic spans, default/disabled NOP fill, explicit oversized/split spans, breakpoint overlap, page-edge failures, raw opt-in and direct/batch/native-action parity. Guest tests verify reported bitness and unsupported direct/batch/action parity. |
| `test/test_shellcode_results.py` | Checks status-only/full target-state refusal, generic/unknown statuses, malformed success and transport failure; direct/batch/BP-action results agree. TCP routing is covered by `test_remote_transport.py`. |
| `test/test_backend_results.py` | Injects rejected, short/oversized and missing backend replies through the existing guest fixture; checks DAP execution/write/termination acknowledgements, pause identity, exception-filter rejection and MCP/DAP empty-versus-failed stacks, including batch parity. |
| `test/test_address_space_deadline.py` | Returns a synthetic root after 31 seconds to cross the previous guest timeout, then checks root application, batch parity and continued connection use. |
| `test/test_pipe_write_failure.py`, `test_target/ipc_transport_regression.cpp` | Runs bounded native fault injection against production PipeClient: a frame delivered before write cancellation cannot be followed by another ordinary request, with/without the reader; cleanup remains available. Build target: `ipc_transport_regression`. |
| `test/owned_mcp_client.py` | Captures the MCP and all descendants in a private Windows job before requests, then terminates and waits exact owned handles even if attach never exposes an agent PID. |
| `test/mcp_test_client.py` | Shared timeout-aware MCP stdio client. It bounds captured diagnostics and terminates only processes it started. |
| `test/dap_test_client.py`, `test/test_dap_thread_errors.py`, `test/test_dap_guest_attach.py` | Bounded DAP stdio client; no-attach error and synthetic external guest attach, scope/identity validation, capability-gated command routing, rejection and acknowledged disconnect retry tests. The adapter runs without opening a console window. `test/test_vm_attach.py` covers malformed guest thread-list IPC through MCP. |
| `tools/run_mcp_scenario.py` | Runs 1-500 calls from a JSON scenario, supports named result references, stops on errors by default, and optionally writes a new report without overwriting. |
| `tools/validate_trace_output.py` | Validates exported trace JSON/JSONL ordering, thread ownership, counts, hashes, and optional `.vtc` code-version references. |
| `tools/read_trace_event_stream.py` | Validates a portable `.vte` ordered-event artifact and converts its interleaved block/edge, memory, and register records to JSON Lines. |
| `tools/run_trace_parity.py` | Runs the basic-block and synthetic memory-access integration suites against one or more build roots to cover direct, `veh_batch`, and breakpoint-action semantics, including inline/file compare-exchange writes and conditional dependencies. |
| `tools/run_ipc_compat_matrix.py` | Stages old-MCP/new-DLL and new-MCP/old-DLL pairs in a temporary directory and runs bounded compatibility smoke tests (default trace; --suite scan for value scans). |
| `tools/measure_mcp_schema.py` | Measures bounded initialize and `tools/list` bytes, input-schema bytes, output-schema count, and eager names for every exposure profile. |

All process-launching helpers use finite timeouts and wait for their children during cleanup. The compatibility runner stages copies under an OS temporary directory and removes them when complete.

## Value scan generations

Reuse `test/test_value_scan.py` and `test/test_value_scan_protocol.py` through
`tools/run_tests.py`, then repeat with `--build-dir build32`. These bounded tests
cover forced disk storage, summary/pages, undo baselines (including unaligned
overlap), stage failure/cancel retention, push completion without status polling,
direct/batch/action parity, exact IDs and malformed/legacy backend receipts.
They create only small synthetic allocations, not billion-candidate artifacts.
See [value scan contract](VALUE_SCAN.md) for usage, budgets, cleanup and the full
backend adoption checklist. Reuse the existing IPC matrix and schema-size helpers.

## Name and address lookup

The existing lazy `veh_symbolize` supports either address(es) or a name search:

```text
veh_symbolize(name="SharedProbe", max_results=10)
veh_symbolize(name="symbol_lookup_a.dll!SharedProbe")
veh_disassemble(address="symbol_lookup_a.dll!SharedProbe", count=20)
veh_read_memory(address="symbol_lookup_a.dll+352DD", size=64)
```

Name search returns at most1-10 `matches` (default10), each with module, name,
qualified symbol, exact hexadecimal address/moduleBase and source. Pattern
searches use DbgHelp's `[module!]name` syntax, including wildcard patterns.
`count` is returned rows, not an invented total. `truncated` means more
candidates exist; `incomplete` marks enumeration-budget/metadata limitations.
`resolved=true` and top-level `address` require exactly one complete candidate.
Forwarded exports have `forwarded=true,address=null`; their export strings
are never returned as code addresses. Select the implementation module instead.
Only available loaded symbols/exports can be found; no A/W suffix alias is
invented. Windows' file-writing API is named
[WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).

Shared MCP address fields also accept unambiguous function names and
`module!function`. Multiple matches, truncated/incomplete searches and
unresolved forwarders refuse automatic address selection with a structured
error. Pattern-based selection belongs in the name search, not an address field.
Legacy function-breakpoint/DAP resolution retains its existing IPC contract.

For module/function offsets, an omitted `0x` means hexadecimal:
`module.dll+10` adds0x10, and `module.dll+352DD` adds0x352DD.
Standalone digit-only literals and literal arithmetic retain existing parsing;
digit-leading literals containing A-F also accept prefix-free hexadecimal.
Letter-leading names remain symbols: write `0xADD` for an address instead of
the possible function name `Add`. Overflow, underflow and negative literals
are rejected. Resolution observes the current loaded namespace; it is not an
atomic guarantee that another thread cannot unload/change code afterwards.

Backend contract: advertise `FindSymbols=0x0045` only when implemented.
Packed request260bytes: `char name[256]`, `uint32 maxResults` (1..10).
Response12bytes: status/count/flags, followed by count*404byte entries.
Entries contain uint64 address/moduleBase, uint32 flags, moduleName[128],
functionName[256]. Header flags1=truncated,2=incomplete; entry flags1=forwarder,
2=export. Strings must terminate; ordinary entries require executable code
addresses. No successful short/oversized response is accepted. Name lookup
does not fall back to the legacy first-match ResolveFunction command.
The in-process implementation serializes DbgHelp through StackWalker's mutex,
uses a bounded callback/table and returns only module basenames.

`test/test_symbolize.py` covers x64/x86 real PDB/export lookup, two independently
loaded DLLs exporting SharedProbe, prefix-free RVA input, caps/incomplete/
malformed receipts, no unsafe legacy fallback, and direct/batch/action parity.
Use `test_target --symbol-lookup` only through the owned harness; the normal
synthetic target does not load the two probe DLLs.

## Explicit instrumentation

See [instrumentation contract](INSTRUMENTATION.md) for the additive version1
IPC and backend qualification requirements. Existing lazy caller/branch tools
provide explicit detour/PTWRITE modes, summary defaults and bounded stopped
capture pages without adding eager tools. `test/test_instrumentation.py` uses the
existing owned guest fixture to verify exact receipts, policies, loss/unknown
metadata, pagination and direct/batch/action parity. Run with the shared test
runner and repeat with `--build-dir build32`.

## Execution ownership and leased writes

`veh_execution` and `veh_value_freeze` are lazy-discovered tools: use a toolbox
manifest/description or call by name. They do not expand the default eager schema.
Attach/launch backend summaries include `frontendOperations` with protocol
`veh-session/1`, `runUntil`, `valueFreeze` and opt-in stop notifications.
Run-until requires reported software breakpoint creation/removal, detailed
Continue, stopped-state query and register commands. Leased writes require both
ReadMemory and WriteMemory. Unknown or missing support is not advertised.
These are MCP operations; they add no DAP configuration or UI.

`veh_execution(operation="state", threadId=77)` returns sessionGeneration and
sequence as exact strings, current PID/thread, a stopped/running/unknown query
result, temporary ownership and the last completion. A VM-wide pause or an old
event is not proof that the selected thread has a debugger stop.
`operation="run_to"` takes a destination address and one current stopped
thread. It resumes that thread only. A simple existing software breakpoint may
be borrowed; cleanup never removes it. Pending/conditional/log/action-bearing
breakpoints and frozen threads conflict with this operation. Capacity refusal is
different from uncertain creation. Lost/malformed creation or removal receipts
retain ownership, and ordinary mutations stay fenced until explicit cancellation
or session cleanup. Detach/terminate/reconnect remain available and do not claim
unconfirmed backend cleanup. Cancellation removes only an owned temporary
breakpoint and does not pause, resume or roll back execution.
CALL `veh_step_over` uses the same owner and return-address stop; it uses the
selected thread's registers rather than requiring a stack walk.

Use `operation="cancel"` to retire an operation. Use
`operation="notifications", enabled=true` to subscribe to
`notifications/veh/stopped`; the default is off. Events carry protocol, exact
sessionGeneration/sequence/operationId, PID, TID, reason, address, breakpoint ID,
local queue loss and ownership-cleanup facts. The queue holds at most 64 records.
Sequence describes frontend admission, not guest capture time. A stop packet
is an event observation; query current state before issuing state-dependent work.
Backend event loss is not quantified by the local queue's dropped count.
All-thread stops, atomic snapshots and backend cleanup are not inferred.

`veh_value_freeze(operation="add", address="0x2000", data="01 00 00 00",
interval_ms=1000, lease_seconds=10)` creates a job and returns an exact string ID.
The lease is required: 1-300 seconds. The interval is a minimum delay after
completion: 250-60000 ms, default1000. Each job stores1-64 bytes; the table holds
at most16 entries, including terminal records until explicitly removed/cleared.
`list` returns states, confirmed writes, skipped intervals and remaining lease.
`renew` extends an active, unexpired job with a new explicit lease;
`remove` deletes one job and `clear` removes all jobs. Overlapping active
ranges, wrong address width and missing read/write support are rejected.

A single injected monotonic millisecond clock supplies all due/completion/expiry
instants; none are UTC or persisted across restart. The existing event loop
schedules one write/readback at a time, with no extra worker, catch-up burst or
automatic retry after uncertainty. Failed write/readback fences every active job.
Target exit, generation/PID changes, input EOF, parent exit or closed output stop
new autonomous effects. A write already admitted can finish; ending a lease or
connection does not undo it. A read-only output-pipe probe adds no heartbeat
notification traffic. A dedicated output writer keeps notifications and protocol
replies from blocking EOF detection. Its queue is bounded to 64 records/64 MiB;
overflow ends the connection rather than accumulating output indefinitely.
Shutdown cancels blocked pipe I/O and waits for bounded in-flight backend commands;
it does not force-kill their threads. Jobs are not restored after restart.

Both tools support direct and batch calls; leased jobs also support breakpoint
actions. Run-to, CALL step-over and blocking Continue are excluded from actions
because action completion already auto-continues. Batch/action steps refuse a
scope changed during a yielded wait. Optional `expected_generation` exact
strings bind operation admission to the caller's current session. Existing
read/inspect operations remain usable during pending execution.

Run `py -3 tools/run_tests.py test_session_operations.py test_operation_lifetime.py
test_session_receipts.py test_system_receipts.py --jobs 2`; repeat with
`--build-dir build32` for x86.

## Assembly patches

`veh_assemble` still defaults to assembly only (`write=false`). With `write=true`,
the default overwrite span covers **enough complete original instructions for
the assembled code**, starting at the supplied address. The caller must supply
an instruction start. Longer JMP encodings automatically extend to that boundary.
`nop_fill=true` fills the unused span with single-byte `90` NOPs.
Set `overwrite_size` (1-4096) to explicitly replace several complete original
instructions. The end must be an instruction boundary and all bytes must lie in
one readable committed memory region. `nop_fill=false` preserves unused original
tail bytes; these can be instruction fragments, so this opt-out does not preserve
instruction integrity.
`raw_write=true` uses the previous byte-write path and cannot be combined with
`overwrite_size` or `nop_fill`. These options require `write=true`.

For example, replacing a two-byte `xor al, al` with `ret` writes `C3 90`.
If a five-byte JMP replaces that XOR and the next original instruction is five
bytes, the default span is seven bytes: JMP plus two NOPs. `overwrite_size=2`
explicitly limits the span and rejects that JMP; `overwrite_size=7` gives the
same output as automatic sizing. Existing raw-code-buffer callers can explicitly
opt into `raw_write=true` to avoid instruction decoding.

The response keeps assembled `size`, `bytes` and `listing`; validated writes
also return `patchSize`, `overwrittenInstructions`, `nopBytes`,
`originalBytes` and `patchedBytes`. With NOP fill disabled, `preservedBytes`
reports the original tail length. Raw writes return `rawWrite=true`.
The backend performs the read/decode/validation/write as one IPC operation.
Software breakpoint records, including temporarily disabled/rearming records,
must not overlap the actual overwrite span. No original instructions are
relocated, and no threads are automatically stopped. Stop relevant execution
before patching: instruction-boundary checks and a final byte recheck do not make
the write atomic with respect to running threads or external/self-modifying writers.
A transport or write-completion error can leave memory/protection changed; inspect
the target before retrying. There is no automatic rollback.

`IpcCommand::PatchCode = 0x0032` uses its command bit in
`GetCapabilities.commands`; no separate named flag is added. The frontend
requires explicit capability reporting and never falls back to byte writes.
External backends must implement the common header contract before advertising it.
Request (pack1, little-endian): version1/flags/address/codeSize/overwriteSize/
addressBits (28 bytes), then codeSize code bytes. Flag bit0 enables NOP fill;
unknown flags and versions are invalid. A zero overwriteSize selects the minimum
whole-instruction span covering codeSize; nonzero selects an exact span. Code size/span limit is4096 bytes.
The backend validates address width against the target.
An Ok response has status/detail0/overwriteSize/instructionCount (16 bytes),
followed by exactly overwriteSize original bytes then overwriteSize patched bytes.
A non-Ok response may be status-only or that header without payload.
See `PatchCodeDetail` in `src/common/ipc_protocol.h` for stable detail values.
Neither capability reporting nor TCP connectivity implies backend implementation.

Run `py -3 tools/run_tests.py test_code_patch.py test_assemble.py --jobs 2`;
use `--build-dir build32` for x86.

## RepoPlane catalog

The reusable commands above and the guarded release workflow are registered as
typed capabilities under `catalog/`. After refreshing RepoPlane catalog discovery,
use `catalog_query` with terms such as `veh trace`, `veh mcp`, or `veh release`.
Executable capabilities still require Runner authorization; catalog discovery alone
does not authorize a build, target launch, tag push, GitHub Release, or Marketplace
publication. `veh.release.publish` is deliberately separate from
`veh.release.prepare` so preparation cannot create external release state.

## MCP exposure profiles and lazy toolbox

The server defaults to `--profile=lite`. Keep `lite`, `interactive` and `capture` at ten eager tools or fewer; `full` explicitly exposes the complete inventory. Use `veh_toolbox` for the long tail:

| Profile | Intended workflow |
|---|---|
| `lite` | Launch/attach/continue/batch/terminate/registers plus lazy discovery |
| `interactive` | Attach, breakpoints, registers, disassembly, and memory inspection |
| `capture` | Process traces, targeted input capture, and checkpoint restore loops |
| `full` | Clients that require the complete eager inventory |

Use `veh_toolbox(operation="profiles")` for current counts and `tools/list` for
the active eager inventory; counts are not fixed documentation contracts.

```json
{"operation":"list","query":"checkpoint"}
{"operation":"manifest","tools":["veh_pause","veh_set_data_breakpoint","veh_search_memory","veh_read_memory"]}
{"operation":"describe","tool":"veh_checkpoint_create"}
{"operation":"call","tool":"veh_checkpoint_create","arguments":{"threadId":1234}}
```

Prefer one `manifest` request when a workflow needs several hidden tools. It returns each complete input schema with a per-tool handle and one `manifest_handle`; repeating the same request with that handle returns only the handle, count, and `unchanged:true`. `compact` defaults to one-sentence descriptions without reducing input schemas. A manifest is limited to 64 exact names or filtered profile/query matches. Reuse the returned `schema_handle` for individual `describe` requests. Tools remain directly callable by name even when they are not in the active `tools/list`, preserving existing scenario, analyzer, and batch automation. `veh_toolbox` is control-plane discovery and deliberately cannot call itself or be nested in `veh_batch`/breakpoint actions.

Batch steps, targeted-capture setup steps, and breakpoint actions call the same tool implementations as direct MCP calls. With no active session, `veh_batch` alone may use exactly one top-level `veh_launch` or `veh_attach` as its first step, then continue with ordinary analysis steps in the same request. Session start is rejected for an active session, input matrices, loops and other nested blocks; `veh_detach`/`veh_terminate` remain unavailable. Targeted capture and breakpoint actions still reject every lifecycle tool. Re-entrant orchestrators (`veh_batch`, `veh_targeted_capture`, `veh_toolbox`) and VM-wide `veh_virtual_machine` are rejected in all nested contexts.

`LimitReached` adds a backend result status, not a tool or input field, so it needs
no eager-profile or gateway-schema expansion. Direct breakpoint failures and
`veh_toolbox` calls retain the error and MCP `isError`; batch steps retain the
same error in their failed step result. `test/test_data_bp_slots.py` checks these
paths across all four profiles against the VEH slot limit.

Measure the current executable rather than estimating token counts from source:

```powershell
py -3 tools/measure_mcp_schema.py
```

For the initial implementation, compact JSON sizes were 5,255 bytes (`lite`), 7,736 (`interactive`), 15,006 (`capture`), and 33,952 (`full`), versus 34,527 bytes for the preceding 45-tool build. Schemas are standalone MCP definitions, so source-level `$defs` deduplication would not reduce the transmitted catalog; profile/gateway exposure removes the repeated prompt surface instead.

The server currently publishes no `outputSchema`. A bounded A/B probe against the installed Codex CLI used a synthetic 256-field output schema: total input tokens were identical both without a tool call and when the tool was forced and called. This verifies that client did not place `outputSchema` in the model prompt in that version; repeat the probe when upgrading clients rather than treating this as a protocol-wide guarantee. Add output schemas only for an actual validation/contract need.

## Scenario runner

A scenario is a JSON object with `calls`, optional `stop_on_error` (default `true`), and optional `terminate_target` (default `true`). Each call contains either `tool` plus `args`, or `method` plus `params`. Give a result an `as` name and reference a nested value later with `$name.field`.

```json
{
  "terminate_target": true,
  "calls": [
    {"tool": "veh_launch", "args": {"program": "build/bin/Release/test_target.exe", "stopOnEntry": true}, "as": "launch"},
    {"tool": "veh_threads", "args": {}}
  ]
}
```

```powershell
py -3 tools/run_mcp_scenario.py test/scenarios/mcp_smoke.json --output scenario-result.json
```

The output path must not exist. Reports default to a 16 MiB serialized limit, configurable from 1 KiB through 64 MiB; use trace `output_file` instead of raising it for large trace arrays. Keep local scenarios and their reports ignored unless they are neutral, deterministic fixtures intended for the repository.

## Trace output validation

`veh_trace_basic_blocks` accepts `output_file` and `output_format` (`json` or `jsonl`). The server writes the complete result to a new MCP-host file and returns only bounded metadata: path, SHA-256, byte size, event counts, truncation state, and errors. JSONL uses one manifest followed by ordered section-item records. Existing files are never overwritten; a failed write removes its randomized sibling partial file when the process can still perform cleanup.

```powershell
py -3 tools/validate_trace_output.py trace.jsonl --sha256 <expected-sha256>
```

The separate `code_output="file"` mode stores executed code versions in a portable `.vtc` artifact. A full trace export can reference that artifact, and the validator checks the referenced version IDs. Relative artifact paths are resolved from the trace file directory. After copying artifacts to another Windows, Linux, or macOS host, pass `--code-artifact <local-file.vtc>` to replace the capture host's path; the file formats themselves do not depend on the capture OS.

The opt-in `events_output="file"` mode stores block/edge, memory, and register events in their actual emission order in a portable `.vte` artifact. Set `events_output_path` to a new MCP-host path, or omit it for a generated temporary path. Existing files are never overwritten. `max_event_file_bytes` includes the header and complete records, defaults to 4 GiB, and accepts lower limits from 88 bytes through 4 GiB. File mode does not allocate or return the inline event arrays, and their legacy per-kind caps do not limit capture. If the byte limit cannot fit the next complete record, event capture stops with `truncated=true` and `limit_reason="size_limit"`; aggregate tracing continues and the file remains parseable. Four fixed 256 KiB buffers are allocated before tracing. If all are full, the traced thread waits for the writer instead of dropping records, and `wait_time_ns`/`wait_time_ms` report that backpressure cost. File event streaming works through direct calls, `veh_batch`, and breakpoint actions. It can be combined with occurrence windows, but not `target_window`, whose pre-trigger eviction semantics require its existing bounded inline rings.

```powershell
py -3 tools/read_trace_event_stream.py trace.vte --output trace-events.jsonl
```

### Ordered-event artifact format (`.vte`)

Schema 1 is packed little-endian and independent of target pointer width. The file begins with this 88-byte header:

| Field | Type | Meaning |
|---|---|---|
| `magic` | `u64` | `0x00544E5645484556` (`VEHEVNT\0`) |
| `schema_version`, `header_size`, `flags` | `u32` each | Version 1; 88 bytes; bit 0 complete and bit 1 truncated |
| `record_header_size` | `u32` | 8 bytes |
| `event_entry_size`, `memory_entry_size`, `register_entry_size` | `u32` each | 48, 84, and 320 bytes for schema 1 |
| `record_bytes` | `u64` | Bytes after the file header |
| `event_count`, `memory_event_count`, `register_event_count` | `u64` each | Per-kind record counts |
| `wait_time_ns` | `u64` | Time the traced thread waited for a free stream buffer |
| `truncation_reason`, `chunk_count`, `reserved` | `u32` each | Reason 0 none, 1 size limit, 2 transfer failure; transmitted chunk count; zero |

Each following record has an 8-byte header: `type:u16`, `reserved:u16`, and `payload_size:u32`. Type 1 contains the 48-byte `TraceBasicBlockEventEntry`, type 2 the 84-byte `TraceBasicBlockMemoryEventEntry`, and type 3 the 320-byte `TraceBasicBlockRegisterEventEntry`, as defined in `src/common/ipc_protocol.h`. Records remain interleaved in capture order and share the trace-step `sequence`; multiple records may have the same sequence. Readers must use `payload_size`, reject unknown types or nonzero reserved fields for schema 1, and stop at exactly `header_size + record_bytes`. A truncated size-limited file ends after a complete record, never in a record header or payload. The supplied reader performs these checks and emits a manifest followed by one JSON object per record.

## Basic-block collection policies and repeated paths

`veh_trace_basic_blocks` retains its defaults. Set `collect_snapshots=false`
to skip snapshot allocation, GPR/flags copying and stack reads for first
block/edge and exception snapshots. Snapshot arrays are empty and references are omitted;
instruction register events remain a separate opt-in collector. Conditions and
precise execution control still use the exception CONTEXT. A path-only capture
can also leave memory reads/writes/events, register events and dependency sources
disabled; the backend then skips their operand/dependency preparation.

Set `compress_paths=true, collect_code=true` to encode consecutive observed
repeated paths. Inline and `events_output="file"` use the same bounded encoder
with a maximum32-event raw template and at most32 pending events. This reduces
event records and transfer bytes, **not TF single-step exceptions**. Code capture
still copies/hashes runtime block bytes and can outweigh record savings for
some workloads; no speedup factor is promised.

Compression initially excludes `target_window` and ordered memory/register
events. Aggregated memory observations remain available. Unknown code versions,
exceptions, collection gaps, external-call gaps and observed per-block version
changes flush the pending run. A partial final cycle is emitted raw. Templates
never contain another repeat. Overflow retains a decodable prefix and drops
later records; aggregates continue. The collector traces one selected thread,
not a process-wide order. It does not validate known instruction metadata on
every execution or guarantee fidelity under arbitrary concurrent self-modifying
code. Missing code/decode metadata is reported as incomplete, never reconstructed
as an observed path.

New policies require explicitly reported `kCapBasicTracePolicies` (bit6) before
any trace effects. Wire11 appends `collectionFlags:u32` to the fixed wire10
request prefix. Bits0/1 mean suppress snapshots/compress paths. The new response
appends applied flags, decode-incomplete and retained expanded-event count;
MCP validates the exact policy receipt. Requests without a new policy still
send wire10 for old-backend compatibility. Enhanced captures refuse enabled
managed HW breakpoints and active DR7 slots before changing TF or resuming:
the legacy TF dispatcher cannot safely promise simultaneous hardware stops.

Ordered event schema3 adds `type="repeat"` with `pattern_events` (1..32),
`additional_repetitions` and `sequence_stride`. The immediately preceding
N raw edge records are the template, already counted once. For extra cycle
r=1..additional_repetitions, each template event has
`sequence = template.sequence + r * sequence_stride`; every other semantic
field is preserved. The marker sequence is the first event of extra cycle1.
The decoder checks reference bounds, thread, ordering and integer overflow.

Compressed `.vte` artifacts/transport frames use schema2; uncompressed files
retain schema1. Record framing and 48-byte basic-event payload sizes do not
change. Payload event type2 is Repeat: `source=N`,
`sourceInstruction=additional_repetitions`, `target=sequence_stride`,
`codeVersion=UINT32_MAX`, zero exception/indirect/reserved and fallthrough
edgeKind. Header event counts and `max_events` count physical records.
`ordering.expanded_events_captured` counts retained logical events;
`events_dropped` counts logical events, including suppressed cycles if a
whole marker cannot fit. Compression never continues across a dropped record.

Use the existing artifact reader to validate references or expand them:

```powershell
py -3 tools/read_trace_event_stream.py trace.vte --expand-paths --output expanded.jsonl
```

Expansion is streaming and capped at5,000,001 logical events. The JSON validator
checks schema3 references and expanded counts without materializing repeats.
The existing basic-block integration suite invokes `trace_path_regression`
(33 template widths, branch/stride changes, barriers, incomplete tails and
overflow arithmetic), then compares raw and expanded real VEH paths in x64/x86,
inline/file and direct/batch/action modes. Build that CMake target with the
normal debugger targets before running `veh.trace.parity`. The existing
`test_backend_results.py` guest fixture also checks malformed repeats, logical
count/thread mismatches, unacknowledged policies and structured backend refusals.
For a retained wire10 build that already supports the existing windows, the IPC
matrix accepts `--old-supports-existing-extensions` and
`--expect-old-no-collection-policies`; it verifies policy refusal before target
execution as well as default old/new compatibility.

### MCP usage size

README and development-document text is not emitted by MCP initialization.
The default `lite` and `interactive` tool inventories do not eagerly expose
`veh_trace_basic_blocks`; discover it through a toolbox manifest/description.
Its two optional fields add no new tools. Measure actual serialized bytes with
`tools/measure_mcp_schema.py`; bytes are not a model-specific token count.
Code collection can add inline bytes even when paths compress: use file artifacts
and `output_file` for bounded metadata responses when large captures are needed.
`output_file` reduces the MCP response while the server still builds the full
JSON result; it does not skip target collection.

### Backend adoption checklist

External backends have not been updated by this frontend/VEH change. Share this
section and `src/common/ipc_protocol.h` with their maintainers:

- Keep wire10 request/response prefixes fixed; use the versioned size constants,
  not a newly enlarged `sizeof` for an old wire layout.
- Implement both wire11 collection flags before advertising
  `kCapBasicTracePolicies` (GetCapabilities flags bit6). CPU support, an existing
  TraceBasicBlocks command or transport connectivity is insufficient.
- Validate flags and incompatible combinations before target effects; refuse
  unsupported policy requests instead of silently ignoring them. Snapshot
  suppression skips collection, not just JSON fields.
- Return the responseV9 header with exact `appliedCollectionFlags`,
  `decodeIncomplete` and retained `expandedEventCount`. Preserve non-Ok refusal
  reasons. Empty snapshot arrays must have no snapshot references.
- For compression, implement event schema3 and immutable raw-suffix Repeat
  records with exact stride, branch choices and thread identity. Flush at
  collection/loss/exception/code-version/unknown-metadata boundaries; retain
  partial tails raw. Never infer an unobserved path.
- File compression uses artifact/transport schema2; raw files remain schema1.
  Count physical records separately from logical retained/dropped events.
  Validate file thread/count receipts against the control response.
- Perform collection in backend IPC, retaining direct/batch/action parity.
  Prove compatibility, real capture boundaries and exact stops on that backend;
  frontend fixture success alone does not qualify another collector. The VEH
  HW-breakpoint conflict refusal is a VEH implementation limitation; another
  backend may support coexistence only if its ownership and precise stops are
  actually verified.

Qualification starts with the existing `veh.trace.parity`, IPC matrix and
`test_backend_results.py` malformed-receipt cases. Default calls must continue
working with a wire10 peer; new policies must fail before execution when bit6 is
absent. See the collection-policy section above for the exact current limits.

This is the trace-policy migration checklist, not a declaration that every
external backend is synchronized with the entire frontend. Backend-wide adoption
must first identify that backend's common-header baseline and compare all command,
capability and result-contract changes since it. Instrumentation and other
interfaces have separate requirements in their applicable sections/documents.

Before declaring this migration complete, retain a concise local evidence record
for each backend with:

- backend/header revisions, x86/x64 target width and supported host/guest/VM scope;
- the supported flag and inline/file combinations, deliberate exclusions and
  old/new-peer compatibility results;
- exact stop ownership, cancellation/timeout behavior, detach/reconnect cleanup,
  bounded buffers/backpressure and partial-transfer/overflow results;
- real collection-gap, indirect-branch, exception and code-version boundary
  results, with unknown identity/loss/completeness kept explicit;
- measured exception counts, collection/transfer sizes and relevant timings if
  performance is claimed. Record reduction alone does not prove fewer exceptions.

Use synthetic fixtures and keep private paths/targets out of shared evidence.
Frontend fixture parity is one part of this record, not backend qualification.

## Occurrence-scoped collection

Use `occurrence_window` to collect one or more dispatcher/instruction cycles:

```json
{"address":"sample.exe+0x1200","from":5,"to":8}
```

Visits are one-based. Collection begins immediately before executing the `from` visit and a bounded window ends immediately before `to + 1`; `to: 0` leaves the upper bound open. The occurrence gate is AND-composed with `start_condition` and `collect_condition`. `stop_condition`, leaving the trace address range, limits, timeout, cancellation, or exception may still stop earlier. The result reports visits, whether collection started, and whether the requested bounded window completed.

For handler-focused work, `target_window={address,occurrence,before_steps,after_steps}` keeps a bounded ordered pre-trigger ring and stops after the post-trigger instruction count. It supports inline runtime code plus ordered block/register/memory events; `code_output="file"`, conditional/occurrence windows, and function-return mode are intentionally incompatible. Aggregate tables are reset at the match and therefore describe the trigger/post-trigger portion, while ordered streams cover the requested pre/post range.

`veh_targeted_capture` wraps this mode for 1-256 inputs. Per-input `steps` use normal batch references to restore a checkpoint or set registers/memory, then the tool captures TEB/FS/GS and optional memory regions, writes a unique JSON artifact under `output_directory`, and returns path/hash/size/count/drop/truncation/match/failure metadata. An input succeeds only after at least one completed instruction and `stop_reason="target_window"`; exception, zero-step, and other partial windows report `capture_complete=false`, an incomplete artifact, and contribute to `failed`/`first_failed_input`. The target must already be attached; session lifecycle operations are deliberately unavailable in setup, and nesting this matrix orchestrator inside `veh_batch` or a breakpoint action is deliberately excluded. The underlying `veh_trace_basic_blocks.target_window` remains available with direct, batch, and action parity.

## Checkpoint thread environment

`veh_checkpoint_create` always records architecture (`x86`, `wow64`, or `x64`), effective TEB address, FS/GS selectors, and effective segment bases when available. `capture_teb: true` adds 256-1,048,576 bytes (`teb_size`, default 4096) from the effective TEB to checkpoint diff data. TEB bytes and segment bases are OS-managed observations and are deliberately not restored. An explicit region in the stopped thread's stack allocation is labeled `stack`; restore copies from the captured SP upward and reports `live_stack_bytes_skipped`, preserving the live VEH exception/wait frames below SP while restoring the logical application stack.

## Batch input reports

`veh_batch` accepts optional `inputs` (1-256), binds each item to `input_variable` (default `$input`), and runs the same steps sequentially in one debug session. `stop_on_error` stops the current execution and remaining inputs after the first failed step. Reports retain existing `results`/step data and add per-input index, status, steps, success/failure counts, first failure, trace summaries, artifact metadata, and top-level totals. No implicit checkpoint restore occurs between inputs; include explicit checkpoint steps when isolation is required.

To start and inspect a target in one round trip, put `veh_launch` (or `veh_attach`) in the first top-level step. This is only valid when no session is active and cannot be combined with `inputs`; later and nested lifecycle operations remain rejected.

```json
{"steps":[{"tool":"veh_launch","args":{"program":"sample.exe","stopOnEntry":true},"result_fields":["success","pid"]},{"tool":"veh_modules","args":{}}]}
```

Each step may set `result_fields` to 1-128 dotted paths such as `registers.rip` or `frames.0.address`. Only those fields are returned for that step, while `$N`, `$last`, named variables, conditions, nested steps, and breakpoint actions continue to use the complete internal result. Missing paths are reported under `_selection` instead of being silently invented.

Set top-level `max_output_bytes` (1 KiB-64 MiB) to bound the complete serialized batch response. If the report is larger, the server writes the complete field-selected report to a generated non-overwriting JSON artifact and returns compact path/SHA-256/size/count plus `partial_reason="max_output_bytes"`. `artifact_directory` may select an existing MCP-host directory; otherwise a dedicated host temporary directory is created. The artifact is a response transport, not target state: memory searches, maps, traces, and other target work still execute through their backend IPC commands. Callers own artifact retention and cleanup.

```json
{"steps":[{"tool":"veh_registers","args":{"threadId":1234,"fields":["rsp"]}},{"tool":"veh_read_memory","args":{"address":"$0.registers.rsp","size":8}}]}
```

```json
{"max_output_bytes":8192,"steps":[{"tool":"veh_disassemble","args":{"address":"module+0x1000","count":500},"result_fields":["instructions","count"]}]}
```

Use `$last` for loop results because absolute step indices change on each iteration:

```json
{"steps":[{"loop":[{"tool":"veh_step_over","args":{"threadId":1234}},{"tool":"veh_registers","args":{"threadId":1234,"fields":["rax"]}}],"until":"$last.registers.rax!=0","max":100}]}
```

Input matrices can restore a checkpoint explicitly before applying each input:

```json
{"inputs":[1,2,3],"steps":[{"tool":"veh_checkpoint_restore","args":{"id":"checkpoint-id"}},{"tool":"veh_set_register","args":{"threadId":1234,"name":"rax","value":"$input"}}]}
```

## Parity and compatibility

```powershell
py -3 tools/run_trace_parity.py --build-dir build --build-dir build32
py -3 tools/run_ipc_compat_matrix.py --old-build-dir <old-build> --new-build-dir build --target build/bin/Release/test_target.exe --expect-old-no-file-mode
```

The parity runner invokes the architecture-sensitive integration suite for each build root. The IPC runner verifies that ordinary tracing remains compatible in both old/new directions and that extensions unsupported by an older injected DLL fail explicitly rather than corrupting response layouts.

## Kernel-stub protocol regression

`py -3 tools/run_tests.py test_kernel_debug_protocol.py --jobs 1 --timeout 30`
uses a synthetic localhost GDB RSP peer with the shared bounded MCP client.
It checks unsolicited stops, NUL-terminated packets, console output, short
register replies, interrupt fallback and safe detach of execution/data
breakpoints. Cleanup rejection must retain the session and prevent detach;
retry must remove each original kind/size before sending `D`. No VM is used.

## Acknowledgements and operation deadlines

DAP command success requires the backend response: status-only operations must
return exactly `IpcStatus::Ok`, and Continue must return complete resumed and
still-stopped lists with `wantDetails=1`. Guest pause stops come from the backend
`Paused` event, whose payload is one `uint32_t` thread ID (0 means all); local
VEH uses its synchronous successful pause acknowledgement for compatibility.
Stack failures remain errors; a valid empty stack stays empty. DAP exception
filters currently support only `all`; empty/uncaught/advanced configurations
are rejected because exception IPC does not identify first/second chance.

`veh_address_space` allows 180 seconds for the complete resolve request, including
scan, page fault-ins, validation and application. MCP clients and test drivers
must allow a longer tool-call deadline when waiting for this operation. A wait
timeout does not cancel the backend or roll back an applied root. After an
ambiguous timeout, reconnect and query the active root before issuing another
state-changing request. Failed pipe writes likewise have ambiguous delivery:
ordinary requests are rejected until reconnect; detach/shutdown remain allowed.

## Backend error event semantics

`IpcEvent::Error` (`0x10FF`) is a non-terminal backend diagnostic. Receipt does
not disconnect the transport, detach the session, terminate the target or
complete a pending stop wait. MCP and DAP currently log receipt only; they do
not decode its payload or forward a structured loss notification to clients.
A backend may use it to diagnose a stop-queue overflow, but it must not count
that diagnostic as delivery of the lost stop. There is no agreed payload or
loss-counter format yet; reliable client-visible loss reporting requires a
separately agreed contract. Target exit uses `ProcessExited`; transport failure
is detected by the transport itself.

## External guest targets

For a backend whose PIDs belong to an analyzed VM, set `target_scope: "guest"`
in its `veh-backends.json` entry, or pass `target_scope: "guest"` with `agent`
to `veh_attach`. Registered entries select a VM through backend-specific `args`;
use a distinct entry per VM. Scope defaults to `host` for existing backends.
Guest peers must advertise `kCapGuestTarget` and implement `GetTargetInfo`
(empty request, exact 16-byte response: status, scope, PID, addressBits).
The frontend accepts only matching guest scope/PID and 32 or 64 address bits.
`test/test_vm_attach.py` also checks a synthetic VM-scoped `GetProcesses`
response through `veh_toolbox` and `veh_batch`, including malformed length,
invalid width and explicit Unsupported responses.
It opens no host process handle for guest targets, installs no host PID monitor,
and uses backend-provided width for disassembly. Guest event ownership is the
authenticated backend's responsibility, not a host Toolhelp lookup. Backend
reuse requires identical path, arguments and scope. Guest `veh_launch` is
explicitly unsupported until guest process creation and stopOnEntry are wired.

For guest DAP module-qualified function breakpoints (`module!function`), the
adapter uses `SetModuleLoadStop` only when that command, Continue and
`IsThreadStopped` are advertised. It arms the DLL-name guard before resolving
and queues `ModuleLoadStopped` to the existing worker. That event is historical:
a foreground Continue/Step may already have consumed the hold. The worker
queries current stop state before binding, drops resumed notices, preserves
known stop reasons, and exposes an observed stop for explicit user continuation.
A failed/unsupported stop query emits a diagnostic without inventing a stop.

A loader-origin stop may retain the target loader lock. During that hold, keep
work to stop-state queries, symbol resolution and breakpoint bookkeeping; do not
invoke ExecuteShellcode, remote-thread creation or other target code execution
that can wait on loader initialization. Finish binding and explicitly Continue
before starting those operations. A manual pause following module load is not
a general-purpose safe call point. Guard names are module base names such as
`version.dll`, not file paths; matching remains the backend substring contract.

There is deliberately no automatic Continue: `IsThreadStopped` proves state,
not ownership, and neither the module event nor Continue carries a hold ID.
Transparent automatic continuation would require a backend-issued stop identity
and an atomic resume-if-that-hold-is-current operation. Arrival counters or a
reason query alone do not close that race. Guards remain while functions are
configured so reloads can rebind; replacement removes only internal patterns
and preserves shared software breakpoint IDs. Backend patterns use substring
matching, so similarly named DLLs may also produce an observed stop. Missing
guard/query support retains best-effort ModuleLoaded handling. This does not enable the explicit guest
`stopOnModuleLoad` configuration option. The short-lifetime VM fixture still
needs to be run by the backend test session after updating the frontend.

DAP uses `targetScope="guest"`, `processId`, an absolute `agent` and optional
`agentArgs`. It validates the pipe peer and guest metadata, then gates command
routing on backend capabilities. Control includes continue/pause, instruction
steps and step out; memory, breakpoint, symbol and inspection commands require
the corresponding advertised IPC commands. Source/function breakpoints use
backend symbol resolution. Stops name the selected thread and do not claim all
threads stopped. Guest launch and `stopOnModuleLoad` remain unsupported.

`py -3 tools/run_tests.py test_guest_backend.py --jobs 1 --timeout 60` builds on
the host-only `guest_backend_fixture` target to check PID collisions, metadata
failures, registered scope, bitness and unsupported pause/terminate handling.
  Query diagnostics cover backend status rejection, truncated versus valid empty
  lists (thread and module lists must match their payload exactly, names
  terminated), direct/batch module-list status, no-hit traces and batch error
  parity. It also
checks immediate step refusals and zero-call hypervisor traces without automatic
Continue/Pause, using the same synthetic fixture rather than a real VM. The
fixture also returns three Detach errors before success to check that direct
detach and attach/launch replacement keep the prior session until the backend
acknowledges cleanup. A dead external agent or disconnected local pipe instead
permits MCP to clear its stale session/cache and reconnect. The agent's original
process handle and matching pipe identify the current peer; PID reuse or a stale
external-agent record cannot stand in for a native DLL. Clearing local state does
not prove target cleanup: explicit `veh_detach` returns
`backendCleanupConfirmed: false` in that case. TCP work closure also cannot
confirm a backend acknowledgement, so TCP detach carries the same marker while
retaining its existing resident-work closure wait. A connected live backend's rejected,
malformed or unavailable reply still retains the session. DAP cleanup is unchanged.

`IpcStatus::InvalidState = 6` means an advertised operation was refused **before
starting** because of the current target state. Values 0-5 and existing response
layouts are unchanged. For `ExecuteShellcode`, a non-Ok status may be sent alone
or in the existing response; success requires the complete response. MCP returns
`backendStatus` for a received failure status and `code: "invalid_state"` for 6,
with identical direct/batch/action errors. Generic Error remains generic; transport
failure does not invent a backend status. Do not infer reasons from backend exit
codes or logs, automatically resume the target, or retry code execution.

Backends should check loader initialization, held module-load stops and stopped
threads owning LoaderLock **in the target's address space**, before creating an
execution thread. For an inner guest these are guest state, not host state. A
loader-related refusal may use InvalidState; the frontend does not implement or
claim those backend checks. Command capabilities describe implemented support;
runtime target-state refusal does not change that capability.

A first top-level `veh_batch` step can attach/launch an unattached session;
repeated/nested batches and breakpoint actions cannot replace sessions.
Inspect commands retain their ordinary batch/action routes. `veh_processes`
also uses the shared dispatcher for direct, toolbox and batch calls; VM-scoped
sessions have no process breakpoint actions.

`py -3 -B test/test_virtual_machine.py` verifies VM-scope MCP behavior using a
synthetic host fixture: direct/toolbox parity, exact64-bit timestamp strings,
loss/partial-failure validation, manual-only nesting and no guest execution.

`py -3 -B test/test_vm_attach.py` checks no-PID VM agent routing, explicit
metadata validation, prior-session preservation and registered VM scope with a
synthetic host fixture. The fixture rejects a VM invocation containing --pid.
