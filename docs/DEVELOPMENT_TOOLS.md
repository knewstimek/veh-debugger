# MCP trace development tools

These bounded command-line helpers are the preferred way to reproduce and validate MCP trace changes. Run them from the repository root. Examples use only synthetic build targets; do not commit local machine paths, credentials, private target names, trace artifacts, or details that identify a real analyzed program.

## Tool catalog

| Tool | Purpose |
|---|---|
| `tools/run_tests.py` | Runs every `test/test_*.py` file in parallel (`--jobs`, longest first from `test/.test_durations.json`) with a per-file timeout, prints durations, flags exit-0 runs that report FAIL, skips `# requires: x64` files on an x86 build and `# slow` files with `--quick`, and cleans up exactly the processes each file started (parent chain + creation time, so reused pids are never adopted). |
| `test/mcp_test_client.py` | Shared timeout-aware MCP stdio client. It bounds captured diagnostics and terminates only processes it started. |
| `tools/run_mcp_scenario.py` | Runs 1-500 calls from a JSON scenario, supports named result references, stops on errors by default, and optionally writes a new report without overwriting. |
| `tools/validate_trace_output.py` | Validates exported trace JSON/JSONL ordering, thread ownership, counts, hashes, and optional `.vtc` code-version references. |
| `tools/read_trace_event_stream.py` | Validates a portable `.vte` ordered-event artifact and converts its interleaved block/edge, memory, and register records to JSON Lines. |
| `tools/run_trace_parity.py` | Runs the trace integration suite against one or more build roots to cover direct, `veh_batch`, and breakpoint-action semantics. |
| `tools/run_ipc_compat_matrix.py` | Stages old-MCP/new-DLL and new-MCP/old-DLL pairs in a temporary directory and runs bounded compatibility smoke tests. |
| `tools/measure_mcp_schema.py` | Measures bounded initialize and `tools/list` bytes, input-schema bytes, output-schema count, and eager names for every exposure profile. |

All process-launching helpers use finite timeouts and wait for their children during cleanup. The compatibility runner stages copies under an OS temporary directory and removes them when complete.

## RepoPlane catalog

The reusable commands above and the guarded release workflow are registered as
typed capabilities under `catalog/`. After refreshing RepoPlane catalog discovery,
use `catalog_query` with terms such as `veh trace`, `veh mcp`, or `veh release`.
Executable capabilities still require Runner authorization; catalog discovery alone
does not authorize a build, target launch, tag push, GitHub Release, or Marketplace
publication. `veh.release.publish` is deliberately separate from
`veh.release.prepare` so preparation cannot create external release state.

## MCP exposure profiles and lazy toolbox

The server defaults to `--profile=lite`. Keep each eager surface at ten tools or fewer, and use `veh_toolbox` for the long tail:

| Profile | Eager tools | Intended workflow |
|---|---:|---|
| `lite` | 7 | Launch/attach/continue/batch/terminate/registers plus lazy discovery |
| `interactive` | 10 | Attach, breakpoints, registers, disassembly, and memory inspection |
| `capture` | 10 | VM trace, targeted input capture, and checkpoint restore loops |
| `full` | 46 | Compatibility with clients that require the complete eager inventory |

```json
{"operation":"list","query":"checkpoint"}
{"operation":"describe","tool":"veh_checkpoint_create"}
{"operation":"call","tool":"veh_checkpoint_create","arguments":{"threadId":1234}}
```

Reuse the returned `schema_handle` in a later `describe`; an unchanged schema returns only the name, handle, and `unchanged:true`. Tools remain directly callable by name even when they are not in the active `tools/list`, preserving existing scenario, analyzer, and batch automation. `veh_toolbox` is control-plane discovery and deliberately cannot call itself or be nested in `veh_batch`/breakpoint actions.

Batch steps, targeted-capture setup steps, and breakpoint actions call the same tool implementations as direct MCP calls, so arguments, validation, and result fields are identical everywhere. Only session lifecycle tools (`veh_attach`, `veh_launch`, `veh_detach`, `veh_terminate`) and re-entrant orchestrators (`veh_batch`, `veh_targeted_capture`, `veh_toolbox`) are rejected in those nested contexts; the `nested` flag in the server tool table is the single source for that policy.

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

```json
{"steps":[{"tool":"veh_registers","args":{"threadId":1234,"fields":["rsp"]}},{"tool":"veh_read_memory","args":{"address":"$0.registers.rsp","size":8}}]}
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
