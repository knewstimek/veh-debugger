# MCP trace development tools

These bounded command-line helpers are the preferred way to reproduce and validate MCP trace changes. Run them from the repository root. Examples use only synthetic build targets; do not commit local machine paths, credentials, private target names, trace artifacts, or details that identify a real analyzed program.

## Tool catalog

| Tool | Purpose |
|---|---|
| `test/mcp_test_client.py` | Shared timeout-aware MCP stdio client. It bounds captured diagnostics and terminates only processes it started. |
| `tools/run_mcp_scenario.py` | Runs 1-500 calls from a JSON scenario, supports named result references, stops on errors by default, and optionally writes a new report without overwriting. |
| `tools/validate_trace_output.py` | Validates exported trace JSON/JSONL ordering, thread ownership, counts, hashes, and optional `.vtc` code-version references. |
| `tools/run_trace_parity.py` | Runs the trace integration suite against one or more build roots to cover direct, `veh_batch`, and breakpoint-action semantics. |
| `tools/run_ipc_compat_matrix.py` | Stages old-MCP/new-DLL and new-MCP/old-DLL pairs in a temporary directory and runs bounded compatibility smoke tests. |

All process-launching helpers use finite timeouts and wait for their children during cleanup. The compatibility runner stages copies under an OS temporary directory and removes them when complete.

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

## Occurrence-scoped collection

Use `occurrence_window` to collect one or more dispatcher/instruction cycles:

```json
{"address":"sample.exe+0x1200","from":5,"to":8}
```

Visits are one-based. Collection begins immediately before executing the `from` visit and a bounded window ends immediately before `to + 1`; `to: 0` leaves the upper bound open. The occurrence gate is AND-composed with `start_condition` and `collect_condition`. `stop_condition`, leaving the trace address range, limits, timeout, cancellation, or exception may still stop earlier. The result reports visits, whether collection started, and whether the requested bounded window completed.

For handler-focused work, `target_window={address,occurrence,before_steps,after_steps}` keeps a bounded ordered pre-trigger ring and stops after the post-trigger instruction count. It supports inline runtime code plus ordered block/register/memory events; `code_output="file"`, conditional/occurrence windows, and function-return mode are intentionally incompatible. Aggregate tables are reset at the match and therefore describe the trigger/post-trigger portion, while ordered streams cover the requested pre/post range.

`veh_targeted_capture` wraps this mode for 1-256 inputs. Per-input `steps` use normal batch references to restore a checkpoint or set registers/memory, then the tool captures TEB/FS/GS and optional memory regions, writes a unique JSON artifact under `output_directory`, and returns path/hash/size/count/drop/truncation/match/failure metadata. The target must already be attached; session lifecycle operations are deliberately unavailable in setup, and nesting this matrix orchestrator inside `veh_batch` or a breakpoint action is deliberately excluded. The underlying `veh_trace_basic_blocks.target_window` remains available with direct, batch, and action parity.

## Checkpoint thread environment

`veh_checkpoint_create` always records architecture (`x86`, `wow64`, or `x64`), effective TEB address, FS/GS selectors, and effective segment bases when available. `capture_teb: true` adds 256-1,048,576 bytes (`teb_size`, default 4096) from the effective TEB to checkpoint diff data. TEB bytes and segment bases are OS-managed observations and are deliberately not restored. An explicit region in the stopped thread's stack allocation is labeled `stack`; restore copies from the captured SP upward and reports `live_stack_bytes_skipped`, preserving the live VEH exception/wait frames below SP while restoring the logical application stack.

## Batch input reports

`veh_batch` accepts optional `inputs` (1-256), binds each item to `input_variable` (default `$input`), and runs the same steps sequentially in one debug session. `stop_on_error` stops the current execution and remaining inputs after the first failed step. Reports retain existing `results`/step data and add per-input index, status, steps, success/failure counts, first failure, trace summaries, artifact metadata, and top-level totals. No implicit checkpoint restore occurs between inputs; include explicit checkpoint steps when isolation is required.

## Parity and compatibility

```powershell
py -3 tools/run_trace_parity.py --build-dir build --build-dir build32
py -3 tools/run_ipc_compat_matrix.py --old-build-dir <old-build> --new-build-dir build --target build/bin/Release/test_target.exe --expect-old-no-file-mode
```

The parity runner invokes the architecture-sensitive integration suite for each build root. The IPC runner verifies that ordinary tracing remains compatible in both old/new directions and that extensions unsupported by an older injected DLL fail explicitly rather than corrupting response layouts.
