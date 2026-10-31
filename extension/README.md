# VEH Debugger

Windows debugger based on **VEH (Vectored Exception Handler)** instead of the Windows Debug API. Ideal for reverse engineering targets with anti-debug protection.

## Module and symbol selection

MCP symbol search lists up to ten candidates with image bases, paths and available address widths. Use `veh_symbolize(name="Function", module_base="0x...")` or `0xBASE!Function` in address expressions to select a duplicate image. Unknown widths stay unknown; external backend support is required for the new queries. See [the changelog](CHANGELOG.md) for upgrade notes.

Persistent MCP comments and labels are managed through `veh_symbolize(analysis=...)` and saved as JSON in a selected local folder. Builds stay isolated and changed code is marked for review; unavailable build identities never auto-apply notes. See the repository's [analysis notes guide](https://github.com/knewstimek/veh-debugger/blob/master/docs/ANALYSIS_NOTES.md).

## Features

- **Anti-debug friendly** — Uses VEH instead of `ntdll!DbgUiRemoteBreakin`, bypasses common anti-debug checks
- **Software breakpoints** — INT3 (0xCC) patching at any address
- **Hardware breakpoints** — DR0-DR3 registers for memory read/write/execute watch (like Cheat Engine's "Find what writes/accesses")
- **x86 & x64** — Debug both 32-bit and 64-bit processes
- **PDB symbols** — Source file + line number mapping, function name breakpoints
- **Disassembly** — Zydis x86/x64 disassembler with full operand display
- **Memory read/write** — Inspect and modify process memory
- **Register editing** — Modify register values directly from the Variables panel
- **Conditional breakpoints** — Break only when condition is met (`RAX==0x1234`, `*0x7FF600!=0`, `RCX>0x100`)
- **Hit count breakpoints** — Break on Nth hit
- **Log points** — Log `{RAX}`, `{*0x7FF600}` to Debug Console without stopping execution
- **Multiple injection methods** — CreateRemoteThread, NtCreateThreadEx, Thread Hijack, QueueUserAPC
- **TCP remote mode** — Debug across VMs or network
- **Authenticated MCP backend connections** — Registered remote profiles use pinned TLS and a resident runner for backend startup, host launch and reconnect; the runner is included in the binary distribution
- **MCP tool server** — Debugger operations exposed directly to AI agents (Claude, Cursor, Codex, etc.)
- **Bounded semantic tracing** — Aggregate blocks/edges plus optional ordered block, memory-access, register-delta, and runtime-code events in one sequence space without per-instruction MCP traffic
- **File-backed trace results** — Process basic-block traces save JSON/JSONL results to generated host files by default and return compact path/hash/count/drop/truncation receipts. Explicit `output_mode="inline"` returns full JSON. Separately stream ordered events to `.vte` or up to 400 MiB of runtime code to `.vtc` on supported local backends
- **Occurrence-scoped capture** — Collect selected dispatcher/instruction visits and combine them explicitly with start, stop, and collection conditions
- **Repeatable analysis sessions** — Capture bounded thread checkpoints including TEB and FS/GS metadata, run input matrices through `veh_batch`, or write occurrence-centered code/register/memory/environment artifacts with `veh_targeted_capture`

## Quick Start

### Launch a program

Add to `.vscode/launch.json`:

```json
{
    "type": "veh",
    "request": "launch",
    "name": "VEH Debug",
    "program": "${workspaceFolder}/target.exe",
    "stopOnEntry": true
}
```

### Attach to running process

```json
{
    "type": "veh",
    "request": "attach",
    "name": "VEH Attach",
    "processId": 1234
}
```

## Configuration

| Property | Type | Description |
|----------|------|-------------|
| `program` | string | Path to executable (launch only) |
| `processId` | number | PID to attach to (attach only) |
| `args` | string[] | Command line arguments |
| `stopOnEntry` | boolean | Break at entry point |
| `injectionMethod` | string | `auto` / `createRemoteThread` / `ntCreateThreadEx` / `threadHijack` / `queueUserApc` |
| `runAsInvoker` | boolean | Bypass UAC elevation prompt (`__COMPAT_LAYER=RunAsInvoker`) |
| `adapterPath` | string | Custom path to `veh-debug-adapter.exe` |
| `adapterPort` | number | TCP port (0 = stdio mode) |
| `logFile` | string | Log file path |
| `logLevel` | string | `debug` / `info` / `warn` / `error` |

## Hardware Breakpoints

Watch memory addresses for read/write access using CPU debug registers (DR0-DR3):

- Up to 4 simultaneous hardware breakpoints
- Watch sizes: 1, 2, 4, or 8 bytes
- Types: write, read/write, execute

This is equivalent to Cheat Engine's "Find out what writes to this address" / "Find out what accesses this address".

## MCP Tool Server (AI Integration)

The bundled `veh-mcp-server.exe` exposes debugging operations through the Model Context Protocol, allowing AI agents to directly control the debugger. Its default token-bounded `lite` profile exposes a small common set plus the `veh_toolbox` lazy gateway; use `--profile=interactive` or `--profile=capture` for small workflow inventories, `--profile=analysis` for 41 advanced analysis tools, `--profile=vmguest` for those tools plus guest process discovery and whole-VM control (43), or `--profile=full` for the complete inventory. Profiles select exposure only; actual operations still require backend support. Known hidden tool names remain directly callable. The running server's MCP `tools/list` response is the authoritative eager inventory.

MCP can also attach through an external backend with `backend` or `agent`.
For VM guest PIDs, register `target_scope: "guest"` in `veh-backends.json`
(or pass it to `veh_attach`); backend PID/address-width validation is required.
Guest `veh_launch`/`stopOnEntry` is unsupported, and other commands depend on
the attach response's `backend.unsupported`. This is MCP support, not a guest
extension to the VSCode DAP launch configuration. Use `veh_toolbox` with
`operation="describe"` for the live attach/launch schema. See the repository's
English README for registration and prerequisites.

Launch/attach defaults to local `backend="veh"` when both `backend` and `agent`
are omitted. Select an explicit registered backend name for remote TCP connections.
The resident `veh-remote-runner.exe` runs on the analysis VM; for VirtualBox/WHPX
it belongs on the analysis host VM, outside the inner guest. Authentication runs
once per connection, using a private token file and pinned server certificate.
Successful reconnects do not consume the failed-authentication limit. Guest launch,
remote frontend conditional breakpoints and target-side trace file pipes remain
unsupported. The adapter's DAP TCP listener is a separate interface. Configuration
and limits are documented in `docs/REMOTE_TRANSPORT.md` in the repository.

`veh_trace_memory` preserves first-write detection when `duration_ms` is omitted.
Add `duration_ms` (10-60000 ms) to collect location counts with `access="write"`
(default) or combined `"readwrite"`; read-only and individual read/write
classification are unsupported. `max_entries` defaults to 64 (maximum 1024), with
`dropped_hits` for unretained locations. On VEH, `instructionAddress` is the
post-access IP (`addressIs="next_instruction"`), and first-hit registers are also
post-access. External backends must implement the collection command; capability
flags do not report numeric breakpoint capacities. Backends may return `LimitReached`
when full; breakpoint tools then report no free slot so an existing breakpoint can be removed.

`veh_value_scan` reuses the existing MCP tool for async first/next, disk-backed
candidates and undo of both addresses and comparison values. Large sets return counts;
up to 32 candidates are listed automatically. Completion/progress uses
`notifications/veh/value_scan`, with no status polling. Clients must consume that
notification; use explicit status/results or bounded async:false when needed.
Reset/detach release owned temporary files; baseline/undo files survive a single scan.
External backends require v2 capability support. See `docs/VALUE_SCAN.md` in the
repository for storage budgets, batch/action sequencing and adoption checks.

`veh_trace_basic_blocks` supports x86/x64 ordered memory and register provenance,
self-modifying code versions, dispatcher occurrence windows, and file-backed
JSON/JSONL, `.vtc` code or `.vte` ordered-event artifacts. Direct calls, `veh_batch`, and breakpoint actions
share the same trace semantics. Process results default to `output_mode="file"`:
`output_file` optionally selects a new path, otherwise a unique file is generated
under the MCP host temporary `veh-mcp-artifacts` directory. `output_format` selects
JSON or JSONL for either path. Explicit `output_mode="inline"` returns full JSON
and cannot be combined with `output_file` or `output_format`. Callers own file
retention and cleanup. This result policy does not change collection limits:
`events_output="file"` separately enables ordered-event streaming on supported
local backends; remote target-side file pipes remain unsupported.
File formats use portable integer layouts, while
the debugger and capture transport remain Windows-hosted.
Set `collect_snapshots=false` to skip first block/edge and exception register/stack
capture. `compress_paths=true, collect_code=true` preserves observed path order,
branch choices and repeat counts in inline/file events, with explicit collection,
loss, exception and observed code-version barriers. It reduces records, not TF
exceptions. Compression excludes ordered memory/register events and target windows;
new policies require backend support and the VEH implementation refuses active
hardware-breakpoint conflicts before execution. These collection policies are
independent of result-file transport.
See the repository's `docs/DEVELOPMENT_TOOLS.md` for usage and backend adoption.
`veh_targeted_capture` repeats bounded setup for an input matrix, retains a
pre/post occurrence ring, embeds thread-environment evidence, and writes one
verified server-side JSON artifact per input.

```bash
# Auto-install to all supported agents
veh-mcp-server.exe --install

# Supported: claude-code, claude-desktop, cursor, windsurf, codex
```

> **Tip**: Numeric arguments (`threadId`, `pid`, `address`, `size`, etc.) accept both numbers and strings, including hex format (e.g. `"0x401000"` or `4198400`). Boolean arguments accept `true`/`false` or `"true"`/`"false"`.

## Architecture

```
VSCode                          AI Agent (Claude, etc.)
  ↕ DAP (stdio/TCP)              ↕ MCP (stdio, JSON-RPC 2.0)
veh-debug-adapter.exe           veh-mcp-server.exe
  ↕ Named Pipe IPC               ↕ Named Pipe IPC
  └────── veh-debugger.dll (injected into target) ──────┘
```

## External guest debugging

DAP attach accepts `targetScope="guest"`, `processId`, an absolute `agent`
executable and optional `agentArgs`. The adapter validates the IPC peer and
reported guest PID/address width. Backend capabilities gate memory/register
inspection and writes, continue/pause, instruction steps, execution/data
breakpoints, symbol-based source/function breakpoints and termination.
Unsupported commands return errors. Stops identify the selected thread;
guest launch, `stopOnEntry` and `stopOnModuleLoad` remain unsupported.
Module-qualified pending guest functions (`module!function`) use advertised
loader-stop and stop-query support to bind while the DLL is held. The adapter
confirms the thread is still stopped and exposes that state for explicit user
continuation, preserving any known exception/breakpoint reason. It does not
automatically resume: the IPC has no token to condition continuation on the
same hold. Other backends retain best-effort module notifications. Loader
patterns use the backend substring contract and may also stop similarly named
DLLs. This is separate from the explicit guest `stopOnModuleLoad` option. A loader-origin stop may retain the loader lock:
finish binding and explicitly continue before executing target code or creating
target threads. Such a stop is not a general-purpose safe call point.

DAP exception filtering currently supports only `all`. Empty, uncaught-only
and advanced filters return an error rather than claiming they were applied.

## Whole-VM attachment and control (MCP)

`veh_virtual_machine(operation="status"|"pause"|"resume"|"trace")` provides
explicit VM-wide control when the backend advertises it. Trace executes one
selected vCPU while the VM remains paused, with CR3/CPL/RIP stop boundaries,
an instruction/time budget, interpreter identification and explicit lost records.
This scope is independent of the attached guest PID. It does not provide a
selective OS-thread stop. The tool is available through `veh_toolbox` discovery
and manual calls; batch/capture setup/breakpoint actions intentionally exclude
it because their process-scoped automation must not resume the entire VM.

VM attachment uses `veh_attach(target_scope="vm", backend="machine")`, with
an external backend registered for that scope, and no `pid`. The backend must
declare VM metadata with PID0/addressBits0. This session has no host process
target, OS thread identity or single process address width. VM agents receive
`--pipe` and configured arguments; process agents also receive `--pid`.
Use `veh_virtual_machine` for explicit whole-VM control and bounded vCPU records.
Physical memory read/write is available when advertised; search/dump needs a
server operation and is unavailable in VM scope. A capable backend exposes
`veh_processes` for one guest OS process snapshot; use a returned PID with
`veh_attach(target_scope="guest")`. Short image names escape non-ASCII bytes as
`\\xNN`. Guest process attachment still uses a validated nonzero guest PID.

## Requirements

- Windows 10 or later (x64)
- Run VSCode as Administrator for DLL injection

## Troubleshooting

**DLL injection fails**
- Run VSCode as Administrator
- Check if antivirus is blocking the injection
- Verify target process bitness matches (32/64-bit)

**Breakpoints not hitting**
- Ensure PDB file is next to the target EXE
- Without PDB, only address-based breakpoints work
- Hardware breakpoints: max 4 at a time

**Pipe connection timeout**
- Default timeout is 7 seconds
- Use `--log=debug.log --log-level=debug` for diagnostics

## License

MIT
