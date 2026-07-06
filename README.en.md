# VEH Debugger for VSCode

[한국어](README.md) | **English**

An in-process Windows debugger built on **VEH (Vectored Exception Handler)**. Breakpoints, hardware watchpoints, memory/register inspection, pointer-chain and runtime call tracing -- **every debugging operation is exposed as a callable, headless primitive.** With no GUI to drive, an AI agent calls them directly as MCP functions; a human uses the same engine through DAP in VSCode.

## Why VEH

It doesn't use the Windows Debug API. Instead of `DebugActiveProcess` / `NtSetInformationThread`, it catches exceptions from inside the target via VEH, so `PEB.BeingDebugged` stays 0. The PEB/NtQuery-based anti-debug checks in Themida and VMProtect don't see the debugger. (Kernel anti-cheats that scan for VEH registration itself, like EAC, are the exception.)

Being in-process has a second effect. A Windows Debug API debugger attaches only one per process, but VEH attaches **alongside an x64dbg session already on the target**. Analyze with a kernel/user debugger while running watchpoints through VEH.

## Control paths: DAP and MCP

The same debugging engine, exposed over two protocols.

- **DAP**: directly in the VSCode debug panel. Source BPs, stepping, disassembly, register editing.
- **MCP**: Claude, Cursor, Codex, etc. call 39 tools directly. No GUI in the loop -- the agent composes and automates debugging operations as functions, *programming* the debugger rather than *driving* it.

## Scenarios

How a natural-language request unfolds into a tool sequence.

**Break inside a module the moment it loads**

Stop the instant Game.dll is mapped, then set a BP inside it.
```
veh_set_module_breakpoint(module="Game.dll")   # stop on load
veh_continue(wait=true)
veh_set_breakpoint(address="Game.dll+0x1234")
veh_continue(wait=true)
veh_registers(threadId=...)
```
Catches modules that only appear after unpacking, and lazily-loaded DLLs, at load time. The `module+RVA` address needs no ASLR base math.

**Find what writes to an address (Find What Writes)**

Find the instruction that wrote to a watched address.
```
veh_set_data_breakpoint(address="0x...", type="write", size=4, condition="value != 0")
veh_continue(wait=true)
veh_registers(threadId=...)            # RIP of the writing instruction
veh_disassemble(address=<RIP above>)
```
DR0~DR3 hardware watchpoints -- no INT3 planted in code, so integrity checks don't trip. `value != 0` skips zero-write noise.

**Trace register changes over N steps**

Collect only the steps where EAX changes over 100 steps.
```
veh_trace_register(threadId=..., register="eax", max_steps=100)
```
The step loop runs inside the target DLL, so there's no IPC round-trip per step. Returns only the steps where the value changed.

**Resolve a pointer chain in one call**

Follow offsets from a base to read the final value.
```
veh_read_pointer_chain(base="game.exe+0x1F00", offsets=[0x10, 0x8, 0x34], size=4)
```
Dereferences each hop (4/8-byte pointer size auto-detected) and returns every hop plus the final value. Replaces one round-trip per hop with a single call. HP/coordinate/entity pointer tracking.

**Batch-resolve obfuscated imports**

Resolve where a set of thunk addresses actually land.
```
veh_resolve_imports(threadId=..., addresses=[...], follow_exceptions=true, system_only=true)
```
Steps from each thunk into the DLL to find the real API (up to 2000). `follow_exceptions` handles exception-based obfuscation. Reconstructs imports on binaries with a mangled IAT.

**Collect runtime call targets on a packed binary**

Gather where call sites actually land at runtime over 5 seconds.
```
veh_trace_calls(addresses=[...], duration_sec=5, resolve=true, system_only=true)
```
Collects the runtime target address + API name for each call/jmp. `resolve=true` follows thunks/trampolines to the end. For IAT reconstruction on packed binaries.

---

## Features

- **VEH-based**: Uses VEH instead of Windows Debug API - bypasses PEB/NtQuery-based anti-debug checks (Themida, VMProtect, etc.)
- **Full DAP support**: Works with VSCode, MCP debug tools, and any DAP-compatible client
- **MCP tool server**: 39 tools for AI agents (Claude, Cursor, Codex, etc.) to directly control the debugger
- **TCP mode**: Remote debugging via `--tcp --port=PORT`
- **Remote access**: `--remote` / `--bind=0.0.0.0` for VM/network debugging
- **32/64-bit**: Debug both x86 and x64 processes (separate 32-bit DLL build; WoW64 injection for 32-bit targets)
- **Software breakpoints**: INT3 (0xCC) patching with original byte masking in ReadMemory
- **Conditional breakpoints**: Break on condition (e.g. `RAX==0x1234`, `*0x7FF600!=0`)
- **Hit count breakpoints**: Break on Nth hit
- **Log points**: Log to Debug Console without stopping (e.g. `RAX={RAX}, ptr={*0x7FF600}`)
- **Hardware breakpoints**: DR0-DR3 (memory read/write watch = Find What Writes/Accesses)
- **PDB symbols**: Source file/line mapping, function name breakpoints
- **PDB O(1) StepOver**: Uses `SymGetLineFromAddrW64` to compute next source line address - single temp BP instead of O(n) single-steps
- **Register editing**: Double-click register values in Variables panel to modify
- **Disassembly**: Zydis x86/x64 disassembler (default) + built-in lightweight decoder (fallback)
- **Memory read/write**: DAP readMemory/writeMemory support
- **Detach/re-attach**: DLL pipe server stays alive after detach, allowing re-attach without restarting the target
- **Static CRT build**: No vcruntime dependency when injecting DLL

## Architecture

```
VSCode / DAP Client                Claude / AI Agent
    ↕ DAP (stdin/stdout or TCP)        ↕ MCP (stdin/stdout, JSON-RPC 2.0)
veh-debug-adapter.exe              veh-mcp-server.exe
    ↕ Named Pipe IPC                   ↕ Named Pipe IPC
    └──────── veh-debugger.dll (inside target process) ────────┘
```

### Components

| Component | Role |
|-----------|------|
| `veh-debugger.dll` (`vcruntime_net.dll`) | Injected into target. Registers VEH handler, manages breakpoints, queries threads/stack/memory |
| `veh-debug-adapter.exe` | DAP protocol server. DLL injection, Named Pipe IPC, JSON-RPC processing |
| `veh-mcp-server.exe` | MCP tool server. 39 tools for AI agents to directly control the debugger |
| VSCode Extension | launch.json schema, adapter path configuration (minimal wrapper) |

## Build

### Requirements
- Windows 10+ x64
- CMake 3.20+
- Visual Studio 2022 (MSVC)
- Node.js 18+ (for VSCode extension, optional)

### C++ Build (64-bit)

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output:
- `build/bin/Release/veh-debug-adapter.exe` — DAP adapter
- `build/bin/Release/veh-mcp-server.exe` — MCP tool server
- `build/bin/Release/vcruntime_net.dll` — VEH debugger DLL

### C++ Build (32-bit DLL)

Required for debugging 32-bit processes:

```bash
cmake -B build32 -G "Visual Studio 17 2022" -A Win32
cmake --build build32 --config Release --target veh-debugger
copy build32\bin\Release\vcruntime_net32.dll build\bin\Release\
```

### VSCode Extension Build

```bash
cd extension
npm install
npm run compile
```

## Usage

### 1. VSCode (stdio mode)

Add to `.vscode/launch.json`:

**Launch**
```json
{
    "type": "veh",
    "request": "launch",
    "name": "VEH Debug - Launch",
    "program": "C:/path/to/target.exe",
    "args": ["arg1", "arg2"],
    "stopOnEntry": true,
    "runAsInvoker": false
}
```
- `runAsInvoker`: Bypass UAC elevation prompt by running with current privileges (default: false)

**Attach**
```json
{
    "type": "veh",
    "request": "attach",
    "name": "VEH Debug - Attach",
    "processId": 1234
}
```

### 2. TCP Mode (Local)

```bash
veh-debug-adapter.exe --tcp --port=4711
```

### 3. TCP Remote Mode (VM/Network)

```bash
# On target machine (bind to all interfaces)
veh-debug-adapter.exe --tcp --port=4711 --remote
```

Connect from external DAP client to `<target-ip>:4711`.

**Security note**: `--remote` binds to all network interfaces. Only use on trusted networks or restrict via firewall.

> Any DAP-capable client can connect to the adapter over TCP -- e.g. the agent-tool `debug` tool via `debug(operation: "launch", address: "localhost:4711", ...)`.

### 4. MCP Tool Server (AI Agent Control)

Separate MCP server for AI agents to control the debugger via function calls.

**Auto-install (recommended)**
```bash
# Install to all supported agents
veh-mcp-server.exe --install

# Install to specific agent
veh-mcp-server.exe --install claude-code
veh-mcp-server.exe --install cursor

# Uninstall
veh-mcp-server.exe --uninstall
```

Supported agents: `claude-code`, `claude-desktop`, `cursor`, `windsurf`, `codex`

| Agent | Config File | Format |
|-------|------------|--------|
| Claude Code | `~/.claude/settings.json` | JSON (`mcpServers`) |
| Claude Desktop | `%APPDATA%/Claude/claude_desktop_config.json` | JSON (`mcpServers`) |
| Cursor | `~/.cursor/mcp.json` | JSON (`mcpServers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON (`mcpServers`) |
| Codex CLI | `~/.codex/config.toml` | TOML (`mcp_servers`) |

**Manual install** (edit the config file directly)

Claude Code / Claude Desktop / Cursor / Windsurf (JSON):
```json
{
  "mcpServers": {
    "veh-debugger": {
      "command": "C:/path/to/veh-mcp-server.exe",
      "args": ["--log=veh-mcp.log"]
    }
  }
}
```

Codex CLI (TOML):
```toml
[mcp_servers.veh-debugger]
command = "C:/path/to/veh-mcp-server.exe"
args = ["--log=veh-mcp.log"]
enabled = true
```

Restart the agent/IDE after configuring to activate.

**MCP Tools (39)**

| Tool | Args | Description |
|------|------|-------------|
| `veh_attach` | `pid` | Inject DLL + connect pipe |
| `veh_launch` | `program, args?, stopOnEntry?, cwd?, env?` | Create process + inject. `cwd` sets the target's working directory (omit to inherit the debugger's cwd). `env` passes environment variables to the target (`{"KEY":"VAL"}` or `["KEY=VALUE"]`, overlaid on the inherited parent environment) |
| `veh_detach` | - | Detach debugger (target keeps running) |
| `veh_terminate` | `exitCode?` | Kill the target from **inside** (the injected DLL calls `TerminateProcess` on its own process). Works even on self-protected targets that deny external `taskkill`/`OpenProcess` (deny-DACL or higher integrity), since a process's own handle always has terminate rights. Auto-detaches afterward. Replaces the `WM_CLOSE->detach->taskkill` dance. |
| `veh_set_breakpoint` | `address, condition?, hitCondition?, logMessage?, action?` | Software BP. `action` auto-executes on hit (veh_batch format) |
| `veh_remove_breakpoint` | `id` | Remove software BP |
| `veh_set_source_breakpoint` | `source, line, condition?, hitCondition?, logMessage?` | Source file + line BP (PDB required; unresolved modules kept `pending` and bound automatically on module load) |
| `veh_set_function_breakpoint` | `name, condition?, hitCondition?, logMessage?` | Function name BP (PDB required; unresolved modules kept `pending` until module loads) |
| `veh_list_breakpoints` | - | List active SW/HW breakpoints |
| `veh_set_data_breakpoint` | `address, type, size, condition?, hitCondition?` | HW BP (write/readwrite/execute). `condition`'s `value` token = current value at the watched address (e.g. `value != 0` filters zero-write noise); `hitCondition:"5"` stops only on the 5th hit |
| `veh_remove_data_breakpoint` | `id` | Remove HW BP |
| `veh_set_module_breakpoint` | `module, enabled?, clear?` | Stop when a module (DLL) whose name matches is loaded (case-insensitive substring, e.g. `"D2Common"`). Freezes the loading thread right after the module is mapped (LdrRegisterDllNotification; no INT3/patching) so you can set BPs inside it or dump it. Fires after the module's DllMain on modern Windows. `enabled:false` removes a pattern, `clear:true` clears all |
| `veh_continue` | `threadId?, wait?, timeout?, pass_exception?, ignore_exceptions?` | Continue. `ignore_exceptions=[0x80000003]` auto-passes specific exceptions to SEH |
| `veh_step_in` | `threadId` | Step Into |
| `veh_step_over` | `threadId` | Step Over |
| `veh_step_out` | `threadId` | Step Out |
| `veh_pause` | `threadId?` | Pause |
| `veh_threads` | - | List threads |
| `veh_stack_trace` | `threadId, maxFrames?` | Stack trace. For PDB-less modules, parses the PE export table directly for accurate function names (instead of DbgHelp's inaccurate `OrdinalNNNNN` labels) |
| `veh_enum_locals` | `threadId, instructionAddress?, frameBase?` | Enumerate locals/parameters in a stopped thread's stack frame (name/type/address/value). Auto-detects the top frame if omitted (PDB required) |
| `veh_registers` | `threadId` | Read registers |
| `veh_set_register` | `threadId, name, value` | Modify register value |
| `veh_evaluate` | `expression, threadId` | Evaluate register/memory/pointer/segment (`[reg+offset]`, `gs:[0x60]`, etc.) |
| `veh_read_memory` | `address, size` | Read memory (hex) |
| `veh_read_pointer_chain` | `base, offsets[], derefFinal?, size?` | Follow a multi-level pointer chain in one call (no per-hop round-trips). Dereferences `*(cur+offset)` at each hop (auto-detects 4/8-byte pointers for x86/x64), returns every hop and the final resolved address. `derefFinal:false` returns the final address without the last deref; `size>0` also reads bytes at the resolved address |
| `veh_write_memory` | `address, data` or `patches` | Write memory. Batch: `patches=[{address,data},...]` |
| `veh_dump_memory` | `address, size, output_path` | Dump memory to binary file (up to 64MB) |
| `veh_allocate_memory` | `size?, protection?` | Allocate memory in target (VirtualAlloc) |
| `veh_free_memory` | `address` | Free allocated memory (VirtualFree) |
| `veh_execute_shellcode` | `shellcode, timeout_ms?` | Execute shellcode (alloc RWX + copy + CreateThread + wait + free) |
| `veh_modules` | - | List modules |
| `veh_disassemble` | `address, count?` | Disassemble (Zydis) |
| `veh_exception_info` | - | Last exception info |
| `veh_trace_register` | `threadId, register, mode?, value?, max_steps?` | Trace register changes (DLL-internal step loop, zero IPC overhead) |
| `veh_trace_memory` | `address, size?, timeout_ms?` | Trace memory writes (temp HW BP, fast detection) |
| `veh_resolve_imports` | `threadId, addresses, max_steps?, follow_exceptions?, system_only?, target_modules?` | Batch-resolve obfuscated imports (step from thunk to DLL, up to 2000) |
| `veh_batch` | `steps` | Execute multiple commands in one call ($N/$last/$prev variable refs, if/loop/for_each control flow) |
| `veh_trace_callers` | `address, duration_sec?` | Profile function callers (auto-resume -> collect for N seconds -> auto-pause). Returns unique callers with hit counts. x64: RtlVirtualUnwind (accurate). x86: [ESP] (accurate only at function entry) |
| `veh_trace_calls` | `addresses, duration_sec?, resolve?, system_only?` | Monitor where call/jmp instructions go at runtime. Sets BPs on call sites, runs program for N seconds, collects actual targets with API names. `resolve=true`: follow thunks/trampolines in natural call context to final API (handles exception-based obfuscation). `system_only=true`: return only system DLL targets. For IAT reconstruction on packed binaries. |

> **Non-stop inspection (no target stop required)**: `veh_read_memory` / `veh_read_pointer_chain` / `veh_write_memory` / `veh_dump_memory` / `veh_disassemble` / `veh_modules` work while the target is **running** (serviced by a dedicated pipe thread inside the DLL -- other threads are never frozen). You don't need a breakpoint or a detach/attach round-trip to read live values during GUI interaction. In contrast, `veh_registers` / `veh_stack_trace` / `veh_enum_locals` / `veh_step_*` need a thread context, so they only work when stopped at a breakpoint or after `veh_pause`.

> **Tip**: Address arguments accept hex (`"0x401000"`), decimal (`4198400`), or **module+RVA** (`"crackme.exe+0x1000"`). Module+RVA eliminates manual ASLR base calculation.

### Command-line Options

**veh-mcp-server.exe**

| Option | Description |
|--------|-------------|
| `--install [AGENT]` | Register the MCP server in AI agent configs (all or specific) |
| `--uninstall [AGENT]` | Remove the MCP server from AI agent configs |
| `--log=FILE` | Log file path |
| `--log-level=LEVEL` | Log level: debug, info, warn, error |
| `--help` | Print help |

**veh-debug-adapter.exe**

| Option | Description |
|--------|-------------|
| `--tcp` | TCP transport mode (default: stdin/stdout) |
| `--port=PORT` | TCP port number (default: 4711) |
| `--remote` | Bind to 0.0.0.0 (allow remote connections) |
| `--bind=0.0.0.0` | Same as `--remote` |
| `--log=FILE` | Log file path |
| `--log-level=LEVEL` | Log level: debug, info, warn, error (default: info) |
| `--help` | Print help |

## DAP Commands

| Category | Commands |
|----------|----------|
| Lifecycle | initialize, launch, attach, disconnect, terminate |
| Breakpoints | setBreakpoints, setFunctionBreakpoints, setExceptionBreakpoints, setInstructionBreakpoints, setDataBreakpoints, dataBreakpointInfo |
| Execution | configurationDone, continue, next, stepIn, stepOut, pause |
| State | threads, stackTrace, scopes, variables, evaluate |
| Memory/Disasm | readMemory, writeMemory, disassemble |
| Misc | modules, loadedSources, exceptionInfo, completions, source, cancel, gotoTargets |

## Launch Debugging

Same as "Start Debugging" in Windows debuggers. Supported by both DAP (`launch` request) and MCP (`veh_launch`).

How it works:
1. `CreateProcess` + `CREATE_SUSPENDED` — create the process in suspended state
2. DLL injection — register VEH handler, start Named Pipe server
3. If `stopOnEntry=true`, keep suspended at entry point; if `false`, `ResumeThread` to continue

For already running processes, use `attach` / `veh_attach`.

## DLL Injection Methods

4 injection methods supported (auto-selected):
1. **CreateRemoteThread** — Default method
2. **NtCreateThreadEx** — For protected processes
3. **Thread Hijacking** — Hijack existing thread
4. **QueueUserAPC** — APC queue method

## Disassembly

- **Zydis backend** (default): Full operand display (`mov rax, qword ptr [rbp-0x10]`)
- **Simple backend** (fallback): Mnemonic only (`mov`, `call` — no external dependency)
- Abstracted via `IDisassembler` interface, created by `CreateDisassembler()` factory

## Troubleshooting

### DLL Injection Fails
- Run VSCode/adapter as Administrator
- Check target process bitness (32/64) — DLL must match
- Check if antivirus is blocking injection

### Pipe Connection Timeout
- Default timeout is 7 seconds
- Check progress with log: `--log=debug.log --log-level=debug`

### Breakpoints Not Hitting
- Ensure PDB file is next to the target EXE
- Without PDB, only address-based BP (`setInstructionBreakpoints`) works
- Hardware BP limit: 4 simultaneous

### Remote Connection Fails
- Verify `--remote` or `--bind=0.0.0.0` option is used
- Check firewall for the port
- Check VM network adapter is in bridged mode

## Dependencies

| Library | Usage | License |
|---------|-------|---------|
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing (header-only) | MIT |
| [Zydis v4.1](https://github.com/zyantific/zydis) | x86/x64 disassembly (vendored in third_party/) | MIT |

## License

MIT License
