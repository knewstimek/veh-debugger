# VEH Debugger for VSCode

[한국어](README.md) | **English**

Windows debugger based on **VEH (Vectored Exception Handler)** instead of the Windows Debug API. Fully supports **DAP** (Debug Adapter Protocol) and **MCP** (Model Context Protocol).

## Why VEH Debugger?

### Anti-debug bypass advantage
Does not use Windows Debug API (`NtSetInformationThread`, `IsDebuggerPresent`, etc.), keeping `PEB.BeingDebugged = 0`. Naturally bypasses PEB/NtQuery-based anti-debug checks used by **Themida, VMProtect**, etc. Note: protections that inspect VEH itself (kernel anti-cheats like EAC) can still detect it.

### Side-by-side with existing debuggers
Windows Debug API debuggers (x64dbg, WinDbg, Visual Studio) allow only one per process, but VEH Debugger can **attach alongside them simultaneously**. Useful for running kernel/user-mode debugger analysis while using VEH Debugger for auxiliary breakpoints/memory watches.

### Native AI agent support
Built-in MCP (Model Context Protocol) tool server lets **Claude, Cursor, Windsurf, Codex** and other AI agents control the debugger directly. Debug with natural language: "Set a breakpoint on this function and check the RAX value."

### Full VSCode integration
No separate debugger GUI needed. **Everything works inside the VSCode debug panel** - disassembly view, register read/write, memory read/write, hardware breakpoints.

---

## Features

- **VEH-based**: Uses VEH instead of Windows Debug API - bypasses PEB/NtQuery-based anti-debug checks (Themida, VMProtect, etc.)
- **Full DAP support**: Works with VSCode, MCP debug tools, and any DAP-compatible client
- **MCP tool server**: 31 tools for AI agents (Claude, Cursor, Codex, etc.) to directly control the debugger
- **TCP mode**: Remote debugging via `--tcp --port=PORT`
- **Remote access**: `--remote` / `--bind=0.0.0.0` for VM/network debugging
- **32/64-bit**: Debug both x86 and x64 processes (WoW64 injection for 32-bit targets)
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
| `veh-mcp-server.exe` | MCP tool server. 30 tools for AI agents to directly control the debugger |
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

**MCP Tools (31)**

| Tool | Args | Description |
|------|------|-------------|
| `veh_attach` | `pid` | Inject DLL + connect pipe |
| `veh_launch` | `program, args?, stopOnEntry?` | Create process + inject |
| `veh_detach` | - | Detach debugger |
| `veh_set_breakpoint` | `address, condition?, hitCondition?, logMessage?` | Software BP (conditional/logpoint supported) |
| `veh_remove_breakpoint` | `id` | Remove software BP |
| `veh_set_source_breakpoint` | `source, line, condition?, hitCondition?, logMessage?` | Source file + line BP (PDB required) |
| `veh_set_function_breakpoint` | `name, condition?, hitCondition?, logMessage?` | Function name BP (PDB required) |
| `veh_list_breakpoints` | - | List active SW/HW breakpoints |
| `veh_set_data_breakpoint` | `address, type, size` | HW BP (write/readwrite/execute) |
| `veh_remove_data_breakpoint` | `id` | Remove HW BP |
| `veh_continue` | `threadId?, wait?, timeout?, pass_exception?` | Continue execution. `pass_exception=true` forwards exception to SEH (for CFF debugging) |
| `veh_step_in` | `threadId` | Step Into |
| `veh_step_over` | `threadId` | Step Over |
| `veh_step_out` | `threadId` | Step Out |
| `veh_pause` | `threadId?` | Pause |
| `veh_threads` | - | List threads |
| `veh_stack_trace` | `threadId, maxFrames?` | Stack trace |
| `veh_registers` | `threadId` | Read registers |
| `veh_set_register` | `threadId, name, value` | Modify register value |
| `veh_evaluate` | `expression, threadId` | Evaluate register/memory/pointer/segment (`[reg+offset]`, `gs:[0x60]`, etc.) |
| `veh_read_memory` | `address, size` | Read memory (hex) |
| `veh_write_memory` | `address, data` or `patches` | Write memory. Batch: `patches=[{address,data},...]` |
| `veh_dump_memory` | `address, size, output_path` | Dump memory to binary file (up to 64MB) |
| `veh_allocate_memory` | `size?, protection?` | Allocate memory in target (VirtualAlloc) |
| `veh_free_memory` | `address` | Free allocated memory (VirtualFree) |
| `veh_execute_shellcode` | `shellcode, timeout_ms?` | Execute shellcode (alloc RWX + copy + CreateThread + wait + free) |
| `veh_modules` | - | List modules |
| `veh_disassemble` | `address, count?` | Disassemble (Zydis) |
| `veh_exception_info` | - | Last exception info |
| `veh_batch` | `steps` | Execute multiple commands in one call ($N variable refs, if/loop/for_each control flow) |
| `veh_trace_callers` | `address, duration_sec?` | Profile function callers (auto-resume -> collect for N seconds -> auto-pause). Returns unique callers with hit counts. x64: RtlVirtualUnwind (accurate). x86: [ESP] (accurate only at function entry) |

> **Tip**: Numeric arguments (`threadId`, `pid`, `address`, `size`, etc.) accept both numbers and strings, including hex format (e.g. `"0x401000"` or `4198400`). Boolean arguments accept `true`/`false` or `"true"`/`"false"`.

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
