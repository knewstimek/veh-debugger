# VEH Debugger for VSCode

[한국어](README.md) | **English**

Windows debugger based on **VEH (Vectored Exception Handler)** instead of the Windows Debug API. Fully supports **DAP** (Debug Adapter Protocol) and **MCP** (Model Context Protocol).

## Features

- **VEH-based**: Uses VEH instead of Windows Debug API — bypasses common anti-debug checks
- **Full DAP support**: Works with VSCode, MCP debug tools, and any DAP-compatible client
- **MCP tool server**: 19 tools for AI agents (Claude, Cursor, etc.) to directly control the debugger
- **TCP mode**: Remote debugging via `--tcp --port=PORT`
- **Remote access**: `--remote` / `--bind=0.0.0.0` for VM/network debugging
- **32/64-bit**: Debug both x86 and x64 processes
- **Software breakpoints**: INT3 (0xCC) patching
- **Hardware breakpoints**: DR0-DR3 (memory read/write watch = Find What Writes/Accesses)
- **PDB symbols**: Source file/line mapping, function name breakpoints
- **Disassembly**: Zydis x86/x64 disassembler (default) + built-in lightweight decoder (fallback)
- **Memory read/write**: DAP readMemory/writeMemory support
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
| `veh-debugger.dll` | Injected into target. Registers VEH handler, manages breakpoints, queries threads/stack/memory |
| `veh-debug-adapter.exe` | DAP protocol server. DLL injection, Named Pipe IPC, JSON-RPC processing |
| `veh-mcp-server.exe` | MCP tool server. 19 tools for AI agents to directly control the debugger |
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
    "stopOnEntry": true
}
```

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

**MCP Tools (19)**

| Tool | Args | Description |
|------|------|-------------|
| `veh_attach` | `pid` | Inject DLL + connect pipe |
| `veh_launch` | `program, args?, stopOnEntry?` | Create process + inject |
| `veh_detach` | - | Detach debugger |
| `veh_set_breakpoint` | `address` | Software BP (hex address) |
| `veh_remove_breakpoint` | `id` | Remove software BP |
| `veh_set_data_breakpoint` | `address, type, size` | HW BP (write/readwrite/execute) |
| `veh_remove_data_breakpoint` | `id` | Remove HW BP |
| `veh_continue` | `threadId?` | Continue execution |
| `veh_step_in` | `threadId` | Step Into |
| `veh_step_over` | `threadId` | Step Over |
| `veh_step_out` | `threadId` | Step Out |
| `veh_pause` | `threadId?` | Pause |
| `veh_threads` | - | List threads |
| `veh_stack_trace` | `threadId, maxFrames?` | Stack trace |
| `veh_registers` | `threadId` | Read registers |
| `veh_read_memory` | `address, size` | Read memory (hex) |
| `veh_write_memory` | `address, data` | Write memory (hex) |
| `veh_modules` | - | List modules |
| `veh_disassemble` | `address, count?` | Disassemble (Zydis) |

## DAP Commands

| Category | Commands |
|----------|----------|
| Lifecycle | initialize, launch, attach, disconnect, terminate |
| Breakpoints | setBreakpoints, setFunctionBreakpoints, setExceptionBreakpoints, setInstructionBreakpoints, setDataBreakpoints, dataBreakpointInfo |
| Execution | configurationDone, continue, next, stepIn, stepOut, pause |
| State | threads, stackTrace, scopes, variables, evaluate |
| Memory/Disasm | readMemory, writeMemory, disassemble |
| Misc | modules, loadedSources, exceptionInfo, completions, source, cancel, gotoTargets |

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
