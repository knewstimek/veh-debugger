# VEH Debugger

Windows debugger based on **VEH (Vectored Exception Handler)** instead of the Windows Debug API. Ideal for reverse engineering targets with anti-debug protection.

## Features

- **Anti-debug friendly** — Uses VEH instead of `ntdll!DbgUiRemoteBreakin`, bypasses common anti-debug checks
- **Software breakpoints** — INT3 (0xCC) patching at any address
- **Hardware breakpoints** — DR0-DR3 registers for memory read/write/execute watch (like Cheat Engine's "Find what writes/accesses")
- **x86 & x64** — Debug both 32-bit and 64-bit processes
- **PDB symbols** — Source file + line number mapping, function name breakpoints
- **Disassembly** — Zydis x86/x64 disassembler with full operand display
- **Memory read/write** — Inspect and modify process memory
- **4 injection methods** — CreateRemoteThread, NtCreateThreadEx, Thread Hijack, QueueUserAPC
- **TCP remote mode** — Debug across VMs or network
- **MCP tool server** — 19 tools for AI agent integration (Claude, Cursor, etc.)

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

The bundled `veh-mcp-server.exe` exposes 19 debugging tools via the Model Context Protocol, allowing AI agents to directly control the debugger.

```bash
# Auto-install to all supported agents
veh-mcp-server.exe --install

# Supported: claude-code, claude-desktop, cursor, windsurf, codex
```

## Architecture

```
VSCode                          AI Agent (Claude, etc.)
  ↕ DAP (stdio/TCP)              ↕ MCP (stdio, JSON-RPC 2.0)
veh-debug-adapter.exe           veh-mcp-server.exe
  ↕ Named Pipe IPC               ↕ Named Pipe IPC
  └────── veh-debugger.dll (injected into target) ──────┘
```

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
