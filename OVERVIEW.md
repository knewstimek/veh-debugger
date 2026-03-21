# Project Overview

Windows VEH(Vectored Exception Handler) debugger with DAP + MCP support.
Injects a DLL into the target process; the DLL registers a VEH handler for breakpoints/stepping.
An adapter EXE communicates with the DLL over Named Pipe IPC and speaks DAP to VSCode (or any client).

## Architecture

```
 VSCode / DAP Client              Claude / AI Agent
     |  DAP (stdin or TCP)            |  MCP (stdin, JSON-RPC 2.0)
     v                                v
 veh-debug-adapter.exe           veh-mcp-server.exe
     |  Named Pipe IPC                |  Named Pipe IPC
     +---------> veh-debugger.dll (vcruntime_net.dll) <---------+
                 (inside target process)
```

- **Adapter** (`src/adapter/`): DAP protocol handler, DLL injection, PDB symbol engine
- **DLL** (`src/dll/`): VEH handler, breakpoint/stepping, pipe server, stack walking
- **MCP** (`src/mcp/`): 26-tool MCP server for AI agents
- **Common** (`src/common/`): IPC protocol definitions, logger

## Key Files

| File | Role |
|------|------|
| `src/adapter/dap_server.cpp/h` | Main DAP request/event handler (~2500 lines) |
| `src/adapter/injector.cpp/h` | CreateProcess + DLL injection (CRT/NtCreate/Hijack/APC, WoW64) |
| `src/adapter/symbol_engine.cpp/h` | Adapter-side PDB loader (O(1) StepOver via SymGetLineFromAddrW64) |
| `src/adapter/pipe_client.cpp/h` | Named Pipe IPC client (SendAndReceive, event callbacks) |
| `src/adapter/transport.cpp/h` | DAP transport layer (stdin/stdout + TCP accept) |
| `src/adapter/disassembler.h` | IDisassembler interface + Zydis/Simple backends |
| `src/dll/veh_handler.cpp/h` | VEH exception handler (INT3, SINGLE_STEP, HW BP) |
| `src/dll/syscall_resolver.cpp/h` | ntdll stub copy + TEB direct access (WinAPI BP immunity) |
| `src/dll/breakpoint.cpp/h` | SW breakpoint management + MaskBreakpointsInBuffer |
| `src/dll/hw_breakpoint.cpp/h` | Hardware breakpoint (DR0-DR3) management |
| `src/dll/pipe_server.cpp/h` | Named Pipe IPC server (DLL side) |
| `src/dll/dllmain.cpp` | DLL entry, LdrRegisterDllNotification for module events |
| `src/dll/stack_walk.cpp/h` | StackWalk64 + DIA SDK local variable enumeration |
| `src/common/ipc_protocol.h` | All IPC command/event/struct definitions (shared) |
| `src/common/logger.h` | Logging utility |
| `src/mcp/mcp_server.cpp/h` | MCP JSON-RPC server, 26 debugger tools |
| `src/mcp/installer.cpp/h` | Auto-install to Claude/Cursor/Windsurf/Codex configs |

## IPC Protocol

Named Pipe (`\\.\pipe\dotnet-diagnostic-{pid}`), binary framed:

```
[IpcHeader: command(u32) + payloadSize(u32)] [payload bytes...]
```

- **Commands** (Adapter -> DLL): `0x0001`-`0x00FF` - request/response, synchronous
- **Events** (DLL -> Adapter): `0x1000`+ - async push, dispatched via callbacks
- **Response format**: Most commands return `reinterpret_cast<T*>(data)` directly
  - Exception: `ReadMemory` returns `IpcStatus(4 bytes) + raw data` (offset required!)

### Key Commands
| Range | Commands |
|-------|----------|
| 0x0001-0x0005 | Breakpoint set/remove (SW + HW) |
| 0x0010-0x0016 | Execution control (Continue, StepOver/Into/Out, Pause) |
| 0x0020-0x0024 | State queries (Threads, StackTrace, Registers, SetRegister) |
| 0x0030-0x0031 | Memory read/write |
| 0x0040-0x0042 | PDB symbol resolution (SourceLine, Function, EnumLocals) |
| 0x00F0/0x00FF | Lifecycle (Detach, Shutdown) |

### Key Events
| Code | Event |
|------|-------|
| 0x1001 | BreakpointHit (includes RegisterSet for condition eval) |
| 0x1002 | StepCompleted |
| 0x1003 | ExceptionOccurred |
| 0x1004-0x1005 | Thread created/exited |
| 0x1006-0x1007 | Module loaded/unloaded |
| 0x1008 | ProcessExited |

## Threading Model

### Adapter (dap_server)
- **Main thread**: DAP request processing
- **Reader thread**: Pipe IPC reader - receives events/responses from DLL
  - Events (>=0x1000): dispatched via callbacks (OnBreakpointHit, OnStepCompleted, etc.)
  - Responses (<0x1000): matched by `expectedCommand_` and signaled via condvar; mismatched (stale) responses are dropped
  - On reader thread exit: sets `responseAborted_` flag to wake up any blocked SendAndReceive caller
  - **CRITICAL**: Never call SendAndReceive from event callbacks (deadlock!)
- **Note**: Pause uses `SendAndReceive` (waits for ack), not fire-and-forget `SendCommand`

### DLL (veh_handler)
- **VEH handler thread**: Whichever thread hits the exception
- **Pipe server thread**: Reads commands, dispatches handlers
  - Registered as internal thread via `ThreadManager::RegisterInternalThread()`
  - Filtered out of `EnumerateThreads`/`GetContext`/`SuspendThread`/`SetContext` (deadlock prevention)
- **TlsAlloc PendingRearm**: VEH state is per-thread (TlsAlloc, ManualMap-safe); pipe server communicates via `stepFlags_` map
- **SyscallResolver**: All WinAPI calls in VEH path replaced with ntdll stub copies (RWX page) + TEB direct reads. Immune to user BPs on VirtualProtect, FlushInstructionCache, GetCurrentThreadId, TlsGetValue etc.

## Stepping Mechanism

### VEH Single-Step Flow
1. BP hit -> save originalByte, write INT3 (0xCC)
2. On INT3 exception: restore originalByte, set TF (Trap Flag) in EFLAGS
3. SINGLE_STEP exception: re-install INT3, report StepCompleted

### StepOver (F10) - Two Paths
```
OnNext
+-- PDB path (SymbolEngine::GetCurrentLineRange success)
|   +-- temp BP at nextLineAddress -> Continue  [O(1), 3 IPC calls]
+-- Fallback (no PDB or edge case)
    +-- Single-step + auto-step in same line + CALL skip  [O(n)]
```

### StepIn (F11)
- Single step via IPC, auto-step while on same source line (skip prologue/nop)

### StepOut (Shift+F11)
- Read return address from stack -> temp BP at return address -> Continue

## TraceCallers

Records which code paths call a given function by placing a trace BP and collecting callers.

### Mechanism
1. `StartTrace(address)` sets `traceAddress_` (atomic)
2. INT3 hit at trace address -> VEH handler reads caller, writes to lock-free ring buffer, auto-continues (no stop)
3. After `duration_sec`, `StopTrace()` + `GetTraceResults()` aggregates ring buffer into `{caller -> hitCount}` map

### Caller Resolution (platform-dependent)
- **x64**: `RtlVirtualUnwind` + `RtlLookupFunctionEntry` -- uses PE unwind tables (`.pdata`) to unwind one frame. Accurate regardless of BP position within the function. Both APIs are lock-free kernel functions, safe inside VEH handler.
- **x86**: Reads `[ESP]` directly -- only accurate when BP is at function entry point (before prologue modifies ESP). No `.pdata` equivalent on x86; frame-pointer-based walking (`[EBP+4]`) is unreliable with `/Oy` (frame pointer omission, default in Release).

### Internal Thread Exclusion
- DLL's pipe server thread (`internalTid_`) is excluded from trace collection
- Without this, the IPC thread hitting the trace BP would delay pipe command processing
- Implemented via `atomic<uint32_t> internalTid_` check in VEH handler (lock-free)

### Design Constraints (VEH handler context)
- No mutex, no heap allocation (deadlock risk if BP hits inside malloc/HeapAlloc)
- Lock-free ring buffer: `traceBuffer_[65536]` + `atomic<uint32_t> traceWriteIdx_`
- `__try/__except` wrapper for stack read (guard against invalid ESP/RSP)

## SyscallResolver (WinAPI BP Immunity)

VEH handler path must not call any WinAPI that a user might set a breakpoint on.
If VirtualProtect has a BP, the INT3 inside PatchByte triggers VEH reentry -> crash.

### Solution: ntdll Stub Copy
1. `Initialize()`: For each ntdll function (NtProtectVirtualMemory, NtFlushInstructionCache, NtWaitForSingleObject, NtCreateEvent, NtClose, NtSetEvent):
   - `GetProcAddress` -> get original stub address
   - `DecodeInsn` loop (built-in x86/x64 length decoder) -> find `ret` instruction -> determine stub size
   - Extract SSN from `mov eax, imm32` (opcode 0xB8)
   - `memcpy` stub to pre-allocated RWX page (VirtualAlloc PAGE_EXECUTE_READWRITE)
2. Wrapper functions call the copied stubs instead of originals
3. If stub copy fails, falls back to `GetProcAddress` direct call (ntdll, not kernel32)

### TEB Direct Reads
These WinAPI functions are replaced with inline TEB field access (no function call at all):
- `GetCurrentThreadId()` -> `__readgsdword(0x48)` (x64) / `__readfsdword(0x24)` (x86)
- `TlsGetValue(index)` -> `TEB.TlsSlots[index]` (index < 64) or `TEB.TlsExpansionSlots[index-64]`
- `TlsSetValue(index, val)` -> same TEB write
- `GetLastError()` -> `TEB.LastError`

### Known Limitations
- `std::mutex::lock()` (CRT) internally calls `RtlEnterCriticalSection` which may call `GetCurrentThreadId` -- cannot be replaced without removing mutex usage from VEH path
- `KiUserExceptionDispatcher` (ntdll) is the OS exception dispatch entry point -- structurally impossible to bypass, but also impossible to safely BP (any debugger would infinite-loop)

## Detach / Re-attach

### Detach Flow
1. `RemoveAll()` -- restore original bytes for all SW BPs
2. `HwBreakpointManager::RemoveAll()` -- clear DR0-DR7
3. `ResumeAllStoppedThreads()` -- signal all waiting threads
4. `Uninstall()` -- remove VEH handler
5. `ThreadManager::ResumeAll()` -- OS-level resume
6. Pipe: `DisconnectNamedPipe` -> outer loop waits for new client

### Forced Resume Safety
When threads are stopped in the VEH handler (WaitForSingleObject) and detach occurs:
- `ResumeAllStoppedThreads()` clears `stoppedContexts_` before signaling events
- Woken threads detect missing context entry -> clear TF (Trap Flag) and `pendingRearm_`
- Prevents SINGLE_STEP exception after VEH uninstall (which would crash the target)

### Re-attach Flow
1. New client connects to existing pipe
2. `VehHandler::Install()` -- re-register VEH handler
3. Ready event sent
4. New BP commands work normally (clean BreakpointManager state)

## Concurrency Guards

| Mutex | Protects |
|-------|----------|
| `steppingMutex_` | steppingMode_, steppingThreadId_, steppingInstruction_, stepOverTempBp*, stepStartLine/File |
| `breakpointMutex_` | breakpointMappings_, functionBpMappings_, instrBpMappings_, dataBreakpointMappings_ |
| `frameMutex_` | storedFrames_, nextFrameId_, frameIdMap_ |
| `sendMutex_` | DAP message serialization |
| `exceptionMutex_` | lastException* fields |

Pattern: reader thread copies state under lock, then uses local copy outside lock.

## Launch Flow
1. `CreateProcess` + `CREATE_SUSPENDED`
2. DLL injection (auto-selects method based on target bitness/protection)
3. Wait for DLL "Ready" event on pipe
4. `configurationDone` -> resume main thread

## Build
```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output: `build/bin/Release/` -> `veh-debug-adapter.exe`, `vcruntime_net.dll`, `veh-mcp-server.exe`

Deploy to: `~/.vscode/extensions/knewstimek.veh-debugger-{version}/bin/`

## Logging & Diagnostics

The release build produces **no log files by default**. Two opt-in mechanisms:

### Runtime log (`--log`)
Pass `--log=FILE` and optionally `--log-level=LEVEL` to the adapter:
```bash
veh-debug-adapter.exe --log=C:\tmp\adapter.log --log-level=debug
```
Levels: `debug`, `info` (default), `warn`, `error`.
In VSCode, set `logFile` / `logLevel` in launch.json:
```json
{ "type": "veh", "logFile": "C:\\tmp\\adapter.log", "logLevel": "debug" }
```

### Compile-time trace (`VEH_DAP_TRACE`)
Enabled via CMake flag - logs raw DAP request/response JSON to a fixed file:
```bash
cmake -B build -DVEH_DAP_TRACE=ON
```
Output: `C:\tmp\veh_dap_trace.log` (REQUEST, setBreakpoints, setInstructionBreakpoints)

### DLL-side logging
The DLL (`vcruntime_net.dll`) uses the same `Logger` class (default: stderr).
Since the DLL runs inside the target process, stderr goes nowhere unless the target has a console.
A few critical paths also use `OutputDebugStringW` - view with DebugView (Sysinternals).

## Test
```bash
py -3 test/test_step.py        # F10 (StepOver) - 10 consecutive steps
py -3 test/test_stepin.py      # F11 (StepIn) - step into function
py -3 test/test_bp_masking.py  # ReadMemory returns original bytes, not INT3
```

Tests speak DAP protocol directly via stdin/stdout to the adapter process.

### MCP Tests
```bash
py -3 test/test_mcp_launch.py       # MCP launch + detach
py -3 test/test_mcp_stepover.py     # MCP StepOver CALL skip
py -3 test/test_mcp_new_features.py # 8 new MCP tools (source BP, func BP, evaluate, etc.)
py -3 test/test_mcp_deep.py         # 28 deep integration tests (value verification)
py -3 test/test_mcp_trace_callers.py # TraceCallers tool
```
