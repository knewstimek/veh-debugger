# Changelog

## Unreleased

### New Features
- **veh_batch**: Execute multiple debugger commands in a single MCP call. Supports `$N` variable references (e.g. `$0.registers.rsp`), and control flow: `if`/`else`, `loop`/`until`/`max`, `for_each`/`as`/`do`. Reduces agent round-trips from N turns to 1

### Architecture
- **DebugSession class**: Extracted pure C++ API from McpServer (no JSON dependency). MCP tools and veh_batch both delegate to DebugSession

## 1.0.93 (2026-03-29)

### Bug Fixes
- **trace_callers stale event drain**: After auto-resume/pause, cached stop events from the tracing period are now cleared. Prevents false stop on next `veh_continue(wait=true)`
- **Shellcode fire-and-forget self-cleanup**: Shellcode thread now unregisters from VEH on exit (prevents tid reuse causing BP skip)
- **ContinueRequest zero-init**: Fixed uninitialized `passException` field that could randomly forward exceptions to SEH
- **ResumeAllStoppedThreads**: Now clears `passExceptionFlags` to prevent stale flags from previous sessions
- **Batch write size limit**: Added 1000-patch cap to prevent long IPC blocking

## 1.0.92 (2026-03-29)

### New Features
- **pass_exception (veh_continue)**: Forward exceptions to process's own SEH handler instead of swallowing them. Enables debugging CFF/obfuscated binaries that use INT3 or structured exceptions for control flow. `veh_continue(pass_exception=true)`
- **Batch write (veh_write_memory)**: Patch multiple addresses in a single call with `patches` array. `veh_write_memory({patches: [{address, data}, ...]})`
- **Shellcode crash reporting**: veh_execute_shellcode now returns crash details (exceptionCode, exceptionAddress) when shellcode crashes, instead of polluting the next veh_continue with stale exceptions
- **trace_callers auto-resume**: Automatically resumes stopped process before tracing, pauses after collection

### Enhancements
- **veh_dump_memory**: Response now includes `sha256` checksum, `fileSize`, and `verified` fields for file integrity confirmation
- **Shellcode SEH wrapper**: Shellcode threads are wrapped in __try/__except and registered with VEH handler to prevent exception leakage to the debugger event queue

## 1.0.91 (2026-03-29)

### New Features (MCP: 26 -> 30 tools)
- **veh_dump_memory**: Dump memory to binary file (up to 64MB, chunked 1MB reads). Avoids hex string token overhead that made large reads impractical
- **veh_allocate_memory**: Allocate memory pages in target process with selectable protection (rwx/rw/rx/r)
- **veh_free_memory**: Free previously allocated memory pages
- **veh_execute_shellcode**: All-in-one shellcode execution -- allocates RWX page, copies code, creates thread, waits for completion, frees page. Supports fire-and-forget mode (timeout_ms=0) for persistent patches

### Enhancements
- **Evaluate expressions (MCP + DAP)**: Both `veh_evaluate` and VSCode Debug Console now support complex expressions:
  - `[reg+offset]` / `[reg-offset]` -- e.g. `[RSP+0x8]`, `[RBP-0x20]`
  - `[reg+reg]` -- e.g. `[RAX+RBX]`
  - `[reg]` -- e.g. `[RSP]` (single register dereference)
  - `gs:[offset]` -- TEB-relative access on x64, e.g. `gs:[0x60]` for PEB pointer
  - `fs:[offset]` -- TEB-relative access on x86 (WoW64)
  - Architecture validation: `fs:[]` rejected on x64, `gs:[]` rejected on x86
- **BP ID separation**: HW breakpoint IDs now start at 10001 (SW BPs start at 1), eliminating ID collision between software and hardware breakpoints
- **breakpointType in veh_continue**: Response now includes `"breakpointType": "software"|"hardware"` when stopped at a breakpoint, removing ambiguity

### Bug Fixes
- **ExecuteShellcode crash on timeout**: TerminateThread followed by immediate VirtualFree could crash if thread hadn't fully terminated. Added WaitForSingleObject after TerminateThread to guarantee thread death before freeing code page
- **DumpMemory unsigned underflow guard**: Prevented potential infinite loop when DLL returns more data than requested

## 1.0.90 (2026-03-22)

### Bug Fixes
- **HW breakpoint DR registers not applied**: Data breakpoints (`veh_set_data_breakpoint`) returned success and appeared in list, but DR0-DR7 were not actually set when target was stopped. VEH handler now applies current HW BPs to context before returning, and `ApplyHwBreakpointsToAllThreads` updates `stoppedContexts` directly for VEH-stopped threads
- **Pause + Continue resume missing**: `pause` used OS `SuspendThread` but `continue` only signaled VEH events, leaving threads frozen. Continue now also calls `ResumeAll()` for OS-suspended threads
- **Disassembler wrong mode for x86**: Disassembler always defaulted to x64 mode, showing `push rbp` instead of `push ebp` for x86 targets. Now auto-detects bitness on launch/attach (both MCP and DAP)
- **dbghelp.dll conflict in target directories**: DLL injection failed when target folder contained old/incompatible `dbghelp.dll`. VEH DLL now uses `/DELAYLOAD:dbghelp.dll` and pre-loads from system directory
- **x86 (WoW64) injection failure**: DLL bitness detection in DAP used process-based check before process creation (always returned x64). Added PE file-based detection (`IsExe32Bit`). Also fixed WoW64 `LoadLibraryA` resolve from existing x86 processes with cmd.exe fallback
- **MCP injection method hardcoded**: MCP `veh_launch` always used `CreateRemoteThread`. Changed default to `Auto` and added `injectionMethod` parameter
- **Re-attach crash after detach**: Threads stopped in VEH handler retained TF (Trap Flag) after forced resume during detach. After VEH uninstall, the pending SINGLE_STEP exception had no handler, crashing the target. VEH handler now clears TF and pendingRearm on forced resume (3 paths: BP hit, HW BP, StepComplete)
- **Duplicate breakpoint at same address**: Setting a BP at an already-breakpointed address created a duplicate entry. Now returns existing BP id (re-enables if disabled). MCP `swBreakpoints_` list also deduplicates by id
- **trace_callers wrong caller address (x64)**: `ReadCallerFromStack` read `[RSP]` which is only correct at function entry. Replaced with `RtlVirtualUnwind` for accurate caller resolution regardless of BP position within the function. x86 retains `[ESP]` (no PE unwind tables available)
- **Nonexistent BP removal returns success**: `RemoveBreakpoint`/`RemoveHwBreakpoint` used fire-and-forget `SendCommand`, always reporting success even for invalid IDs. Changed to `SendAndReceive` with `NotFound` status check
- **Wrong threadId step returns timeout instead of error**: Step commands on non-stopped threads blocked until timeout with no useful message. DLL now validates thread is stopped (`IsThreadStopped`) before stepping, returns `NotFound`. MCP reports descriptive error with threadId
- **trace_callers on DLL internal thread**: Pipe server thread hitting trace BP caused IPC processing delays. VEH handler now skips caller collection for the internal IPC thread (`internalTid_` atomic check)
- **Breakpoint rearm failure (single-hit only)**: `ResumeStoppedThread`/`ResumeAllStoppedThreads` erased `stoppedContexts_` before `SetEvent`, causing VEH handler to mistake normal continue for detach -- clearing TF and canceling rearm. INT3 was never reinstalled after first hit. Fixed by deferring context cleanup to VEH handler (after restore) and adding `forDetach` flag to `ResumeAllStoppedThreads`
- **Exception not captured (ACCESS_VIOLATION etc.)**: VEH handler only handled INT3 and SINGLE_STEP, silently passing all other exceptions. Now catches crash-like exceptions (ACCESS_VIOLATION, INT_DIVIDE_BY_ZERO, ILLEGAL_INSTRUCTION, etc.), pauses the thread, and reports via IPC. DAP sends `stopped(reason=exception)`, MCP returns `reason: "exception"` from `veh_continue(wait=true)`. Exception details available via `exceptionInfo` / `veh_exception_info`
- **MCP `veh_continue(wait=true)` race with running process**: When target was already running (e.g. `stopOnEntry=false`), events occurring before `veh_continue` call were lost -- `bpHitOccurred_` was reset to false, IPC Continue resumed the stopped thread prematurely. Now checks for cached events before resetting, returns immediately if an event already occurred
- **Rapid consecutive step race condition**: VEH handler called `callback_` (sending IPC event) before creating the wait event handle (`GetOrCreateThreadEvent`). If the adapter responded fast enough with the next step command, `IsThreadStopped` returned false ("Thread not stopped"). Fixed by creating the wait event before firing the callback. Also fixed handle lifecycle: VEH handler now owns handle closure (was previously closed by `ResumeStoppedThread`, risking use-after-close)
- **Internal thread BP deadlock**: Setting a breakpoint on functions used by the DLL pipe server thread (e.g. `Sleep`, `GetCurrentProcessId`) caused deadlock -- the pipe server thread stopped in VEH handler, blocking all IPC. VEH handler now detects internal thread BP hits and transparently skips them (restore original byte + TF + rearm, no callback/wait)
- **Internal thread visible in threads list**: `RegisterInternalThread` was called inside the server thread (race with adapter's first `EnumerateThreads`). Pipe server thread appeared in thread list until a system function BP was set. Fixed by signaling thread ID back to `Start()` via condvar and registering before `Start()` returns

### Improvements
- **VEH handler `NotifyAndWait` refactor**: Extracted repeated stop/wait/resume pattern (context save, event create, callback, wait, context restore) from 4 exception paths into a single `NotifyAndWait` method with `WaitResult` enum
- **`thread_local` replaced with `TlsAlloc`**: `PendingRearm` per-thread state changed from `thread_local` to `TlsAlloc`/`HeapAlloc` for ManualMap DLL injection compatibility
- **SyscallResolver -- VEH handler WinAPI BP immunity**: VEH handler path no longer calls any WinAPI that could have user breakpoints set on it. All critical syscalls (`NtProtectVirtualMemory`, `NtFlushInstructionCache`, `NtWaitForSingleObject`, `NtCreateEvent`, `NtClose`, `NtSetEvent`) are copied from ntdll stubs to an RWX page at init time. Stub parsing uses a built-in x86/x64 instruction length decoder (no Zydis dependency in DLL). `GetCurrentThreadId`, `TlsGetValue`, `TlsSetValue`, `GetLastError` replaced with TEB direct reads (`__readgsqword`/`__readfsdword`). TLS expansion slots (index 64-1088) also handled via TEB pointer
- **Shutdown leak-safe**: `SyscallResolver::Shutdown()` intentionally does not `VirtualFree` the exec page -- threads woken during `Uninstall` may still be executing copied stubs. OS reclaims on process exit

## 1.0.83 (2026-03-21)

### Features
- **runAsInvoker option**: Bypass UAC elevation prompt by running target with current privileges (`__COMPAT_LAYER=RunAsInvoker`). Available in DAP (`launch.json`), MCP (`veh_launch`), and VSCode UI. Default: `false`

## 1.0.82 (2026-03-21)

### Bug Fixes
- **Auto+APC double-free**: When `Auto` injection fell back to `QueueUserAPC`, `remoteStr` was freed twice (once internally by APC, once by cleanup). Added `apcUsed` flag to track APC-internal memory ownership
- **ThreadHijack shellcode free timing**: Freeing shellcode memory before confirming DLL load could crash the target (shellcode still executing). Now only freed after module load is confirmed
- **OnRestart orphan process**: If pipe connection failed after successful relaunch, the new process was left alive with no way to terminate. Now calls `TerminateProcess` on pipe connect failure
- **OnRestart targetPid_ stale**: `targetPid_` was assigned before checking relaunch success, leaving stale state on failure. Now assigned only after success
- **CreateProcessA mutable buffer**: `lpCommandLine` must point to a writable buffer per MSDN contract. Changed from `string::data()` to `vector<char>`

### Improvements
- **Launch error diagnostics**: Added `LaunchResult.error` field with detailed `GetLastError` info (file not found, access denied, bad PE format, etc.). Propagated to both MCP and DAP error responses
- **DLL not found messages**: Now specify exact DLL name per architecture (`vcruntime_net.dll` for x64, `vcruntime_net32.dll` for x86)
- **veh_evaluate description**: Added guidance for indirect call tracing (vtable dispatch via register dereference)

### Tests
- Converted 5 test files from hardcoded absolute paths to relative paths
- Added `test_launch_errors.py` (10 tests for error diagnostics)
- Added `test_crackme_debug.py` (12 tests for real-world debugging scenarios)
- Removed deprecated `test_register_syntax.py` v1

## 1.0.81 (2026-03-19)

### Bug Fixes
- **Pipe server self-suspend deadlock**: DLL pipe server thread appeared in `EnumerateThreads()` result, causing `GetContext()`/`SuspendThread()` to deadlock when called on it (internal thread registry + filtering)
- **Stale response pipe contamination**: Fire-and-forget commands (Pause, Continue, Step) left unconsumed responses on the pipe, causing subsequent `SendAndReceive` queries to receive wrong data ("truncated data" error). Fixed by adding `expectedCommand_` check in ReaderThread to drop stale responses
- **Pause response consumed**: Changed `ToolPause` from `SendCommand` (fire-and-forget) to `SendAndReceive` to properly consume the DLL response
- **ReaderThread exit false-positive**: When reader thread exited (pipe disconnect), `SendAndReceive` returned `true` with empty data instead of `false`. Added `responseAborted_` flag for proper failure propagation
- **GetOverlappedResult unchecked**: `AsyncReadExact`/`AsyncWriteExact` ignored `GetOverlappedResult` return value, potentially masking I/O errors
- **Connect timeout handle leak**: `stopEvent_` handle leaked when `Connect()` timed out
- **SetContext deadlock prevention**: Added `IsInternalThread()` guard to `SetContext()` and `SuspendThread()` (same as `GetContext()`)

## 1.0.80 (2026-03-19)

### Bug Fixes
- **Transport closed root cause**: Child process stdout (printf/cout) leaked into MCP server's JSON-RPC pipe, corrupting transport. Fixed by adding `DETACHED_PROCESS` flag to CreateProcess (affects both MCP and DAP)
- **continue(wait) hang on process exit**: condvar predicate now checks `!attached_` in addition to `bpHitOccurred_`, so process exit immediately wakes the wait instead of blocking until timeout
- **stepOver hang on process exit**: Same condvar fix applied to `stepCv_` wait; ProcessMonitor and ProcessExited handler now also notify `stepCv_`
- **ProcessMonitor always notifies**: Removed `attached_` guard from ProcessMonitor cleanup block -- even if another code path already set `attached_=false`, condvar notification is always sent to prevent deadlocks
- **installer.cpp stdout leak**: Changed 7 `printf()` calls to `fprintf(stderr)` to prevent potential stdout pipe contamination in `--install` mode

## 1.0.79 (2026-03-19)

### Bug Fixes
- **MCP Transport closed on target crash**: ProcessMonitor used detach() allowing pipe cleanup to race with concurrent tool calls, crashing the MCP server. Now uses SetEvent + join for safe cancellation
- **MCP race condition**: Set attached_=false before pipe cleanup to block new tool calls immediately; signal bpHitCv_ before Disconnect so veh_continue(wait) exits cleanly

## 1.0.78 (2026-03-19)

### Bug Fixes
- **MCP Connection closed on target crash**: ProcessMonitor now fully cleans up pipe state when target process exits, preventing stale pipe from breaking subsequent launch/attach
- **MCP re-attach support**: `veh_attach` detects existing DLL pipe (WaitNamedPipeW) and skips injection, enabling detach -> re-attach to same PID
- **MCP race conditions**: Fixed bpMutex_ missing on breakpoint clear, targetProcess_ double-close race between ProcessMonitor and ToolDetach
- **DAP ProcessMonitor**: Added automatic crash detection for DAP adapter (sends terminated event on process exit)
- **DAP ProcessMonitor thread safety**: StopProcessMonitor uses SetEvent + join instead of detach, preventing use-after-free on restart/cleanup
- **DAP duplicate terminated event**: atomic flag prevents OnTerminate and ProcessMonitor from both sending terminated event

## 1.0.77 (2026-03-19)

### Bug Fixes
- **MCP reader thread blocked by long-running tools**: Tool calls now run in a detached thread, so blocking tools (veh_continue wait=true, veh_launch, veh_attach) no longer freeze the entire MCP server (-32000 Connection closed)
- **veh_launch/veh_attach pipe connect timeout**: Reduced from 7000ms to 3500ms

## 1.0.76 (2026-03-19)

### New Features
- **veh_continue wait mode**: `veh_continue(wait=true, timeout=N)` blocks until breakpoint hit, exception, pause, or process exit. Default timeout 10s, max 300s. Eliminates need for polling or notification handling
- **MCP instructions field**: Initialize response includes workflow guide for AI agents (launch -> set BP -> continue(wait=true) -> inspect -> step -> repeat)

### Improvements
- **MCP standard notifications**: Changed `notifications/message` to `notifications/logging` (MCP spec compliance, 7 sites)
- **Improved tool descriptions**: `veh_continue` documents wait/timeout params; `veh_step_in`/`veh_step_over` clarify synchronous behavior

## 1.0.75 (2026-03-19)

### Bug Fixes
- **MCP stderr pipe buffer block**: Redirect stderr fd to NUL in MCP mode. Some clients (e.g. Codex) have no stderr reader timeout, causing pipe buffer (~4KB) to fill, blocking server writes and stalling stdout responses ("Transport closed")
- **veh_attach hangs on CREATE_SUSPENDED process**: Detect uninitialized suspended processes (thread suspend count + low module count) and return immediate error instead of blocking 12+ seconds on injection timeout

### Improvements
- **Auto-detach on re-attach/re-launch**: `veh_attach` and `veh_launch` now auto-detach from previous session instead of returning "Already attached" error
- **Updated tool descriptions**: `veh_attach` description warns about CREATE_SUSPENDED processes; `veh_launch` clarifies it handles process creation internally

## 1.0.74 (2026-03-19)

### Bug Fixes
- **MCP server stdin EOF zombie**: Server process did not exit when stdin was closed by the MCP client (e.g. Codex CLI "Transport closed"). Root cause: CRT `_read()` failed to detect broken pipe on Windows. Replaced with Win32 `PeekNamedPipe` + `ReadFile` and added `CloseCallback` to propagate transport shutdown to the server loop
- **MCP stdout unbuffered**: Added `setvbuf(stdout, NULL, _IONBF, 0)` to ensure JSON-RPC responses are flushed immediately

## 1.0.73 (2026-03-19)

### New MCP Tool (25 -> 26)
- **veh_trace_callers** -- Trace all callers of a function for N seconds (like Cheat Engine's "Find out what accesses this address"). Returns unique caller addresses with hit counts

### Bug Fixes
- **StartEventListener race condition**: Reader thread might not have entered its loop before SendAndReceive was called, causing condvar timeout. Now waits for reader thread ready signal before returning
- **VEH trace lock-free**: Replaced mutex + unordered_map in VEH handler with lock-free ring buffer to prevent malloc deadlock when breakpoint hits inside heap allocator
- **Trace BP race condition**: StopTrace before Remove to prevent threads from entering normal BP wait path during teardown
- **RSP dereference protection**: Added SEH __try/__except around stack pointer read in trace mode to handle invalid RSP gracefully
- **TraceCallers IPC pack alignment**: Moved TraceCallerEntry/TraceCallersResponse inside #pragma pack(1) scope to prevent array indexing mismatch

### Improvements
- **snake_case instructionReference fallback**: Accept both `instructionReference` (DAP spec) and `instruction_reference` (snake_case) in setInstructionBreakpoints and setBreakpoints for non-standard DAP client compatibility
- **Trace BP conflict protection**: Skip removing trace breakpoint if a user-set breakpoint already existed at the same address

## 1.0.72 (2026-03-18)

### Bug Fixes
- **DAP StepOver BP rearm + CALL**: Same fix as MCP 1.0.71 applied to DAP adapter fallback path. When PDB path falls back to legacy stepping, BP rearm could enter CALL functions instead of skipping

## 1.0.71 (2026-03-18)

### Bug Fixes
- **StepOver on BP with next CALL**: When stepping over a non-CALL instruction sitting on a breakpoint, the BP rearm mechanism caused 2 instructions to execute. If the second was a CALL, step-over entered the function instead of skipping it. Now pre-checks if the next instruction is CALL via `IsNextInstructionCall()` and uses temp BP to skip
- **StepOver synchronous wait**: ToolStepOver now waits for StepCompleted event before returning, preventing race conditions with subsequent register reads

### Improvements
- **"Not attached" detailed messages**: All 23 "Not attached" error sites now check if the target process has exited and include the exit code (e.g. "Not attached - target process exited (code 0)")
- **Launch file validation**: `veh_launch` checks if the program file exists before attempting launch. Returns "File not found: <path>" instead of generic "Launch failed"
- **Launch error includes path**: "Launch failed" now includes the program path for easier debugging
- **OpenProcess permission fix**: Added `PROCESS_QUERY_LIMITED_INFORMATION` to OpenProcess flags so `GetExitCodeProcess` can retrieve the exit code
- **Unicode-safe file check**: Replaced `GetFileAttributesA` with `std::filesystem::exists()` for path validation

## 1.0.70 (2026-03-18)

### New MCP Tools (19 -> 25)
- **veh_set_source_breakpoint** -- Set breakpoint by source file and line number (resolves via PDB symbols)
- **veh_set_function_breakpoint** -- Set breakpoint by function name (resolves via PDB symbols)
- **veh_evaluate** -- Evaluate register names, memory addresses, and pointer dereferences
- **veh_set_register** -- Modify CPU register values on stopped threads
- **veh_exception_info** -- Get last exception details (code, address, description)
- **veh_list_breakpoints** -- List all active software and hardware breakpoints

### Enhanced Existing Tools
- **veh_set_breakpoint** -- Added `condition`, `hitCondition`, `logMessage` parameters for conditional breakpoints and logpoints

### Conditional Breakpoint Infrastructure
- Condition evaluation using register comparisons and memory reads (e.g. `RAX==0x1000`, `[0x7FF600001000]==42`)
- Hit condition support (break after N-th hit)
- Logpoint support with register interpolation (e.g. `"RSP={RSP}, value={RAX}"`)
- Auto-continue when condition not met or logpoint fires (deadlock-safe via pending queue)

### DLL Improvements
- **SetRegister IPC handler** -- DLL now handles SetRegister commands with VEH-aware context modification
- **VEH context restore on resume** -- Modified registers are correctly applied when VEH-stopped threads resume (3 handler paths: BP hit, HW BP, step complete)

### Bug Fixes
- **hwBreakpoints_ accessed without mutex** -- Added bpMutex_ protection in set/remove/list data breakpoint operations
- **veh_evaluate with threadId=0** -- Now returns error instead of sending invalid IPC request

## 1.0.66 (2026-03-18)

### Bug Fixes
- **Codex CLI: Transport closed on MCP tool calls** -- Codex sends `resources/list`, `resources/templates/list`, and `prompts/list` during MCP initialization. Server returned `-32601 Method not found`, which Codex treated as fatal. Now returns empty lists per MCP spec

## 1.0.65 (2026-03-18)

### Bug Fixes
- **MCP server not updated after extension upgrade** -- The `--install` command updated `settings.json` and per-project entries in `.claude.json`, but missed the root-level `mcpServers` in `.claude.json`. After upgrading (e.g. 1.0.5 to 1.0.64), the old version's binary kept running. Now updates all MCP path entries (global + per-project) in `.claude.json`
- **Uninstall left stale entries in .claude.json** -- `--uninstall` only removed from `settings.json` and `claude mcp remove`. Now also cleans up `.claude.json` (global + per-project mcpServers)

## 1.0.64 (2026-03-18)

### Bug Fixes
- **Hardcoded threadId=1 in DAP adapter** -- 5 places assumed DAP thread ID 1 (stopOnEntry event, OnStackTrace, OnVariables, OnEvaluate, OnSetExpression). Our debugger uses OS thread IDs, so hardcoding 1 caused wrong thread context in multi-threaded targets. Now uses `launchedMainThreadId_` or `lastStoppedThreadId_` as appropriate fallbacks

### Improvements
- **Process exit auto-detection (MCP)** -- Background monitor thread watches target process handle; sends `process_exited` notification with exit code when process terminates
- **IPC error messages include exit code and pipe state** -- `IpcErrorMessage()` now distinguishes: process exited (with code), pipe disconnected (crash), or IPC timeout
- **Specific DLL failure responses** -- Memory read/write errors mention "address may be invalid or inaccessible"; register/thread/locals errors hint at likely cause (thread state, PDB symbols); "Invalid response" now says "truncated data"

## 1.0.63 (2026-03-18)

### Bug Fixes
- **Hardware data breakpoints not applied to running threads** -- `SetHwBreakpoint` only stored BP in internal data structure but never wrote DR0-DR3 registers to thread contexts. Now immediately applies DR registers to all threads via `GetThreadContext`/`SetThreadContext` after set/remove
- **Unhelpful "IPC failed" error messages** -- All 17 IPC error sites now check if the target process has exited and return specific messages: "Target process has exited" or "IPC communication failed (pipe broken or timeout)" instead of generic "IPC failed"

### Improvements
- **MCP tool descriptions clarify OS thread ID** -- `threadId` parameter descriptions now say "OS thread ID (from veh_threads)" to prevent confusion with DAP's 1-based thread IDs

## 1.0.62 (2026-03-18)

### Bug Fixes
- **MCP launch: process frozen after veh_launch** -- `ToolLaunch` never called `ResumeThread` on the main thread after `CREATE_SUSPENDED` injection. The process stayed OS-suspended forever, and `veh_continue` only does VEH-level resume. Added `ResumeMainThread()` to MCP server, called from `ToolLaunch` (when `stopOnEntry=false`), `ToolContinue`, `ToolStepIn/Over/Out`, and `ToolDetach`

## 1.0.61 (2026-03-18)

### Improvements
- **GDB/LLDB register syntax** -- `evaluate` now accepts `$rax`, `$rip` etc. in addition to `RAX`, `rip`. The `$` prefix is stripped before matching

## 1.0.6 (2026-03-18)

### Bug Fixes
- **MCP server not connecting to Claude Code** -- MCP stdio transport used DAP-style `Content-Length` framing instead of MCP-standard newline-delimited JSON. Claude Code could never parse the server's responses, showing "Failed to connect". Added `McpStdioTransport` class with correct framing
- Fix `ResumeAllStoppedThreads` not closing event handles / clearing stepFlags (resource cleanup consistency with `ResumeStoppedThread`)

## 1.0.5 (2026-03-18)

### New Features
- **PDB inline frame-based StepOver (O(1))** -- `SymbolEngine` uses `SymGetLineFromAddrW64` to calculate next source line address, sets a single temp BP + Continue instead of O(n) single-steps. Falls back to legacy step when Jcc detected in range or PDB unavailable
- **Register modification** -- Double-click register values in Variables panel to edit them
- **Conditional breakpoints** -- Break only when condition is met (e.g. `RAX==0x1234`, `*0x7FF600!=0`)
- **Hit count breakpoints** -- Break on Nth hit (e.g. hit count = 5, break on 5th hit)
- **Log points** -- Log messages to Debug Console without stopping (e.g. `RAX={RAX}, ptr={*0x7FF600}`)
- **Debug registers (DR0~DR7) in Variables panel** -- Hardware breakpoint addresses (DR0~DR3), status (DR6), and control (DR7) now visible in VSCode Registers scope and MCP `veh_registers` tool
- **Detach/re-attach support** -- DLL pipe server stays alive after detach, allowing re-attach without process restart
- **F9 breakpoint toggle in disassembly** -- Added `disassemblyViewFocus` keybinding and `contributes.breakpoints` for proper F9 support in disassembly view

### Bug Fixes

#### Critical
- **Reader thread deadlock on conditional breakpoints** -- `EvaluateCondition`/`ExpandLogMessage` called `SendAndReceive` from the IPC reader thread callback, blocking the only thread that could read the response. Fixed by embedding `RegisterSet` in `BreakpointHitEvent` payload and using `ReadProcessMemory` (direct Win32) for memory reads
- **Memory read values corrupted** -- All `ReadMemory` IPC responses include a 4-byte `IpcStatus` header that was not skipped. Conditional breakpoints, log points, and `readMemory` DAP request all returned data offset by 4 bytes
- **DAP `exceptionBreakpointFilters` key typo** -- JSON key was `"default_"` instead of `"default"`, causing VSCode to ignore the default-enabled state of exception filters

#### High
- **Temp breakpoint deleting user breakpoint at same address** -- StepOver temp BP removal now checks whether the BP ID belongs to a user-set breakpoint before issuing `RemoveBreakpoint`
- **`setFunctionBreakpoints` not replacing existing function BPs** -- DAP spec requires full-replace semantics; now removes all existing `BpType::Function` breakpoints before setting new ones
- **`setInstructionBreakpoints` removing function BPs** -- Added `BpType` enum (`Source`/`Function`/`Instruction`) to `BreakpointMapping`; each `set*Breakpoints` handler now only removes its own type
- **Restart losing args and cwd** -- `launchArgStr_` and `launchCwd_` now saved in `OnLaunch` and reused in `OnRestart`
- **Restart sending duplicate `initialized` event** -- Removed spurious `SendEvent("initialized")` from `OnRestart`
- **Stepping state race condition** -- All stepping variables now protected by `steppingMutex_` with copy-under-lock pattern on the reader thread
- **Pipe reader thread dying (error 997)** -- `ERROR_IO_PENDING` after `CancelIoEx` was misinterpreted as fatal pipe error
- **Reader thread use-after-free** -- Replaced `std::thread::detach()` with `TerminateThread` + `join()`

#### Medium
- **HW data breakpoint type mismatch** -- `readWrite` access type sent DR7 R/W value `2` instead of correct `3`
- **OnLaunch args injection** -- Command-line arguments with spaces/quotes were not escaped per Windows `CommandLineToArgvW` rules
- **OnSetDataBreakpoints race condition** -- Missing `breakpointMutex_` lock on data breakpoint operations
- **GetDllPath ANSI path** -- Replaced `GetModuleFileNameA` with `GetModuleFileNameW` in DAP adapter
- **ExceptionEvent.description buffer overread** -- Null-termination now enforced before `std::string` construction
- **SetVariable EFLAGS truncation** -- `EFLAGS` was incorrectly treated as 32-bit register due to `E` prefix check
- **ParseAddress 0 ambiguity** -- Added 2-arg `ParseAddress(str, &addr)` overload; reject invalid memoryReference with error
- **Stack trace not showing after Pause** -- `stopped` event was missing after `OnPause`
- **Instruction breakpoint offset ignored** -- VSCode sends `instructionReference + offset`; offset was not applied
- **HeartbeatAck flooding logs** -- `IpcEvent::HeartbeatAck` logged as "Unknown IPC event" on every cycle
- **MCP ProcessExited not handled** -- `attached_` flag stayed true after target exit
- **MCP GetModuleFileNameA** -- Replaced with `GetModuleFileNameW` for non-ASCII path support
- **MCP JSON parse error silently dropped** -- Invalid JSON now returns `-32700 Parse error` JSON-RPC response
- **OnCompletions column off-by-one** -- DAP `column` is 1-based; now correctly converted to 0-based

#### Low
- **Thread safety** -- Added `frameMutex_`, `sendMutex_`, `exceptionMutex_`; dataBreakpointMappings_ now under breakpointMutex_
- **memoryReference validation** -- ReadMemory/WriteMemory now reject empty memoryReference
- **IpcEvent::Paused not handled** -- Both DAP and MCP now handle DLL's Paused event
- **Log points ignoring condition** -- Log message now only emitted when condition passes
- **Stop button requires two clicks** -- VSCode sends terminate then disconnect; now both handled immediately
- **Stack frames not appearing** -- GetStackTrace fallback via GetRegisters when DLL stack walking fails
- **Registers panel empty** -- Frame ID encoding overflow with large Windows thread IDs; replaced bit-packing with sequential ID map
- **Registers scope not expandable** -- Added namedVariables hint so VSCode shows expand arrow
- **Disconnect hang** -- Response sent before Cleanup; reader thread join with 2s timeout

### Improvements
- **Disassembly/memory view shows original bytes at breakpoint addresses** -- `ReadMemory` IPC handler masks active INT3 (`0xCC`) bytes with the saved `originalByte`, so disassembly always displays original instructions regardless of breakpoint state
- **Removed hardcoded debug logging** -- `D:/veh-adapter.log` fallback removed; use `--log=FILE` or launch.json `logFile` option
- **Fixed EasyAntiCheat false claim in README** -- VEH does not bypass kernel anti-cheats
- **Added OVERVIEW.md** -- Architecture and IPC protocol reference for AI agent onboarding

## 1.0.4 (2026-03-17)

- Unreleased on Marketplace (VSIX packaged with stale binaries). All changes included in 1.0.5.

## 1.0.3 (2026-03-17)

- Add extension icon

## 1.0.2 (2026-03-16)

- Security: Replace all ANSI Win32 APIs with Unicode (W) versions for proper path handling
- Security: Fix command injection in installer (CreateProcessW with lpApplicationName)
- Security: Add toml++ library for proper TOML parsing (Codex CLI support)
- Security: Atomic file writes with temp+rename pattern for config files
- Fix: MCP server bitness detection — PE header-based for launch, pid-based for attach
- Fix: Disassembler null safety check
- Fix: ToolDetach SendCommand exception handling
- Fix: WaitForSingleObject zombie process prevention
- Auto-register MCP server on extension activation

## 1.0.1 (2026-03-16)

- Fix MCP installer: Claude CLI support (`claude mcp add --scope user`)
- Auto-register permissions (`mcp__veh-debugger__*`)
- Updated binaries

## 1.0.0 (2026-03-16)

- Initial release
- VEH-based debugging (no Windows Debug API)
- Software breakpoints (INT3)
- Hardware breakpoints (DR0-DR3) — memory read/write watch
- 4 DLL injection methods (CreateRemoteThread, NtCreateThreadEx, Thread Hijack, QueueUserAPC)
- PDB symbol support (source-level debugging)
- x86 and x64 process debugging
- Zydis disassembler with full operand display
- Memory read/write
- TCP remote debugging mode
- MCP tool server for AI agent integration (19 tools)
