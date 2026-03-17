# Changelog

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
