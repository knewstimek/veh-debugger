# Changelog

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
