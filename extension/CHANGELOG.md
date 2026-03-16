# Changelog

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
