Follow the release procedure in `CLAUDE.md` exactly before publishing any release.

- When adding a public MCP tool or extending a tool with batch-meaningful behavior, wire it into `veh_batch` and breakpoint actions unless the operation is inherently unsafe or nonsensical there. Keep direct, batch, and action result semantics in parity and add integration coverage for each supported path; document any deliberate exclusion.
- Test harnesses that launch a target, adapter, or MCP server must use real non-blocking timeouts and `try/finally` cleanup. They must terminate and wait for every process they started on success, assertion failure, timeout, and interruption.
- After tests, verify that no `test_target`, adapter, or MCP server started by the current work remains. Before terminating a leftover process, match its executable path and verify its full parent chain; never classify or terminate a process by age alone, and never touch unrelated active terminal/session trees.
