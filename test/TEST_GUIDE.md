# VEH Debugger test guide

Automated DAP/MCP integration tests are the primary validation path. Use manual
VSCode testing only for UI behavior that the protocol harnesses cannot cover.

## Prerequisites

Build both target architectures:

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
cmake -B build32 -G "Visual Studio 17 2022" -A Win32
cmake --build build32 --config Release
```

Run tests from the repository root. Test harnesses must use real timeouts,
`try/finally` cleanup, and must terminate and wait for every process they start.

## Core integration coverage

```powershell
py -3 test/test_step.py
py -3 test/test_stepin.py
py -3 test/test_bp_masking.py
py -3 test/test_batch.py
py -3 test/test_mcp_launch.py
py -3 test/test_mcp_deep.py
py -3 test/test_mcp_new_features.py
py -3 test/test_trace_basic_blocks.py
py -3 test/test_trace_code_stream_failure.py
```

For architecture-sensitive MCP behavior, rerun the applicable test against the
x86 build:

```powershell
$env:VEH_TEST_BUILD_DIR = (Resolve-Path build32).Path
py -3 test/test_trace_basic_blocks.py
Remove-Item Env:VEH_TEST_BUILD_DIR
```

After a test run, inspect only processes whose executable path belongs to the
build directory used by that run. Before terminating a leftover, verify its full
parent chain and do not touch unrelated terminal or agent sessions.

## Optional VSCode UI smoke test

Install the freshly packaged VSIX or run the extension development host, then use
a launch configuration pointing at `build/bin/Release/test_target.exe`.

Verify:

- launch and attach stop with the expected thread and address;
- hover displays register and memory values;
- register edits are applied after continue;
- conditional and hit-count breakpoints filter correctly;
- log points write to Debug Console without stopping;
- step-in, step-over, and step-out stop at the expected instructions;
- x86 targets load `vcruntime_net32.dll` and expose 32-bit registers.

Do not use a hard-coded extension version or depend on a repository-local
`.vscode/launch.json`; those files are intentionally local configuration.
