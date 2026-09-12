# Release procedure

Releases are deliberate external actions. Start this procedure only after the
user explicitly authorizes publishing and chooses the version number.

## 1. Prepare the release

1. Finish all feature, bug-fix, audit, documentation, and test work intended for
   the release. A Marketplace version cannot be replaced after publication.
2. Review the working tree and ensure no credentials, local profiles, logs, test
   outputs, or unrelated files will be committed or packaged.
3. Promote `extension/CHANGELOG.md`'s `Unreleased` entries to
   `## VERSION - YYYY-MM-DD` and create a fresh empty `Unreleased` section.
4. Set the exact same version in:
   - `CMakeLists.txt` (`project(... VERSION ...)`)
   - `extension/package.json`
   - `extension/package-lock.json` (both root package entries)
   - `src/mcp/mcp_server.cpp` (`serverInfo.version`)
5. Synchronize user-facing and technical documentation when behavior, MCP tools,
   protocol structures, packaging, or tool counts changed:
   - `README.md`
   - `README.en.md`
   - `extension/README.md`
   - `OVERVIEW.md`

Do not put a Marketplace PAT, GitHub token, private host, or other credential in
the repository or directly in a recorded command.

## 2. Build and test

Configure build directories when they do not already exist:

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake -B build32 -G "Visual Studio 17 2022" -A Win32
```

Build the shipped x64 programs/DLL and x86 DLL:

```powershell
cmake --build build --config Release
cmake --build build32 --config Release --target veh-debugger
```

Run the relevant DAP and MCP integration suites, including x64 and x86 coverage
for architecture-sensitive changes. Test harnesses must enforce real timeouts and
`finally` cleanup. Afterward, verify by executable path and full parent chain that
no target, adapter, or MCP server started by the tests remains.

After a successful agent-driven build, also follow `AGENTS.md` and deploy the
verified binaries beside `agent-tool.exe` with the `agent-tool` `copy` operation.

## 3. Package

The checked-in helper validates version synchronization, rebuilds both
architectures, copies the four shipped binaries into `extension/bin`, compiles the
extension, and creates the VSIX and binary ZIP. It does not commit, push, or
publish anything.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-release.ps1 -Version VERSION -ValidateOnly
powershell -ExecutionPolicy Bypass -File scripts/prepare-release.ps1 -Version VERSION
```

Expected assets:

- `extension/veh-debugger-VERSION.vsix`
- `extension/veh-debugger-VERSION-bin.zip`
  - `veh-debug-adapter.exe`
  - `veh-mcp-server.exe`
  - `vcruntime_net.dll`
  - `vcruntime_net32.dll`

Inspect both archives before continuing.

## 4. Commit and publish

1. Review `git diff`, `git diff --check`, and the exact staged file list.
2. Commit the release, push the intended branch, and verify the remote commit.
3. Create GitHub release `vVERSION` with only the reviewed VSIX and binary ZIP.
4. Publish that reviewed VSIX to Marketplace using the authenticated `vsce`
   credential store or a protected environment variable. Never place the token in
   documentation or command text.
5. Verify the GitHub assets and Marketplace version after publication.

If any verification fails, stop before publishing and fix the same release
candidate. Do not silently increment or choose a version on the user's behalf.
