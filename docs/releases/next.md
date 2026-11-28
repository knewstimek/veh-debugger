# VEH Debugger — Unreleased

Release-note draft for changes after v1.2.5.

## Added

- `injectionMethod="importTable"` for launch (MCP and DAP): the VEH DLL loads
  before the target's static DLLs, for targets whose loader blocks remote-thread
  injection. `stopOnEntry` is unchanged. `restoreImports=true` restores the
  original import directory after load. Not auto-selected; attach cannot use it.

## Fixed

- Injection no longer rejects a loaded DLL as an invalid module handle when the
  target's loader changes its module list during the check.
