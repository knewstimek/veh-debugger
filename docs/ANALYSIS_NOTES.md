# Persistent analysis notes

Use the existing `veh_symbolize` tool to manage comments and labels. No extra MCP
tool or database library is required. Notes are frontend metadata; they do not
patch instructions, alter registers, create target threads, or become PDB symbols.
This version adds annotations to MCP results, not a VS Code annotation editor.

## Open once, then use ordinary inspection

Choose an absolute local directory explicitly. The following path is synthetic:

```python
veh_symbolize(analysis={"operation":"open", "directory":"C:/analysis/example", "create":True})
veh_symbolize(analysis={"operation":"set", "address":"sample.dll+352DD",
    "label":"length_check", "comment":"EAX is the request length in bytes",
    "position":"after", "status":"hypothesis", "author":"ai",
    "context":"normal request path", "evidence":["capture:request-16"]})
veh_disassemble(address="sample.dll+352DD", count=10)
```

Each edit is saved immediately to `analysis.json` in that directory. Modules and
old/new builds share that one file instead of scattering sidecars beside binaries.
`analysis.lock` coordinates cooperating MCP processes and should remain in place.
The last selected directory is remembered under
`%LOCALAPPDATA%/VEHDebugger/analysis-settings.json`; the target binary is not copied.
An unavailable/corrupt remembered project produces a status warning, not a new file.

`VEH_ANALYSIS_DIR` in the local MCP launch profile overrides the remembered path
and opens an existing project. `VEH_ANALYSIS_STATE_DIR` overrides the directory
holding the remembered-path settings (useful for isolated profiles/tests).
`analysis={"operation":"close"}` closes the current project and forgets its saved
path; an explicit environment override remains effective on the next restart.
Without a selected project, normal inspection results are unchanged.

## Meaning and identity

- A build-bound note is keyed by backing-image SHA-256, image width and hexadecimal
  RVA, not a process address or basename. ASLR therefore does not move the note.
  The backend supplies identity; a guest/remote path is never opened on the MCP host.
- A different build keeps its old notes but does not inherit them. Inspection can
  report `analysis_previous_records`/`annotation_history` without applying their
  labels or comments. No heuristic offset migration is performed.
- Notes preserve original instruction bytes. Disassembly compares those bytes and
  marks changes with `stale:true`. Updating that anchor requires an explicit
  `accept_code_change:true`. Symbol-only results say `code_validation:"not_checked"`.
- `status` is `hypothesis`, `observed`, or `refuted`. `observed` describes the saved
  observation and context, not a universal proof. `position` is `before` or `after`
  the instruction. Evidence stores short references, not embedded traces/dumps.
- If stable image identity is unavailable, the write explicitly reports
  `persistent_identity:false` and saves a distinct **unbound** note. It can be read,
  edited and deleted by its returned ID, but is never automatically attached to an
  address, even in the same session: base reuse and matching bytes cannot establish
  module lifetime. No guessed hash or basename-based cross-session match is used.

## Read, update, search and delete

```python
veh_symbolize(analysis={"operation":"status"})
veh_symbolize(analysis={"operation":"get", "address":"sample.dll+352DD"})
# Copy the revision returned by get; do not guess or convert it to a JS number.
veh_symbolize(analysis={"operation":"set", "address":"sample.dll+352DD",
    "expected_revision":"1", "comment":"Length comparison, observed for input 16",
    "status":"observed"})
veh_symbolize(analysis={"operation":"search", "query":"length", "limit":20})
veh_symbolize(analysis={"operation":"get", "id":"<returned-id>", "history_limit":2})
veh_symbolize(analysis={"operation":"delete", "id":"<returned-id>", "expected_revision":"2"})
```

Revisions are exact decimal strings. Existing records require `expected_revision`
for changes; conflict means read again before editing. Revisions increase with the
document even after deletion/recreation, so old writers cannot overwrite a new
incarnation. Up to eight earlier revisions are retained; mutations return compact
receipts and `history_count`, while `get(history_limit=1..8)` explicitly expands
history. Unbound notes also accept `set` by ID with a revision; that edits stored
text without claiming any current code validation.

`list`/`search` default to 20 previews, cap `limit` at 100, and page with `offset`
and `next_offset`. Filter with `module` or `build_id`. Normal disassembly and symbol
results include short previews; `include_annotations:false` disables enrichment.
Full comments/evidence are fetched explicitly. Labels remain separate from real
symbols and do not silently change address-expression resolution.

Direct calls, batches and breakpoint actions share the same record operations.
Opening/closing a project is direct-only because it changes frontend project
ownership. Existing batch session requirements still apply; direct offline
status/list/search/get/delete remain available without a target.

## Storage and failure behavior

The JSON format is `veh-analysis`, version 1, with string document revision and an
entries object. Files are limited to 8 MiB and 4096 records; comments are at most
4096 UTF-8 bytes, labels 128, context/evidence references 512 each, evidence 16,
and history eight revisions. Address/RVA/ID/revision values are strings. The same
field/enum/depth limits apply to manually edited files and API writes.

Writes hold an exclusive lock, reread the latest document, check the expected
record revision, flush a same-directory temporary file and replace the original.
Malformed/unknown versions and failed replacements preserve existing data rather
than resetting it. Retry a busy lock; reread on a revision conflict; check folder
permissions when saving fails. Do not edit files concurrently without the lock.
Project data is private analysis material; choose an ignored/local folder and
review it before sharing. No automatic upload or telemetry is involved.

## Optional backend identity

Advertise `GetModuleIdentity=0x0048` only when implemented. Packed little-endian
request: uint64 moduleBase (8 bytes). Response: IpcStatus, uint64 moduleBase,
uint32 addressBits, uint32 imageSize, uint8 sha256[32], uint64 moduleEpoch (60 bytes). Ok requires a
coherent current loaded image, width 32/64, matching module size and backing-file
SHA-256; unknown/malformed identity is never a stable key. moduleEpoch is an opaque lifetime counter that changes on module load/unload. A base=0 request returns only the epoch (other fields zero), without file I/O. The frontend brackets code/symbol inspection with this counter and rejects changes before saving or committing previews; a file hash alone cannot detect module replacement between IPC requests. The native backend refuses identity/epoch requests until DLL notification registration succeeds, and after tracking is disabled. Epoch validation protects the module map, not an atomic snapshot of all running threads/memory; stop relevant threads for repeatable observations.

The VEH DLL reads mapped-file metadata and loaded/file headers, normalizes the
legitimate ASLR ImageBase difference, and caches file hashes by module epoch and
file identity. It does not take the loader lock or pin/unpin modules during this
command; a module-epoch change invalidates the result. SHA provider first-use is
warmed before Ready, outside client-installed module-load stops. Hashing is bounded
to backing files up to 256 MiB with headers fitting the 4 KiB inspection budget.
Unavailable/unusual images degrade to unbound notes. No background tracing/polling
or per-instruction IPC is added. Enrichment is optional and bounds module lookups
and preview output. External backends can adopt this command independently.
