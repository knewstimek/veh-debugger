# Value scan sessions

The existing lazy `veh_value_scan` tool owns one backend scan session. No new
MCP tool or frontend ReadMemory loop is involved. Backend summaries report
`valueScan.protocol`; protocol `veh-value-scan/2` enables the features below.
A backend without the capability keeps its legacy synchronous first/next/results/reset
interface and existing limits. Explicit v2 options fail before starting on that backend.

## Workflow and output

`first` starts a fresh candidate generation. `next` filters the committed generation
using its captured comparison values. Both default to `async:true`: return a short
receipt with exact string `sessionId`, `jobId`, `generationId` and `state:running`.
The receipt is admission, not completed data. Completion/failure/cancellation arrives
as `notifications/veh/value_scan`. Clients must consume this custom notification to
show live UI; clients that ignore it can explicitly request `status`. There is no
automatic status timer or polling loop. `async:false` waits and is appropriate for
small bounded scans and sequential batch/action dependencies.

`result_mode:auto` returns counts without entries above 32 candidates. At or below
32, completion includes up to `max_results` (default 32). `summary` suppresses the
automatic list; `list` explicitly requests a bounded list in responses. Async admission
never reads a page. Terminal notifications always cap entries at 32, even with list.
`results` explicitly pages the committed generation, with `offset` (integer or exact
string) and `max_results` (1–1000). Filtering does not transfer the candidate set.

Example sequence, with completion notifications awaited between first and next:

```json
{"operation":"first","compare":"unknown","value_type":"i32","storage":"auto"}
{"operation":"next","compare":"changed","value_type":"i32"}
{"operation":"undo"}
{"operation":"results","offset":0,"max_results":32}
{"operation":"reset"}
```

Specify module/start/end to limit work. As in the legacy API, specify the original
value_type on next when it differs from the default i32. Undo restores both addresses
and captured comparison baselines; it does not modify target memory or re-read it.
A new successful first discards prior scan history. Next retains `undo_depth` prior
generations (default 1, range 0–8); undo drops the generation it replaces. No redo.
First/next/undo reject another active scan; they never silently cancel it.
Cancel requires the exact string `job_id`. Cancellation is cooperative, can lose a
race with commit, and returns cancelling until the terminal event confirms cancellation.
Status optionally accepts job_id as a stale-job guard. Never blindly retry a lost
start receipt: the operation may already exist; explicitly inspect or reset.

## Storage and lifetime

`storage:auto` selects RAM when the conservative stage estimate fits and otherwise
uses an owned temporary file. `ram` and `file` are explicit policies.
Default logical budgets are 128 MiB RAM and 16 GiB disk (MiB units, despite the
`ram_budget_mb`/`disk_budget_mb` option names). They include current, retained undo
and staged generations together. RAM admission also reserves 1 MiB workspace,
discovery records and conservative block capacity. These are collector storage budgets,
not a cap on the target's total RSS, allocator overhead or the OS file cache.
No billions-entry address vector is built: dense chunks retain bytes plus an alive
bitmap, while sparse chunks retain address/value pairs, whichever is smaller.
Metadata remains in RAM; exceptionally fragmented scans can therefore hit the RAM
budget even with disk storage.

Before file capture, check the conservative estimate against disk budget and free
space with a 16 MiB margin. Chunk writes enforce the budget again; free space may
change and file I/O can still fail. Low quotas fail explicitly. Current/undo state
survives validation, cancellation, budget, allocation and write failures. A staging
generation becomes current only after completion, flush and a final cancel check.
The budget may require space for a third generation while current and undo are live.

Files use unique system-temp names and non-inheritable delete-on-close handles.
Keep only data required by current/undo, reclaim failed/cancelled staging and discarded
history, and close all owned handles on reset, detach, shutdown, transport loss or
target exit. Ending one first/next operation cannot discard its current baseline.
There is no age-based sweep of other sessions' files. Process death closes handles
through the OS. A storage-device stall can delay cooperative cancellation/cleanup;
this implementation does not claim a hard disk-I/O completion deadline.

## Progress, consistency and cost

Events carry job/session/generation IDs and monotonically increasing per-job sequence,
phase, processed/total, matched, scannedBytes, elapsedMs, unreadableBytes and retained
storage. Discovering traverses virtual addresses (`address_bytes`, unknown total);
capturing/filtering use candidate slots. A null total means unknown, not 0% or 100%.
Intermediate progress is throttled to at most one update per ten seconds plus phase
changes; the MCP queue coalesces intermediate updates and reports coalescedUpdates.
Terminal state is distinct from a full progress denominator. Notification allocation
or pipe failure does not terminate the target; explicit status recovers backend state.
Custom notification rendering and whether notifications enter an LLM context depend
on the MCP client. Byte/schema measurements are not billed-token measurements.
Measured tools/list bytes remain lite=7921 (7 tools), interactive=9601 (10),
capture=16826 (10); full=65929 (84), up 1104 bytes from the preceding build.
Initialize instructions remain 218 bytes. No new tool is exposed eagerly.

Running scans are live observations, not an atomic process snapshot. No original code
is patched or target thread resumed/paused by scanning or undo. Existing breakpoint
bytes are masked during reads. Scan workers are registered as debugger-internal before
admission and excluded from freeze/enumeration. Unreadable/remapped ranges are skipped
and reported as unreadableBytes; no values are invented. A failed chunk can omit
otherwise readable candidates in that chunk. Self-modifying/data-writing threads can
change memory during capture. Stop the relevant target threads first when a stable
comparison is required. This does not claim protection against arbitrary target heap
corruption or loader-lock deadlocks.

Direct calls, veh_batch and breakpoint actions share this handler. Use async:false
for a bounded scan whose result is needed by the following step; an async receipt
does not cause later batch steps to wait for completion. Reset/cancel remain explicit.

## Backend adoption checklist

Implement the existing ValueScan IPC command inside the backend, not as a client
ReadMemory loop. Driver/hypervisor backends can choose their own storage location,
while preserving isolation, quotas, undo baselines and cleanup semantics.

- Preserve the legacy packed 56-byte request, 28-byte response and 16-byte entries.
  Advertise command support and flag `kCapValueScanV2` (bit 7) only after v2 works.
- Accept exactly the packed 104-byte request, version 2; emit a 140-byte response
  with version/headerSize and exactly count entries. Layout assertions live in
  ipc_protocol.h; x86/x64 use the same layout. Reject reserved/unknown flags and
  invalid ranges/types/budgets without mutation.
- Support First=0, Next=1, Results=2, Reset=3, Status=4, Cancel=5, Undo=6.
  Validate job IDs, busy state and cancellation races. IDs are opaque uint64 values,
  serialized as strings in MCP. Lost control replies must not trigger automatic retry.
- Keep the control loop responsive while a backend-owned worker runs; register it as
  internal before replying. Avoid pipe I/O under state locks or joining under a pipe
  write lock. Publish immutable generations atomically, including baselines.
- Emit `IpcEvent::ValueScanProgress` (0x100B) with the same header plus at most 32
  entries; report actual phases/counters, unknown denominators and terminal failures.
  No client polling. Preserve session/job/sequence identity and bound queues/output.
- Enforce combined current/history/staging budgets, preserve state on failure, and
  reclaim only owned temporary files on every lifecycle path, including abrupt loss.
- Confirm scans preserve exact stops, existing software/hardware breakpoints, thread
  separation, live/unreadable-memory semantics and target-width values. Do not claim
  target-wide atomicity or permission to resume a stopped target.
- Run the shared bounded scan tests on x64/x86 and direct/batch/actions, malformed
  receipts and legacy capability fallback. Publish the implementing commit and
  supported/unsupported behavior with measured evidence; flag bit alone is insufficient.

## Verification

Reuse `tools/run_tests.py test_value_scan.py test_value_scan_protocol.py --jobs 2`
and repeat with `--build-dir build32`. They use small synthetic target allocations
(up to 8 MiB), force file storage, verify count-first output, explicit pages, undo
including overlapping values, failed-stage retention, cancellation, event completion
without status polling, direct/batch/action behavior, reset/detach/exit/abrupt-loss cleanup and malformed/legacy receipts.
Use `tools/run_ipc_compat_matrix.py --suite scan` for old/new executable pairs (build roots or existing Release directories) and
`tools/measure_mcp_schema.py` for discovery bytes. Long TEMP-path refusal has a small regression; worker-registration allocation failure is statically reviewed, without injected allocation failure. Large throughput claims require a
separately approved, capacity-bounded workload; these boundary tests make no speed claim.
