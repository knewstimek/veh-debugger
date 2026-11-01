# Process trace resource limits (wire12)

A backend advertising `kCapBasicTraceLazy = 1u << 8` supports process
`veh_trace_basic_blocks` wire12. Attach/launch reports
`backend.basicTrace.protocol="veh-trace/12"` and `lazyDecode=true`.
Hardware-event and KD tracing keep their independently negotiated contracts.

## Usage and costs

```json
{
  "threadId": 77,
  "start": "module.dll+1000",
  "end": "module.dll+800000",
  "max_steps": "10000000000",
  "max_decoded_instructions": 1000000,
  "timeout_ms": 60000,
  "collect_snapshots": false,
  "collect_events": true,
  "events_output": "file"
}
```

This is a requested ceiling, not a speed guarantee. Native VEH single-steps
through exceptions: billions of instructions can take a very long time.
`timeout_ms` independently stops capture. The bounded regression requests ten
billion steps but executes only a few synthetic instructions.

- Process `max_steps` defaults to 1,000,000. Wire12 accepts positive 64-bit values
  through 18,446,744,073,709,551,614. Use decimal strings when values exceed exact
  JSON/JavaScript integer precision. Execution counts remain 64-bit on x86 too.
- `max_decoded_instructions` defaults to 1,000,000, accepts 1..4,294,967,294,
  and controls distinct decoded addresses, including block lookahead. It is
  independent of repeated executions. The dense metadata array is reserved
  before execution; an open-addressing index has the next power of two at least
  twice the entry capacity. The result's `resource_limits.decode_cache_bytes`
  reports their actual combined capacity in bytes. Other trace buffers and file
  receivers have separate budgets.
- A larger cache uses more target address space/RAM. x86 is still constrained by
  its process address space. Impossible sizes or failed allocation return
  `allocation_failed` before target execution; the accepted numeric range does
  not promise that the host can allocate it.
- Wire12 accepts ranges larger than 4 MiB without scanning their unused bytes.
  On first entry it decodes a bounded straight-line run. Code collection extends
  decoding within that entered block as needed, bounded by code/cache budgets.
  Cached instruction bytes are checked before reuse; changed bytes are decoded
  again so self-modification updates instruction length and operand semantics.
- The cache does not evict historical instruction hit/dependency metadata.
  Reaching an uncached executed address at capacity stops before that instruction,
  with `stop_reason="decode_budget"`, `truncated=true`, and
  `decode_incomplete=true`. An undecodable executed address stops as
  `decode_failed`. Code lookahead gaps never imply complete code capture.
- `timeout_ms` accepts 100..2,147,468,647 on wire12 (default10,000). It uses the
  existing target-side monotonic GetTickCount64 elapsed duration. No cross-host
  UTC clock comparison is introduced.
- Event file limits (`max_event_file_bytes`), code bytes/versions, unique
  blocks/edges, and inline event buffers retain their existing independent
  bounds. Select file events for long captures; a larger step ceiling alone
  does not enlarge output retention.

Direct calls, `veh_batch`, and breakpoint actions share validation and receipts.
`resource_limits` contains exact decimal-string `max_steps` and
`decode_cache_bytes`, the accepted cache entry budget, and `decode_mode="lazy"`.

## Frozen additive IPC layout

All structures remain packed, little endian, and pointer-width independent in
`src/common/ipc_protocol.h`. Existing request prefixes and response sizes do not
change. Wire11 responses remain401bytes.

Wire12 request appends to the frozen wire11 prefix:

| Field | Type |
|---|---|
| maxSteps64 | uint64 |
| maxDecodedInstructions | uint32 |

The existing32-bit `maxSteps` prefix field is a saturated compatibility value;
wire12 execution uses `maxSteps64`. Zero selects defaults. The capability bit,
wireVersion12 and exact `kTraceBasicBlocksRequestV12Size` are required.

Response v10 appends44bytes to response v9 (445bytes total):

| Field | Type |
|---|---|
| appliedMaxSteps | uint64 |
| decodeCacheBytes | uint64 |
| appliedMaxDecodedInstructions | uint32 |
| filteredSteps64 | uint64 |
| unsupportedMemoryWrites64 | uint64 |
| unsupportedMemoryReads64 | uint64 |

Successful responses must acknowledge both requested limits exactly and report a
nonzero cache size. The legacy counter fields saturate rather than wrap; new
clients use the64-bit fields. Stop reasons12/13 are DecodeBudget/DecodeFailed.
Start failure11 is AllocationFailed. Existing status and failure fields retain
their meanings. Lazy out-of-range start rejection decodes zero instructions.

New clients send wire10/11 to peers without the new capability and refuse
explicit cache budgets, expanded ranges/steps, and unsupported long timeouts
before effects. Legacy clients retain their old sweep and limits on the new DLL.
No backend is assumed to support wire12 just because it supports wire11.

## Errors and verification

A parsed DLL startup failure is the primary error even for
`events_output=file` or `code_output=file`. Stream errors remain secondary
diagnostics. A failed stream alone never proves that a DLL lacks file support.
Local file validation failures retain their existing error contract.

Run `test_trace_lazy_decode.py` through `tools/run_tests.py` for large unused
ranges, default/custom/tiny budgets, exact64-bit requests, numeric validation,
file-mode failure reasons and direct/batch/action parity. Existing
`test_trace_basic_blocks.py`, `test_trace_overlap.py`,
`test_trace_inaccessible_range.py`, and `test_trace_memory_access.py` cover
self-modification, block/code extents, inaccessible gaps and operand semantics.
Repeat on build32; reuse `tools/run_ipc_compat_matrix.py` for mixed peers.
