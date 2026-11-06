# VEH page-exception data breakpoints, v1

Use the existing MCP data-breakpoint tools:

```text
veh_set_data_breakpoint(address="0x...", method="page", type="write", size=4)
veh_continue(wait=true)
veh_remove_data_breakpoint(id=...)
```

Omitting method preserves hardware DR0..DR3 behavior and its four-slot/1,2,4,8-byte
limits. Page mode is optional, local VEH DLL only. It consumes no DR slot.
External/hypervisor/legacy backends do not have to implement this mode and return
an explicit unsupported error before a new page-watch command is sent.

## Meaning and limits

Page mode uses PAGE_GUARD plus a one-instruction TF lease. Microsoft describes
guards as one-shot access alarms: [guard pages](https://learn.microsoft.com/windows/win32/memory/creating-guard-pages).
The complete page is affected; watch filtering compares the exception's reported
access address against the requested half-open byte range. It does not infer an
entire operand span or promise that every overlapping vector/REP access is observed.

- type is write or readwrite. A write stop is before the attempted instruction,
  so it is not proof that a write completed. Windows can report an already-denied
  access before the guard alarm. An original access violation still
  belongs to the target; continuing the guard does not grant otherwise absent rights.
- A watch spans1..4096 bytes entirely inside one committed MEM_PRIVATE data page.
  The original protection must be PAGE_READWRITE or PAGE_READONLY. Existing guard,
  executable, mapped/image and stack-growth guard reservations are refused.
  Prefer dedicated VirtualAlloc data pages: changing protections on shared heap
  pages can affect unrelated allocations.
- At most32 non-overlapping watch ranges and128 simultaneous pending TF leases.
  Multiple non-overlapping ranges can share a page. A page has one saved original
  protection and a reference count; removing one range retains the others.
- coverage is always best_effort. The OS clears a guard before dispatch; the page
  is guarded again while a reported hit is parked. On continuation it is opened
  for one instruction and rearmed before the internal single-step is consumed.
  Other threads or kernel memory accesses can pass during these windows. There is
  no claim of zero loss, no exact missed-hit count, and no implicit suspension of
  all other threads. Use a hardware/EPT watch when that guarantee matters.
- Remove watches before freeing/reallocating/changing protection of their backing
  allocation. Concurrent target-side remapping/protection changes are unsupported.
  Tracing, shellcode execution, writes/patches and protection/free commands are refused with
  InvalidState while page watches or their TF leases are active.

Register-only conditions and hitCondition use existing breakpoint handling.
Value and memory-dereference conditions are refused for page mode: external reads
of a guarded page cannot be assumed safe or current. Registers in a page stop
describe the pre-instruction context. An existing DR data breakpoint can
also stop after that instruction; the page rearm must not consume that HW event.

## Results and nested calls

Creation returns method=page, coverage=best_effort and accessTiming=before_instruction,
with no fabricated DR slot. veh_list_breakpoints places page entries in page
(the existing software/hardware lists retain their meaning).

A waiting continue/step page stop exposes breakpointType=page, accessedAddress,
access (read/write/execute), registers, registersAt and rearmFailed. RIP/address
is the faulting instruction. A rearm failure is a visible stop with rearmFailed=true,
not a claim of a successfully armed watch.

Direct calls, veh_batch and breakpoint actions use the same handlers. The data
breakpoint's optional action runs the existing batch-step executor on a hit.
An action which completes normally follows the existing automatic continuation
policy. No new MCP tool or separate polling loop is introduced.

## Lifecycle

Page ownership is process-wide; pending rearm and original TF are per thread.
Thread handles retain the identity of a pending lease. Unrelated accesses are
continued through the internal one-step/rearm path without a user stop. A normal
debugger step and simultaneous DR hit retain their existing stop semantics.
An intervening target exception rearms/cleans the page lease before the ordinary
exception path. Existing TF is preserved rather than unconditionally cleared.

Removal restores the original protection only for the final owner while the
mapping/protection still matches our ownership. A disappeared mapping or a
protection changed by the target is retired without overwriting the new state. Detach,
shutdown and disconnect cleanup restore page state and borrowed TF before the
VEH handler is removed. A failed restore refuses successful detach/uninstall;
it must not silently overwrite protection changed by another component.

## Native wire

kCapPageBreakpointV1=1<<11 is advertised only by the supporting VEH DLL,
with SetPageBreakpoint0x0007 and RemovePageBreakpoint0x0008 command bits.
Set request: packed address:u64, size:u32, access:u8 (1=write,3=readwrite),
reserved[3]=0,16 bytes. Reply: status:u32,id:u32,8 bytes. Remove uses the existing
4-byte ID request and4-byte status receipt.

Only a page hit appends accessedAddress:u64, access:u32 (exception codes0/1/8)
and flags:u32 (bit0=rearm failure) to the unchanged BreakpointHitEvent prefix.
Ordinary SW/HW events, all existing requests and external contracts remain unchanged.
Native IDs are not a portable type discriminator; frontend tracking and the
advertised optional event tail identify page watches.

test/test_page_breakpoints.py exercises the actual injected DLL on x64/x86:
DR independence, page sharing/removal, false-positive filtering, pre-access state,
read/write stops, step/rearm, a preserved original access violation, two live
threads parked on one page, later protection changes, detach/broken-pipe cleanup
and direct/batch/action paths. Host fixtures
also verify unsupported external peers. These tests do not establish zero-loss
multi-thread coverage.
