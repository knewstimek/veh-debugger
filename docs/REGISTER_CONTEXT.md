# Register context, version 1

A backend opts in with `kCapRegisterContextV1 = 1u << 10` in
GetCapabilities.flags. All command IDs, packed layouts and existing values 0/1
of RegisterSet.is32bit remain unchanged. Empty GetCapabilities requests only
discover support and retain the legacy process-bitness contract. A client opts
in by sending GetCapabilitiesRequestV1 {uint32 version=1,uint32 flags=1<<10},
eight little-endian bytes. A supporting backend enables this contract for that
connection before replying with the advertised flag. Unsupported/invalid versions
or flags fail without enabling it. Connection teardown resets the selection.
Older backends/clients continue using their unchanged layouts and semantics.
An older backend may ignore the request suffix; absence of the returned flag
means legacy behavior. New frontends first send empty discovery after Ready, and send the versioned
request only if its response advertises support. A legacy peer never receives
an unsupported extension payload. A failed exchange is not retried on a stream
which may contain a late response.

With this capability, is32bit describes the register context supplied by
GetRegisters and stop events, independently of the process image bitness.
A 32-bit process can stop in native 64-bit code. Such a snapshot has is32bit=0,
full 64-bit GPRs/RIP/RSP and actual selectors; its process metadata stays32-bit.
A 32-bit context has is32bit=1 and the existing low GPR/EIP/ESP representation.
The backend derives the context width from the observed CPU code state or the
verified OS context contract, never from the executable image alone.

SetRegister/SetRegisters use the held context's width, not a caller-provided
is32bit value, to interpret edits. A 64-bit context permits full R8..R15 edits.
A 32-bit edit preserves native transition state that its register view does not
represent, including R8..R15 and XMM8..XMM15. GPR writes do not change segment
selectors, code mode or original debug-register ownership.

Frontends select register names and width from each returned context. They keep
process bitness separately for process metadata and do not infer a process
architecture change from a native 64-bit stop. Existing clients already using
is32bit to format the supplied registers retain that behavior; clients relying
on process bitness must negotiate this capability before assuming the new
contract. The flag introduces no new XMM capture or write guarantee.

When selected, explicit 64-bit addresses must not be truncated or rejected solely
because the process image is32-bit. Backends validate the actual mapped source.
Detailed caller records report each hit's actual width and valid-register mask;
unavailable high registers in 32-bit hits do not match register filters.

MCP disassembly uses an independent decoder per request. At the current stop PC,
opted-in peers select the observed context automatically. `veh_disassemble`
accepts `threadId` to select a held thread's code width, or `address_bits:32|64`
for other code; these options are mutually exclusive. The result reports
`addressBits`. Away from the stop PC, omission retains the process-width default.
Direct, batch and breakpoint actions use the same handler. CALL detection for
MCP stepping uses the supplied registers' width rather than a shared decoder.
Standard DAP disassembly at the stopped PC also uses the negotiated context,
including offsets around that PC; other addresses retain the process default.
A memory address alone does not prove an instruction's execution mode.

## Register validity, version 1

`kCapRegisterValidityV1 = 1u << 12` is selected the same way, alone or together
with context v1. Backends that support it pass both flags to
`SelectRegisterContext`'s `supported` argument. On a selecting connection every
GetRegisters reply is `GetRegistersResponseV1`, the unchanged response followed by
`uint64 validMask`. Bit i is RegisterSet field i in `SetRegisterRequest.regIndex`
order (0-15 GPRs, 16 RIP, 17 RFLAGS, 18-23 CS/SS/DS/ES/FS/GS, 24-29 DR0-3/DR6/DR7),
and XMM0-15 are bits 30-45. A complete context sets all 46 bits; unreadable fields
are zero. SetRegister of an unreadable field and SetRegisters on a partial context
return `InvalidState`. Without the selection, a backend refuses a context it
cannot read completely.

MCP `veh_registers` shows unreadable fields as `null` and adds `partial: true`.
Disassembly width needs only RIP. Evaluation, checkpoints, stepping and every
other consumer require a complete context. DAP does not select this flag yet.

Use synthetic mixed-mode stops with nonzero high GPRs and addresses above 4 GiB
to verify read/write round trips and resumed effects. Also verify a32-bit edit
preserves hidden native state. Low addresses or matching CS alone are not proof.
