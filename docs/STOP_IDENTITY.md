# Stop identity and conditional continuation, version 1

This agreed additive contract lets a frontend release only its own internal
module-load guard after a function-breakpoint binding pass. It does not change
public MCP/DAP arguments, ordinary Continue, trace wire10/11/12, or legacy structs.
Canonical packed little-endian definitions and size assertions are in
`src/common/ipc_protocol.h`.

## Discovery and exact layouts

A backend advertises `kCapStopIdentityV1 = 1u << 9` in GetCapabilities.flags only
after implementing this entire contract, plus command ContinueIfStopped0x0017.
Existing commands retain their IDs; struct sizes are identical on x86/x64.

| Message | Legacy bytes | Opt-in v1 bytes |
|---|---:|---:|
| SetModuleLoadStop request | 257 | 265 |
| ModuleLoadStopped event | 272 | 288 |
| IsThreadStopped request | 4 | 8 |
| IsThreadStopped response | 5 | 21 |
| ContinueIfStopped request (new0x0017) | — | 28 |
| ContinueIfStopped response | — | 21 |

SetModuleLoadStopRequestV1 appends uint32 version=1 and uint32 flags to the
unchanged257-byte prefix. IsThreadStoppedRequestV1 appends version=1 to the
unchanged threadId request. Extended events/responses append StopIdentityV1 to
their legacy prefix. StopIdentityV1 is kind:uint32, stopSequence:uint64,
flags:uint32 (16 bytes, sequence offset4). No implicit padding or variable tail.

Legacy4-byte IsThreadStopped requests ALWAYS receive the legacy5-byte response,
even after a connection opts into extended events. Legacy257-byte module-stop
requests preserve their behavior. Never append identities indiscriminately:
old MCP and DAP consumers require exact legacy response lengths.

A valid extended module registration opts that connection into extended
ModuleLoadStopped events before arming, so a stop may precede the registration
acknowledgement. A legacy-only connection keeps272-byte events. Unsupported
versions, sizes, flags and malformed requests are rejected before effects;
never reinterpret an extended Continue as ordinary Continue.

## Hold kinds and sequence lifetime

| Value | Kind |
|---:|---|
| 0 | Unknown (also no hold when stopped=0) |
| 1 | Breakpoint |
| 2 | Step |
| 3 | Exception |
| 4 | ModuleLoad |
| 5 | Pause |
| 6 | Resync |

stopSequence is a logical64-bit identity, not a timestamp, address, TID, or
frontend receipt counter. Zero is reserved for unknown/legacy. Every genuinely
new hold gets a never-reused identity within the same VM lifetime, including
immediate stops at the same RIP/TID and stops after TID reuse. A changed kind
or ownership set is a new hold. Do not mint an ID merely on each query.

The owner persists a durable ledger high watermark before publishing issued
identities and continues above it after restart. Restoring guest state must not
roll back the external sequence allocator. On exhaustion or lost durability,
refuse the capability/operation rather than wrap or manufacture proof. If an
old hold can be re-attested from the ledger it retains its identity; uncertain
adoption creates a fresh Resync hold, never an invented internal guard.

A stopped snapshot has either a known kind1..6 with nonzero sequence, or
Unknown/0/flags0 when proof is unavailable. Unknown never permits conditional
continuation. A running snapshot is stopped=0, Unknown/0/flags0. Other mixtures
are malformed. Sequence values remain uint64 in native code and exact strings
if represented in JSON/log tooling; never route them through floating point.

## Internal guard ownership

The only v1 flag is kStopInternalModuleGuard=1. On an extended registration it
marks a frontend-owned internal guard. On a hold/event it means the hold is
EXCLUSIVELY caused by this connection's internal guards, with no coexisting
user stop or foreign connection's hold. It is valid only for ModuleLoad. Reserved flag bits are rejected.

Backend registration identity includes the bound frontend connection/owner,
pattern AND ownership class. The flag is an authoritative per-connection view,
not permission granted by a client-supplied bit; conditional release must verify
that same connection owns the guard. Another connection's internal guard cannot
be released by copying its kind/sequence. A legacy
user pattern and an internal guard of the same name can coexist; removing an
internal pattern must not remove the user pattern. A matching user stop wins:
the emitted hold has flags0, even if an internal guard matches too. A change in
coexisting ownership gets a fresh sequence. This prevents resuming a user stop
merely because its module name happens to match an internal pattern.

## Atomic ContinueIfStopped

Request fields: version=1:uint32, nonzero threadId:uint32,
expected:StopIdentityV1, passException:uint8 and three reserved zero bytes.
Unknown kind or sequence0 is InvalidArgs before effects. passException is0/1
with the same meaning as ordinary Continue; the internal guard path always uses0.

Inside the owner's command serialization/hold lock, atomically compare the
bound process/thread lifetime and all expected identity fields against the
current hold. Only an exact match releases that one hold/thread, using ordinary
Continue's freeze and exception-delivery rules. Other threads remain untouched.
No match/no hold returns InvalidState with NO resume, hold consumption, exception
delivery, register write or memory write. No implicit global continue or retry.

Ok and InvalidState MUST return the complete21-byte response: IpcStatus +
stopped:uint8 + current identity. The snapshot is taken in the same serialized
operation after the decision. Ok attests release of the expected hold, not
instruction execution or that it remained running afterwards. An immediate
restop has a different nonzero identity and its own normal event. A stopped Ok
response with the same expected identity is invalid. Other errors may return a
status only; their state/outcome is not attested.

A query followed by ordinary Continue is NOT an implementation of this contract.
The thread can acquire another hold between those commands. Conditional checks
must be adjacent to the release in the authoritative owner transaction.

## Frontend behavior

On a fully advertising backend, DAP registers its internal guards with v1 and
queries the current hold with the8-byte request. It binds pending function
breakpoints using only loader-safe state/symbol/breakpoint operations: never
execute code or create a target thread while the loader may be locked.

After one bounded binding pass, an owned event can auto-release only when event
and current hold are both the same known ModuleLoad/internal-guard identity and
no stop for that thread has already been exposed to the user. It submits
ContinueIfStopped with that identity, never adopts a different queried identity.
Release is allowed even when binding remains pending, to avoid pinning a loader
forever after a failed binding attempt; breakpoint state remains truthful.

On Ok do not expose the old internal stop or an artificial continued event.
Preserve newer stops/events observed while awaiting the reply. On InvalidState,
do not retry or use ordinary Continue: ignore a now-running old hold, or expose
the current still-stopped thread as pause only if a more specific stop has not
already been exposed. Unknown identities, missing capabilities or legacy
responses keep the existing conservative explicit-resume path.

Malformed/failed/unconfirmed conditional replies never authorize another
continuation. A bounded fresh state query may reconcile whether a visible stop
is still needed; if the state cannot be confirmed, report a diagnostic instead
of inventing a stopped or running result.

## Compatibility and verification

New frontend + old backend uses legacy requests and never auto-releases a guard.
Old frontend + new backend receives exact legacy replies and retains its policy.
MCP's legacy boolean IsThreadStopped requests remain4/5 bytes. No public tool,
batch/action argument, ordinary Continue request or response shape changes.

Host fixtures must exercise matching identities, missing/partial capability,
old layouts, binding failure, same-TID replacement before/during binding and at
the conditional boundary, no current hold, immediate restop before reply,
explicit user module holds with matching names, malformed replies, unknown/zero
identities, and sequences above2^53. Live backend acceptance must additionally
prove ledger durability across owner restart, real loader load/unload progress,
and atomic compare/release under SMP. A synthetic test is not that live proof.
