# Kernel exception stops

An optional version 1 GDB RSP extension distinguishes a held guest exception from
a completed debugger step. Process IPC is unchanged.

Example:

    T0bthread:1;stepmeta:1;reason:exception;progress:fault;vector:e;xerror:5;xaddress:ffffffffffffffff;

Fields follow the ordinary signal and thread fields:

| Field | Contract |
|---|---|
| stepmeta | Literal 1; consumers must not infer another version's progress semantics |
| reason | exception |
| progress | fault, trap, partial, or unknown |
| vector | Unsigned exception vector in hexadecimal, at most ff |
| xerror | Optional unsigned architectural error code in hexadecimal, at most ffffffff; presence distinguishes an error code of zero |
| xaddress | Fault address in hexadecimal; required for a page-fault vector e |

All added field names begin with a non-hex digit, so legacy GDB consumers can
ignore them instead of confusing them with expedited registers. The shared
constants are in src/common/kd_stop_protocol.h.

A fault has not retired the faulting instruction. Partial effects may exist;
partial explicitly reports known progress without a completed instruction.
A trap follows a retired instruction, even when its saved/normalized PC equals
the instruction address. Unknown makes no completion claim. Entry attempts and
PC changes are not completion evidence.

veh_kd_step stops its batch on an exception. It reports confirmed earlier steps,
adds one only for a validated trap, and returns structured stop metadata. Fault,
partial, unknown and malformed metadata add zero steps. A non-trap legacy signal
also stops the batch without claiming completion. Legacy ordinary trap stops
retain their previous single-step behavior.

Exception metadata describes a still-held guest delivery. Ordinary continue
preserves that delivery; it does not implement an exception-suppression command.
The provider must preserve the original vector, error code, fault address and
software-event instruction length, and remove only its own execution-control
state before the guest's exception frame is built. Hardware exception stops and
Windows user-mode exception records are separate observation phases.

Whole-machine KD execution remains direct-only: it can stop or resume every CPU
and is excluded from generic batches, capture setup and process breakpoint
actions. A step request's count is still bounded by the first exception stop.
