#pragma once
// Optional GDB RSP exception-stop metadata, version 1. Unknown named fields are
// ignored by legacy clients. Names begin with a non-hex digit (not registers).
// See docs/KERNEL_EXCEPTION_STOPS.md. This is independent of process IPC wire.
namespace veh::kdstop {
constexpr const char* kVersion="1";
constexpr const char* kFault="fault";   // faulting instruction has not retired
constexpr const char* kTrap="trap";     // instruction retired before its exception
constexpr const char* kPartial="partial"; // partial progress, not a completed instruction
constexpr const char* kUnknown="unknown"; // no completion claim
} // namespace veh::kdstop
