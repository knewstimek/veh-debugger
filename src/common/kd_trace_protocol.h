#pragma once
// Optional RSP bounded basic-block capture, version 1. All fields are packed
// little-endian. Collection belongs to the stopped-machine backend, never a
// frontend loop over single-step or memory-read requests.
#include <stdint.h>
namespace veh::kdtrace {
constexpr uint32_t kVersion = 1;
constexpr uint32_t kCapacity = 4096;
constexpr uint32_t kSnapshots = 1;
enum End : uint32_t { Budget = 1, Range = 2, Interrupted = 3, Exception = 4,
    CodeUnavailable = 5, OtherStop = 6, UnsupportedInstruction = 7 };
#pragma pack(push, 1)
struct Header {
    uint32_t version, recordSize;
    uint64_t generation;
    uint32_t count, steps, end, flags;
    uint64_t finalAddress;
    uint32_t cpu, reserved;
};
struct Record {
    uint64_t address, nextAddress, cr3;
    // rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15, rip, rflags.
    // Zero when kSnapshots is absent; address/nextAddress always remain present.
    uint64_t registers[18];
    uint32_t cpu, pid, tid;
    uint8_t addressBits, cpl, codeSize, reserved;
    uint8_t code[16];
};
#pragma pack(pop)
static_assert(sizeof(Header) == 48, "KD trace header");
static_assert(sizeof(Record) == 200, "KD trace record");
} // namespace veh::kdtrace
