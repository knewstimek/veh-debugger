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
// Version 2 streams a logical capture through the same fixed-size ring.
// Version 1 layouts and commands remain unchanged.
constexpr uint32_t kStreamVersion = 2;
constexpr uint32_t kMaxStreamSteps = 5000000;
constexpr uint32_t kBufferFull = 8;
#pragma pack(push, 1)
struct HeaderV2 {
    Header base;
    uint64_t recordOffset; // first global instruction index in this immutable chunk
    uint64_t maxSteps;
    uint32_t paused;       // 1 only at BufferFull; explicit acknowledgement resumes
    uint32_t reserved;
};
struct CompactRecord {
    uint64_t address, nextAddress, cr3;
    uint32_t cpu, pid, tid;
    uint8_t addressBits, cpl, codeSize, reserved;
    uint8_t code[16];
};
struct FullRecordV2 { CompactRecord base; uint64_t registers[18]; };
#pragma pack(pop)
static_assert(sizeof(HeaderV2) == 72, "KD streamed header");
static_assert(sizeof(CompactRecord) == 56, "KD compact record");
static_assert(sizeof(FullRecordV2) == 200, "KD streamed snapshot record");
// Portable capture artifact. Exactly records * sizeof(Record) bytes follow.
#pragma pack(push, 1)
struct CaptureFileHeader {
    char magic[8]; // "VEHKDTR2"
    uint32_t version, recordSize;
    uint64_t records, generation;
    uint32_t flags, cpu;
    uint64_t rangeStart, rangeEnd, reserved;
};
#pragma pack(pop)
static_assert(sizeof(CaptureFileHeader) == 64, "KD capture artifact");
} // namespace veh::kdtrace
