#pragma once
#include "ipc_protocol.h"

// Detailed caller capture is independent of legacy TraceCallers and
// Instrumentation v1. See docs/CALLER_CAPTURE_PROTOCOL.md for normative rules.
namespace veh::callercapture {
constexpr uint32_t kVersion = 1;
constexpr uint32_t kMaxStackBytes = 4096, kMaxRecords = 65536;
constexpr uint32_t kMaxBufferBytes = 64 * 1024 * 1024, kMaxPageBytes = 65536;
constexpr uint32_t kMaxFilters = 8, kMaxDurationMs = 60000, kRegisterCount = 18;
enum Register : uint32_t { Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rbp, Rsp,
    R8, R9, R10, R11, R12, R13, R14, R15, Rip, Rflags };
constexpr uint32_t kRegisterMask = (1u << kRegisterCount) - 1;
constexpr uint32_t kRequiredRegisters = (1u << Rsp) | (1u << Rip);
enum Feature : uint32_t { Available = 1, Stack = 2, Filters = 4, X86 = 8, X64 = 16,
    Registers = 32, Timestamp = 64, SynchronizedClock = 128 };
constexpr uint32_t kFeatures = 255;
enum class Clock : uint32_t { None = 0, Tsc = 1, MonotonicNs = 2 };
enum class StopReason : uint32_t { Active = 0, User = 1, MaxHits = 2,
    Duration = 3, Buffer = 4, Detached = 5, Error = 6 };
enum CaptureFlag : uint32_t { Active = 1, Incomplete = 2, Overflow = 4 };
enum RecordFlag : uint32_t { CallerValid = 1, TimestampValid = 2 };
enum class StackStatus : uint32_t { NotRequested = 0, Complete = 1, Partial = 2, Unreadable = 3 };

#pragma pack(push, 1)
struct QueryRequest { uint32_t version; };
struct QueryResponse {
    IpcStatus status;
    uint32_t version, features, maxStackBytes, maxRecords, maxBufferBytes,
        maxPageBytes, maxFilters;
    Clock clock;
    uint32_t reserved;
    uint64_t clockFrequency, currentTraceId;
    char provider[32], reason[128];
};
struct Filter {
    uint32_t reg, reserved;
    uint64_t mask, expected; // (register & mask) == expected; AND across filters
};
struct StartRequest {
    uint32_t version, stackBytes, bufferRecords, bufferBytes, durationMs, filterCount;
    uint64_t address, maxHits; // zero maxHits/duration disables that boundary, not both
    InstrumentationDataPolicy dataPolicy;
    InstrumentationTransactionPolicy transactionPolicy;
    Filter filters[kMaxFilters];
};
struct StopRequest { uint32_t version, reserved; uint64_t traceId; };
struct ReadRequest {
    uint32_t version, maxRecords; // zero returns summary; details only after stop
    uint64_t traceId, cursor;
    uint32_t maxBytes, reserved; // entire reply including Response
};
struct Response {
    IpcStatus status;
    uint32_t version, flags;
    StopReason stopReason;
    uint64_t traceId;
    StartRequest config; // exact accepted config, immutable for this capture
    uint64_t cursor, nextCursor, totalRecords, matchedHits, filteredHits, lostRecords;
    uint32_t count, payloadBytes;
    Clock clock;
    uint32_t reserved;
    uint64_t clockFrequency;
};
// Each read appends count records, each immediately followed by stackCaptured
// bytes. No padding. recordBytes includes this header and its stack bytes.
struct Record {
    uint32_t recordBytes, flags;
    uint64_t sequence, timestamp;
    uint32_t pid, tid, cpu, addressBits;
    uint32_t validRegisters;
    StackStatus stackStatus;
    uint32_t stackRequested, stackCaptured;
    uint64_t functionAddress, callerAddress;
    uint64_t registers[kRegisterCount];
};
#pragma pack(pop)
static_assert(sizeof(QueryRequest) == 4);
static_assert(sizeof(QueryResponse) == 216);
static_assert(sizeof(Filter) == 24);
static_assert(sizeof(StartRequest) == 240);
static_assert(sizeof(StopRequest) == 16);
static_assert(sizeof(ReadRequest) == 32);
static_assert(sizeof(Response) == 336);
static_assert(sizeof(Record) == 216);
static_assert(offsetof(Response, config) == 24);
static_assert(offsetof(Record, registers) == 72);
} // namespace veh::callercapture
