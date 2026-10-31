#pragma once
// Standalone KD hardware transport contract. Definitions only: see
// docs/KD_HARDWARE_TRACE_PROTOCOL.md. Existing TraceBB v1/v2 is unchanged.
#include "kd_trace_protocol.h"
#include "trace_hardware_protocol.h"
#include <cstddef>
#include <cstdint>
namespace veh::kdhardware {
inline constexpr uint32_t kVersion = 1;
inline constexpr uint32_t kInstructionCapacity = 4096, kHardwareCapacity = 4096;
inline constexpr uint32_t kMaxSteps = 5000000, kMaxTimeoutMs = 600000;
inline constexpr uint32_t kMaxReplyBytes = 4096, kAllCpusHalted = 1;
inline constexpr uint32_t kInstructionStream = 1, kHardwareStream = 2;
inline constexpr uint32_t kSnapshotFlag = 1, kRunPeerCpusFlag = 2, kFlags = 3;
inline constexpr uint64_t kMaxFileBytes = UINT64_C(4294967296);
enum class End : uint32_t {
    Budget = 1, Range = 2, Interrupted = 3, Exception = 4, CodeUnavailable = 5,
    OtherStop = 6, UnsupportedInstruction = 7, BufferFull = 8,
    CodeUncertain = 9, CompletionUncertain = 10, ScopeExit = 11, FileBudget = 12
};
#pragma pack(push, 1)
struct CapabilitiesV1 {
    uint32_t version = kVersion, headerBytes = 64;
    uint32_t supportedKinds = 0, supportedFlags = 0;
    uint32_t instructionCapacity = kInstructionCapacity, hardwareCapacity = kHardwareCapacity;
    uint32_t maxPerInstruction = hardwaretrace::kMaxPerInstruction, maxSteps = kMaxSteps;
    uint32_t maxTimeoutMs = kMaxTimeoutMs, eventRecordBytes = sizeof(hardwaretrace::EventV1);
    uint64_t maxFileBytes = kMaxFileBytes;
    uint32_t maxReplyBytes = kMaxReplyBytes, fileSchema = hardwaretrace::kSchema;
    uint64_t reserved = 0;
};
struct HeaderV1 {
    uint32_t version = kVersion, status = 0, headerBytes = 192, instructionRecordBytes = 56;
    uint64_t generation = 0, requestId = 0;
    uint32_t cpu = 0, appliedFlags = 0, appliedKinds = 0;
    End end = End::Interrupted;
    uint64_t chunkIndex = 0, instructionOffset = 0, instructionCount = 0,
        hardwareOffset = 0, hardwareCount = 0;
    uint64_t steps = 0, attempts = 0, maxSteps = 0, finalAddress = 0;
    uint64_t retainedHardware = 0, droppedHardware = 0, unknownValueFields = 0, uncertainRecords = 0;
    uint32_t resultFlags = 0;
    hardwaretrace::ScopeExit scopeExit = hardwaretrace::ScopeExit::None;
    uint32_t paused = 0, haltFlags = 0;
    uint64_t reserved[3]{};
};
struct PageV1 {
    uint16_t version = kVersion, headerBytes = 64;
    uint32_t recordBytes = 0;
    uint64_t generation = 0, requestId = 0, chunkIndex = 0, offset = 0;
    uint32_t count = 0, stream = 0;
    uint64_t payloadHash = 0, reserved = 0;
};
struct CaptureFileV1 {
    char magic[8] = {'V','E','H','K','D','H','W','1'};
    uint32_t version = kVersion, headerBytes = 216, recordBytes = 200, reserved = 0;
    HeaderV1 terminal;
};
#pragma pack(pop)
static_assert(sizeof(CapabilitiesV1) == 64 && sizeof(HeaderV1) == 192);
static_assert(sizeof(PageV1) == 64 && sizeof(CaptureFileV1) == 216);
static_assert(offsetof(HeaderV1, generation) == 16 && offsetof(HeaderV1, requestId) == 24);
static_assert(offsetof(HeaderV1, instructionOffset) == 56 && offsetof(HeaderV1, hardwareOffset) == 72);
static_assert(offsetof(HeaderV1, resultFlags) == 152 && offsetof(HeaderV1, scopeExit) == 156);
static_assert(offsetof(HeaderV1, haltFlags) == 164 && offsetof(HeaderV1, reserved) == 168);
static_assert(offsetof(PageV1, payloadHash) == 48 && offsetof(CaptureFileV1, terminal) == 24);

// Negotiation is independent of GetCapabilities and TraceBB policies2.
inline bool ValidCapabilities(const CapabilitiesV1& c) {
    return c.version == kVersion && c.headerBytes == sizeof(c) &&
        !(c.supportedKinds & ~hardwaretrace::kKinds) && !(c.supportedFlags & ~kFlags) &&
        c.instructionCapacity && c.instructionCapacity <= kInstructionCapacity &&
        c.hardwareCapacity >= c.maxPerInstruction && c.hardwareCapacity <= kHardwareCapacity &&
        c.maxPerInstruction && c.maxPerInstruction <= hardwaretrace::kMaxPerInstruction &&
        c.maxSteps && c.maxSteps <= kMaxSteps && c.maxTimeoutMs && c.maxTimeoutMs <= kMaxTimeoutMs &&
        c.eventRecordBytes == sizeof(hardwaretrace::EventV1) && c.fileSchema == hardwaretrace::kSchema &&
        c.maxFileBytes >= 1912 && c.maxFileBytes <= kMaxFileBytes &&
        c.maxReplyBytes >= 2 * (sizeof(PageV1) + sizeof(kdtrace::FullRecordV2)) + 1 &&
        c.maxReplyBytes <= kMaxReplyBytes && !c.reserved;
}
// Structural header checks. The collector must additionally check requested
// flags/kinds/CPU/nonce, negotiated budgets, prior offsets and record contents.
inline bool ValidHeader(const HeaderV1& h) {
    const auto end = static_cast<uint32_t>(h.end);
    const auto scope = static_cast<uint32_t>(h.scopeExit);
    if (h.version != kVersion || h.status != 0 || h.headerBytes != sizeof(h) ||
        !h.generation || !h.requestId || h.cpu >= 64 || (h.appliedFlags & ~kFlags) ||
        !h.appliedKinds || (h.appliedKinds & ~hardwaretrace::kKinds) || end < 1 || end > 12 ||
        h.instructionRecordBytes != ((h.appliedFlags & kSnapshotFlag) ? 200u : 56u) ||
        h.instructionCount > kInstructionCapacity || h.hardwareCount > kHardwareCapacity ||
        !h.maxSteps || h.maxSteps > kMaxSteps || h.steps > h.maxSteps ||
        h.instructionOffset > h.steps || h.instructionCount != h.steps - h.instructionOffset ||
        h.hardwareOffset > h.retainedHardware || h.hardwareCount != h.retainedHardware - h.hardwareOffset ||
        h.attempts < h.steps || h.retainedHardware > UINT32_MAX ||
        h.unknownValueFields > h.retainedHardware * 3 || h.uncertainRecords > h.retainedHardware ||
        (h.resultFlags & ~hardwaretrace::kResultFlags) || !(h.resultFlags & hardwaretrace::kFinalPcValid) ||
        h.haltFlags != kAllCpusHalted || h.reserved[0] || h.reserved[1] || h.reserved[2] ||
        ((h.resultFlags & hardwaretrace::kScopeExit) ? scope < 1 || scope > 5 : scope != 0) ||
        (h.uncertainRecords && !(h.resultFlags & hardwaretrace::kCountLowerBound)) ||
        ((h.resultFlags & hardwaretrace::kNoTargetInstructionAttempted) &&
            (h.steps || h.attempts || h.retainedHardware || h.droppedHardware || h.uncertainRecords ||
             (h.resultFlags & hardwaretrace::kCountLowerBound)))) return false;
    if ((h.end == End::CodeUncertain && !(h.resultFlags & hardwaretrace::kCodeUncertain)) ||
        (h.end == End::CompletionUncertain && !(h.resultFlags & hardwaretrace::kCountLowerBound)) ||
        (h.end == End::ScopeExit && !(h.resultFlags & hardwaretrace::kScopeExit))) return false;
    if (h.end == End::BufferFull)
        return h.paused == 1 && (h.instructionCount || h.hardwareCount) &&
            h.steps < h.maxSteps && h.resultFlags == hardwaretrace::kFinalPcValid &&
            h.droppedHardware == 0 && h.uncertainRecords == 0;
    return h.paused == 0;
}
} // namespace veh::kdhardware
