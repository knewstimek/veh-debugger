#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

// Packed little-endian hardware instruction trace v1. Independent of host width.
// The base request remains wire10; collectionFlags is never appended.
namespace veh::hardwaretrace {
inline constexpr uint16_t kVersion = 1, kBaseWireVersion = 10;
inline constexpr uint32_t kSchema = 3, kMaxPerInstruction = 16;
inline constexpr uint32_t kControl = 1, kMsr = 2, kPort = 4, kKinds = 7;
inline constexpr uint32_t kHasHardware = 4;
inline constexpr uint32_t kUser = 1, kKernel = 2, kSingleCpu = 0x100;
inline constexpr uint32_t kFinalPcValid = 1, kCountLowerBound = 2, kUnsupportedAtPc = 4,
    kNoTargetInstructionAttempted = 8, kCodeUncertain = 16, kScopeExit = 32, kResultFlags = 63;
enum class ScopeExit : uint32_t { None = 0, AddressSpace = 1, Cpl = 2, Thread = 3,
    RipRange = 4, IdentityUnavailable = 5 };
enum class Kind : uint8_t { ControlRegister = 1, Msr = 2, Port = 3 };
enum class Operation : uint8_t { Read = 1, Write = 2 };
enum class Completion : uint8_t { Confirmed = 1, Uncertain = 2 };
enum Known : uint16_t { Value = 1, Before = 2, After = 4, Thread = 8,
    Cpu = 16, Step = 32, Pc = 64, CplAfter = 128 };
#pragma pack(push, 1)
struct CapabilitiesV1 {
    uint32_t status = 0;
    uint16_t version = kVersion, headerBytes = 64;
    uint32_t supportedKinds = 0, maxPerInstruction = kMaxPerInstruction;
    uint16_t baseWireVersion = kBaseWireVersion, baseRequestBytes = 0;
    uint32_t fileSchema = kSchema, maxSteps = 5000000, eventChunkBytes = 262144;
    uint64_t maxFileBytes = UINT64_C(4294967296);
    uint32_t maxTimeoutMs = 1800000, modeFlags = 0;
    uint64_t reserved[2]{};
};
struct RequestV1 {
    uint16_t version = kVersion, headerBytes = 32;
    uint32_t baseRequestBytes = 0, kinds = 0, fileSchema = kSchema,
        maxPerInstruction = kMaxPerInstruction;
    uint32_t reserved0 = 0;
    uint64_t reserved1 = 0;
};
struct ResponseV1 {
    uint32_t status = 1;
    uint16_t version = kVersion, headerBytes = 64;
    uint32_t baseResponseBytes = 0, appliedKinds = 0;
    uint64_t retainedRecords = 0, droppedRecords = 0, unknownValueFields = 0,
        uncertainRecords = 0;
    uint32_t resultFlags = 0;
    ScopeExit scopeExit = ScopeExit::None;
    uint64_t reserved1 = 0;
};
struct EventV1 {
    uint64_t sequence = 0, attempt = 0, instruction = 0, subject = 0,
        value = 0, before = 0, after = 0;
    uint32_t eventIndex = 0;
    uint8_t cplBefore = 0, cplAfter = 255;
    uint16_t reserved = 0;
    uint32_t threadId = 0;
    uint16_t cpu = 0;
    Kind kind = Kind::ControlRegister;
    Operation operation = Operation::Read;
    uint8_t width = 8;
    Completion completion = Completion::Confirmed;
    uint16_t known = 0;
    uint32_t flags = 0;
};
#pragma pack(pop)
static_assert(sizeof(CapabilitiesV1) == 64 && sizeof(RequestV1) == 32 && sizeof(ResponseV1) == 64);
static_assert(offsetof(ResponseV1, resultFlags) == 48 && offsetof(ResponseV1, scopeExit) == 52 &&
    offsetof(ResponseV1, reserved1) == 56);
static_assert(sizeof(EventV1) == 80 && offsetof(EventV1, threadId) == 64 &&
    offsetof(EventV1, known) == 74 && offsetof(EventV1, flags) == 76);
static_assert(std::is_trivially_copyable_v<EventV1>);

inline bool ValidEvent(const EventV1& e) {
    if (!e.attempt || e.eventIndex >= kMaxPerInstruction || e.reserved ||
        (e.known & ~255u) || (e.flags & ~1u) || e.cplBefore > 3 ||
        !(e.known & Cpu) || !(e.known & Pc) ||
        ((e.known & CplAfter) ? e.cplAfter > 3 : e.cplAfter != 255) ||
        ((e.known & Thread) ? !e.threadId : e.threadId != 0) ||
        (!(e.known & Value) && e.value) || (!(e.known & Before) && e.before) ||
        (!(e.known & After) && e.after)) return false;
    if (e.completion == Completion::Confirmed) {
        if (!(e.known & Step) || !e.sequence || !(e.known & Value)) return false;
    } else if (e.completion == Completion::Uncertain) {
        if ((e.known & Step) || e.sequence) return false;
    } else return false;
    if (e.operation != Operation::Read && e.operation != Operation::Write) return false;
    if (e.kind == Kind::Msr) return e.width == 8 && e.subject <= UINT32_MAX;
    if (e.kind == Kind::ControlRegister) return (e.width == 4 || e.width == 8) &&
        (e.subject == 0 || e.subject == 2 || e.subject == 3 || e.subject == 4 || e.subject == 8);
    if (e.kind != Kind::Port || e.subject > UINT16_MAX ||
        (e.width != 1 && e.width != 2 && e.width != 4) || (e.known & (Before | After))) return false;
    return e.value < (UINT64_C(1) << (e.width * 8));
}

// A bounded validator: no allocation and no target access. Uncertain attempts
// can only appear at the tail; never infer completion from their side effects.
class EventValidator {
public:
    bool Accept(const EventV1& e) {
        if (!ValidEvent(e)) return false;
        if (seen_) {
            if (e.attempt < last_.attempt || (uncertain_ && e.attempt != last_.attempt)) return false;
            if (e.attempt == last_.attempt) {
                if (e.eventIndex != last_.eventIndex + 1 || e.sequence != last_.sequence ||
                    e.completion != last_.completion || e.instruction != last_.instruction ||
                    e.cpu != last_.cpu || e.threadId != last_.threadId ||
                    e.cplBefore != last_.cplBefore) return false;
            } else if (e.eventIndex || (e.sequence && e.sequence <= lastSequence_)) return false;
        } else if (e.eventIndex) return false;
        last_ = e; seen_ = true;
        if (e.sequence) lastSequence_ = e.sequence;
        uncertain_ = e.completion == Completion::Uncertain;
        ++counts[static_cast<unsigned>(e.kind) - 1];
        if (uncertain_) ++uncertainRecords;
        if (!(e.known & Value)) ++unknownValueFields;
        if (!(e.known & Before)) ++unknownValueFields;
        if (!(e.known & After)) ++unknownValueFields;
        if (e.flags & 1) codeUncertain = true;
        appliedKinds |= 1u << (static_cast<unsigned>(e.kind) - 1);
        return true;
    }
    uint64_t counts[3]{}, uncertainRecords = 0, unknownValueFields = 0;
    uint64_t LastSequence() const { return lastSequence_; }
    uint32_t appliedKinds = 0;
    bool codeUncertain = false;
private:
    EventV1 last_{};
    uint64_t lastSequence_ = 0;
    bool seen_ = false, uncertain_ = false;
};
} // namespace veh::hardwaretrace
