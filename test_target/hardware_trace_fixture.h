// Synthetic host-only wire fixtures for frontend contract tests.
#include "trace_hardware_protocol.h"

bool hardwareCapabilities(HANDLE pipe, uint32_t command, const std::wstring& mode) {
    veh::hardwaretrace::CapabilitiesV1 caps;
    caps.baseRequestBytes = veh::kTraceBasicBlocksRequestV10Size;
    caps.supportedKinds = 7;
    caps.modeFlags = 0x103;
    if (mode == L"hardware-legacy") return reply(pipe, command, veh::IpcStatus::Unsupported);
    if (mode == L"hardware-zero") caps.supportedKinds = 0;
    if (mode == L"hardware-partial-kinds") caps.supportedKinds = 1;
    if (mode == L"hardware-version") caps.version = 2;
    if (mode == L"hardware-size") caps.baseRequestBytes++;
    if (mode == L"hardware-reserved") caps.reserved[1] = 1;
    if (mode == L"hardware-user-only") caps.modeFlags = 0x101;
    if (mode == L"hardware-budget") caps.maxSteps = 1;
    if (mode == L"hardware-cap-short") return send(pipe, command, &caps, sizeof(caps) - 1);
    return reply(pipe, command, caps);
}

bool hardwareCapture(HANDLE pipe, uint32_t command, const std::vector<unsigned char>& bytes,
    const std::wstring& mode) {
    namespace ht = veh::hardwaretrace;
    ht::RequestV1 envelope;
    veh::TraceBasicBlocksRequest request{};
    if (bytes.size() != sizeof(envelope) + veh::kTraceBasicBlocksRequestV10Size)
        return reply(pipe, command, veh::IpcStatus::InvalidArgs);
    std::memcpy(&envelope, bytes.data(), sizeof(envelope));
    std::memcpy(&request, bytes.data() + sizeof(envelope), veh::kTraceBasicBlocksRequestV10Size);
    if (envelope.version != 1 || envelope.headerBytes != sizeof(envelope) ||
        envelope.baseRequestBytes != veh::kTraceBasicBlocksRequestV10Size ||
        !envelope.kinds || (envelope.kinds & ~7u) || envelope.reserved0 || envelope.reserved1 ||
        request.wireVersion != 10 || request.requestSize != veh::kTraceBasicBlocksRequestV10Size ||
        request.eventOutputMode != 1 || !request.collectEvents || request.collectionFlags ||
        request.maxSteps > 5000000 || request.timeoutMs > 1800000)
        return reply(pipe, command, veh::IpcStatus::InvalidArgs);
    std::vector<unsigned char> records;
    uint64_t count = 0, unknown = 0, uncertain = 0;
    const unsigned iterations = mode == L"hardware-many" ? 75 : 3;
    for (unsigned i = 0; i < iterations; ++i) {
        unsigned kind = i % 3;
        if (!(envelope.kinds & (1u << kind))) continue;
        ht::EventV1 e;
        e.sequence = i + 1; e.attempt = UINT64_C(9007199254740993) + i;
        e.instruction = request.rangeStart + i;
        e.threadId = request.threadId; e.cpu = 0;
        e.kind = static_cast<ht::Kind>(kind + 1);
        e.operation = kind == 2 ? ht::Operation::Read : ht::Operation::Write;
        e.cplBefore = 0; e.cplAfter = 0; e.width = kind == 2 ? 1 : 8;
        e.known = ht::Value | ht::Thread | ht::Cpu | ht::Step | ht::Pc | ht::CplAfter;
        if (kind == 0) {
            e.subject = 3; e.value = 0x12345005; e.before = 0x11111001; e.after = 0x22222002;
            e.known |= ht::Before | ht::After;
        } else if (kind == 1) { e.subject = 0xC0000082; e.value = UINT64_C(0xFFFF800000002000); }
        else { e.subject = 0x80; e.value = 0; }
        if (mode == L"hardware-uncertain" && i == 2) {
            e.sequence = 0; e.known &= ~ht::Step; e.completion = ht::Completion::Uncertain; ++uncertain;
        }
        if (mode == L"hardware-code") e.flags = 1;
        if (mode == L"hardware-bad-known" && i == 1) { e.value = 9; e.known &= ~ht::Value; }
        if (mode == L"hardware-bad-index" && i == 1) e.eventIndex = 2;
        if (!(e.known & ht::Value)) ++unknown;
        if (!(e.known & ht::Before)) ++unknown;
        if (!(e.known & ht::After)) ++unknown;
        veh::TraceEventArtifactRecordHeader record{4, 0, sizeof(e)};
        const size_t offset = records.size(); records.resize(offset + sizeof(record) + sizeof(e));
        std::memcpy(records.data() + offset, &record, sizeof(record));
        std::memcpy(records.data() + offset + sizeof(record), &e, sizeof(e)); ++count;
    }
    // Connect only after the frontend has created the receiver and sent the request.
    // Use the shared canonical pipe name; its token uses a fixed hex encoding.
    const std::wstring actualName = veh::GetTraceEventPipeName(request.eventStreamOwnerPid, request.eventStreamToken);
    HANDLE stream = CreateFileW(actualName.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (stream == INVALID_HANDLE_VALUE) return reply(pipe, command, veh::IpcStatus::Error);
    veh::TraceEventStreamFrameHeader frame{};
    frame.magic = veh::kTraceEventStreamMagic; frame.schemaVersion = 3; frame.token = request.eventStreamToken;
    frame.type = 1; frame.payloadSize = static_cast<uint32_t>(records.size());
    frame.payloadHash = veh::TraceEventPayloadHash(records.data(), records.size());
    if (mode == L"hardware-bad-hash") frame.payloadHash++;
    if (mode == L"hardware-bad-token") frame.token++;
    if (mode == L"hardware-bad-offset") frame.streamOffset = 1;
    bool ok = transfer(stream, true, &frame, sizeof(frame)) &&
        transfer(stream, true, records.data(), static_cast<DWORD>(records.size()));
    if (mode != L"hardware-raw-error") {
        struct Complete { veh::TraceEventStreamComplete base; uint64_t hardware; } complete{};
        static_assert(sizeof(complete) == 64);
        complete.base.committedRecordBytes = records.size(); complete.base.chunkCount = 1;
        complete.hardware = count;
        if (mode == L"hardware-bad-count") complete.hardware++;
        frame.type = 2; frame.chunkIndex = 1; frame.streamOffset = records.size();
        frame.payloadSize = sizeof(complete); frame.payloadHash = veh::TraceEventPayloadHash(&complete, sizeof(complete));
        ok = ok && transfer(stream, true, &frame, sizeof(frame)) && transfer(stream, true, &complete, sizeof(complete));
        if (mode == L"hardware-trailing") { unsigned char extra = 1; transfer(stream, true, &extra, 1); }
    }
    // Drain buffered writes before closing, including the connect/read race.
    FlushFileBuffers(stream);
    CloseHandle(stream);
    if (!ok) return reply(pipe, command, veh::IpcStatus::Error);
    if (mode == L"hardware-raw-error") return reply(pipe, command, veh::IpcStatus::Error);
    veh::TraceBasicBlocksResponse base{};
    base.status = veh::IpcStatus::Ok; base.headerSize = sizeof(base);
    base.threadId = request.threadId; base.stepsExecuted = iterations - uncertain;
    base.finalAddress = request.rangeStart + iterations;
    base.stopReason = mode == L"hardware-maxsteps" ? veh::TraceBasicBlockStopReason::MaxSteps :
        veh::TraceBasicBlockStopReason::LeftRange;
    base.eventCollectionEnabled = 1; base.eventSchemaVersion = 1; base.returnSnapshot = UINT32_MAX;
    ht::ResponseV1 response;
    response.status = 0; response.baseResponseBytes = sizeof(base); response.appliedKinds = envelope.kinds;
    response.retainedRecords = count; response.unknownValueFields = unknown;
    response.uncertainRecords = uncertain; response.resultFlags = ht::kFinalPcValid;
    if (mode == L"hardware-uncertain") response.resultFlags |= ht::kCountLowerBound;
    if (mode == L"hardware-code") response.resultFlags |= ht::kCodeUncertain;
    if (mode == L"hardware-unsupported") response.resultFlags |= ht::kUnsupportedAtPc;
    if (mode == L"hardware-unknown-loss") response.droppedRecords = UINT64_MAX;
    if (mode == L"hardware-bad-applied") response.appliedKinds = 0;
    if (mode == L"hardware-no-pc") response.resultFlags = 0;
    if (mode == L"hardware-unknown-flags") response.resultFlags |= 64;
    if (mode == L"hardware-envelope-reserved") response.reserved1 = 1;
    if (mode.size() == 16 && mode.rfind(L"hardware-scope-", 0) == 0) {
        response.resultFlags |= ht::kScopeExit;
        response.scopeExit = static_cast<ht::ScopeExit>(std::stoul(mode.substr(15)));
    }
    if (mode == L"hardware-bad-scope-zero") response.resultFlags |= ht::kScopeExit;
    if (mode == L"hardware-bad-scope-unflagged") response.scopeExit = ht::ScopeExit::AddressSpace;
    if (mode == L"hardware-bad-scope-value") { response.resultFlags |= ht::kScopeExit; response.scopeExit = static_cast<ht::ScopeExit>(6); }
    if (mode == L"hardware-scope-priority") {
        response.resultFlags |= ht::kScopeExit | ht::kCodeUncertain | ht::kUnsupportedAtPc | ht::kCountLowerBound;
        response.scopeExit = ht::ScopeExit::AddressSpace;
    }
    if (mode == L"hardware-export-fail") {
        wchar_t directory[MAX_PATH]{};
        GetEnvironmentVariableW(L"TEMP", directory, MAX_PATH);
        const std::wstring destination = std::wstring(directory) + L"\\export-collision.json";
        HANDLE collision = CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
        if (collision != INVALID_HANDLE_VALUE) CloseHandle(collision);
    }
    #pragma pack(push, 1)
    struct PackedResult { ht::ResponseV1 hardware; veh::TraceBasicBlocksResponse base; } result{response, base};
    #pragma pack(pop)
    return reply(pipe, command, result);
}
