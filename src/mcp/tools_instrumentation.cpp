#include "mcp_server.h"
#include "tools_common.h"
#include "common/ipc_response_validation.h"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>

namespace veh {
namespace {
bool Number(const json& args, const char* key, uint32_t fallback, uint32_t maximum, uint32_t& out) {
    if (!args.contains(key)) { out = fallback; return true; }
    const auto& value = args[key];
    if (!value.is_number_integer() || value < 0 || value > maximum) return false;
    out = value.get<uint32_t>();
    return true;
}
bool ExactId(const json& args, const char* key, uint64_t& out, bool optional = false) {
    if (!args.contains(key)) { out = 0; return optional; }
    if (!args[key].is_string()) return false;
    const auto text = args[key].get<std::string>();
    if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && (optional || out != 0);
}
template<size_t N> std::string Text(const char (&value)[N]) {
    return std::string(value, std::find(value, value + N, '\0'));
}
json Counter(uint64_t value) {
    return value == UINT64_MAX ? json(nullptr) : json(std::to_string(value));
}
}

json McpServer::ToolInstrumentation(const json& args, InstrumentationKind kind) {
    if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
    const std::string name = kind == InstrumentationKind::DetourCalls ? "detour" : "ptwrite";
    const std::string operation = args.value("operation", "status");
    if (operation != "status" && operation != "start" && operation != "stop" && operation != "read")
        return {{"error", "operation must be status, start, stop or read"}};
    for (const auto* key : {"duration_ms", "duration_sec", "threadId", "buffer_kb"})
        if (args.contains(key)) return {{"error", std::string(key) + " is not an instrumentation option"}};
    if (operation != "start")
        for (const auto* key : {"address", "buffer_records", "data_policy", "transaction_policy", "include_ip"})
            if (args.contains(key)) return {{"error", std::string(key) + " applies only to start"}};
    if (operation != "read" && (args.contains("cursor") || args.contains("max")))
        return {{"error", "cursor and max apply only to read"}};
    if ((operation == "status" || operation == "start") && args.contains("trace_id"))
        return {{"error", "trace_id applies only to read/stop"}};

    const auto& info = session_.GetBackendInfo();
    auto supported = [&](IpcCommand command) { return info.reported && info.Supports(command); };
    auto exchange = [&](IpcCommand command, const void* request, uint32_t size, std::vector<uint8_t>& bytes, json& error) {
        if (!supported(command)) {
            error = {{"error", "Backend does not advertise the instrumentation command"}, {"available", false}};
            return false;
        }
        PipeExchangeDiagnostics diagnostics{};
        if (!session_.GetPipeClient().SendAndReceive(command, request, size, bytes, 3000, &diagnostics)) {
            error = {{"error", session_.DescribeIpcFailure(&diagnostics) + "; operation outcome is unconfirmed"}};
            return false;
        }
        if (bytes.size() < sizeof(IpcStatus)) {
            error = {{"error", "Malformed instrumentation status; outcome is unconfirmed"}}; return false;
        }
        IpcStatus status{}; std::memcpy(&status, bytes.data(), sizeof(status));
        if (status != IpcStatus::Ok) {
            error = {{"error", "Instrumentation: " + BackendStatusText(status)}, {"backendStatus", static_cast<uint32_t>(status)}};
            return false;
        }
        return true;
    };
    QueryInstrumentationResponse query{};
    std::vector<uint8_t> bytes;
    json error;
    if (operation == "status" || operation == "start") {
        if (!supported(IpcCommand::QueryInstrumentation)) {
            if (operation == "status") return {{"kind", name}, {"protocolSupported", false}, {"available", false},
                {"intelPtSupported", nullptr}, {"ptwriteSupported", nullptr},
                {"reason", "Backend does not advertise instrumentation version 1; hardware support is unknown"}};
            return {{"error", "Backend does not advertise instrumentation version 1"}, {"available", false}};
        }
        const QueryInstrumentationRequest request{kInstrumentationVersion, kind};
        if (!exchange(IpcCommand::QueryInstrumentation, &request, sizeof(request), bytes, error)) return error;
        if (bytes.size() != sizeof(query)) return {{"error", "Malformed instrumentation query"}};
        std::memcpy(&query, bytes.data(), sizeof(query));
        if (query.version != kInstrumentationVersion || query.kind != kind || (query.features & ~511u) ||
            query.maxBufferRecords > kInstrumentationMaxRecords || query.maxPageRecords > kInstrumentationMaxPage)
            return {{"error", "Invalid instrumentation version, kind, flags or limits"}};
        if ((query.features & kInstrumentationPtWriteAvailable) &&
            (query.features & (kInstrumentationIntelPt | kInstrumentationPtWrite)) !=
                (kInstrumentationIntelPt | kInstrumentationPtWrite))
            return {{"error", "Inconsistent PTWRITE hardware/collector capability report"}};
        const bool commands = supported(IpcCommand::StartInstrumentation) &&
            supported(IpcCommand::StopInstrumentation) && supported(IpcCommand::ReadInstrumentation);
        const bool available = commands && (query.features & (kind == InstrumentationKind::DetourCalls ?
            kInstrumentationDetourAvailable : kInstrumentationPtWriteAvailable)) &&
            query.maxBufferRecords && query.maxPageRecords;
        if (operation == "status") return {{"kind", name}, {"protocolSupported", true}, {"available", available},
            {"provider", Text(query.provider)}, {"intelPtSupported", bool(query.features & kInstrumentationIntelPt)},
            {"ptwriteSupported", bool(query.features & kInstrumentationPtWrite)},
            {"reason", commands ? (kind == InstrumentationKind::DetourCalls ? Text(query.detourReason) : Text(query.ptWriteReason)) :
                "Backend is missing start/stop/read commands"},
            {"intelPtReason", Text(query.intelPtReason)}, {"maxBufferRecords", query.maxBufferRecords},
            {"maxPageRecords", query.maxPageRecords}, {"policies", {
                {"original", bool(query.features & kInstrumentationOriginal)}, {"patched", bool(query.features & kInstrumentationPatched)},
                {"omit", bool(query.features & kInstrumentationOmit)}, {"rollback", bool(query.features & kInstrumentationRollback)},
                {"includeIp", bool(query.features & kInstrumentationIncludeIp)}}}};
        if (!available) return {{"error", "Requested instrumentation collector is unavailable"}, {"available", false}};
    }

    uint64_t trace = 0, cursor = 0;
    uint32_t maximum = 0;
    StartInstrumentationRequest start{};
    IpcCommand command;
    if (operation == "start") {
        const auto data = args.value("data_policy", "original");
        const auto transaction = args.value("transaction_policy", "omit");
        if (data != "original" && data != "patched") return {{"error", "data_policy must be original or patched"}};
        if (transaction != "omit" && transaction != "rollback") return {{"error", "transaction_policy must be omit or rollback"}};
        if (args.contains("include_ip") && !args["include_ip"].is_boolean()) return {{"error", "include_ip must be boolean"}};
        start.version = kInstrumentationVersion; start.kind = kind;
        start.dataPolicy = data == "patched" ? InstrumentationDataPolicy::Patched : InstrumentationDataPolicy::Original;
        start.transactionPolicy = transaction == "rollback" ? InstrumentationTransactionPolicy::Rollback : InstrumentationTransactionPolicy::Omit;
        start.includeIp = args.value("include_ip", true) ? 1u : 0u;
        if (!Number(args, "buffer_records", std::min(4096u, query.maxBufferRecords), query.maxBufferRecords, start.bufferRecords) || !start.bufferRecords)
            return {{"error", "buffer_records exceeds the advertised limit or is not a positive integer"}};
        const uint32_t required = (data == "original" ? kInstrumentationOriginal : kInstrumentationPatched) |
            (transaction == "omit" ? kInstrumentationOmit : kInstrumentationRollback) |
            (start.includeIp ? kInstrumentationIncludeIp : 0u);
        if ((query.features & required) != required) return {{"error", "Backend cannot guarantee the requested data/transaction/IP policy"}};
        if (kind == InstrumentationKind::DetourCalls) {
            if (!args.contains("address") || !args["address"].is_string() ||
                !ParseAddress(args["address"].get<std::string>(), start.address) || !start.address)
                return {{"error", "A detour function entry address is required"}};
            const auto bits = session_.TargetAddressBits();
            if ((bits != 32 && bits != 64) || (bits == 32 && start.address > UINT32_MAX))
                return {{"error", "Detour address is outside the known target address space"}};
        } else if (args.contains("address")) return {{"error", "PTWRITE collection is passive and does not take an address"}};
        command = IpcCommand::StartInstrumentation;
        if (!exchange(command, &start, sizeof(start), bytes, error)) return error;
    } else {
        if (!ExactId(args, "trace_id", trace) || (operation == "read" &&
            (!ExactId(args, "cursor", cursor, true) || !Number(args, "max", 0, kInstrumentationMaxPage, maximum))))
            return {{"error", "trace_id/cursor must be exact decimal strings; max must be 0-256"}};
        if (operation == "stop") {
            command = IpcCommand::StopInstrumentation;
            const StopInstrumentationRequest request{kInstrumentationVersion, kind, trace};
            if (!exchange(command, &request, sizeof(request), bytes, error)) return error;
        } else {
            command = IpcCommand::ReadInstrumentation;
            const ReadInstrumentationRequest request{kInstrumentationVersion, kind, trace, cursor, maximum};
            if (!exchange(command, &request, sizeof(request), bytes, error)) return error;
        }
    }

    if (bytes.size() < sizeof(InstrumentationResponse)) return {{"error", "Incomplete instrumentation receipt; outcome is unconfirmed"}};
    InstrumentationResponse header{}; std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.version != kInstrumentationVersion || header.kind != kind || !header.traceId ||
        (trace && trace != header.traceId) || (header.flags & ~7u) ||
        static_cast<uint32_t>(header.dataPolicy) > 1 || static_cast<uint32_t>(header.transactionPolicy) > 1 ||
        !header.bufferRecords || header.bufferRecords > kInstrumentationMaxRecords ||
        header.totalRecords > header.bufferRecords || header.cursor != cursor || header.cursor > header.totalRecords ||
        header.count > maximum || header.count > header.totalRecords - header.cursor ||
        (maximum && header.cursor < header.totalRecords && !header.count) ||
        header.nextCursor != header.cursor + header.count ||
        bytes.size() != sizeof(header) + static_cast<size_t>(header.count) * sizeof(InstrumentationRecord) ||
        (operation == "stop" && (header.flags & kInstrumentationActive)) ||
        (header.count && (header.flags & kInstrumentationActive)) ||
        (operation == "start" && (header.dataPolicy != start.dataPolicy ||
            header.transactionPolicy != start.transactionPolicy || header.bufferRecords != start.bufferRecords)))
        return {{"error", "Malformed or inconsistent instrumentation receipt; outcome is unconfirmed"}};
    bool incomplete = (header.flags & (kInstrumentationIncomplete | kInstrumentationOverflow)) || header.lostRecords != 0;
    json records = json::array();
    for (uint32_t i = 0; i < header.count; ++i) {
        InstrumentationRecord record{};
        std::memcpy(&record, bytes.data() + sizeof(header) + i * sizeof(record), sizeof(record));
        if (record.flags & ~3u) return {{"error", "Malformed instrumentation record flags"}};
        if (!(record.flags & kInstrumentationIpValid)) incomplete = true;
        json item = {{kind == InstrumentationKind::PtWrite ? "value" : "functionAddress", HexAddr(record.value)},
            {"instructionAddress", (record.flags & kInstrumentationIpValid) ? json(HexAddr(record.instructionAddress)) : json(nullptr)},
            {"threadId", record.threadId ? json(record.threadId) : json(nullptr)}};
        if (kind == InstrumentationKind::DetourCalls)
            item["callerAddress"] = (record.flags & kInstrumentationCallerValid) ? json(HexAddr(record.callerAddress)) : json(nullptr);
        records.push_back(std::move(item));
    }
    json result = {{"kind", name}, {"trace_id", std::to_string(header.traceId)},
        {"active", bool(header.flags & kInstrumentationActive)}, {"totalRecords", std::to_string(header.totalRecords)},
        {"lostRecords", Counter(header.lostRecords)}, {"incomplete", incomplete},
        {"bufferOverflow", bool(header.flags & kInstrumentationOverflow)},
        {"data_policy", header.dataPolicy == InstrumentationDataPolicy::Original ? "original" : "patched"},
        {"transaction_policy", header.transactionPolicy == InstrumentationTransactionPolicy::Omit ? "omit" : "rollback"},
        {"omittedTransactionalRecords", Counter(header.omittedTransactionalRecords)},
        {"abortedTransactions", Counter(header.abortedTransactions)}, {"bufferRecords", header.bufferRecords},
        {"cursor", std::to_string(header.cursor)}, {"nextCursor", std::to_string(header.nextCursor)},
        {"hasMore", header.nextCursor < header.totalRecords}};
    if (maximum) result["records"] = std::move(records);
    if (header.dataPolicy == InstrumentationDataPolicy::Patched)
        result["warning"] = "Target data reads may see E9/detour patch bytes; integrity checks and self-code reads can change";
    return result;
}
} // namespace veh
