#pragma once
#include "ipc_protocol.h"
#include <cstring>
#include <string>
#include <vector>

namespace veh {

inline std::string BackendStatusText(IpcStatus status) {
    switch (status) {
    case IpcStatus::Ok: return "ok";
    case IpcStatus::Error: return "backend execution error";
    case IpcStatus::NotFound: return "requested object or state not found";
    case IpcStatus::InvalidArgs: return "backend rejected arguments";
    case IpcStatus::Unsupported: return "request unsupported by backend";
    case IpcStatus::LimitReached: return "backend resource limit reached";
    default: return "unknown backend status " + std::to_string(static_cast<uint32_t>(status));
    }
}

// A status-only failure is valid even when success requires a larger payload.
inline bool ValidateBackendStatus(const std::vector<uint8_t>& bytes,
    const char* operation, std::string& error) {
    error = std::string(operation) + ": malformed or incomplete backend response";
    if (bytes.size() < sizeof(IpcStatus)) return false;
    IpcStatus status{};
    std::memcpy(&status, bytes.data(), sizeof(status));
    if (status != IpcStatus::Ok) {
        error = std::string(operation) + ": " + BackendStatusText(status);
        return false;
    }
    return true; // caller must validate the complete successful payload
}

inline bool ValidateStackTraceReply(const std::vector<uint8_t>& bytes,
    uint32_t maxFrames, GetStackTraceResponse& header, std::string& error) {
    if (!ValidateBackendStatus(bytes, "GetStackTrace", error)) return false;
    if (bytes.size() < sizeof(header)) return false;
    std::memcpy(&header, bytes.data(), sizeof(header));
    const size_t payloadSize = bytes.size() - sizeof(header);
    if (payloadSize % sizeof(StackFrameInfo) != 0 ||
        header.count != payloadSize / sizeof(StackFrameInfo) ||
        header.count > maxFrames || header.totalFrames < header.count)
        return false;
    for (uint32_t i = 0; i < header.count; ++i) {
        StackFrameInfo frame{};
        std::memcpy(&frame, bytes.data() + sizeof(header) + size_t(i) * sizeof(frame), sizeof(frame));
        if (!std::memchr(frame.moduleName, '\0', sizeof(frame.moduleName)) ||
            !std::memchr(frame.functionName, '\0', sizeof(frame.functionName)) ||
            !std::memchr(frame.sourceFile, '\0', sizeof(frame.sourceFile)))
            return false;
    }
    error.clear();
    return true;
}

} // namespace veh
