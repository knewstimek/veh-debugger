#include "tcp_ipc_transport.h"
#include "common/startup_diagnostics.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <utility>
#include <cstdio>

namespace veh {
namespace {
void AppendStartupDiagnostics(std::string& error, const nlohmann::json& reply) {
    const auto item = reply.find("diagnostics");
    if (item == reply.end() || !item->is_object()) return;
    const auto stageItem = item->find("stage");
    if (stageItem == item->end() || !stageItem->is_string()) return;
    const auto& stage = stageItem->get_ref<const std::string&>();
    constexpr const char* stages[] = {"validation", "work_setup", "target_create", "target_job",
        "target_open", "target_metadata", "agent_start", "agent_job", "agent_resume",
        "agent_pipe", "agent_ready", "capabilities", "target_info", "startup_deadline",
        "target_resume", "agent_watch", "agent_bind"};
    bool known = false;
    for (const auto* candidate : stages) if (stage == candidate) known = true;
    if (!known) return; // Never echo arbitrary remote text, paths or backend logs.
    auto number = [&](const char* key, uint32_t& value) {
        const auto field = item->find(key);
        if (field == item->end() || !field->is_number_unsigned() || field->get<uint64_t>() > UINT32_MAX) return false;
        value = field->get<uint32_t>(); return true;
    };
    uint32_t exitCode = 0, systemError = 0;
    const bool exited = number("agent_exit_code", exitCode);
    const bool systemFailure = number("system_error", systemError);
    if (exited) error = "Remote backend agent exited during startup";
    error += " [stage=" + stage;
    if (exited) {
        char hex[16]{};
        snprintf(hex, sizeof(hex), "0x%08lX", static_cast<unsigned long>(exitCode));
        error += ", agent_exit_code=" + std::to_string(exitCode) + " (" + hex + ")";
    }
    if (systemFailure) error += ", win32_error=" + std::to_string(systemError);
    uint32_t kind = 0, detail = 0, backendSystemError = 0;
    StartupDiagnostic diagnostic;
    if (number("startup_error", kind) && number("startup_detail", detail)) {
        diagnostic.error = static_cast<StartupError>(kind);
        diagnostic.detail = static_cast<StartupDetail>(detail);
        if (ValidStartupDiagnostic(diagnostic)) {
            error += ", error=" + std::string(StartupErrorName(diagnostic.error));
            error += ", detail=" + std::string(StartupDetailName(diagnostic.detail));
            if (number("backend_system_error", backendSystemError))
                error += ", backend_win32_error=" + std::to_string(backendSystemError);
        }
    }
    error += "]";
    // A remote attach opens the new work before releasing the current one.
    if (diagnostic.detail == StartupDetail::BackendBusy && ValidStartupDiagnostic(diagnostic))
        error += "; the backend serves one session at a time: detach the current session first";
}
}
TcpIpcTransport::TcpIpcTransport(RemoteEndpoint endpoint, std::string openRequest)
    : endpoint_(std::move(endpoint)), openRequest_(std::move(openRequest)) {}

bool TcpIpcTransport::Connect(uint32_t, int timeoutMs) {
    error_ = "Remote connection or authentication failed";
    openOutcome_ = RemoteOpenOutcome::NotSent;
    const int budget = std::clamp(std::min(timeoutMs, endpoint_.timeoutMs), 100, 30000);
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(budget);
    auto remaining = [&]() -> int {
        const auto now = GetTickCount64();
        return now < deadline ? static_cast<int>(deadline - now) : 0;
    };
    if (openRequest_.size() > 65536 || !channel_.Connect(endpoint_.address, endpoint_.port,
        endpoint_.certificateSha256, remaining()) ||
        !remote::AuthenticateClient(channel_, endpoint_.tokenFile, remaining())) {
        channel_.Close(); return false;
    }
    // A failed write can still have delivered the complete OpenWork request.
    openOutcome_ = RemoteOpenOutcome::Unknown;
    error_ = "Remote work open result unknown; check resident work before repeating launch";
    if (!remote::WriteControl(channel_, remote::Control::OpenWork, openRequest_.data(),
            static_cast<uint32_t>(openRequest_.size()), remaining())) {
        channel_.Close(); return false;
    }
    std::vector<uint8_t> bytes;
    if (!remote::ReadControl(channel_, remote::Control::Work, bytes, remaining())) {
        error_ = "Remote work open result unknown; check resident work before repeating launch";
        channel_.Close(); return false;
    }
    try {
        auto reply = nlohmann::json::parse(bytes);
        if (!reply.at("success").is_boolean()) throw std::invalid_argument("metadata");
        if (!reply.at("success").get<bool>()) {
            // Validate the complete rejection before clearing duplicate-launch protection.
            const auto code = reply.at("code").get<std::string>();
            if (code != "unsupported" && code != "busy" && code != "expired" &&
                code != "invalid" && code != "unavailable") throw std::invalid_argument("metadata");
            // Older/ambiguous replies must not clear duplicate-launch protection.
            if (reply.contains("outcome_unknown") && reply.at("outcome_unknown").is_boolean() &&
                !reply.at("outcome_unknown").get<bool>()) openOutcome_ = RemoteOpenOutcome::Rejected;
            // Server sends fixed reason codes, never exception text or credentials.
            if (code == "unsupported") error_ = "Remote backend does not implement this operation";
            else if (code == "busy") error_ = "Remote work already has an active connection";
            else if (code == "expired") error_ = "Remote work expired or requires a fresh attachment";
            else error_ = "Remote work could not be opened";
            AppendStartupDiagnostics(error_, reply);
            channel_.Close(); return false;
        }
        work_.id = reply.at("work_id").get<std::string>();
        work_.scope = reply.at("target_scope").get<std::string>();
        for (const char* key : {"pid", "address_bits"}) {
            if (!reply.at(key).is_number_unsigned() || reply.at(key).get<uint64_t>() > UINT32_MAX)
                throw std::invalid_argument("metadata");
        }
        if (!reply.at("outcome_unknown").is_boolean()) throw std::invalid_argument("metadata");
        work_.pid = reply.at("pid").get<uint32_t>();
        work_.addressBits = reply.at("address_bits").get<uint32_t>();
        work_.mainThreadId = 0; // absent metadata from an older peer must not retain an earlier ID
        if (const auto initial = reply.find("main_thread_id"); initial != reply.end()) {
            if (work_.scope != "host" || !initial->is_number_unsigned() ||
                initial->get<uint64_t>() == 0 || initial->get<uint64_t>() > UINT32_MAX)
                throw std::invalid_argument("metadata");
            work_.mainThreadId = initial->get<uint32_t>();
        }
        work_.outcomeUnknown = reply.at("outcome_unknown").get<bool>();
        if (!remaining() || work_.id.size() != 64 || !std::all_of(work_.id.begin(), work_.id.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }) || (work_.scope != "host" && work_.scope != "guest" && work_.scope != "vm") ||
            (work_.scope == "vm" ? work_.pid != 0 || work_.addressBits != 0 :
                !work_.pid || (work_.addressBits != 32 && work_.addressBits != 64))) {
            channel_.Close(); return false;
        }
    } catch (...) { channel_.Close(); return false; }
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) { channel_.Close(); return false; }
    { std::lock_guard<std::mutex> lock(readyMutex_); readyReceived_ = false; }
    lastRecvTime_ = GetTickCount64();
    connected_ = true;
    openOutcome_ = RemoteOpenOutcome::Opened;
    error_.clear();
    return true;
}
bool TcpIpcTransport::MatchesWork(const RemoteEndpoint& endpoint, const std::string& scope, uint32_t pid) const {
    return endpoint_.address == endpoint.address && endpoint_.port == endpoint.port &&
        endpoint_.certificateSha256 == endpoint.certificateSha256 && endpoint_.backend == endpoint.backend &&
        endpoint_.tokenFile == endpoint.tokenFile && work_.scope == scope && work_.pid == pid;
}
bool TcpIpcTransport::WaitForWorkClose(int timeoutMs, IpcCommand finalCommand, IpcStatus* acknowledgement) {
    if (acknowledgement) *acknowledgement = IpcStatus::Error;
    if (timeoutMs <= 0) return false;
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    auto remaining = [&]() -> int {
        const auto now = GetTickCount64();
        return now < deadline ? static_cast<int>(deadline - now) : 0;
    };
    for (;;) {
        IpcHeader header{};
        const int budget = remaining();
        if (!budget) return false;
        // stopEvent_ belongs to the stopped reader. This final drain waits for
        // the resident to retire work and close, not for that local stop signal.
        if (!channel_.Read(&header, sizeof(header), budget)) return GetLastError() == ERROR_BROKEN_PIPE;
        if (header.payloadSize > 64 * 1024 * 1024) return false;
        // The resident relays the backend's Detach/Shutdown status before closing
        // (older residents close without it, which stays unconfirmed).
        if (header.command == static_cast<uint32_t>(finalCommand) && header.payloadSize == sizeof(IpcStatus)) {
            IpcStatus status{};
            const int statusBudget = remaining();
            if (!statusBudget || !channel_.Read(&status, sizeof(status), statusBudget)) return false;
            if (acknowledgement) *acknowledgement = status;
            continue;
        }
        uint8_t buffer[4096];
        auto left = header.payloadSize;
        while (left) {
            const auto count = std::min<uint32_t>(left, sizeof(buffer));
            const int payloadBudget = remaining();
            if (!payloadBudget || !channel_.Read(buffer, count, payloadBudget)) return false;
            left -= count;
        }
    }
}
void TcpIpcTransport::Disconnect() {
    channel_.Cancel();
    PipeClient::Disconnect();
    channel_.Close();
}
bool TcpIpcTransport::AsyncReadExact(void* data, DWORD size, DWORD timeoutMs) {
    return channel_.Read(data, size, static_cast<int>(timeoutMs), stopEvent_);
}
bool TcpIpcTransport::AsyncWriteExact(const void* data, DWORD size, DWORD timeoutMs) {
    return channel_.Write(data, size, static_cast<int>(timeoutMs));
}
void TcpIpcTransport::CancelPendingIo() {
    // StopEventListener signals stopEvent_; Channel::Read checks it every 100ms.
    // Preserve the write side so DebugSession can send its final Detach frame.
}
} // namespace veh
