#include "debug_session.h"
#include <nlohmann/json.hpp>
#include <utility>

namespace veh {
bool DebugSession::ConnectRemoteWork(uint32_t pid, const ExternalAgent& agent, const LaunchOptions* launch) {
    const std::string scope = agent.vmTarget ? "vm" : agent.guestTarget ? "guest" : "host";
    if (!agent.remote || (agent.vmTarget ? pid != 0 : !launch && pid == 0)) {
        lastAttachError_ = "Invalid remote work selection"; return false;
    }
    if (launch && scope != "host") {
        lastAttachError_ = "Guest/VM process launch is not supported; attach to an existing target"; return false;
    }
    if (!launch && attached_) {
        const auto* current = dynamic_cast<const TcpIpcTransport*>(ipcTransport_.get());
        if (current && current->MatchesWork(*agent.remote, scope, pid) && !Detach()) return false;
    }
    nlohmann::json request{{"backend", agent.remote->backend}, {"operation", launch ? "launch" : "attach"},
        {"target_scope", scope}, {"pid", pid}, {"heartbeat_ms", agent.remote->heartbeatMs}};
    const bool retryingUncertainLaunch = launch && !pendingRemoteRequestId_.empty();
    if (launch) {
        if (launch->program.empty()) { lastAttachError_ = "program is required"; return false; }
        request["launch"] = {{"program", launch->program}, {"args", launch->args}, {"env", launch->env},
            {"cwd", launch->cwd}, {"stopOnEntry", launch->stopOnEntry}, {"runAsInvoker", launch->runAsInvoker}};
        const auto identity = agent.remote->address + ":" + std::to_string(agent.remote->port) + ":" +
            agent.remote->certificateSha256 + ":" + request.dump();
        if (!pendingRemoteRequestId_.empty()) {
            if (identity != pendingRemoteLaunch_ || GetTickCount64() - pendingRemoteLaunchAt_ >= 60000) {
                lastAttachError_ = "Previous remote launch may exist; inspect resident work before another launch"; return false;
            }
        } else {
            pendingRemoteRequestId_ = remote::RandomId();
            pendingRemoteLaunch_ = identity; pendingRemoteLaunchAt_ = GetTickCount64();
        }
        if (pendingRemoteRequestId_.empty()) { lastAttachError_ = "Cannot create remote work identity"; return false; }
        request["request_id"] = pendingRemoteRequestId_;
    }
    auto transport = std::make_unique<TcpIpcTransport>(*agent.remote, request.dump());
    if (!transport->Connect(pid, agent.remote->timeoutMs)) {
        const auto outcome = transport->OpenOutcome();
        if (launch && (outcome == RemoteOpenOutcome::Rejected ||
            (outcome == RemoteOpenOutcome::NotSent && !retryingUncertainLaunch))) {
            pendingRemoteRequestId_.clear(); pendingRemoteLaunch_.clear(); pendingRemoteLaunchAt_ = 0;
        }
        lastAttachError_ = transport->Error(); return false;
    }
    const auto work = transport->Work();
    if (work.scope != scope || (!launch && work.pid != pid)) {
        transport->Disconnect(); lastAttachError_ = "Remote target identity does not match the requested scope"; return false;
    }
    if (launch) { pendingRemoteRequestId_.clear(); pendingRemoteLaunch_.clear(); pendingRemoteLaunchAt_ = 0; }
    // Stage work before replacing the current session; no local PID operations.
    if (attached_) Detach();
    else { StopProcessMonitor(); ipcTransport_->Disconnect(); }
    ipcTransport_ = std::move(transport);
    transportPipe_.clear();
    guestTarget_ = agent.guestTarget; vmTarget_ = agent.vmTarget;
    externalAttachPending_ = true; backendInfo_ = {};
    targetPid_ = work.pid; targetAddressBits_ = work.addressBits;
    targetProcess_ = nullptr; launchedByUs_ = false;
    launchedMainThreadId_ = 0; mainThreadResumed_ = false;
    disassembler_ = CreateDisassembler(work.addressBits != 32);
    attached_ = true; lastAttachError_.clear();
    return true;
}
} // namespace veh
