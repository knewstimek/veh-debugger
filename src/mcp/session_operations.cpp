#include "mcp_server.h"
#include "tools_common.h"
#include "common/ipc_response_validation.h"
#include <algorithm>
#include <chrono>
#include <limits>
#include <sstream>

namespace veh {
namespace {
constexpr size_t kMaxFreezeJobs = 16;
constexpr size_t kMaxFreezeBytes = 64;
bool FreezeActive(const std::string& state) { return state == "active"; }
bool ExactUnsigned(const json& args, const char* key, uint64_t low, uint64_t high, uint64_t& value) {
    if (!args.contains(key)) return false;
    const auto& item = args[key];
    if (!item.is_number_integer() || item < 0 || item > high) return false;
    value = item.get<uint64_t>();
    return value >= low;
}
bool Bytes(const std::string& text, std::vector<uint8_t>& bytes) {
    if (text.empty() || text.size() > kMaxFreezeBytes * 3) return false;
    int high = -1;
    for (unsigned char ch : text) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
        const int digit = ch >= '0' && ch <= '9' ? ch - '0' :
            ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (digit < 0) return false;
        if (high < 0) high = digit;
        else { bytes.push_back(static_cast<uint8_t>((high << 4) | digit)); high = -1; }
    }
    return high < 0 && !bytes.empty() && bytes.size() <= kMaxFreezeBytes;
}
bool ReportedCommands(const DebugSession::BackendInfo& info, std::initializer_list<IpcCommand> commands) {
    return info.reported && std::all_of(commands.begin(), commands.end(),
        [&](IpcCommand command) { return info.Supports(command); });
}
}

thread_local McpServer::OperationAdmission* McpServer::currentAdmission_ = nullptr;
McpServer::OperationAdmission::OperationAdmission(McpServer& owner, bool tryOnly)
    : server(owner), lock(owner.operationMutex_, std::defer_lock), previous(currentAdmission_), wakeOnRelease(!tryOnly) {
    if (previous && &previous->server == &owner) return;
    if (tryOnly) lock.try_lock(); else lock.lock();
    if (lock.owns_lock()) { outer = true; currentAdmission_ = this; }
}
McpServer::OperationAdmission::~OperationAdmission() { if (outer) { release(); currentAdmission_ = previous; } }
bool McpServer::OperationAdmission::acquired() const {
    return lock.owns_lock() || (!outer && previous && &previous->server == &server && previous->acquired());
}
void McpServer::OperationAdmission::release() {
    if (!lock.owns_lock()) return;
    lock.unlock();
    if (wakeOnRelease) SetEvent(server.eventsReady_);
    if (server.operationRetryPending_.exchange(false)) server.NotifyRetry();
}
StopEvent McpServer::WaitForSessionStop(int seconds, uint64_t generation) {
    auto* admission = currentAdmission_;
    if (!admission || &admission->server != this || !admission->lock.owns_lock())
        return session_.WaitForStop(seconds, generation);
    admission->lock.unlock();
    SetEvent(eventsReady_); // retry queued actions after a previously failed try-admission
    try {
        auto event = session_.WaitForStop(seconds, generation);
        admission->lock.lock();
        if (session_.GetSessionGeneration() != generation) {
            event.sessionChanged = true;
            event.timeout = false;
        }
        return event;
    } catch (...) { admission->lock.lock(); throw; }
}

void McpServer::ReapToolWorkers(bool all) {
    std::vector<std::thread> finished;
    {
        std::lock_guard<std::mutex> lock(toolWorkersMutex_);
        for (auto it = toolWorkers_.begin(); it != toolWorkers_.end();) {
            if (all || it->done->load()) {
                finished.push_back(std::move(it->thread));
                it = toolWorkers_.erase(it);
            } else ++it;
        }
    }
    if (all) {
        // Cancel every live sender each round: a worker waiting on sendMutex_
        // cannot finish until the worker holding it leaves synchronous output.
        std::vector<HANDLE> pending;
        for (auto& thread : finished) if (thread.joinable()) pending.push_back(thread.native_handle());
        while (!pending.empty()) {
            pending.erase(std::remove_if(pending.begin(), pending.end(),
                [](HANDLE handle) { return WaitForSingleObject(handle, 0) == WAIT_OBJECT_0; }), pending.end());
            if (pending.empty()) break;
            for (HANDLE handle : pending) (void)CancelSynchronousIo(handle);
            (void)WaitForMultipleObjects(static_cast<DWORD>(pending.size()), pending.data(), FALSE, 100);
        }
    }
    for (auto& thread : finished) if (thread.joinable()) thread.join();
}

void McpServer::StopValueFreezes(const char* reason) {
    for (auto& job : valueFreezes_) if (FreezeActive(job.state)) job.state = reason;
}

void McpServer::ClearRunUntil(const char* reason, bool cleanupConfirmed, bool reached) {
    if (!runUntil_.active) return;
    lastRunUntil_ = {{"operationId", std::to_string(runUntil_.operation)},
        {"sessionGeneration", std::to_string(runUntil_.generation)}, {"reason", reason},
        {"reached", reached}, {"backendCleanupConfirmed", cleanupConfirmed}};
    runUntil_ = {};
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        tempStepOverBpId_ = 0;
    }
    operationRetryPending_ = true;
}

void McpServer::SynchronizeOperations() {
    const auto generation = session_.GetSessionGeneration();
    const bool unavailable = !session_.IsAttached() || !session_.GetPipeClient().IsConnected();
    if (generation && terminalNoticeGeneration_.load() == generation) {
        terminalGeneration_ = generation;
        StopValueFreezes("target-exited");
        ClearRunUntil("target-exited", false);
    }
    if (runUntil_.active && (unavailable || generation != runUntil_.generation))
        ClearRunUntil(unavailable ? "session-unavailable" : "session-changed", false);
    const auto now = operationClock_();
    for (auto& job : valueFreezes_) if (FreezeActive(job.state)) {
        if (unavailable || generation != job.generation || session_.GetTargetPid() != job.pid ||
            terminalGeneration_ == generation) job.state = "scope-ended";
        else if (now >= job.expires) job.state = "expired";
    }
}

bool McpServer::OperationAllowed(const std::string& name, const json& args) {
    if (!runUntil_.active) return true;
    // Explicit lifecycle cleanup must remain available even after uncertain
    // breakpoint creation/removal or backend death.
    if (name == "veh_attach" || name == "veh_launch" || name == "veh_detach" ||
        name == "veh_terminate" || name == "veh_execution" || name == "veh_pause" ||
        name == "veh_toolbox" || name == "veh_batch") return true;
    if (name == "veh_continue" && JsonBool(args, "wait")) return true;
    if (name == "veh_value_freeze") return args.value("operation", "list") != "add";
    static const char* reads[] = {"veh_threads", "veh_registers", "veh_stack_trace", "veh_read_memory",
        "veh_read_pointer_chain", "veh_modules", "veh_disassemble", "veh_list_breakpoints",
        "veh_processes", "veh_symbolize", "veh_exception_info"};
    if (std::find(std::begin(reads), std::end(reads), name) != std::end(reads)) return true;
    return name == "veh_virtual_machine" &&
        (args.value("operation", "") == "status" || args.value("operation", "") == "pause");
}

bool McpServer::RetireRunUntil(bool explicitRequest, std::string& error) {
    SynchronizeOperations();
    if (!runUntil_.active) return true;
    if (!explicitRequest && runUntil_.cleanupAttempted) return false;
    if (!runUntil_.owned) { ClearRunUntil("cancelled", true); return true; }
    if (!runUntil_.breakpoint) {
        error = "Breakpoint creation outcome is unknown; detach to end the old backend session";
        runUntil_.uncertain = true;
        return false;
    }
    runUntil_.cleanupAttempted = true;
    const auto status = session_.RemoveBreakpointStatus(runUntil_.breakpoint, false, &error);
    if (!status || (*status != IpcStatus::Ok && *status != IpcStatus::NotFound)) {
        runUntil_.uncertain = true;
        if (error.empty()) error = "Temporary breakpoint cleanup was not confirmed";
        return false;
    }
    ClearRunUntil("cancelled", true);
    return true;
}

void McpServer::QueueExecutionStop(const char* reason, uint64_t address, uint32_t thread, uint32_t breakpoint) {
    const auto generation = session_.GetSessionGeneration();
    if (std::string(reason) == "exit") terminalNoticeGeneration_ = generation;
    std::lock_guard<std::mutex> lock(eventMutex_);
    if (executionNotices_.size() >= 64) { executionNotices_.pop(); ++executionLost_; }
    executionNotices_.push({++executionSequence_, generation, address, executionLost_,
        operationPid_.load(), thread, breakpoint, reason});
    SetEvent(eventsReady_);
}

void McpServer::DrainExecutionStops() {
    std::queue<ExecutionNotice> pending;
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        std::swap(pending, executionNotices_);
    }
    while (!pending.empty()) {
        auto event = std::move(pending.front()); pending.pop();
        if (event.generation != session_.GetSessionGeneration()) continue;
        bool reached = false, cleanup = false, considered = false;
        uint64_t operation = 0;
        if (event.reason == "exit") {
            terminalGeneration_ = event.generation;
            StopValueFreezes("target-exited");
            ClearRunUntil("target-exited", false);
        } else if (runUntil_.active && event.generation == runUntil_.generation &&
            event.sequence > runUntil_.watermark &&
            (event.thread == runUntil_.thread || (event.reason == "pause" && event.thread == 0))) {
            const bool terminalThread = event.reason == "thread-exit";
            const auto stopped = terminalThread ? std::optional<bool>(true) :
                session_.QueryThreadStopped(runUntil_.thread);
            if (stopped == std::optional<bool>(true)) {
                considered = true;
                operation = runUntil_.operation;
                const auto regs = terminalThread ? std::optional<RegisterSet>{} : session_.GetRegisters(runUntil_.thread);
                const bool atDestination = regs && (regs->is32bit ? regs->rip & UINT32_MAX : regs->rip) == runUntil_.address;
                reached = atDestination && event.reason == "breakpoint" && event.thread == runUntil_.thread &&
                    event.address == runUntil_.address && event.breakpoint == runUntil_.breakpoint;
                std::string error;
                cleanup = RetireRunUntil(false, error);
                if (cleanup && lastRunUntil_.is_object()) {
                    lastRunUntil_["reason"] = reached ? "destination" : terminalThread ? "thread-exited" : "interrupted";
                    lastRunUntil_["reached"] = reached;
                }
            }
        }
        if (executionNotifications_) SendNotification("notifications/veh/stopped", {
            {"protocol", "veh-session/1"}, {"sessionGeneration", std::to_string(event.generation)},
            {"sequence", std::to_string(event.sequence)}, {"pid", event.pid}, {"threadId", event.thread},
            {"address", HexAddr(event.address)}, {"breakpointId", event.breakpoint}, {"reason", event.reason},
            {"dropped", std::to_string(event.lost)}, {"operationId", std::to_string(operation)},
            {"runUntilReached", reached}, {"runUntilInterrupted", considered && !reached},
            {"backendCleanupConfirmed", cleanup}});
    }
}

json McpServer::ExecutionSnapshot(uint32_t thread) {
    SynchronizeOperations();
    DrainExecutionStops();
    std::optional<bool> stopped;
    std::string queryError;
    if (thread && session_.IsAttached() && session_.IsThreadOwnedByTarget(thread) &&
        terminalGeneration_ != session_.GetSessionGeneration())
        stopped = session_.QueryThreadStopped(thread, &queryError);
    json run = {{"active", runUntil_.active}};
    if (runUntil_.active) run.update({
        {"operationId", std::to_string(runUntil_.operation)}, {"sessionGeneration", std::to_string(runUntil_.generation)},
        {"threadId", runUntil_.thread}, {"address", HexAddr(runUntil_.address)},
        {"breakpointId", runUntil_.breakpoint}, {"owned", runUntil_.owned}, {"uncertain", runUntil_.uncertain}});
    json out = {{"protocol", "veh-session/1"}, {"attached", session_.IsAttached()},
        {"targetExited", terminalGeneration_ != 0 && terminalGeneration_ == session_.GetSessionGeneration()},
        {"sessionGeneration", std::to_string(session_.GetSessionGeneration())}, {"pid", session_.GetTargetPid()},
        {"threadId", thread}, {"state", stopped ? (*stopped ? "stopped" : "running") : "unknown"},
        {"notifications", executionNotifications_}, {"sequence", std::to_string(executionSequence_.load())},
        {"runUntil", run}, {"lastRunUntil", lastRunUntil_}};
    if (!queryError.empty()) out["queryError"] = queryError;
    return out;
}

json McpServer::StartRunUntil(uint64_t destination, uint32_t thread) {
    SynchronizeOperations();
    if (runUntil_.active) return {{"error", "Cancel the current run-until operation first"}};
    if (!session_.IsAttached() || session_.IsVirtualMachineTarget() ||
        terminalGeneration_ == session_.GetSessionGeneration()) return {{"error", "A live process session is required"}};
    if (std::any_of(valueFreezes_.begin(), valueFreezes_.end(), [](const auto& j){return FreezeActive(j.state);}))
        return {{"error", "Remove active value-freeze jobs before run-until"}};
    if (!ReportedCommands(session_.GetBackendInfo(), {IpcCommand::SetBreakpoint, IpcCommand::RemoveBreakpoint,
        IpcCommand::Continue, IpcCommand::IsThreadStopped, IpcCommand::GetRegisters}))
        return {{"error", "Run-until requires reported breakpoint, removal, continue, stopped-query and register support"}};
    if (!thread || !session_.IsThreadOwnedByTarget(thread) ||
        session_.QueryThreadStopped(thread) != std::optional<bool>(true))
        return {{"error", "Select a current thread with a confirmed debugger stop"}};
    const auto bits = session_.TargetAddressBits();
    if (!destination || (bits != 32 && bits != 64) || (bits == 32 && destination > UINT32_MAX))
        return {{"error", "Destination is outside the target address space"}};
    if (session_.GetBackendInfo().Supports(IpcCommand::FreezeThread)) {
        std::vector<uint32_t> frozen;
        if (!session_.FreezeThread(FreezeOp::List, 0, frozen) ||
            std::find(frozen.begin(), frozen.end(), thread) != frozen.end())
            return {{"error", "The selected thread is frozen or freeze state is unavailable"}};
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        if (!pendingBreakpointActions_.empty() || !pendingAutoContinue_.empty())
            return {{"error", "Earlier queued execution work must finish first"}};
    }
    uint32_t borrowed = 0;
    {
        std::lock_guard<std::mutex> lock(session_.GetBpMutex());
        if (!bpActions_.empty()) return {{"error", "Run-until cannot overlap breakpoint actions"}};
        for (const auto& bp : session_.GetSwBreakpoints()) {
            if (bp.pending || !bp.condition.empty() || !bp.hitCondition.empty() || !bp.logMessage.empty())
                return {{"error", "Run-until cannot overlap pending, conditional or log breakpoints"}};
            if (bp.address == destination) borrowed = bp.id;
        }
        for (const auto& bp : session_.GetHwBreakpoints())
            if (!bp.condition.empty() || !bp.hitCondition.empty())
                return {{"error", "Run-until cannot overlap conditional hardware breakpoints"}};
    }
    if (const auto regs = session_.GetRegisters(thread)) {
        const auto rip = regs->is32bit ? regs->rip & UINT32_MAX : regs->rip;
        if (rip == destination) return {{"success", true}, {"alreadyAtTarget", true}, {"address", HexAddr(destination)}};
    }
    const uint64_t id = nextOperation_++;
    runUntil_ = {true, borrowed == 0, false, false, id, session_.GetSessionGeneration(), destination, 0, borrowed, thread};
    if (!borrowed) {
        const auto created = session_.SetBreakpoint(destination);
        runUntil_.breakpoint = created.id;
        if (!created.ok || !created.id) {
            if (created.full) { ClearRunUntil("capacity-refused", true); return {{"error", "No breakpoint slot is available"}}; }
            runUntil_.uncertain = true;
            return {{"error", "Breakpoint creation outcome is unknown; cancel or detach before retrying"},
                {"operationId", std::to_string(id)}};
        }
    }
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        tempStepOverBpId_ = runUntil_.breakpoint;
    }
    runUntil_.watermark = executionSequence_.load();
    const auto resumed = session_.ContinueWithDetails(thread, false);
    bool attested = resumed.ok && std::find(resumed.resumedThreadIds.begin(), resumed.resumedThreadIds.end(), thread) != resumed.resumedThreadIds.end();
    if (resumed.ok && !attested) {
        bool destinationStop = false;
        {
            std::lock_guard<std::mutex> lock(eventMutex_);
            auto events = executionNotices_;
            while (!events.empty()) {
                const auto& e = events.front();
                destinationStop = destinationStop || (e.generation == runUntil_.generation && e.sequence > runUntil_.watermark &&
                    e.thread == thread && e.reason == "breakpoint" && e.address == destination && e.breakpoint == runUntil_.breakpoint);
                events.pop();
            }
        }
        const auto regs = destinationStop ? session_.GetRegisters(thread) : std::optional<RegisterSet>{};
        attested = destinationStop && regs && (regs->is32bit ? regs->rip & UINT32_MAX : regs->rip) == destination &&
            session_.QueryThreadStopped(thread) == std::optional<bool>(true);
    }
    if (!attested) {
        runUntil_.uncertain = true;
        return {{"error", "Selected-thread resume was not confirmed; temporary ownership retained"},
            {"operationId", std::to_string(id)}};
    }
    DrainExecutionStops();
    return {{"success", true}, {"pending", runUntil_.active}, {"operationId", std::to_string(id)},
        {"requestedThreadId", thread}, {"resumeScope", "single"}, {"address", HexAddr(destination)}};
}

json McpServer::ToolExecution(const json& args) {
    if (!args.is_object() || (args.contains("operation") && !args["operation"].is_string()) ||
        (args.contains("address") && !args["address"].is_string()))
        return {{"error", "operation and address must be strings"}};
    const std::string operation = args.value("operation", "state");
    if (operation != "state" && args.contains("expected_generation") &&
        (!args["expected_generation"].is_string() || args["expected_generation"] != std::to_string(session_.GetSessionGeneration())))
        return {{"error", "Session generation changed"}};
    if (operation == "notifications") {
        if (!args.contains("enabled") || !args["enabled"].is_boolean()) return {{"error", "enabled must be boolean"}};
        executionNotifications_ = args["enabled"].get<bool>();
        return {{"success", true}, {"enabled", executionNotifications_}};
    }
    if (operation == "state") return ExecutionSnapshot(JsonUint32(args, "threadId", 0));
    if (operation == "cancel") {
        std::string error;
        const bool ok = RetireRunUntil(true, error);
        return ok ? json{{"success", true}, {"lastRunUntil", lastRunUntil_}} :
            json{{"error", error}, {"runUntil", ExecutionSnapshot(runUntil_.thread)["runUntil"]}};
    }
    if (operation == "run_to") {
        uint64_t address = 0;
        if (!ParseAddress(args.value("address", ""), address)) return {{"error", "A valid destination address is required"}};
        return StartRunUntil(address, JsonUint32(args, "threadId", 0));
    }
    return {{"error", "operation must be state, run_to, cancel or notifications"}};
}

json McpServer::FreezeSnapshot() {
    SynchronizeOperations();
    const auto now = operationClock_();
    json jobs = json::array();
    for (const auto& job : valueFreezes_) {
        std::ostringstream data; data << std::hex;
        for (auto byte : job.bytes) { const char* hex = "0123456789ABCDEF"; data << hex[byte >> 4] << hex[byte & 15]; }
        jobs.push_back({{"id", std::to_string(job.id)}, {"pid", job.pid},
            {"sessionGeneration", std::to_string(job.generation)}, {"address", HexAddr(job.address)},
            {"data", data.str()}, {"state", job.state}, {"interval_ms", job.intervalMs},
            {"leaseRemainingMs", job.expires > now ? job.expires - now : 0}, {"writes", std::to_string(job.writes)},
            {"skippedIntervals", std::to_string(job.skipped)},
            {"lastConfirmedAgoMs", job.writes ? json(now - job.completedAt) : json(nullptr)}});
    }
    return {{"jobs", jobs}, {"maxJobs", kMaxFreezeJobs}, {"maxBytes", kMaxFreezeBytes}};
}

json McpServer::ToolValueFreeze(const json& args) {
    if (!args.is_object() || (args.contains("operation") && !args["operation"].is_string()) ||
        (args.contains("address") && !args["address"].is_string()) ||
        (args.contains("data") && !args["data"].is_string()))
        return {{"error", "operation, address and data must be strings"}};
    const std::string operation = args.value("operation", "list");
    if (operation != "list" && args.contains("expected_generation") &&
        (!args["expected_generation"].is_string() || args["expected_generation"] != std::to_string(session_.GetSessionGeneration())))
        return {{"error", "Session generation changed"}};
    if (operation == "list") return FreezeSnapshot();
    if (operation == "clear") {
        valueFreezes_.clear();
        SetEvent(eventsReady_);
        return {{"success", true}};
    }
    if (operation == "remove" || operation == "renew") {
        if (!args.contains("id") || !args["id"].is_string()) return {{"error", "id must be the exact returned string"}};
        auto it = std::find_if(valueFreezes_.begin(), valueFreezes_.end(),
            [&](const auto& entry){return std::to_string(entry.id) == args["id"].get<std::string>();});
        if (it == valueFreezes_.end()) return {{"error", "Unknown value-freeze job"}};
        if (operation == "remove") valueFreezes_.erase(it);
        else {
            uint64_t lease = 0;
            if (!ExactUnsigned(args, "lease_seconds", 1, 300, lease)) return {{"error", "lease_seconds must be 1-300"}};
            const auto now = operationClock_();
            if (!FreezeActive(it->state) || now >= it->expires) return {{"error", "Only an active unexpired lease can be renewed"}};
            it->expires = now + lease * 1000;
        }
        SetEvent(eventsReady_);
        return {{"success", true}};
    }
    if (operation != "add") return {{"error", "operation must be add, list, remove, renew or clear"}};
    if (!session_.IsAttached() || session_.IsVirtualMachineTarget() ||
        terminalGeneration_ == session_.GetSessionGeneration() || !session_.GetPipeClient().IsConnected())
        return {{"error", "A live process session is required"}};
    if (runUntil_.active) return {{"error", "Cancel run-until before adding a value freeze"}};
    if (!ReportedCommands(session_.GetBackendInfo(), {IpcCommand::ReadMemory, IpcCommand::WriteMemory}))
        return {{"error", "Value freezing requires reported ReadMemory and WriteMemory support"}};
    auto* output = dynamic_cast<dap::McpStdioTransport*>(transport_);
    if (!output || !output->IsOutputConnected()) return {{"error", "A connected MCP output pipe is required for autonomous writes"}};
    uint64_t address = 0, interval = 1000, lease = 0;
    std::vector<uint8_t> data;
    if (!ParseAddress(args.value("address", ""), address) || !address || !Bytes(args.value("data", ""), data))
        return {{"error", "A nonzero address and 1-64 exact hex bytes are required"}};
    if (args.contains("interval_ms") && !ExactUnsigned(args, "interval_ms", 250, 60000, interval))
        return {{"error", "interval_ms must be 250-60000"}};
    if (!ExactUnsigned(args, "lease_seconds", 1, 300, lease)) return {{"error", "An explicit lease_seconds from 1 to 300 is required"}};
    const auto bits = session_.TargetAddressBits();
    const auto maximum = bits == 32 ? uint64_t{UINT32_MAX} : UINT64_MAX;
    if ((bits != 32 && bits != 64) || address > maximum || data.size() - 1 > maximum - address)
        return {{"error", "Value range exceeds the target address space"}};
    if (valueFreezes_.size() >= kMaxFreezeJobs) return {{"error", "Remove old jobs before exceeding 16 entries"}};
    for (const auto& job : valueFreezes_) if (FreezeActive(job.state) &&
        address <= job.address + job.bytes.size() - 1 && job.address <= address + data.size() - 1)
        return {{"error", "An active value freeze already overlaps this range"}};
    const auto now = operationClock_();
    ValueFreeze job; job.id = nextFreeze_++; job.generation = session_.GetSessionGeneration(); job.pid = session_.GetTargetPid();
    job.address = address; job.bytes = std::move(data); job.intervalMs = static_cast<uint32_t>(interval);
    job.due = now; job.expires = now + lease * 1000;
    valueFreezes_.push_back(std::move(job));
    SetEvent(eventsReady_);
    return {{"success", true}, {"id", std::to_string(valueFreezes_.back().id)}};
}

uint32_t McpServer::OperationWaitMs() {
    std::unique_lock<std::recursive_mutex> lock(operationMutex_, std::try_to_lock);
    if (!lock.owns_lock()) return INFINITE;
    const auto now = operationClock_();
    uint64_t delay = INFINITE;
    for (const auto& job : valueFreezes_) if (FreezeActive(job.state)) {
        const auto deadline = std::min(job.due, job.expires);
        delay = std::min(delay, deadline <= now ? uint64_t{0} : deadline - now);
    }
    return static_cast<uint32_t>(delay);
}

void McpServer::RunDueFreeze() {
    if (!running_) return;
    std::unique_lock<std::recursive_mutex> lock(operationMutex_, std::try_to_lock);
    if (!lock.owns_lock()) return;
    SynchronizeOperations();
    DrainExecutionStops();
    if (!running_) { StopValueFreezes("control-ended"); return; }
    const auto now = operationClock_();
    auto selected = valueFreezes_.end();
    for (auto it = valueFreezes_.begin(); it != valueFreezes_.end(); ++it)
        if (FreezeActive(it->state) && it->due <= now &&
            (selected == valueFreezes_.end() || it->due < selected->due)) selected = it;
    if (selected == valueFreezes_.end()) return;
    auto* output = dynamic_cast<dap::McpStdioTransport*>(transport_);
    if (!output || !output->IsOutputConnected()) { StopValueFreezes("control-ended"); Stop(); return; }
    auto& job = *selected;
    // All instants in this operation use the injected monotonic clock in ms.
    const auto before = operationClock_();
    if (before >= job.expires) { job.state = "expired"; return; }
    if (!running_ || terminalNoticeGeneration_.load() == job.generation ||
        !session_.IsAttached() || !session_.GetPipeClient().IsConnected() ||
        session_.GetSessionGeneration() != job.generation || session_.GetTargetPid() != job.pid) {
        StopValueFreezes("scope-ended"); return;
    }
    job.skipped += (before - job.due) / job.intervalMs;
    const bool written = session_.WriteMemory(job.address, job.bytes.data(), static_cast<uint32_t>(job.bytes.size()));
    if (!written) { StopValueFreezes("write-unconfirmed"); return; }
    if (!running_ || terminalNoticeGeneration_.load() == job.generation || !output->IsOutputConnected() || !session_.IsAttached() ||
        session_.GetSessionGeneration() != job.generation || session_.GetTargetPid() != job.pid) {
        StopValueFreezes("scope-ended"); return;
    }
    const auto observed = session_.ReadMemory(job.address, static_cast<uint32_t>(job.bytes.size()));
    const auto completed = operationClock_();
    if (observed != job.bytes) { StopValueFreezes("readback-unconfirmed"); return; }
    ++job.writes; job.completedAt = completed;
    if (!running_ || !session_.IsAttached() || session_.GetSessionGeneration() != job.generation ||
        session_.GetTargetPid() != job.pid) { StopValueFreezes("scope-ended"); return; }
    if (completed >= job.expires) { job.state = "expired"; return; }
    job.skipped += (completed - before) / job.intervalMs;
    job.due = completed + job.intervalMs; // no catch-up and no automatic retry
}
} // namespace veh
