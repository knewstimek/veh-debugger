#include "mcp_server.h"
#include "tools_common.h"
#include "batch_executor.h"
#include "trace_basic_blocks_tool.h"
#include "assembler.h"
#include "adapter/disassembler.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <limits>
#include <stdexcept>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

namespace {

// Commands a backend may leave out, named after the tools that need them.
struct CommandName {
	IpcCommand cmd;
	const char* name;
};
constexpr CommandName kOptionalCommands[] = {
	{IpcCommand::SetBreakpoint, "breakpoints"}, {IpcCommand::SetHwBreakpoint, "hw_breakpoints"},
	{IpcCommand::SetModuleLoadStop, "module_load_stop"}, {IpcCommand::Continue, "continue"},
	{IpcCommand::StepInto, "step"}, {IpcCommand::Pause, "pause"}, {IpcCommand::FreezeThread, "freeze_thread"},
	{IpcCommand::GetThreads, "threads"}, {IpcCommand::GetStackTrace, "stack_trace"},
	{IpcCommand::GetRegisters, "registers"}, {IpcCommand::SetRegisters, "set_registers"},
	{IpcCommand::GetModules, "modules"}, {IpcCommand::ReadMemory, "read_memory"},
	{IpcCommand::WriteMemory, "write_memory"}, {IpcCommand::ResolveSourceLine, "source_line"},
	{IpcCommand::ResolveFunction, "resolve_function"}, {IpcCommand::EnumLocals, "locals"},
	{IpcCommand::Symbolize, "symbolize"}, {IpcCommand::DisplayType, "display_type"},
	{IpcCommand::TraceCallers, "trace_callers"}, {IpcCommand::AllocateMemory, "allocate_memory"},
	{IpcCommand::ExecuteShellcode, "execute_shellcode"}, {IpcCommand::QueryMemoryMap, "memory_map"},
	{IpcCommand::SearchMemory, "search_memory"}, {IpcCommand::ProtectMemory, "protect_memory"},
	{IpcCommand::ValueScan, "value_scan"}, {IpcCommand::TraceRegister, "trace_register"},
	{IpcCommand::TraceMemory, "trace_memory"}, {IpcCommand::ResolveImport, "resolve_import"},
	{IpcCommand::TraceCalls, "trace_calls"}, {IpcCommand::TraceBasicBlocks, "trace_basic_blocks"},
	{IpcCommand::Terminate, "terminate"}, {IpcCommand::ReadPhysical, "system_inspection"},
    {IpcCommand::ControlVirtualMachine, "virtual_machine_control"}, {IpcCommand::TraceVirtualCpu, "virtual_cpu_trace"},
};

// "agent" (path, optional "agent_args") or a "backend" name other than "veh"
// selects an out-of-process agent. Names come from veh-backends.json next to the
// server, or the file named by VEH_BACKENDS:
//   { "<name>": { "path": "agent.exe", "args": ["..."] } }
// Relative paths resolve against that file's folder.
bool ResolveBackend(const json& args, std::optional<DebugSession::ExternalAgent>& out, std::string& error) {
	auto strings = [](const json& j) {
		std::vector<std::string> v;
		if (j.is_array())
			for (const auto& s : j)
				if (s.is_string()) v.push_back(s.get<std::string>());
		return v;
	};
    auto scope = [&](const json& defaults, bool& guest, bool& vm) {
        const json value = args.contains("target_scope") ? args["target_scope"] : defaults.value("target_scope", json("host"));
        if (!value.is_string() || (value != "host" && value != "guest" && value != "vm")) {
            error = "target_scope must be host, guest or vm";
            return false;
        }
        guest = value == "guest";vm = value == "vm";
        return true;
    };
	if (args.contains("agent") && args["agent"].is_string()) {
		out = DebugSession::ExternalAgent{args["agent"].get<std::string>(), strings(args.value("agent_args", json::array()))};
		return scope(json::object(), out->guestTarget, out->vmTarget);
	}
	const std::string name = args.value("backend", "veh");
	if (name == "veh") {
        bool guest = false, vm = false;
        if (!scope(json::object(), guest, vm)) return false;
        if (guest || vm) { error = "guest/vm target_scope requires an external backend"; return false; }
        return true;
    }

	std::filesystem::path file;
	wchar_t env[MAX_PATH] = {};
	if (GetEnvironmentVariableW(L"VEH_BACKENDS", env, MAX_PATH)) {
		file = env;
	} else {
		wchar_t exe[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, exe, MAX_PATH);
		file = std::filesystem::path(exe).parent_path() / "veh-backends.json";
	}
	std::ifstream in(file);
	json table = in ? json::parse(in, nullptr, false) : json();
	if (!table.is_object() || !table.contains(name) || !table[name].is_object() ||
        (!table[name].contains("path") && !table[name].contains("remote"))) {
		error = "Unknown backend '" + name + "' (not in " + file.string() + "). Use \"veh\", register it there, or pass \"agent\".";
		return false;
	}
    if (table[name].contains("remote")) {
        try {
            if (table[name].contains("path") || args.contains("agent_args")) throw std::runtime_error("ambiguous");
            const auto& remote = table[name].at("remote");
            if (remote.contains("token") || remote.contains("password")) throw std::runtime_error("inline credential");
            RemoteEndpoint endpoint;
            endpoint.address = remote.at("address").get<std::string>();
            if (!remote.at("port").is_number_unsigned()) throw std::runtime_error("port");
            const auto port = remote.at("port").get<uint64_t>();
            if (!port || port > 65535) throw std::runtime_error("port");
            endpoint.port = static_cast<uint16_t>(port);
            endpoint.certificateSha256 = remote.at("certificate_sha256").get<std::string>();
            if (endpoint.certificateSha256.size() != 64) throw std::runtime_error("pin");
            auto token = std::filesystem::u8path(remote.at("token_file").get<std::string>());
            if (token.is_relative()) token = file.parent_path() / token;
            endpoint.tokenFile = token.wstring();
            endpoint.backend = remote.value("backend", name);
            if (remote.contains("timeout_ms")) {
                const auto& timeout = remote.at("timeout_ms");
                if (!timeout.is_number_unsigned() || timeout.get<uint64_t>() > 30000) throw std::runtime_error("timeout");
                endpoint.timeoutMs = timeout.get<int>();
            }
            if (endpoint.backend.empty() || endpoint.timeoutMs < 100 || endpoint.timeoutMs > 30000)
                throw std::runtime_error("selection");
            out = DebugSession::ExternalAgent{};
            out->remote = std::move(endpoint);
            return scope(table[name], out->guestTarget, out->vmTarget);
        } catch (...) { error = "Invalid remote backend profile; use numeric address, TLS pin and private token_file"; return false; }
    }
	std::filesystem::path path = table[name]["path"].get<std::string>();
	if (path.is_relative()) path = file.parent_path() / path;
	out = DebugSession::ExternalAgent{path.string(), strings(table[name].value("args", json::array()))};
	return scope(table[name], out->guestTarget, out->vmTarget);
}

json BackendSummary(const DebugSession::BackendInfo& info, const RemoteWorkInfo* work = nullptr) {
	json out = {{"name", info.name},
		{"kind", info.backend == IpcBackend::Hypervisor ? "hypervisor" : "veh-dll"},
		{"stopsThreads", (info.flags & kCapStopsThreads) != 0},
		{"hiddenBreakpoints", (info.flags & kCapHiddenBreakpoints) != 0},
		{"noTargetFootprint", (info.flags & kCapNoTargetFootprint) != 0},
		{"targetScope", (info.flags & kCapVirtualMachineTarget) ? "vm" : (info.flags & kCapGuestTarget) ? "guest" : "host"}};
	json missing = json::array();
	for (const auto& c : kOptionalCommands)
		if (!info.Supports(c.cmd)) missing.push_back(c.name);
    if (work) {
        out["remote"] = {{"work_id", work->id}, {"outcome_unknown", work->outcomeUnknown}};
        missing.push_back("frontend_conditional_breakpoints");
        missing.push_back("target_data_pipe_artifacts");
    }
	if (!missing.empty()) out["unsupported"] = missing;
	return out;
}

} // namespace

json McpServer::ToolAttach(const json& args) {
	if (args.contains("logFile") && args["logFile"].is_string()) {
		std::string lf = args["logFile"].get<std::string>();
		if (!lf.empty()) veh::Logger::Instance().SetFile(lf);
	}
    uint32_t pid=JsonUint32(args,"pid");
    std::optional<DebugSession::ExternalAgent> agent;
    if(std::string error;!ResolveBackend(args,agent,error))return {{"error",error}};
    const bool vm=agent&&agent->vmTarget;
    if(vm&&pid)return {{"error","VM attachment has no OS PID; omit pid"}};
    if(!vm&&!pid)return {{"error","pid is required for host/guest attachment"}};
	if (session_.IsAttached() && !(agent && agent->remote)) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new attach", session_.GetTargetPid());
		const auto detached = ToolDetach({});
		if (detached.contains("error")) return detached;
	} else if (session_.GetPipeClient().IsConnected() && !(agent && agent->remote)) {
		LOG_WARN("Stale pipe connection detected, cleaning up");
		session_.GetPipeClient().StopHeartbeat();
		session_.GetPipeClient().StopEventListener();
		session_.GetPipeClient().Disconnect();
	}


	if (!session_.Attach(pid, agent ? &*agent : nullptr)) {
		std::string why = session_.LastAttachError();
		if (why.empty()) why = "Attach failed for PID " + std::to_string(pid) + ". Check logs for details.";
		return {{"error", why}};
	}
	ResetSessionEventState();

	// Start event listener + heartbeat + process monitor
	session_.SetEventCallback([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	// VEH 설치 완료(Ready) 대기 (이벤트 리스너 시작 후 -- condvar). attach 직후 BP race 방지.
	if (!session_.GetPipeClient().WaitForReady(3000)) {
		LOG_WARN("No Ready after attach/launch; proceeding (VEH may not be installed yet)");
	}
	session_.QueryBackendInfo();
    if (!session_.CompleteBackendAttach()) {
        const auto error = session_.LastAttachError();
        session_.Detach();
        return {{"error", error.empty() ? "Backend target scope validation failed" : error}};
    }
	session_.StartProcessMonitor();

	json ret={{"success",true},{"message",vm?"Attached to virtual machine":"Attached to process"}};
    if(!vm)ret["pid"]=pid;
	ret["backend"] = BackendSummary(session_.GetBackendInfo(), session_.RemoteWork());
	if (session_.IsGuestTarget()) ret["addressBits"] = session_.TargetAddressBits();
	// Include main module info (saves a veh_modules round-trip)
	auto modules = vm ? std::vector<ModuleEntry>{} : session_.GetModules();
	if (!modules.empty()) {
		char buf[20]; snprintf(buf, sizeof(buf), "0x%llX", modules[0].baseAddress);
		ret["mainModule"] = {{"name", modules[0].name}, {"baseAddress", buf}, {"size", modules[0].size}};
	}
	return ret;
}

json McpServer::ToolLaunch(const json& args) {
	if (args.contains("logFile") && args["logFile"].is_string()) {
		std::string lf = args["logFile"].get<std::string>();
		if (!lf.empty()) veh::Logger::Instance().SetFile(lf);
	}
	std::optional<DebugSession::ExternalAgent> agent;
	if (std::string error; !ResolveBackend(args, agent, error))
		return {{"error", error}};
    if(agent&&agent->vmTarget)
        return {{"error","VM attachment does not create a process. Use veh_attach with target_scope=vm."}};
    if (agent && agent->guestTarget)
        return {{"error", "Guest process launch is not supported yet. Start the program in the guest and attach with target_scope=guest."}};
	if (session_.IsAttached() && !(agent && agent->remote)) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new launch", session_.GetTargetPid());
		const auto detached = ToolDetach({});
		if (detached.contains("error")) return detached;
	} else if (session_.GetPipeClient().IsConnected() && !(agent && agent->remote)) {
		LOG_WARN("Stale pipe connection detected, cleaning up");
		session_.GetPipeClient().StopHeartbeat();
		session_.GetPipeClient().StopEventListener();
		session_.GetPipeClient().Disconnect();
	}

	std::string program = args.value("program", "");
	if (program.empty()) return {{"error", "program is required"}};

	DebugSession::LaunchOptions opts;
	opts.program = program;
	if (args.contains("args") && args["args"].is_array()) {
		for (auto& a : args["args"]) {
			if (a.is_string()) opts.args.push_back(a.get<std::string>());
		}
	}
	// env: object {"KEY":"VAL"} 또는 array ["KEY=VAL"] 둘 다 수용
	if (args.contains("env")) {
		const auto& e = args["env"];
		if (e.is_object()) {
			for (auto it = e.begin(); it != e.end(); ++it) {
				std::string v = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
				opts.env.push_back(it.key() + "=" + v);
			}
		} else if (e.is_array()) {
			for (auto& s : e) {
				if (s.is_string()) opts.env.push_back(s.get<std::string>());
			}
		}
	}
	opts.stopOnEntry = JsonBool(args, "stopOnEntry", true);
	opts.runAsInvoker = JsonBool(args, "runAsInvoker", false);
	opts.injectionMethod = args.value("injectionMethod", "auto");
	opts.cwd = args.value("cwd", "");
	opts.agent = agent ? &*agent : nullptr;

	auto result = session_.Launch(opts);
	if (!result.ok) {
		return {{"error", result.error}};
	}
	ResetSessionEventState();

	// Start event listener + heartbeat + process monitor
	session_.SetEventCallback([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	// VEH 설치 완료(Ready) 대기 (이벤트 리스너 시작 후 -- condvar). attach 직후 BP race 방지.
	if (!session_.GetPipeClient().WaitForReady(3000)) {
		LOG_WARN("No Ready after attach/launch; proceeding (VEH may not be installed yet)");
	}
	session_.QueryBackendInfo();
    if (!session_.CompleteBackendAttach()) {
        const auto error = session_.LastAttachError();
        session_.Terminate();
        return {{"error", error.empty() ? "Backend target scope validation failed" : error}};
    }
	session_.StartProcessMonitor();

	// stopOnEntry=false: VEH 설치 완료(WaitForReady) 이후에야 메인스레드를 재개한다.
	// (Launch 내부에서 재개하면 핸들러 설치 전 조기 실행 레이스가 생김)
	if (!opts.stopOnEntry) {
		session_.ResumeMainThread();
	}

	json ret = {{"success", true}, {"pid", result.pid}, {"message",
		opts.stopOnEntry ? "Launched and attached (stopped on entry)" : "Launched and attached"}};
	ret["backend"] = BackendSummary(session_.GetBackendInfo(), session_.RemoteWork());
    const auto addressBits = session_.TargetAddressBits();
    if (addressBits == 32 || addressBits == 64) ret["addressBits"] = addressBits;
    if (const auto threadId = session_.LaunchMainThreadId()) ret["mainThreadId"] = threadId;
	auto modules = session_.GetModules();
	if (!modules.empty()) {
		char buf[20]; snprintf(buf, sizeof(buf), "0x%llX", modules[0].baseAddress);
		ret["mainModule"] = {{"name", modules[0].name}, {"baseAddress", buf}, {"size", modules[0].size}};
	}
	return ret;
}

json McpServer::ToolDetach(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	// Deferred BP 워커는 영속(McpServer 생애). 워커는 session_.IsAttached()를 확인하므로
	// detach 후 죽은 세션에 접근하지 않는다. 여기서 join하지 않는다(재attach 시 재사용).
    if (!session_.Detach()) {
        const auto& error = session_.LastAttachError();
        return {{"error", error.empty() ? "Detach completion could not be confirmed" : error}};
    }
	if (!session_.LastDetachBackendConfirmed())
		return {{"success", true}, {"message", "Session cleared; backend cleanup acknowledgement unavailable"},
			{"backendCleanupConfirmed", false}};
	return {{"success", true}, {"message", "Detached"}};
}

json McpServer::ToolTerminate(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t pid = session_.GetTargetPid();
	int exitCode = JsonInt(args, "exitCode", 0);
	if (!session_.Terminate(static_cast<uint32_t>(exitCode)))
		return {{"error", "Target termination is unsupported or the session is unavailable"}};
	return {{"success", true}, {"pid", pid},
	        {"message", "Terminated target from inside (in-process kill; works on self-protected targets) and detached"}};
}

json McpServer::ToolSetRegister(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	std::string name = args.value("name", "");
	std::string valueStr = args.value("value", "");
	if (threadId == 0) return {{"error", "threadId is required"}};
	if (name.empty()) return {{"error", "name (register name) is required"}};
	if (valueStr.empty()) return {{"error", "value is required"}};

	uint32_t regIndex = DebugSession::GetRegisterIndex(name);
	if (regIndex == UINT32_MAX) {
		return {{"error", "Unknown register: " + name}};
	}

	uint64_t newVal;
	try {
		newVal = std::stoull(valueStr, nullptr, 0);
	} catch (...) {
		return {{"error", "Invalid value: " + valueStr}};
	}

	if (!session_.SetRegister(threadId, regIndex, newVal)) {
		return {{"error", "Failed to set register"}};
	}

	char buf[32];
	snprintf(buf, sizeof(buf), "0x%llX", newVal);
	return {{"success", true}, {"name", name}, {"value", buf}};
}

json McpServer::ToolContinue(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	CleanupTempStepOverBp();

	uint32_t threadId = JsonUint32(args, "threadId");
	bool wait = JsonBool(args, "wait");
	bool passException = JsonBool(args, "pass_exception");
	uint64_t sessionGeneration = session_.GetSessionGeneration();
	int timeoutSec = JsonInt(args, "timeout", 10);
	if (timeoutSec < 1) timeoutSec = 1;
	if (timeoutSec > 300) timeoutSec = 300;

	// Update exception filter
	if (args.contains("ignore_exceptions") && args["ignore_exceptions"].is_array()) {
		std::lock_guard<std::mutex> lock(filterMutex_);
		ignoreExceptionCodes_.clear();
		for (auto& v : args["ignore_exceptions"]) {
			if (v.is_number()) ignoreExceptionCodes_.push_back(v.get<uint32_t>());
			else if (v.is_string()) {
				try { ignoreExceptionCodes_.push_back(static_cast<uint32_t>(std::stoull(v.get<std::string>(), nullptr, 0))); }
				catch (...) {}
			}
		}
	}

	// A stop reported for a thread that runs again (resumed meanwhile by any
	// command) is over: a trace asked right after it would find no stopped thread.
	const auto stillStopped = [this](const StopEvent& ev) {
		return ev.threadId == 0 || ev.reason == "exit" || !session_.IsAttached() ||
			!session_.GetBackendInfo().Supports(IpcCommand::IsThreadStopped) || session_.IsThreadStopped(ev.threadId);
	};

	// Check for cached stop event before sending Continue
	if (wait && !passException) {
		auto cached = session_.ConsumeCachedStop();
		// A breakpoint stop is current only while the thread is still at its
		// address (live, guest backend: a duplicate hit event delivered after a
		// trace moved the thread to the function's return made the next
		// continue return at once without resuming).
		const auto atStop = [this](const StopEvent& ev) {
			if (ev.reason != "breakpoint" || !ev.threadId) return true;
			const auto regs = session_.GetRegisters(ev.threadId);
			if (!regs) return true;
			const uint64_t rip = regs->is32bit ? (regs->rip & 0xFFFFFFFFull) : regs->rip;
			return rip == ev.address;
		};
		if (cached && IsCurrentStopEvent(*cached) && stillStopped(*cached) && atStop(*cached)) {
			json ret = {
				{"stopped", true},
				{"reason", cached->reason},
				{"address", (std::ostringstream() << "0x" << std::hex << cached->address).str()},
				{"threadId", cached->threadId},
				{"breakpointId", cached->breakpointId}
			};
			if (!cached->bpType.empty()) ret["breakpointType"] = cached->bpType;
			return ret;
		}
	}

	auto continueResult = session_.ContinueWithDetails(threadId, passException);
	if (!continueResult.ok) {
		return {{"error", IpcErrorMessage()}};
	}
	auto addResumeDetails = [&](json& ret) {
		ret["resumeScope"] = threadId == 0 ? "all" : "single";
		ret["requestedThreadId"] = threadId;
		ret["resumedThreadIds"] = continueResult.resumedThreadIds;
		ret["stillStoppedThreadIds"] = continueResult.stillStoppedThreadIds;
	};

	if (!wait) {
		json ret = {{"success", true}, {"threadId", threadId}};
		addResumeDetails(ret);
		return ret;
	}

	// Wait for a stop from the current process. A stale event is discarded and the
	// remaining timeout is used without issuing a second Continue command.
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec);
	StopEvent stopEvent;
	for (;;) {
		auto now = std::chrono::steady_clock::now();
		if (now >= deadline) {
			json ret = {{"timeout", true}, {"message", "No stop event within timeout. Process still running."}};
			addResumeDetails(ret);
			return ret;
		}
		auto remaining = std::chrono::duration_cast<std::chrono::seconds>(deadline - now);
		int remainingSec = static_cast<int>(remaining.count());
		if (remainingSec < 1) remainingSec = 1;
		stopEvent = session_.WaitForStop(remainingSec, sessionGeneration);
		if (stopEvent.timeout) {
			json ret = {{"timeout", true}, {"message", "No stop event within timeout. Process still running."}};
			addResumeDetails(ret);
			return ret;
		}
		if (stopEvent.sessionChanged) {
			return {{"error", "Debug session changed while waiting for a stop event"}};
		}
		if (IsCurrentStopEvent(stopEvent) && stillStopped(stopEvent)) break;
	}

	json ret = {
		{"stopped", true},
		{"reason", stopEvent.reason},
		{"address", (std::ostringstream() << "0x" << std::hex << stopEvent.address).str()},
		{"threadId", stopEvent.threadId},
		{"breakpointId", stopEvent.breakpointId}
	};
	if (!stopEvent.bpType.empty()) ret["breakpointType"] = stopEvent.bpType;
	addResumeDetails(ret);
	return ret;
}

// Why a backend refused to start a step (no StepCompleted event follows).
static std::string StepRefusedMessage(uint32_t threadId, IpcStatus status) {
	const std::string thread = "Thread " + std::to_string(threadId);
	switch (status) {
	case IpcStatus::NotFound: return thread + " is not stopped (not found or already running)";
	case IpcStatus::Unsupported:
		return thread + " is suspended (pause/freeze) without a stop the backend can step from; continue to a breakpoint first";
	default: return thread + ": step refused (status " + std::to_string(static_cast<int>(status)) + ")";
	}
}

json McpServer::ToolStepIn(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	session_.ResumeMainThread();
	CleanupTempStepOverBp();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};
	{
		std::lock_guard<std::mutex> lock(stepMutex_);
		stepCompleted_ = false;
		stepCompletedAddr_ = 0;
		stepCompletedThread_ = 0;
	}

	if (const IpcStatus st = session_.StepIn(threadId); st != IpcStatus::Ok)
		return {{"error", StepRefusedMessage(threadId, st)}};

	std::unique_lock<std::mutex> lock(stepMutex_);
	if (!stepCv_.wait_for(lock, std::chrono::seconds(5), [this, threadId]{
			return (stepCompleted_ && stepCompletedThread_ == threadId) || !session_.IsAttached();
		})) {
		return {{"error", "Step timed out (threadId=" + std::to_string(threadId) + "). Thread may not be stopped or may be deadlocked."}};
	}
	if (!(stepCompleted_ && stepCompletedThread_ == threadId) && !session_.IsAttached()) {
		return {{"error", "Target process exited during step"}};
	}
	return {{"success", true}, {"threadId", threadId},
		{"instructionPointer", (std::ostringstream() << "0x" << std::hex << stepCompletedAddr_).str()}};
}

json McpServer::ToolStepOver(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	session_.ResumeMainThread();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	// Clean up any stale temp BP from previous step-over
	CleanupTempStepOverBp();

	// Check if current instruction is CALL - if so, skip over it
	uint64_t nextAddr = 0;
	if (IsCallInstruction(threadId, nextAddr)) {
		if (SetTempBpAndContinue(nextAddr)) {
			return {{"success", true}, {"threadId", threadId}, {"skippedCall", true}};
		}
	}

	// Check if we're on a BP (rearm will execute 2 instructions)
	uint64_t callAfterAddr = 0;
	if (IsNextInstructionCall(threadId, callAfterAddr)) {
		if (SetTempBpAndContinue(callAfterAddr)) {
			return {{"success", true}, {"threadId", threadId}, {"skippedCall", true}};
		}
	}

	// Normal single-step with synchronous wait
	{
		std::lock_guard<std::mutex> lock(stepMutex_);
		stepCompleted_ = false;
		stepCompletedAddr_ = 0;
		stepCompletedThread_ = 0;
	}

	if (const IpcStatus st = session_.StepOver(threadId); st != IpcStatus::Ok)
		return {{"error", StepRefusedMessage(threadId, st)}};

	// Wait for StepCompleted event (up to 5s)
	{
		std::unique_lock<std::mutex> lock(stepMutex_);
		if (!stepCv_.wait_for(lock, std::chrono::seconds(5),
				[this, threadId]{ return (stepCompleted_ && stepCompletedThread_ == threadId) || !session_.IsAttached(); })) {
			return {{"error", "Step timed out (threadId=" + std::to_string(threadId) + "). Thread may not be stopped or may be deadlocked."}};
		}
		if (!(stepCompleted_ && stepCompletedThread_ == threadId) && !session_.IsAttached()) {
			return {{"error", "Target process exited during step"}};
		}
	}

	return {{"success", true}, {"threadId", threadId},
		{"instructionPointer", (std::ostringstream() << "0x" << std::hex << stepCompletedAddr_).str()}};
}

json McpServer::ToolStepOut(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	session_.ResumeMainThread();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};
	const int timeoutSec = std::clamp(args.value("timeout", 30), 1, 300);
	{
		std::lock_guard<std::mutex> lock(stepMutex_);
		stepCompleted_ = false;
		stepCompletedAddr_ = 0;
		stepCompletedThread_ = 0;
	}

	if (const IpcStatus st = session_.StepOut(threadId); st != IpcStatus::Ok)
		return {{"error", StepRefusedMessage(threadId, st)}};
	// Like step_in: report where the step out stopped. A function can run
	// long before it returns, so the wait is bounded by `timeout`.
	std::unique_lock<std::mutex> lock(stepMutex_);
	if (!stepCv_.wait_for(lock, std::chrono::seconds(timeoutSec), [this, threadId]{
			return (stepCompleted_ && stepCompletedThread_ == threadId) || !session_.IsAttached();
		})) {
		return {{"error", "Step out did not complete within " + std::to_string(timeoutSec) + " s (threadId=" +
			std::to_string(threadId) + "); the thread is still running toward its return."}};
	}
	if (!(stepCompleted_ && stepCompletedThread_ == threadId) && !session_.IsAttached()) {
		return {{"error", "Target process exited during step out"}};
	}
	return {{"success", true}, {"threadId", threadId},
		{"instructionPointer", (std::ostringstream() << "0x" << std::hex << stepCompletedAddr_).str()}};
}

json McpServer::ToolPause(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (!session_.Pause(threadId)) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolThreads(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string error;
	auto threads = session_.GetThreads(&error);
	if (!error.empty()) return {{"error", error}};
	std::vector<uint32_t> frozen;
	session_.FreezeThread(FreezeOp::List, 0, frozen);
	json arr = json::array();
	for (auto& t : threads) {
		json entry = {{"id", t.id}, {"name", t.name}};
		if (std::find(frozen.begin(), frozen.end(), t.id) != frozen.end()) entry["frozen"] = true;
		arr.push_back(std::move(entry));
	}
	return {{"threads", arr}, {"count", threads.size()}};
}

json McpServer::ToolFreezeThread(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	uint32_t threadId = JsonUint32(args, "threadId");
	bool freeze = JsonBool(args, "frozen", true);
	if (freeze && threadId == 0) return {{"error", "threadId is required to freeze (use veh_pause to stop all threads)"}};
	std::vector<uint32_t> frozen;
	bool ok = session_.FreezeThread(freeze ? FreezeOp::Freeze : FreezeOp::Thaw, threadId, frozen);
	json result = {{"frozenThreads", frozen}};
	if (!ok) {
		result["error"] = freeze
			? "freeze failed (thread not found or a debugger-internal thread)"
			: "thread is not frozen";
		return result;
	}
	result["success"] = true;
	return result;
}

} // namespace veh
