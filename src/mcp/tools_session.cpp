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
#include <limits>
#include <stdexcept>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

json McpServer::ToolAttach(const json& args) {
	if (args.contains("logFile") && args["logFile"].is_string()) {
		std::string lf = args["logFile"].get<std::string>();
		if (!lf.empty()) veh::Logger::Instance().SetFile(lf);
	}
	if (session_.IsAttached()) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new attach", session_.GetTargetPid());
		ToolDetach({});
	} else if (session_.GetPipeClient().IsConnected()) {
		LOG_WARN("Stale pipe connection detected, cleaning up");
		session_.GetPipeClient().StopHeartbeat();
		session_.GetPipeClient().StopEventListener();
		session_.GetPipeClient().Disconnect();
	}

	uint32_t pid = JsonUint32(args, "pid");
	if (pid == 0) return {{"error", "pid is required"}};

	if (!session_.Attach(pid)) {
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
	session_.StartProcessMonitor();

	json ret = {{"success", true}, {"pid", pid}, {"message", "Attached to process"}};
	// Include main module info (saves a veh_modules round-trip)
	auto modules = session_.GetModules();
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
	if (session_.IsAttached()) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new launch", session_.GetTargetPid());
		ToolDetach({});
	} else if (session_.GetPipeClient().IsConnected()) {
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
	session_.StartProcessMonitor();

	// stopOnEntry=false: VEH 설치 완료(WaitForReady) 이후에야 메인스레드를 재개한다.
	// (Launch 내부에서 재개하면 핸들러 설치 전 조기 실행 레이스가 생김)
	if (!opts.stopOnEntry) {
		session_.ResumeMainThread();
	}

	json ret = {{"success", true}, {"pid", result.pid}, {"message",
		opts.stopOnEntry ? "Launched and attached (stopped on entry)" : "Launched and attached"}};
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
	session_.Detach();
	return {{"success", true}, {"message", "Detached"}};
}

json McpServer::ToolTerminate(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t pid = session_.GetTargetPid();
	int exitCode = JsonInt(args, "exitCode", 0);
	session_.Terminate(static_cast<uint32_t>(exitCode));
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

	// Check for cached stop event before sending Continue
	if (wait && !passException) {
		auto cached = session_.ConsumeCachedStop();
		if (cached && IsCurrentStopEvent(*cached)) {
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
		if (IsCurrentStopEvent(stopEvent)) break;
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

	if (!session_.StepIn(threadId)) {
		return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
	}

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

	if (!session_.StepOver(threadId)) {
		return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
	}

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

	if (!session_.StepOut(threadId)) {
		return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
	}
	return {{"success", true}, {"threadId", threadId}};
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

	auto threads = session_.GetThreads();
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
