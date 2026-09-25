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

// Returns the PID of our parent process via NtQueryInformationProcess.
static DWORD GetParentPid() {
	typedef LONG(WINAPI* NtQIP_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
	auto NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	if (!NtQIP) return 0;
	ULONG_PTR pbi[6] = {};
	ULONG len = 0;
	if (NtQIP(GetCurrentProcess(), 0 /*ProcessBasicInformation*/, pbi, sizeof(pbi), &len) != 0)
		return 0;
	return (DWORD)pbi[5]; // InheritedFromUniqueProcessId
}

namespace veh {

// JSON args helper: accept both number and string for integer fields.
// AI agents often send "threadId": "12345" instead of "threadId": 12345.




// Eager-profile bits for McpServer::ToolDef::profiles
constexpr unsigned kLite = 1, kInteractive = 2, kCapture = 4, kFullProfile = ~0u;

McpServer::McpServer(std::string toolProfile)
	: toolProfile_(std::move(toolProfile)) {
	StartRetryThread();
}
McpServer::~McpServer() {
	running_ = false;
	// Deferred BP 워커 정리 (session_ 멤버가 아직 유효할 때 stop+join).
	// 단일 영속 워커라 여기서만 join하며, 이후 reader가 NotifyRetry해도 재기동 없음.
	StopRetryThread();
}

void McpServer::SetTransport(dap::Transport* transport) {
	transport_ = transport;
}

void McpServer::Run() {
	if (!transport_) return;
	running_ = true;

	transport_->SetMessageCallback([this](const std::string& msg) {
		OnMessage(msg);
	});

	// Wire up close callback so stdin EOF stops the server loop
	auto* mcpTransport = dynamic_cast<dap::McpStdioTransport*>(transport_);
	if (mcpTransport) {
		mcpTransport->SetCloseCallback([this]() {
			running_ = false;
		});
	}

	if (!transport_->Start()) {
		LOG_ERROR("Transport start failed");
		return;
	}

	// Open parent process handle for exit detection.
	// If stdin is NUL/console (not a pipe), ReadFile never unblocks on parent
	// exit, so we poll the parent handle as a second-layer termination guard.
	HANDLE hParent = NULL;
	DWORD parentPid = GetParentPid();
	if (parentPid) {
		hParent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
		LOG_INFO("Watching parent PID %u for exit", (unsigned)parentPid);
	}

	while (running_) {
		if (hParent && WaitForSingleObject(hParent, 0) == WAIT_OBJECT_0) {
			LOG_INFO("Parent process exited, stopping MCP server");
			running_ = false;
			break;
		}
		FlushEvents();
		Sleep(100);
	}

	if (hParent) CloseHandle(hParent);
	transport_->Stop();
}

void McpServer::Stop() {
	running_ = false;
}

// --- JSON-RPC message handling ---

void McpServer::OnMessage(const std::string& jsonStr) {
	json msg;
	try {
		msg = json::parse(jsonStr);
	} catch (const std::exception& e) {
		LOG_ERROR("JSON parse error: %s", e.what());
		SendError(nullptr, -32700, std::string("Parse error: ") + e.what());
		return;
	}

	json id = msg.contains("id") ? msg["id"] : json(nullptr);

	try {
		LOG_DEBUG("MCP recv: %s", msg.value("method", "").c_str());

		std::string method = msg.value("method", "");
		json params = msg.value("params", json::object());

		if (method == "initialize") {
			OnInitialize(id, params);
		} else if (method == "notifications/initialized") {
			LOG_INFO("Client initialized");
		} else if (method == "tools/list") {
			OnToolsList(id, params);
		} else if (method == "tools/call") {
			OnToolsCall(id, params);
		} else if (method == "ping") {
			SendResult(id, json::object());
		} else if (method == "resources/list" || method == "resources/templates/list" ||
		           method == "prompts/list") {
			if (method == "prompts/list") {
				SendResult(id, {{"prompts", json::array()}});
			} else if (method == "resources/templates/list") {
				SendResult(id, {{"resourceTemplates", json::array()}});
			} else {
				SendResult(id, {{"resources", json::array()}});
			}
		} else {
			if (!id.is_null()) {
				SendError(id, -32601, "Method not found: " + method);
			}
		}
	} catch (const std::exception& e) {
		LOG_ERROR("Message handling error: %s", e.what());
		if (!id.is_null()) {
			SendError(id, -32603, std::string("Internal error: ") + e.what());
		}
	}
}

void McpServer::SendResult(const json& id, const json& result) {
	json msg = {
		{"jsonrpc", "2.0"},
		{"id", id},
		{"result", result}
	};
	std::lock_guard<std::mutex> lock(sendMutex_);
	transport_->Send(msg.dump());
}

void McpServer::SendError(const json& id, int code, const std::string& message) {
	json msg = {
		{"jsonrpc", "2.0"},
		{"id", id},
		{"error", {{"code", code}, {"message", message}}}
	};
	std::lock_guard<std::mutex> lock(sendMutex_);
	transport_->Send(msg.dump());
}

void McpServer::SendNotification(const std::string& method, const json& params) {
	json msg = {
		{"jsonrpc", "2.0"},
		{"method", method},
		{"params", params}
	};
	std::lock_guard<std::mutex> lock(sendMutex_);
	transport_->Send(msg.dump());
}

// --- MCP Protocol Handlers ---

void McpServer::OnInitialize(const json& id, const json& params) {
	json result = {
		{"protocolVersion", "2024-11-05"},
		{"capabilities", {
			{"tools", json::object()}
		}},
		{"serverInfo", {
			{"name", "veh-debugger"},
			{"version", "1.2.0"}
		}},
		{"instructions",
			"Windows x86/x64 in-process debugger. The default lite profile keeps common session tools eager; use veh_toolbox to discover, describe, and call all other tools. veh_batch steps call most tools by name without describe. Inspection requires a stopped target."
		}
	};
	SendResult(id, result);
}

void McpServer::OnToolsList(const json& id, const json& params) {
	SendResult(id, {{"tools", GetToolsList()}});
}

void McpServer::OnToolsCall(const json& id, const json& params) {
	std::thread([this, id, params]() {
		std::string name = params.value("name", "");
		json args = params.value("arguments", json::object());

		LOG_INFO("Tool call: %s", name.c_str());

		try {
			bool known = false;
			json result = DispatchTool(name, args, &known);
			if (!known) {
				SendError(id, -32602, "Unknown tool: " + name);
				return;
			}

		// MCP tool result format -- top-level "error" means the tool failed
		json response = {
			{"content", json::array({
				{{"type", "text"}, {"text", result.dump(2)}}
			})}
		};
		if (result.is_object() && result.contains("error")) response["isError"] = true;
		SendResult(id, response);
		} catch (const std::exception& e) {
			SendResult(id, {
				{"content", json::array({
					{{"type", "text"}, {"text", std::string("Error: ") + e.what()}}
				})},
				{"isError", true}
			});
		}
	}).detach();
}



















void McpServer::ResetSessionEventState() {
	// The previous pipe listener has been stopped before lifecycle code reaches here,
	// and the new listener has not started yet. Clear every session-scoped event cache
	// in this gap so the first command cannot observe the prior process.
	std::scoped_lock lock(eventMutex_, exceptionMutex_, stepMutex_, filterMutex_,
		session_.GetBpMutex());
	session_.ResetStopState();
	pendingEvents_ = {};
	pendingAutoContinue_ = {};
	pendingBreakpointActions_ = {};
	tempStepOverBpId_ = 0;
	stepCompleted_ = false;
	stepCompletedAddr_ = 0;
	stepCompletedThread_ = 0;
	lastException_ = {};
	ignoreExceptionCodes_.clear();
	bpActions_.clear();
	{
		std::lock_guard<std::mutex> checkpointLock(checkpointMutex_);
		checkpoints_.clear();
		checkpointBytes_ = 0;
	}
}

bool McpServer::IsCurrentStopEvent(const StopEvent& event) {
	if (event.sessionGeneration != 0 &&
		event.sessionGeneration != session_.GetSessionGeneration()) {
		LOG_WARN("Discarding stop event from session generation %llu (current %llu)",
			static_cast<unsigned long long>(event.sessionGeneration),
			static_cast<unsigned long long>(session_.GetSessionGeneration()));
		return false;
	}
	if (event.threadId == 0) return true; // pause/exit events intentionally have no TID
	if (session_.IsThreadOwnedByTarget(event.threadId)) return true;

	LOG_WARN("Discarding stale stop event '%s': TID %u does not belong to current PID %u",
		event.reason.c_str(), event.threadId, session_.GetTargetPid());
	return false;
}
























// Shared range arguments: start/end addresses or a module name (whole image range).

































// --- Event Queue Flush ---

void McpServer::FlushEvents() {
	std::queue<std::pair<std::string, json>> events;
	std::queue<uint32_t> autoContinues;
	std::queue<PendingBreakpointAction> actions;
	{
		std::lock_guard<std::mutex> lock(eventMutex_);
		std::swap(events, pendingEvents_);
		std::swap(autoContinues, pendingAutoContinue_);
		std::swap(actions, pendingBreakpointActions_);
	}
	while (!events.empty()) {
		auto& [method, params] = events.front();
		SendNotification(method, params);
		events.pop();
	}
	// Never run action commands on PipeClient's sole reader thread: commands such as
	// SetBreakpoint need that thread to receive their response. Running here also
	// allows actions to install breakpoints (including breakpoints with actions).
	while (!actions.empty()) {
		auto pending = std::move(actions.front());
		actions.pop();
		BatchExecutor executor = NewBatchExecutor();
		json result = executor.Execute(pending.steps);
		if (result.dump().find("\"error\"") != std::string::npos) {
			LOG_WARN("Breakpoint action completed with an error: %s", result.dump().c_str());
		}
		// Actions auto-continue by contract. An explicit veh_continue as the last
		// action step is harmless; a second resume finds no stopped event.
		if (!session_.Continue(pending.threadId)) {
			LOG_WARN("Breakpoint action auto-continue failed for thread %u", pending.threadId);
		}
	}
	while (!autoContinues.empty()) {
		uint32_t tid = autoContinues.front();
		autoContinues.pop();
		if (!session_.Continue(tid)) {
			LOG_WARN("Auto-continue failed for thread %u", tid);
		}
	}
}

void McpServer::StoreBreakpointAction(uint32_t breakpointId, const json& action) {
	std::lock_guard<std::mutex> lock(session_.GetBpMutex());
	if (action.is_array() && !action.empty()) bpActions_[breakpointId] = action;
	else bpActions_.erase(breakpointId);
}

// --- Condition/LogMessage helpers ---

bool McpServer::EvaluateCondition(const std::string& condition, uint32_t threadId, const RegisterSet* cachedRegs) {
	struct { const char* op; size_t len; } ops[] = {
		{"==", 2}, {"!=", 2}, {">=", 2}, {"<=", 2}, {">", 1}, {"<", 1},
	};
	std::string lhs, rhs, opStr;
	for (auto& [op, len] : ops) {
		auto pos = condition.find(op);
		if (pos != std::string::npos) {
			lhs = condition.substr(0, pos);
			rhs = condition.substr(pos + len);
			opStr = op;
			break;
		}
	}
	if (opStr.empty() || lhs.empty() || rhs.empty()) return true;

	auto trim = [](std::string& s) {
		while (!s.empty() && s.front() == ' ') s.erase(s.begin());
		while (!s.empty() && s.back() == ' ') s.pop_back();
	};
	trim(lhs); trim(rhs);

	// Resolve an operand to a value. Returns false when it cannot be resolved, so the
	// caller fail-safes (stops) instead of silently comparing garbage and free-running.
	// Callback-thread safe: cachedRegs + ReadProcessMemory only (no reentrant IPC).
	auto resolveVal = [&](const std::string& tok, uint64_t& out) -> bool {
		if (tok.empty()) return false;
		if (tok[0] == '*' || tok[0] == '[') {
			std::string inner = tok.substr(1);
			if (!inner.empty() && inner.back() == ']') inner.pop_back();
			trim(inner);
			uint64_t addr = 0;
			if (!DebugSession::ResolveAddrExpr(inner, cachedRegs, addr)) return false;
			uint64_t val = 0;
			SIZE_T bytesRead = 0;
			HANDLE hProc = session_.GetTargetProcess();
			if (hProc && ReadProcessMemory(hProc, (LPCVOID)addr, &val, 8, &bytesRead) && bytesRead == 8) {
				out = val;
				return true;
			}
			return false;
		}
		if (DebugSession::TryParseRegisterName(tok)) {
			if (!cachedRegs) return false;
			out = DebugSession::ResolveRegisterByName(tok, *cachedRegs);
			return true;
		}
		// Full-consume check: a partial parse (e.g. "0x12+0x1") is an unsupported operand,
		// so report unresolved and let the caller fail-safe (stop) instead of comparing garbage.
		try { size_t pos; out = std::stoull(tok, &pos, 0); return pos == tok.size(); } catch (...) { return false; }
	};

	uint64_t lhsVal = 0, rhsVal = 0;
	if (!resolveVal(lhs, lhsVal) || !resolveVal(rhs, rhsVal)) {
		// Unresolvable operand -> fail-safe: stop so the user notices, never a silent free-run.
		return true;
	}

	if (opStr == "==") return lhsVal == rhsVal;
	if (opStr == "!=") return lhsVal != rhsVal;
	if (opStr == ">=") return lhsVal >= rhsVal;
	if (opStr == "<=") return lhsVal <= rhsVal;
	if (opStr == ">")  return lhsVal > rhsVal;
	if (opStr == "<")  return lhsVal < rhsVal;
	return true;
}

std::string McpServer::ExpandLogMessage(const std::string& msg, uint32_t threadId, const RegisterSet* cachedRegs) {
	std::string result;
	result.reserve(msg.size());
	size_t i = 0;
	while (i < msg.size()) {
		if (msg[i] == '{') {
			auto end = msg.find('}', i + 1);
			if (end == std::string::npos) { result += msg[i++]; continue; }
			std::string expr = msg.substr(i + 1, end - i - 1);
			while (!expr.empty() && expr.front() == ' ') expr.erase(expr.begin());
			while (!expr.empty() && expr.back() == ' ') expr.pop_back();

			char buf[32];
			if (DebugSession::TryParseRegisterName(expr) && cachedRegs) {
				uint64_t val = DebugSession::ResolveRegisterByName(expr, *cachedRegs);
				if (cachedRegs->is32bit)
					snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
				else
					snprintf(buf, sizeof(buf), "0x%016llX", val);
				result += buf;
			} else if (!expr.empty() && (expr[0] == '*' || expr[0] == '[')) {
				std::string addrStr = expr.substr(1);
				if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
				try {
					uint64_t addr = std::stoull(addrStr, nullptr, 0);
					uint64_t val = 0;
					SIZE_T bytesRead = 0;
					HANDLE hProc = session_.GetTargetProcess();
					if (hProc && ReadProcessMemory(hProc, (LPCVOID)addr, &val, 8, &bytesRead) && bytesRead >= 8) {
						snprintf(buf, sizeof(buf), "0x%016llX", val);
						result += buf;
					} else {
						result += "???";
					}
				} catch (...) {
					result += "???";
				}
			} else {
				result += '{'; result += expr; result += '}';
			}
			i = end + 1;
		} else {
			result += msg[i++];
		}
	}
	return result;
}

// --- StepOver CALL skip helpers ---

bool McpServer::SetTempBpAndContinue(uint64_t address) {
	auto bpResult = session_.SetBreakpoint(address);
	if (bpResult.ok) {
		{
			std::lock_guard<std::mutex> lock(eventMutex_);
			tempStepOverBpId_ = bpResult.id;
		}
		session_.Continue(0);
		return true;
	}
	return false;
}

bool McpServer::IsNextInstructionCall(uint32_t threadId, uint64_t& addrAfterCall) {
	auto frames = session_.GetStackTrace(threadId, 1);
	if (frames.empty()) return false;
	uint64_t rip = frames[0].address;

	// Check if this address has a BP (only relevant for BP rearm case)
	bool onBp = false;
	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		for (const auto& bp : session_.GetSwBreakpoints()) {
			if (bp.address == rip) { onBp = true; break; }
		}
	}
	if (!onBp) return false;

	// Read memory at RIP (BP-masked) and disassemble 2 instructions
	auto mem = session_.ReadMemory(rip, 32);
	if (mem.empty()) return false;

	auto* disasm = session_.GetDisassembler();
	if (!disasm) return false;
	auto insns = disasm->Disassemble(mem.data(), (uint32_t)mem.size(), rip, 2);
	if (insns.size() < 2) return false;

	const auto& insn = insns[1];
	if (insn.mnemonic.size() >= 4
		&& (insn.mnemonic[0] == 'c' || insn.mnemonic[0] == 'C')
		&& (insn.mnemonic[1] == 'a' || insn.mnemonic[1] == 'A')
		&& (insn.mnemonic[2] == 'l' || insn.mnemonic[2] == 'L')
		&& (insn.mnemonic[3] == 'l' || insn.mnemonic[3] == 'L')) {
		addrAfterCall = rip + insns[0].length + insn.length;
		LOG_DEBUG("IsNextInstructionCall: RIP=0x%llX, next insn at 0x%llX is CALL, after=0x%llX",
			rip, rip + insns[0].length, addrAfterCall);
		return true;
	}
	return false;
}

bool McpServer::IsCallInstruction(uint32_t threadId, uint64_t& nextInsnAddr) {
	auto frames = session_.GetStackTrace(threadId, 1);
	if (frames.empty()) return false;
	uint64_t rip = frames[0].address;

	auto mem = session_.ReadMemory(rip, 16);
	if (mem.empty()) return false;

	auto* disasm = session_.GetDisassembler();
	if (!disasm) return false;
	auto insns = disasm->Disassemble(mem.data(), (uint32_t)mem.size(), rip, 1);
	if (insns.empty()) return false;

	const auto& insn = insns[0];
	if (insn.mnemonic.size() >= 4
		&& (insn.mnemonic[0] == 'c' || insn.mnemonic[0] == 'C')
		&& (insn.mnemonic[1] == 'a' || insn.mnemonic[1] == 'A')
		&& (insn.mnemonic[2] == 'l' || insn.mnemonic[2] == 'L')
		&& (insn.mnemonic[3] == 'l' || insn.mnemonic[3] == 'L')) {
		nextInsnAddr = rip + insn.length;
		LOG_DEBUG("IsCallInstruction: RIP=0x%llX -> CALL detected, next=0x%llX", rip, nextInsnAddr);
		return true;
	}
	return false;
}

void McpServer::CleanupTempStepOverBp() {
	uint32_t tempId = 0;
	{
		std::lock_guard<std::mutex> lock(eventMutex_);
		tempId = tempStepOverBpId_;
		tempStepOverBpId_ = 0;
	}
	if (tempId != 0) {
		session_.RemoveBreakpoint(tempId);
		LOG_DEBUG("CleanupTempStepOverBp: removed temp BP #%u", tempId);
	}
}

// --- Deferred BP retry (worker thread) ---

// Deferred BP: 단일 영속 워커 + condvar.
void McpServer::StartRetryThread() {
	retryStop_ = false;
	retryThread_ = std::thread(&McpServer::RetryThreadLoop, this);
}

void McpServer::StopRetryThread() {
	{
		std::lock_guard<std::mutex> lk(retryMutex_);
		retryStop_ = true;
	}
	retryCv_.notify_one();
	if (retryThread_.joinable()) retryThread_.join();
}

// reader 스레드(ModuleLoaded)에서 호출: BP 락이나 std::thread 객체를 건드리지 않고
// wake signal만 보낸다 -> reader/tool/main 스레드 간 thread 객체 race 원천 차단.
void McpServer::NotifyRetry() {
	{
		std::lock_guard<std::mutex> lk(retryMutex_);
		retryWake_ = true;
	}
	retryCv_.notify_one();
}

void McpServer::RetryThreadLoop() {
	for (;;) {
		{
			std::unique_lock<std::mutex> lk(retryMutex_);
			retryCv_.wait(lk, [this] { return retryWake_ || retryStop_; });
			if (retryStop_) return;
			retryWake_ = false;   // 처리 중 새 signal이 오면 다시 set됨(lost-wakeup 방지)
		}
		try {
			RetryPendingBreakpointsOnce();
		} catch (...) {
			LOG_ERROR("RetryPendingBreakpointsOnce threw");
		}
	}
}

// pending BP를 DLL 심볼로 재해석하고, 성공하면 실제 BP 설정 +
// notifications/logging으로 통지한다 (에이전트는 veh_list_breakpoints로도 확인 가능).
// 워커 스레드에서만 호출되므로 IPC(SendAndReceive)를 안전하게 쓸 수 있다.
void McpServer::RetryPendingBreakpointsOnce() {
	for (;;) {
		if (!session_.IsAttached()) return;

		struct Retry { bool isFunc; std::string source; uint32_t line; std::string functionName; };
		std::vector<Retry> todo;
		{
			std::lock_guard<std::mutex> lock(session_.GetBpMutex());
			for (auto& bp : session_.GetSwBreakpoints()) {
				if (!bp.pending) continue;
				todo.push_back({!bp.functionName.empty(), bp.source, bp.line, bp.functionName});
			}
		}
		if (todo.empty()) return;

		bool anyResolved = false;
		for (auto& r : todo) {
			uint64_t addr = r.isFunc ? session_.ResolveFunction(r.functionName)
			                         : session_.ResolveSourceLine(r.source, r.line);
			if (addr == 0) continue;  // 아직 해석 불가 (이 모듈이 아님)

			auto bpResult = session_.SetBreakpoint(addr);
			if (!bpResult.ok) continue;

			bool updated = false;
			{
				std::lock_guard<std::mutex> lock(session_.GetBpMutex());
				for (auto& bp : session_.GetSwBreakpoints()) {
					if (!bp.pending) continue;
					bool match = r.isFunc ? (bp.functionName == r.functionName)
					                      : (bp.source == r.source && bp.line == r.line);
					if (match) {
						bp.id = bpResult.id;
						bp.address = addr;
						bp.pending = false;
						updated = true;
						break;
					}
				}
			}
			if (!updated) {
				// 매핑이 사라짐(동시 재설정) -> 방금 설정한 BP 정리
				session_.RemoveBreakpoint(bpResult.id);
				continue;
			}
			anyResolved = true;

			std::string label = r.isFunc ? r.functionName : (r.source + ":" + std::to_string(r.line));
			char buf[320];
			snprintf(buf, sizeof(buf), "Deferred breakpoint #%u bound: %s -> 0x%llX",
				bpResult.id, label.c_str(), addr);
			std::lock_guard<std::mutex> lock(eventMutex_);
			pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
		}
		if (!anyResolved) return;  // 이번 라운드에 아무것도 못 풀면 종료
	}
}

// --- IPC Event Handler ---

void McpServer::OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size) {
	auto evt = static_cast<IpcEvent>(eventId);

	switch (evt) {
	case IpcEvent::BreakpointHit: {
		if (size >= sizeof(BreakpointHitEvent)) {
			auto* e = reinterpret_cast<const BreakpointHitEvent*>(payload);

			// Check if this is our temp step-over breakpoint
			bool isTempBp = false;
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				if (tempStepOverBpId_ != 0 && e->breakpointId == tempStepOverBpId_) {
					isTempBp = true;
				}
			}

			if (isTempBp) {
				char buf[128];
				snprintf(buf, sizeof(buf), "Step completed at 0x%llX (thread %u)",
					e->address, e->threadId);
				{
					std::lock_guard<std::mutex> lock(eventMutex_);
					pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
				}
			} else {
				// Look up BpMapping for condition/hitCondition/logMessage
				bool shouldStop = true;
				std::string logOutput;
				{
					std::lock_guard<std::mutex> lock(session_.GetBpMutex());
					for (auto& bp : session_.GetSwBreakpoints()) {
						if (bp.id == e->breakpointId) {
							bp.hitCount++;

							if (!bp.condition.empty()) {
								if (!EvaluateCondition(bp.condition, e->threadId, &e->regs)) {
									shouldStop = false;
									break;
								}
							}

							if (!bp.hitCondition.empty()) {
								try {
									uint32_t target = std::stoul(bp.hitCondition);
									if (bp.hitCount < target) {
										shouldStop = false;
										break;
									}
								} catch (...) {}
							}

							if (!bp.logMessage.empty()) {
								logOutput = ExpandLogMessage(bp.logMessage, e->threadId, &e->regs);
								shouldStop = false;
							}
							break;
						}
					}

					// Hardware data breakpoint: condition / hit-skip filter.
					// 'value' 토큰 = 감시 주소의 현재 값 (예: 'value != 0' -> 0 쓰기 노이즈 무시)
					for (auto& bp : session_.GetHwBreakpoints()) {
						if (bp.id != e->breakpointId) continue;
						bp.hitCount++;
						if (!bp.condition.empty()) {
							std::string cond = bp.condition;
							bool canEval = true;
							// 'value' 토큰 = 감시 주소에서 size 바이트 읽은 현재 값.
							// 이벤트 콜백 스레드이므로 IPC ReadMemory(재진입 불가) 대신 ReadProcessMemory 사용.
							if (cond.find("value") != std::string::npos) {
								uint32_t rsz = bp.size ? bp.size : 8;
								if (rsz > 8) rsz = 8;
								uint64_t cv = 0;
								SIZE_T rgot = 0;
								HANDLE hp = session_.GetTargetProcess();
								if (!hp || !ReadProcessMemory(hp, (LPCVOID)bp.address, &cv, rsz, &rgot) || rgot != rsz) {
									// 값을 못 읽으면 조건 판단 불가 -> cv=0 로 오판(거짓 정지/거짓 통과) 방지, 안전하게 정지 유지
									canEval = false;
								} else {
									char lit[24]; snprintf(lit, sizeof(lit), "0x%llX", (unsigned long long)cv);
									for (size_t p = cond.find("value"); p != std::string::npos; p = cond.find("value", p)) {
										bool lb = (p == 0) || !(isalnum((unsigned char)cond[p-1]) || cond[p-1] == '_');
										size_t rpos = p + 5;
										bool rb = (rpos >= cond.size()) || !(isalnum((unsigned char)cond[rpos]) || cond[rpos] == '_');
										if (lb && rb) { cond.replace(p, 5, lit); p += strlen(lit); }
										else p = rpos;
									}
								}
							}
							if (canEval && !EvaluateCondition(cond, e->threadId, &e->regs)) shouldStop = false;
						}
						if (shouldStop && !bp.hitCondition.empty()) {
							try {
								uint32_t target = std::stoul(bp.hitCondition);
								if (bp.hitCount < target) shouldStop = false;
							} catch (...) {}
						}
						break;
					}
				}

				if (!shouldStop) {
					std::lock_guard<std::mutex> lock(eventMutex_);
					if (!logOutput.empty()) {
						pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "logpoint"}, {"data", logOutput}}});
					}
					pendingAutoContinue_.push(e->threadId);
				} else {
					// Check for BP action (auto-execute commands on hit)
					json action;
					{
						std::lock_guard<std::mutex> lock(session_.GetBpMutex());
						auto ait = bpActions_.find(e->breakpointId);
						if (ait != bpActions_.end()) action = ait->second;
					}

					if (!action.empty() && action.is_array()) {
						// Queue action for McpServer::Run. OnIpcEvent executes on the pipe's
						// sole reader thread, so synchronous action IPC here would deadlock
						// waiting for a response that only this thread can receive.
						char buf[128];
						snprintf(buf, sizeof(buf), "BP #%u action executing at 0x%llX (thread %u)",
							e->breakpointId, e->address, e->threadId);
						{
							std::lock_guard<std::mutex> lock(eventMutex_);
							pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
						}
						{
							std::lock_guard<std::mutex> lock(eventMutex_);
							pendingBreakpointActions_.push({e->threadId, std::move(action)});
						}
					} else {
						// Normal stop
						char buf[128];
						snprintf(buf, sizeof(buf), "Breakpoint #%u hit at 0x%llX (thread %u)",
							e->breakpointId, e->address, e->threadId);
						{
							std::lock_guard<std::mutex> lock(eventMutex_);
							pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
						}
						std::string bpType;
						if (e->breakpointId >= 10001) bpType = "hardware";
						else if (e->breakpointId > 0) bpType = "software";

						session_.SignalStop("breakpoint", e->address, e->threadId, e->breakpointId, bpType);
					}
				}
			}
		}
		break;
	}
	case IpcEvent::StepCompleted: {
		if (size >= sizeof(StepCompletedEvent)) {
			auto* e = reinterpret_cast<const StepCompletedEvent*>(payload);
			char buf[128];
			snprintf(buf, sizeof(buf), "Step completed at 0x%llX (thread %u)",
				e->address, e->threadId);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			// Signal synchronous step waiters.
			{
				std::lock_guard<std::mutex> lock(stepMutex_);
				stepCompleted_ = true;
				stepCompletedAddr_ = e->address;
				stepCompletedThread_ = e->threadId;
			}
			stepCv_.notify_all();
		}
		break;
	}
	case IpcEvent::HeartbeatAck:
		break;
	case IpcEvent::Ready:
		LOG_INFO("VEH DLL ready");
		break;
	case IpcEvent::Paused: {
		{
			std::lock_guard<std::mutex> lock(eventMutex_);
			pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", "Target paused"}}});
		}
		session_.SignalStop("pause", 0, 0, 0);
		break;
	}
	case IpcEvent::ProcessExited: {
		if (size >= sizeof(ProcessExitEvent)) {
			auto* e = reinterpret_cast<const ProcessExitEvent*>(payload);
			char buf[64];
			snprintf(buf, sizeof(buf), "Process exited (code=%u)", e->exitCode);
			LOG_INFO("%s", buf);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			session_.SignalStop("exit", 0, 0, 0);
		}
		break;
	}
	case IpcEvent::ExceptionOccurred: {
		if (size >= sizeof(ExceptionEvent)) {
			auto* e = reinterpret_cast<const ExceptionEvent*>(payload);
			{
				std::lock_guard<std::mutex> lock(exceptionMutex_);
				lastException_.threadId = e->threadId;
				lastException_.code = e->exceptionCode;
				lastException_.address = e->address;
				lastException_.description = e->description;
			}

			// Check exception filter: auto-pass if code is in ignore list
			bool autoPass = false;
			{
				std::lock_guard<std::mutex> lock(filterMutex_);
				for (auto code : ignoreExceptionCodes_) {
					if (code == e->exceptionCode) { autoPass = true; break; }
				}
			}
			if (autoPass) {
				char buf[384];
				snprintf(buf, sizeof(buf), "Exception 0x%08X auto-passed (filter) at 0x%llX (thread %u)",
					e->exceptionCode, e->address, e->threadId);
				{
					std::lock_guard<std::mutex> lock(eventMutex_);
					pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
				}
				// Auto-continue with pass_exception=true
				session_.Continue(e->threadId, true);
				break;
			}

			char buf[384];
			snprintf(buf, sizeof(buf), "Exception 0x%08X at 0x%llX (thread %u): %s",
				e->exceptionCode, e->address, e->threadId, e->description);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "warning"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			session_.SignalStop("exception", e->address, e->threadId, 0);
		}
		break;
	}
	case IpcEvent::ModuleLoaded: {
		// 새 모듈 심볼로 pending(deferred) BP 재해석. 이 콜백은 reader 스레드이므로
		// SendAndReceive/락 직접 호출 금지 -> NotifyRetry로 wake signal만, 영속 워커가 처리.
		NotifyRetry();
		break;
	}
	case IpcEvent::ModuleLoadStopped: {
		if (size >= sizeof(ModuleLoadStopEvent)) {
			auto* e = reinterpret_cast<const ModuleLoadStopEvent*>(payload);
			char buf[320];
			snprintf(buf, sizeof(buf), "Stopped at module load: %s (base 0x%llX, thread %u)",
				e->name, (unsigned long long)e->baseAddress, e->threadId);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			session_.SignalStop("module-load", e->baseAddress, e->threadId, 0, e->name);
		}
		break;
	}
	case IpcEvent::Error:
		LOG_ERROR("VEH DLL error event received");
		break;
	default:
		LOG_DEBUG("IPC event: 0x%04X", eventId);
		break;
	}
}

// --- Helpers ---

bool McpServer::ParseAddress(const std::string& addrStr, uint64_t& out) {
	std::string s = addrStr;
	while (!s.empty() && s.front() == ' ') s.erase(s.begin());
	while (!s.empty() && s.back() == ' ') s.pop_back();
	if (s.empty()) return false;

	auto parseNum = [](const std::string& t, uint64_t& v) -> bool {
		if (t.empty()) return false;
		try { size_t pos; v = std::stoull(t, &pos, 0); return pos == t.size(); }
		catch (...) { return false; }
	};
	auto trimTok = [](std::string t) {
		while (!t.empty() && t.front() == ' ') t.erase(t.begin());
		while (!t.empty() && t.back() == ' ') t.pop_back();
		return t;
	};

	// 1) Plain hex/decimal address (fully consumed).
	if (parseNum(s, out)) return true;

	// 2) '+' form: module+RVA ("crackme.exe+0x1000") or literal arithmetic ("0x1000+0x34").
	//    Fully-numeric left => arithmetic; otherwise treat left as a module name.
	auto plusPos = s.find('+');
	if (plusPos != std::string::npos && plusPos > 0) {
		std::string left = trimTok(s.substr(0, plusPos));
		std::string right = trimTok(s.substr(plusPos + 1));
		uint64_t rv;
		if (!parseNum(right, rv)) return false;  // offset/RVA must be numeric
		uint64_t lv;
		if (parseNum(left, lv)) {  // literal arithmetic
			uint64_t r = lv + rv;
			if (r < lv) return false;  // overflow -> reject rather than wrap to a bogus address
			out = r; return true;
		}
		if (session_.IsAttached()) {
			auto toLo = [](char c) { return (char)::tolower((unsigned char)c); };
			std::string modLower = left;
			std::transform(modLower.begin(), modLower.end(), modLower.begin(), toLo);
			for (auto& m : session_.GetModules()) {
				std::string nameLower = m.name;
				std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), toLo);
				if (nameLower == modLower) { out = m.baseAddress + rv; return true; }
			}
		}
		return false;  // module not found
	}

	// 3) '-' form: literal subtraction only ("0x1000-0x10"). A module name may itself
	//    contain '-', so require both sides to be pure numbers before treating it as math.
	auto minusPos = s.find('-', 1);
	if (minusPos != std::string::npos) {
		uint64_t lv, rv;
		if (parseNum(trimTok(s.substr(0, minusPos)), lv) &&
		    parseNum(trimTok(s.substr(minusPos + 1)), rv)) {
			if (rv > lv) return false;  // underflow -> reject rather than wrap
			out = lv - rv;
			return true;
		}
	}
	return false;
}

// --- Tool List Definition ---

std::vector<McpServer::ToolDef> McpServer::BuildAllToolsList() {
	std::vector<ToolDef> tools = {
		Tool(&McpServer::ToolAttach, "session", kLite | kInteractive, false,
			{{"name", "veh_attach"}, {"description", "Attach to a running process by PID. Injects VEH debugger DLL. Auto-detaches if already attached. Target process must be running (not CREATE_SUSPENDED)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"pid", {{"type", "integer"}, {"description", "Process ID to attach to"}}},
			{"logFile", {{"type", "string"}, {"description", "Enable server-side logging to this file path (e.g. 'veh-mcp.log'). Omit to disable logging."}}}
		 }}, {"required", json::array({"pid"})}}}}),

		Tool(&McpServer::ToolLaunch, "session", kLite | kInteractive | kCapture, false,
			{{"name", "veh_launch"}, {"description", "Launch a program and attach the debugger. Auto-detaches if already attached. Handles CREATE_SUSPENDED internally."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"program", {{"type", "string"}, {"description", "Path to executable"}}},
			{"args", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Command line arguments"}}},
			{"cwd", {{"type", "string"}, {"description", "Working directory for the target process. Omit to inherit the debugger's current directory. Use this when the program loads config/resources/DLLs by relative path from its own folder."}}},
			{"env", {{"type", "object"}, {"description", "Environment variables for the target, applied on top of the inherited parent environment (e.g. {\"ORACLE_M4_HOME\":\"C:/oracle\"}). Enables debugging headless processes configured via env vars. Also accepts an array of \"KEY=VALUE\" strings."}}},
			{"stopOnEntry", {{"type", "boolean"}, {"description", "Stop at entry point (default: true)"}}},
			{"runAsInvoker", {{"type", "boolean"}, {"description", "Bypass UAC elevation prompt by setting __COMPAT_LAYER=RunAsInvoker (default: false)"}}},
			{"injectionMethod", {{"type", "string"}, {"enum", json::array({"auto", "createRemoteThread", "ntCreateThreadEx", "threadHijack", "queueUserApc"})}, {"description", "DLL injection method (default: auto). Auto tries all methods in order."}}},
			{"logFile", {{"type", "string"}, {"description", "Enable server-side logging to this file path (e.g. 'veh-mcp.log'). Omit to disable logging."}}}
		 }}, {"required", json::array({"program"})}}}}),

		Tool(&McpServer::ToolDetach, "session", 0, false,
			{{"name", "veh_detach"}, {"description", "Detach debugger from the target process (leaves it running)."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}),

		Tool(&McpServer::ToolTerminate, "session", kLite | kInteractive | kCapture, false,
			{{"name", "veh_terminate"}, {"description", "Kill the target process from inside (the injected DLL calls TerminateProcess on its own process). Works even on self-protected targets that deny external OpenProcess/taskkill (deny-DACL or higher integrity), because a process's own-handle always has terminate rights. Detaches afterward. Use this instead of the WM_CLOSE->detach->taskkill dance."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"exitCode", {{"type", "integer"}, {"description", "Process exit code (default: 0)"}}}
		 }}}}}),

		Tool(&McpServer::ToolSetBreakpoint, "breakpoint", kInteractive, true,
			{{"name", "veh_set_breakpoint"}, {"description", "Set a software breakpoint (INT3) at an address. Supports module+RVA (e.g. 'crackme.exe+0x1000'). Duplicate address returns existing BP id. Use 'action' to auto-execute commands on hit (no agent intervention needed)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Address: hex (0x7FF600001000) or module+RVA (crackme.exe+0x1000)"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression (e.g. 'RAX==0x1000', 'RCX>5'). BP only fires when true."}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold. BP fires only on Nth hit (e.g. '5' = fire on 5th hit)."}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint). Use {expr} for interpolation (e.g. 'x={RAX}'). Does NOT stop execution."}}},
			{"action", {{"type", "array"}, {"items", {{"oneOf", json::array({json{{"type", "object"}}, json{{"type", "string"}}})}}}, {"description", "Auto-execute on BP hit (same format as veh_batch steps). Items may be step objects or JSON-encoded object strings. After action, auto-continues. Example: [{\"tool\":\"veh_set_register\",\"args\":{\"threadId\":0,\"name\":\"RAX\",\"value\":\"1\"}}]"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolRemoveBreakpoint, "breakpoint", 0, true,
			{{"name", "veh_remove_breakpoint"}, {"description", "Remove a software breakpoint by ID."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"type", "integer"}, {"description", "Breakpoint ID from veh_set_breakpoint"}}}
		 }}, {"required", json::array({"id"})}}}}),

		Tool(&McpServer::ToolSetSourceBreakpoint, "breakpoint", 0, true,
			{{"name", "veh_set_source_breakpoint"}, {"description", "Set a breakpoint by source file and line number. Requires PDB symbols. If the symbol's module is not loaded yet, the breakpoint is kept pending (response has pending:true) and auto-binds when the module loads -- poll veh_list_breakpoints (status: pending|active). This is normal, not an error."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"source", {{"type", "string"}, {"description", "Source file path (e.g. 'main.cpp', 'src/app.cpp')"}}},
			{"line", {{"type", "integer"}, {"description", "Line number in the source file"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression (e.g. 'RAX==0x1000')"}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold"}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint)"}}}
		 }}, {"required", json::array({"source", "line"})}}}}),

		Tool(&McpServer::ToolSetFunctionBreakpoint, "breakpoint", 0, true,
			{{"name", "veh_set_function_breakpoint"}, {"description", "Set a breakpoint at the entry of a function by name. Requires PDB symbols. If the function's module is not loaded yet, the breakpoint is kept pending (response has pending:true) and auto-binds when the module loads -- poll veh_list_breakpoints (status: pending|active). This is normal, not an error."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"name", {{"type", "string"}, {"description", "Function name (e.g. 'main', 'MyClass::DoSomething')"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression"}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold"}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint)"}}}
		 }}, {"required", json::array({"name"})}}}}),

		Tool(&McpServer::ToolListBreakpoints, "breakpoint", 0, true,
			{{"name", "veh_list_breakpoints"}, {"description", "List all active software and hardware breakpoints with their properties."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}),

		Tool(&McpServer::ToolSetDataBreakpoint, "breakpoint", kInteractive, true,
			{{"name", "veh_set_data_breakpoint"}, {"description", "Set a hardware data breakpoint (DR0-DR3). Like Cheat Engine's 'Find out what writes/accesses'. Max 4 simultaneous. Supports condition/hitCondition to filter noisy writes (e.g. a clear-helper writing 0)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address to watch (also accepts module+RVA)"}}},
			{"type", {{"type", "string"}, {"enum", json::array({"write", "readwrite", "execute"})}, {"description", "Breakpoint type (default: write)"}}},
			{"size", {{"type", "integer"}, {"enum", json::array({1, 2, 4, 8})}, {"description", "Watch size in bytes (default: 4)"}}},
			{"condition", {{"type", "string"}, {"description", "Only stop when true. Token 'value' = current value at the watched address (e.g. 'value != 0' skips zero-writes; 'value > 100'). Registers and [0xADDR] deref also allowed."}}},
			{"hitCondition", {{"type", "string"}, {"description", "Stop only on the Nth hit (skips first N-1). E.g. '5' = stop on 5th write."}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolRemoveDataBreakpoint, "breakpoint", 0, true,
			{{"name", "veh_remove_data_breakpoint"}, {"description", "Remove a hardware data breakpoint by ID."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"type", "integer"}, {"description", "Data breakpoint ID"}}}
		 }}, {"required", json::array({"id"})}}}}),

		Tool(&McpServer::ToolContinue, "session", kLite | kInteractive | kCapture, true,
			{{"name", "veh_continue"}, {"description", "Continue execution. threadId=0 resumes all debugger-stopped threads; threadId=X resumes only X and leaves the others stopped. Every executed continue reports resumedThreadIds and stillStoppedThreadIds. Use wait=true to block until a breakpoint hit, exception, pause, or process exit occurs (returns stop reason, address, threadId). Use pass_exception=true to forward the current exception to the process's own SEH handler (for CFF/obfuscated INT3, etc.). Default timeout 10s, configurable."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "Thread ID (0 = resume all debugger-stopped threads; nonzero = resume only that thread and keep all others stopped; default: 0)"}}},
			{"wait", {{"type", "boolean"}, {"description", "If true, block until target stops (breakpoint/exception/pause/exit). Default: false"}}},
			{"timeout", {{"type", "integer"}, {"description", "Max seconds to wait when wait=true (1-300, default: 10)"}}},
			{"pass_exception", {{"type", "boolean"}, {"description", "If true, pass the current exception to the process's SEH handler instead of handling it. Use for CFF/obfuscated code with INT3. Default: false"}}},
			{"ignore_exceptions", {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Exception codes to auto-pass to SEH (persistent until changed). E.g. [2147483651] for INT3 (0x80000003). Filters exceptions while catching real crashes."}}}
		 }}}}}),

		Tool(&McpServer::ToolStepIn, "session", 0, true,
			{{"name", "veh_step_in"}, {"description", "Single step into (execute one instruction, entering calls). Waits for completion and returns the new instruction pointer."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolStepOver, "session", 0, true,
			{{"name", "veh_step_over"}, {"description", "Step over (execute one instruction, skipping calls). Waits for completion and returns the new instruction pointer."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolStepOut, "session", 0, true,
			{{"name", "veh_step_out"}, {"description", "Step out (run until current function returns)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolPause, "session", 0, true,
			{{"name", "veh_pause"}, {"description", "Pause execution. threadId=0 pauses all threads."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "Thread ID (0 = all)"}}}
		 }}}}}),

		Tool(&McpServer::ToolThreads, "session", 0, true,
			{{"name", "veh_threads"}, {"description", "List all threads in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}),

		Tool(&McpServer::ToolFreezeThread, "session", 0, true,
			{{"name", "veh_freeze_thread"}, {"description", "Freeze or thaw one thread. A frozen thread stays suspended across veh_continue until thawed (or detach), e.g. to hold a watchdog or worker thread while the rest runs. frozen=false with threadId 0 thaws all. veh_threads marks frozen threads. Caution: freezing a thread that holds a heap or loader lock can stall other threads."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"frozen", {{"type", "boolean"}, {"description", "true freezes (default), false thaws"}}}
		 }}}}}),

		Tool(&McpServer::ToolStackTrace, "trace", 0, true,
			{{"name", "veh_stack_trace"}, {"description", "Get stack trace for a thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"maxFrames", {{"type", "integer"}, {"description", "Max frames to return (default: 20)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolRegisters, "inspect", kLite | kInteractive, true,
			{{"name", "veh_registers"}, {"description", "Get CPU registers for a thread. 32-bit targets return eax/ebx/.../esp/eip; 64-bit targets return rax/.../rsp/rip plus r8-r15. The is32bit flag tells which set to expect."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"fields", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Return only these registers (e.g. [\"rsp\",\"rip\"]); is32bit is always included"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolReadMemory, "memory", kInteractive, true,
			{{"name", "veh_read_memory"}, {"description", "Read memory from the target process. Returns hex dump."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address"}}},
			{"size", {{"type", "integer"}, {"description", "Bytes to read (default: 64, max: 1MB)"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolReadPointerChain, "memory", 0, true,
			{{"name", "veh_read_pointer_chain"}, {"description", "Follow a pointer chain in one call (no per-hop round-trips). Starts at base, then for each offset dereferences *(cur+offset). E.g. base='unit', offsets=['0x2c','0x1c','0x10','0x58'] resolves unit->+0x2c->+0x1c->+0x10->+0x58. Auto-detects 4/8-byte pointers (x86/x64). Returns each hop and the final resolved address; pass size>0 to also read bytes there."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"base", {{"type", "string"}, {"description", "Base address: hex or module+RVA (e.g. 'game.exe+0x1a340')"}}},
			{"offsets", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Offsets applied and dereferenced in order, hex strings or ints (e.g. ['0x2c','0x1c','0x10'])"}}},
			{"derefFinal", {{"type", "boolean"}, {"description", "If true (default) the last offset is also dereferenced (resolved = final pointer value). If false, resolved = cur+lastOffset (the address itself, not dereferenced)."}}},
			{"size", {{"type", "integer"}, {"description", "If >0, also read this many bytes at the resolved address (max 4096). Returns hex + little-endian integer value."}}}
		 }}, {"required", json::array({"base", "offsets"})}}}}),

		Tool(&McpServer::ToolWriteMemory, "memory", 0, true,
			{{"name", "veh_write_memory"}, {"description", "Write memory to the target process. Single mode: address+data. Batch mode: patches array for multi-address patching in one call."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address (single mode)"}}},
			{"data", {{"type", "string"}, {"description", "Hex bytes to write (single mode, e.g. '90 90 90')"}}},
			{"patches", {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {{"address", {{"type", "string"}}}, {"data", {{"type", "string"}}}}}}}, {"description", "Batch mode: [{address, data}, ...]. Overrides address/data if provided."}}}
		 }}}}}),

		Tool(&McpServer::ToolModules, "inspect", 0, true,
			{{"name", "veh_modules"}, {"description", "List loaded modules (DLLs) in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}),

		Tool(&McpServer::ToolDisassemble, "inspect", kInteractive, true,
			{{"name", "veh_disassemble"}, {"description", "Disassemble instructions at an address."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address"}}},
			{"count", {{"type", "integer"}, {"description", "Number of instructions (default: 20)"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolEnumLocals, "inspect", 0, true,
			{{"name", "veh_enum_locals"}, {"description", "Enumerate local variables and parameters for a stopped thread's stack frame. Returns variable names, types, addresses, and values."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"instructionAddress", {{"type", "string"}, {"description", "RIP/EIP hex address of the frame (auto-detected from top frame if omitted)"}}},
			{"frameBase", {{"type", "string"}, {"description", "RBP/EBP hex address (auto-detected from top frame if omitted)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolSymbolize, "inspect", 0, true,
			{{"name", "veh_symbolize"}, {"description", "Resolve addresses to module!function+offset (PDB symbol, else nearest export, else module+RVA) plus source file/line when available. Works while the target runs. Up to 256 addresses per call, e.g. trace targets or stack values."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "One address (hex, or module+RVA)"}}},
			{"addresses", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Several addresses (max 256)"}}}
		 }}}}}),

		Tool(&McpServer::ToolAssemble, "memory", 0, true,
			{{"name", "veh_assemble"}, {"description", "Assemble Intel-syntax x86/x64 text (asmjit/asmtk) at an address so relative jmp/call/jcc and rip-relative operands are computed for that location. Instructions separated by ';' or newlines; labels allowed. Returns bytes plus a decoded listing. write=true patches the bytes into the target at address. Works without a target (arch defaults to x64)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"code", {{"type", "string"}, {"description", "e.g. \"mov esi, eax; jmp 0x140001000\""}}},
			{"address", {{"type", "string"}, {"description", "Where the code will live (hex or module+RVA); default 0"}}},
			{"arch", {{"type", "string"}, {"enum", json::array({"x64", "x86"})}, {"description", "Default: the attached target's bitness, else x64"}}},
			{"write", {{"type", "boolean"}, {"description", "Write the bytes into the target at address (default false)"}}}
		 }}, {"required", json::array({"code"})}}}}),

		Tool(&McpServer::ToolDisplayType, "inspect", 0, true,
			{{"name", "veh_display_type"}, {"description", "Show a PDB struct/class/union layout like WinDbg dt: member offsets, types, sizes, bitfields, base classes, and nested members up to depth. With address, also reads scalar, pointer, enum and bitfield values from that address. Needs PDB type info for the module (\"module!Type\" to pick one)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"type", {{"type", "string"}, {"description", "Type name, e.g. \"Player\" or \"game.exe!Player\""}}},
			{"address", {{"type", "string"}, {"description", "Instance address to read values from (omit for layout only)"}}},
			{"depth", {{"type", "integer"}, {"description", "Nested struct/base-class expansion levels, 0-4 (default 1)"}}},
			{"max_members", {{"type", "integer"}, {"description", "Maximum members returned (default 200, max 1024)"}}}
		 }}, {"required", json::array({"type"})}}}}),

		Tool(&McpServer::ToolEvaluate, "inspect", 0, true,
			{{"name", "veh_evaluate"}, {"description", "Evaluate an expression. Supports: register names (RAX, RBX, etc.), hex addresses (0x...), pointer dereference (*addr, [addr], [RAX+0x10], [RAX-8], [RAX+RBX]), and segment registers (gs:[0x60] for PEB, fs:[0x30] for TEB on x86)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"expression", {{"type", "string"}, {"description", "Expression to evaluate (register name, hex address, *addr for dereference)"}}},
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID for register context"}}}
		 }}, {"required", json::array({"expression", "threadId"})}}}}),

		Tool(&McpServer::ToolSetRegister, "session", 0, true,
			{{"name", "veh_set_register"}, {"description", "Set a CPU register value for a stopped thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID"}}},
			{"name", {{"type", "string"}, {"description", "Register name (e.g. RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, R8-R15, RIP, RFLAGS)"}}},
			{"value", {{"type", "string"}, {"description", "New value (hex or decimal, e.g. '0x1000' or '4096')"}}}
		 }}, {"required", json::array({"threadId", "name", "value"})}}}}),

		Tool(&McpServer::ToolExceptionInfo, "inspect", 0, true,
			{{"name", "veh_exception_info"}, {"description", "Get information about the last exception that occurred in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}),

		Tool(&McpServer::ToolTraceCallers, "trace", 0, true,
			{{"name", "veh_trace_callers"}, {"description", "Profile who calls a function: sets BP at address, auto-resumes process, collects all unique callers with hit counts for duration_sec seconds, then pauses and returns results. Useful for call graph analysis and finding hot callers. x64: uses RtlVirtualUnwind for accurate caller resolution. x86: uses [ESP] (accurate only at function entry). Process is automatically resumed before tracing and paused after."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address to set breakpoint (e.g. '0x7FF600001000')"}}},
			{"duration_sec", {{"type", "integer"}, {"description", "How long to collect callers in seconds (default: 5, max: 60)"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolTraceCalls, "trace", 0, true,
			{{"name", "veh_trace_calls"}, {"description", "Monitor where call/jmp instructions go at runtime. Sets breakpoints on call sites, runs program for N seconds, collects actual targets. With resolve=true, follows through obfuscated thunks to the final API using natural call context (no forced RIP). Ideal for IAT reconstruction on packed binaries."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"addresses", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Array of call/jmp site addresses to monitor (hex or module+RVA)"}}},
			{"duration_sec", {{"type", "integer"}, {"description", "How long to monitor in seconds (default: 5, max: 60)"}}},
			{"resolve", {{"type", "boolean"}, {"description", "Follow through thunks to final target (system DLL). Uses natural call context. Default: false"}}},
			{"system_only", {{"type", "boolean"}, {"description", "Only resolve to system DLLs. Default: false"}}}
		 }}, {"required", json::array({"addresses"})}}}}),

		Tool(&McpServer::ToolTraceBasicBlocks, "trace", kCapture, true,
			{{"name", "veh_trace_basic_blocks"}, {"description", "Bounded semantic trace for one VEH-stopped thread. Returns versioned aggregate metadata and unique blocks/edges; optional ordered streams cover transitions, per-occurrence memory accesses, instruction register deltas, and runtime code versions in one sequence space. Function-scoped mode records the entry return contract, filters external-call execution, and stops at the original return. Startup failures report structured stopped/IP/range/decode diagnostics."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID currently stopped by VEH; its RIP/EIP must be inside the range"}}},
			{"start", {{"type", "string"}, {"description", "Inclusive range start (hex or module+RVA)"}}},
			{"end", {{"type", "string"}, {"description", "Exclusive range end (hex or module+RVA, max range size 4 MiB)"}}},
			{"max_blocks", {{"type", "integer"}, {"description", "Maximum unique executed block entries (default 4096, max 16384)"}}},
			{"max_edges", {{"type", "integer"}, {"description", "Maximum unique observed edges (default 8192, max 32768)"}}},
			{"max_steps", {{"type", "integer"}, {"description", "Maximum instruction/exception events (default 100000, max 5000000)"}}},
			{"timeout_ms", {{"type", "integer"}, {"description", "Wall-clock limit (default 10000, max 60000)"}}},
			{"stack_bytes", {{"type", "integer"}, {"description", "Bytes to capture from SP per snapshot (default 128, max 256; 0 disables stack bytes)"}}},
			{"stop_on_return", {{"type", "boolean"}, {"description", "Record entry SP/return address, exclude external call execution from collection, and stop with function_return plus the return register snapshot (default false)"}}},
			{"follow_exceptions", {{"type", "boolean"}, {"description", "Pass target exceptions to its handlers and record handled continuations as edges (default true)"}}},
			{"collect_memory_writes", {{"type", "boolean"}, {"description", "Collect bounded memory-write before/after transitions (default false)"}}},
			{"max_memory_writes", {{"type", "integer"}, {"description", "Maximum unique memory-write transitions (default 4096, max 16384)"}}}
			,{"collect_memory_reads", {{"type", "boolean"}, {"description", "Collect bounded memory-read address/value observations (default false)"}}}
			,{"max_memory_reads", {{"type", "integer"}, {"description", "Maximum unique memory-read observations (default 4096, max 16384)"}}}
			,{"collect_memory_events", {{"type", "boolean"}, {"description", "Collect bounded per-occurrence memory reads/writes with sequence, thread ID, values, and dependencies; implies collect_events (default false)"}}}
			,{"max_memory_events", {{"type", "integer"}, {"description", "Maximum ordered memory-access events retained; further accesses increment the dropped count (default 8192, max 65536)"}}}
			,{"collect_register_events", {{"type", "boolean"}, {"description", "Collect one bounded register-delta event per completed instruction occurrence with sequence and thread ID; implies collect_events (default false)"}}}
			,{"max_register_events", {{"type", "integer"}, {"description", "Maximum ordered instruction register-delta events retained; further occurrences increment the dropped count (default 8192, max 65536)"}}}
			,{"collect_events", {{"type", "boolean"}, {"description", "Collect every observed block entry/transition in execution order with sequence and thread ID (default false)"}}}
			,{"max_events", {{"type", "integer"}, {"description", "Maximum ordered events retained without stopping aggregate collection (default 8192, max 32768)"}}}
			,{"collect_code", {{"type", "boolean"}, {"description", "Capture runtime bytes for unique executed block versions and map version IDs to ordered events; implies collect_events (default false)"}}}
			,{"max_code_bytes", {{"type", "integer"}, {"description", "Total runtime code-byte budget across unique versions (default 262144; max 16777216 inline or 419430400 file)"}}}
			,{"max_code_versions", {{"type", "integer"}, {"description", "Maximum unique block code versions retained (default 4096, max 16384)"}}}
			,{"code_output", {{"type", "string"}, {"enum", {"inline", "file"}}, {"description", "Return bytes inline (default) or stream a portable artifact to a file"}}}
			,{"code_output_path", {{"type", "string"}, {"description", "Optional new artifact path on the MCP host for code_output=file; an existing file is never overwritten"}}}
			,{"code_chunk_bytes", {{"type", "integer"}, {"description", "File-stream chunk size, 262144-8388608 in 65536-byte multiples (default 4194304)"}}}
			,{"events_output", {{"type", "string"}, {"enum", {"inline", "file"}}, {"description", "Return ordered events inline (default) or stream them in execution order to a portable artifact"}}}
			,{"events_output_path", {{"type", "string"}, {"description", "Optional new artifact path on the MCP host for events_output=file; an existing file is never overwritten"}}}
			,{"max_event_file_bytes", {{"type", "integer"}, {"minimum", sizeof(TraceEventArtifactHeader)}, {"maximum", kTraceEventMaxFileBytes}, {"description", "Total event artifact size limit including its header (default and max 4294967296)"}}}
			,{"dependency_sources", {{"type", "array"}, {"maxItems", 32}, {"description", "Conservative dependency sources: register names or {address,size,label?} memory ranges"}}}
			,{"start_condition", {{"type", "string"}, {"description", "Begin collection when a register/memory comparison becomes true; supports up to four && or || clauses"}}}
			,{"stop_condition", {{"type", "string"}, {"description", "Stop trace when a register/memory comparison becomes true"}}}
			,{"collect_condition", {{"type", "string"}, {"description", "Collect only while a register/memory comparison is true"}}}
			,{"occurrence_window", {{"type", "object"}, {"properties", {
				{"address", {{"type", "string"}, {"description", "Dispatcher/instruction address inside the trace range"}}},
				{"from", {{"type", "integer"}, {"minimum", 1}, {"description", "First visit whose following cycle is collected"}}},
				{"to", {{"type", "integer"}, {"minimum", 0}, {"description", "Last collected visit; 0 keeps the upper bound open"}}}
			}}, {"required", json::array({"address", "from"})}, {"description", "AND-composed with start_condition and collect_condition; collection runs entry-to-entry and a bounded window stops before visit to+1"}}}
			,{"target_window", {{"type", "object"}, {"properties", {
				{"address", {{"type", "string"}, {"description", "Trigger address inside the trace range"}}},
				{"occurrence", {{"type", "integer"}, {"minimum", 1}, {"description", "One-based trigger occurrence"}}},
				{"before_steps", {{"type", "integer"}, {"minimum", 0}, {"maximum", 100000}, {"description", "Completed instruction steps retained before the trigger"}}},
				{"after_steps", {{"type", "integer"}, {"minimum", 1}, {"maximum", 100000}, {"description", "Completed instruction steps retained after the trigger"}}}
			}}, {"required", json::array({"address", "occurrence", "before_steps", "after_steps"})}, {"description", "Bounded pre-trigger ring plus post-trigger capture; incompatible with occurrence_window, conditions, stop_on_return, code_output=file, and events_output=file"}}}
			,{"output_file", {{"type", "string"}, {"description", "Write the complete trace result to a new MCP-host file and return compact path/hash/count metadata"}}}
			,{"output_format", {{"type", "string"}, {"enum", {"json", "jsonl"}}, {"description", "output_file encoding (default json); JSONL uses a manifest plus section-item records"}}}
		 }}, {"required", json::array({"threadId", "start", "end"})}}}}),

		Tool(&McpServer::ToolCheckpointCreate, "checkpoint", kCapture, true,
			{{"name", "veh_checkpoint_create"}, {"description", "Capture one VEH-stopped thread's GPR/flags (plus x64 XMM), TEB and FS/GS selector/base metadata, and explicitly selected memory ranges. Stack ranges expose the safe logical restore start at the saved SP. Checkpoints are session-local and bounded; they do not capture other threads, handles, allocations, files, sockets, or kernel state."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "VEH-stopped thread to capture"}}},
			{"regions", {{"type", "array"}, {"maxItems", 16}, {"items", {{"type", "object"}, {"properties", {
				{"address", {{"type", "string"}}}, {"size", {{"type", "integer"}, {"minimum", 1}, {"maximum", 4194304}}}
			}} , {"required", json::array({"address", "size"})}}}, {"description", "Non-overlapping committed ranges; max 16 MiB total"}}},
			{"capture_teb", {{"type", "boolean"}, {"description", "Also capture bytes at the effective x86/WOW64/x64 TEB address (default false)"}}},
			{"teb_size", {{"type", "integer"}, {"minimum", 256}, {"maximum", 1048576}, {"description", "Bytes captured when capture_teb=true (default 4096)"}}}
		 }}, {"required", json::array({"threadId"})}}}}),

		Tool(&McpServer::ToolCheckpointRestore, "checkpoint", kCapture, true,
			{{"name", "veh_checkpoint_restore"}, {"description", "Restore selected memory and the captured thread context. Stack restores preserve live VEH exception/wait frames below saved SP and report skipped bytes. Refuses changed mappings, rolls memory back on failure, and requires the original thread to be VEH-stopped."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"description", "Checkpoint ID returned by veh_checkpoint_create"}}}
		 }}, {"required", json::array({"id"})}}}}),

		Tool(&McpServer::ToolCheckpointDiff, "checkpoint", 0, true,
			{{"name", "veh_checkpoint_diff"}, {"description", "Compare a checkpoint with current stopped-thread state or another compatible checkpoint. Returns register changes and bounded changed-memory spans."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"description", "Base checkpoint ID"}}},
			{"other_id", {{"description", "Optional checkpoint ID; omit to compare with current state"}}}
		 }}, {"required", json::array({"id"})}}}}),

		Tool(&McpServer::ToolCheckpointDelete, "checkpoint", kCapture, true,
			{{"name", "veh_checkpoint_delete"}, {"description", "Delete a session-local checkpoint and release its memory budget."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"description", "Checkpoint ID to delete"}}}
		 }}, {"required", json::array({"id"})}}}}),

		Tool(&McpServer::ToolDumpMemory, "memory", 0, true,
			{{"name", "veh_dump_memory"}, {"description", "Dump memory to a binary file. Reads in 1MB chunks, supports up to 64MB. Avoids token overhead of hex string encoding."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex start address"}}},
			{"size", {{"type", "integer"}, {"description", "Bytes to dump (default: 4096, max: 64MB)"}}},
			{"output_path", {{"type", "string"}, {"description", "Output file path for the binary dump"}}}
		 }}, {"required", json::array({"address", "output_path"})}}}}),

		Tool(&McpServer::ToolAllocateMemory, "memory", 0, true,
			{{"name", "veh_allocate_memory"}, {"description", "Allocate memory pages in the target process via VirtualAlloc."},
			 {"inputSchema", {{"type", "object"}, {"properties", {
				{"size", {{"type", "integer"}, {"description", "Allocation size in bytes (default: 4096)"}}},
				{"protection", {{"type", "string"}, {"enum", json::array({"rwx", "rw", "rx", "r"})}, {"description", "Memory protection (default: rwx = PAGE_EXECUTE_READWRITE)"}}}
			 }}}}}),

		Tool(&McpServer::ToolProtectMemory, "memory", 0, true,
			{{"name", "veh_protect_memory"}, {"description", "Change page protection inside the target and return the previous protection. Select VirtualProtect, ntdll NtProtectVirtualMemory, or the copied direct-syscall stub; syscall falls back to nt when unavailable."},
			 {"inputSchema", {{"type", "object"}, {"properties", {
				{"address", {{"type", "string"}, {"description", "Start address. Accepts hex, decimal, or module+RVA."}}},
				{"size", {{"type", "integer"}, {"minimum", 1}, {"description", "Region size in bytes"}}},
				{"protection", {{"type", "string"}, {"description", "Protection: none, r, rw, rc, x, rx, rwx, or rxc; append +guard and/or +nocache"}}},
				{"method", {{"type", "string"}, {"enum", json::array({"api", "nt", "syscall"})}, {"description", "Protection mechanism (default: api)"}}}
			 }}, {"required", json::array({"address", "size", "protection"})}}}}),

		Tool(&McpServer::ToolMemoryMap, "memory", 0, true,
			{{"name", "veh_memory_map"}, {"description", "List virtual memory regions (VirtualQuery) with state, protection (r/rw/rx/rwx, +guard), type (image/private/mapped) and owning module. Limited by max_regions; when truncated, pass next_start as start to continue."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"start", {{"type", "string"}, {"description", "Start address (default: lowest user address). Accepts module+RVA."}}},
			{"end", {{"type", "string"}, {"description", "End address, exclusive (default: end of user space)"}}},
			{"module", {{"type", "string"}, {"description", "Limit to one module's image range, e.g. \"kernel32.dll\""}}},
			{"include_free", {{"type", "boolean"}, {"description", "Include free (unallocated) ranges (default: false)"}}},
			{"max_regions", {{"type", "integer"}, {"description", "Maximum regions returned (default: 200, max: 4096)"}}}
		 }}}}}),

		Tool(&McpServer::ToolSearchMemory, "memory", 0, true,
			{{"name", "veh_search_memory"}, {"description", "Search readable committed memory inside the target. Give exactly one of: pattern (AOB, e.g. \"48 8B ?? ?? E8\", nibble wildcards like \"4?\" allowed), string (with encoding), or value (with value_type). Breakpoint bytes are compared as the original code. Results are capped by max_results; when truncated, pass next_start as start to continue."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"pattern", {{"type", "string"}, {"description", "Hex byte pattern; ?? or ? is a wildcard byte"}}},
			{"string", {{"type", "string"}, {"description", "Text to find"}}},
			{"encoding", {{"type", "string"}, {"enum", json::array({"ascii", "utf8", "utf16"})}, {"description", "Encoding for string (default: ascii)"}}},
			{"value", {{"description", "Number to find (JSON number or string, hex allowed)"}}},
			{"value_type", {{"type", "string"}, {"enum", json::array({"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "ptr"})}, {"description", "Encoding for value (default: i32). Floats match exact bit patterns."}}},
			{"start", {{"type", "string"}, {"description", "Start address (default: lowest user address). Accepts module+RVA."}}},
			{"end", {{"type", "string"}, {"description", "End address, exclusive"}}},
			{"module", {{"type", "string"}, {"description", "Limit to one module's image range"}}},
			{"writable", {{"description", "true: only writable regions, false: exclude them, \"any\": no filter (default: any)"}}},
			{"executable", {{"description", "true: only executable regions, false: exclude them, \"any\": no filter (default: any)"}}},
			{"type", {{"description", "Region type filter: \"image\", \"private\", \"mapped\", or an array of them"}}},
			{"alignment", {{"type", "integer"}, {"description", "Only report addresses that are multiples of this (default: 1)"}}},
			{"max_results", {{"type", "integer"}, {"description", "Maximum matches (default: 100, max: 10000)"}}}
		 }}}}}),

		Tool(&McpServer::ToolValueScan, "memory", 0, true,
			{{"name", "veh_value_scan"}, {"description", "Cheat Engine style target-side value scan session. Start with first, repeatedly filter with next, page candidates with results, and release all scan storage with reset. Candidate state and snapshots stay inside the target DLL."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"operation", {{"type", "string"}, {"enum", json::array({"first", "next", "results", "reset"})}}},
			{"value_type", {{"type", "string"}, {"enum", json::array({"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"})}, {"description", "Stored value type (default: i32)"}}},
			{"compare", {{"type", "string"}, {"enum", json::array({"exact", "between", "greater", "less", "unknown", "changed", "unchanged", "increased", "decreased", "increased_by", "decreased_by"})}, {"description", "Comparison (default: exact). Change comparisons are next-only."}}},
			{"value", {{"description", "Comparison value, or delta for increased_by/decreased_by"}}},
			{"value2", {{"description", "Inclusive upper bound for between"}}},
			{"start", {{"type", "string"}, {"description", "First scan start address (default: lowest user address)"}}},
			{"end", {{"type", "string"}, {"description", "First scan end address, exclusive"}}},
			{"module", {{"type", "string"}, {"description", "Limit the first scan to one module image"}}},
			{"writable", {{"description", "First scan filter: true, false, or \"any\" (default: true)"}}},
			{"executable", {{"description", "First scan filter: true, false, or \"any\" (default: any)"}}},
			{"type", {{"description", "First scan region type: image, private, mapped, or an array"}}},
			{"alignment", {{"type", "integer"}, {"description", "First scan address alignment (default: value size, max: 4096)"}}},
			{"offset", {{"type", "integer"}, {"description", "Candidate offset for results paging (default: 0)"}}},
			{"max_results", {{"type", "integer"}, {"description", "Maximum returned entries (default: 20, max: 1000)"}}}
		 }}, {"required", json::array({"operation"})}}}}),

		Tool(&McpServer::ToolFreeMemory, "memory", 0, true,
			{{"name", "veh_free_memory"}, {"description", "Free previously allocated memory pages in the target process via VirtualFree."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address of the allocation to free"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolExecuteShellcode, "memory", 0, true,
			{{"name", "veh_execute_shellcode"}, {"description", "Execute shellcode in the target process. Allocates RWX page, copies code, creates thread, waits for completion, frees page. Set timeout_ms=0 for fire-and-forget (page not freed)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"shellcode", {{"type", "string"}, {"description", "Hex-encoded shellcode bytes (e.g. 'C3' for ret, '33C0C3' for xor eax,eax; ret)"}}},
			{"timeout_ms", {{"type", "integer"}, {"description", "Max wait time in ms (default: 5000, max: 60000). 0 = fire-and-forget (don't wait, don't free)."}}}
		 }}, {"required", json::array({"shellcode"})}}}}),

		Tool(&McpServer::ToolSetModuleBreakpoint, "breakpoint", 0, true,
			{{"name", "veh_set_module_breakpoint"}, {"description",
			"Stop when a module (DLL) whose name matches is loaded into the target. Matching is case-insensitive substring on the base name (e.g. \"D2Common\" matches \"D2Common.dll\"). The loading thread is frozen right after the module is mapped (via LdrRegisterDllNotification), so you can then set breakpoints inside it, resolve its exports, or dump it -- ideal for headless capture. NOTE: on modern Windows the notification fires AFTER the module's own DllMain has run, so use this to catch a module becoming present/initialized, not to freeze before its init code executes. Pass enabled=false to remove one pattern, or clear=true to remove all. The stop surfaces via veh_continue(wait=true) with reason \"module-load\". While stopped here, registers/memory/stack/modules are readable, but this is an inspection stop -- register/RIP writes (veh_set_register) are not applied to the loader thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"module", {{"type", "string"}, {"description", "Module-name substring to stop on (case-insensitive), e.g. \"D2Common.dll\""}}},
			{"enabled", {{"type", "boolean"}, {"description", "false removes this pattern; default true adds it"}}},
			{"clear", {{"type", "boolean"}, {"description", "true clears ALL module-load breakpoints (module ignored)"}}}
		 }}}}}),

		Tool(&McpServer::ToolBatch, "orchestration", kLite | kCapture, false,
			{{"name", "veh_batch"}, {"description",
			"Execute sequential debugger steps, conditions, loops, or input matrices in one call. "
			"Use $N/$last/$prev references between results and args.fields to bound register output. "
			"Detailed examples are in docs/DEVELOPMENT_TOOLS.md."
		},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"steps", {{"type", "array"}, {"items", {{"oneOf", json::array({json{{"type", "object"}}, json{{"type", "string"}}})}}}, {"description", "Array of step objects, or JSON-encoded object strings for compatibility. Each decoded step is {tool, args}, {if, then, else}, {loop, until, max}, or {for_each, as, do}."}}},
			{"file", {{"type", "string"}, {"description", "Load steps from a JSON file instead of inline. File can be a JSON array of steps or {\"steps\": [...]}. Example: veh_batch({file: \"patch_sequence.json\"})"}}},
			{"inputs", {{"type", "array"}, {"maxItems", 256}, {"description", "Repeat the steps once per input object/value in the same debug session"}}},
			{"input_variable", {{"type", "string"}, {"description", "Variable bound to each input (default $input)"}}},
			{"stop_on_error", {{"type", "boolean"}, {"description", "Stop the current batch and any remaining input runs after the first failed step (default false)"}}}
		 }}}}}),

		Tool(&McpServer::ToolTraceRegister, "trace", 0, true,
			{{"name", "veh_trace_register"}, {"description", "Trace a register: single-steps internally (inside DLL, zero IPC overhead per step) until the register meets a condition. Returns the instruction that caused the change. Thread must be stopped at a breakpoint (not via veh_pause). Much faster than manual step+check loops."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (must be stopped)"}}},
			{"register", {{"type", "string"}, {"description", "Register name (RAX, RBX, RCX, etc.)"}}},
			{"mode", {{"type", "string"}, {"enum", json::array({"changed", "equals", "not_equals"})}, {"description", "Condition: 'changed' (any change), 'equals' (== value), 'not_equals' (!= value). Default: changed"}}},
			{"value", {{"type", "string"}, {"description", "Compare value for equals/not_equals mode (hex or decimal)"}}},
			{"max_steps", {{"type", "integer"}, {"description", "Max instructions to step (default: 10000, max: 100000)"}}}
		 }}, {"required", json::array({"threadId", "register"})}}}}),

		Tool(&McpServer::ToolTraceMemory, "trace", 0, true,
			{{"name", "veh_trace_memory"}, {"description", "Trace memory writes: sets a temporary hardware data breakpoint, resumes the process, and waits for any thread to write to the address. Returns the writing instruction, thread ID, and old/new values. Uses DR0-DR3 (1 slot occupied during trace)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Memory address to watch (hex or module+RVA)"}}},
			{"size", {{"type", "integer"}, {"enum", json::array({1, 2, 4, 8})}, {"description", "Watch size in bytes (default: 4)"}}},
			{"timeout_ms", {{"type", "integer"}, {"description", "Max wait time in ms (default: 10000, max: 60000)"}}}
		 }}, {"required", json::array({"address"})}}}}),

		Tool(&McpServer::ToolResolveImports, "trace", 0, true,
			{{"name", "veh_resolve_imports"}, {"description", "Resolve obfuscated/packed imports by single-stepping from thunk addresses until RIP enters a loaded DLL. Returns API names (module!function) for each thunk. Processes up to 2000 imports in a single call. With follow_exceptions=true, passes non-single-step exceptions (INT3, AV, PRIV_INSTRUCTION) to SEH handlers while keeping trace active -- enables resolving exception-based obfuscated thunks (Themida, VMProtect style). Thread must be stopped at a breakpoint."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (must be stopped at breakpoint)"}}},
			{"addresses", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Array of thunk addresses (hex or module+RVA)"}}},
			{"max_steps", {{"type", "integer"}, {"description", "Max steps per thunk (default: 1000, max: 10000)"}}},
			{"follow_exceptions", {{"type", "boolean"}, {"description", "Pass non-SINGLE_STEP exceptions to SEH during trace (for exception-based obfuscated thunks). Default: false"}}},
			{"system_only", {{"type", "boolean"}, {"description", "Only resolve to system DLLs (C:\\Windows\\System32). Filters out packer/runtime DLLs. Default: false"}}},
			{"target_modules", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Only resolve to these specific modules (e.g. [\"kernel32\", \"ntdll\"]). Overrides system_only."}}}
		 }}, {"required", json::array({"threadId", "addresses"})}}}})
	};
	json targetedProperties = json::object();
	targetedProperties["inputs"] = {{"type", "array"}, {"minItems", 1}, {"maxItems", 256},
		{"description", "Sequential input matrix"}};
	targetedProperties["input_variable"] = {{"type", "string"},
		{"description", "Bound input variable (default $input)"}};
	targetedProperties["steps"] = {{"type", "array"}, {"maxItems", 500},
		{"description", "Per-input veh_batch setup steps"}};
	targetedProperties["trace"] = {{"type", "object"},
		{"description", "veh_trace_basic_blocks arguments including threadId/start/end"}};
	targetedProperties["trigger"] = {{"type", "object"},
		{"description", "{address, occurrence?}; address may use a batch reference"}};
	targetedProperties["window"] = {{"type", "object"},
		{"description", "{before_steps?, after_steps?}; bounds are 0/1 through 100000"}};
	targetedProperties["environment"] = {{"type", "object"},
		{"description", "Optional {capture_teb, teb_size, regions}; capture_teb defaults true"}};
	targetedProperties["output_directory"] = {{"type", "string"},
		{"description", "MCP-host artifact directory"}};
	targetedProperties["stop_on_error"] = {{"type", "boolean"},
		{"description", "Stop after first failed input (default true)"}};
	tools.push_back(Tool(&McpServer::ToolTargetedCapture, "trace", kCapture, false,
			{{"name", "veh_targeted_capture"},
		{"description", "Run an input matrix in one attached session and write one bounded occurrence-triggered trace artifact per input. Setup steps may restore checkpoints and apply each $input; the trace retains a pre/post instruction ring with ordered code/register/memory events and embeds a pre-trace TEB/FS/GS environment snapshot. Success requires at least one completed instruction and the requested target-window stop; exception, zero-step, and partial windows fail explicitly. Returns per-input path/hash/count/drop/truncation/match/failure metadata. Session lifecycle tools are deliberately excluded from setup steps."},
		{"inputSchema", {{"type", "object"}, {"properties", std::move(targetedProperties)},
			{"required", json::array({"inputs", "trace", "trigger", "window", "output_directory"})}}}}));
	tools.push_back(Tool(&McpServer::ToolToolbox, "orchestration", kLite | kInteractive | kCapture, false,
			{{"name", "veh_toolbox"},
		{"description", "Discover, describe, or call VEH tools that are not eager in the active profile. Describe before calling and reuse schema_handle when possible."},
		{"inputSchema", {{"type", "object"}, {"properties", {
			{"operation", {{"type", "string"}, {"enum", json::array({"list", "describe", "call", "profiles"})}, {"description", "Operation (default: list)"}}},
			{"tool", {{"type", "string"}, {"description", "Tool name for describe or call"}}},
			{"arguments", {{"type", "object"}, {"description", "Arguments for call"}}},
			{"profile", {{"type", "string"}, {"enum", json::array({"lite", "interactive", "capture", "full"})}, {"description", "Filter list by profile"}}},
			{"query", {{"type", "string"}, {"description", "Case-insensitive list filter"}}},
			{"schema_handle", {{"type", "string"}, {"description", "Handle from an earlier describe"}}}
		}}}}}));
	return tools;
}

McpServer::ToolDef McpServer::Tool(json (McpServer::*handler)(const json&), const char* category,
	unsigned profiles, bool nested, json definition) {
	std::string name = definition.value("name", "");
	return {std::move(name), handler, category, profiles, nested, std::move(definition)};
}




json McpServer::GetToolsList() const {
	const unsigned mask = ProfileMask(toolProfile_);
	json exposed = json::array();
	for (const auto& tool : tools_) {
		if (tool.InProfile(mask)) exposed.push_back(tool.definition);
	}
	return exposed;
}

const McpServer::ToolDef* McpServer::FindTool(const std::string& name) const {
	auto it = std::find_if(tools_.begin(), tools_.end(),
		[&name](const ToolDef& tool) { return tool.name == name; });
	return it == tools_.end() ? nullptr : &*it;
}

json McpServer::DispatchTool(const std::string& name, const json& args, bool* known) {
	const ToolDef* tool = FindTool(name);
	if (known) *known = tool != nullptr;
	if (!tool) return {{"error", "Unknown tool: " + name}};
	return (this->*tool->handler)(args);
}

json McpServer::RunNestedTool(const std::string& name, const json& args) {
	const ToolDef* tool = FindTool(name);
	if (tool && !tool->nested)
		return {{"error", name + " is not available in batch steps, capture setup, or breakpoint actions"}};
	return DispatchTool(name, args);
}

BatchExecutor McpServer::NewBatchExecutor() {
	return BatchExecutor([this](const std::string& name, const json& args) {
		return RunNestedTool(name, args);
	});
}


std::string McpServer::NotAttachedMessage() {
	HANDLE hProc = session_.GetTargetProcess();
	// WaitForSingleObject(,0) reliably detects termination; GetExitCodeProcess alone is
	// ambiguous when the real exit code is 259 (== STILL_ACTIVE).
	if (hProc && WaitForSingleObject(hProc, 0) == WAIT_OBJECT_0) {
		DWORD exitCode = 0;
		GetExitCodeProcess(hProc, &exitCode);
		char buf[128];
		snprintf(buf, sizeof(buf), "Not attached - target process exited (code %lu)", exitCode);
		return buf;
	}
	return "Not attached";
}

std::string McpServer::IpcErrorMessage() {
	if (!session_.IsAttached()) return NotAttachedMessage();
	HANDLE hProc = session_.GetTargetProcess();
	if (hProc && WaitForSingleObject(hProc, 0) == WAIT_OBJECT_0) {
		DWORD exitCode = 0;
		GetExitCodeProcess(hProc, &exitCode);
		char buf[128];
		snprintf(buf, sizeof(buf), "Target process has exited (exit code: %lu)", exitCode);
		return buf;
	}
	if (!session_.GetPipeClient().IsConnected()) return "Target pipe disconnected (process may have crashed)";
	return "IPC communication failed (timeout)";
}

} // namespace veh
