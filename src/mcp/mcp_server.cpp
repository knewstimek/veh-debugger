#include "mcp_server.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

// JSON args helper: accept both number and string for integer fields.
// AI agents often send "threadId": "12345" instead of "threadId": 12345.
static uint32_t JsonUint32(const json& args, const char* key, uint32_t defaultVal = 0) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_number()) return v.get<uint32_t>();
	if (v.is_string()) {
		const auto& s = v.get<std::string>();
		if (s.empty() || s[0] == '-') return defaultVal;
		try {
			return static_cast<uint32_t>(std::stoul(s, nullptr, 0));
		} catch (...) {
			return defaultVal;
		}
	}
	return defaultVal;
}

static int JsonInt(const json& args, const char* key, int defaultVal = 0) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_number()) return v.get<int>();
	if (v.is_string()) {
		try {
			return std::stoi(v.get<std::string>(), nullptr, 0);
		} catch (...) {
			return defaultVal;
		}
	}
	return defaultVal;
}

static bool JsonBool(const json& args, const char* key, bool defaultVal = false) {
	if (!args.contains(key)) return defaultVal;
	const auto& v = args[key];
	if (v.is_boolean()) return v.get<bool>();
	if (v.is_string()) {
		auto s = v.get<std::string>();
		return s == "true" || s == "1";
	}
	if (v.is_number_integer()) return v.get<int>() != 0;
	if (v.is_number()) return v.get<double>() != 0.0;
	return defaultVal;
}

McpServer::McpServer() {}
McpServer::~McpServer() {
	running_ = false;
	StopProcessMonitor();
	if (attached_) {
		try {
			pipeClient_.SendCommand(IpcCommand::Detach);
		} catch (...) {}
		pipeClient_.Disconnect();
		attached_ = false;
	}
	if (launchedByUs_ && targetProcess_) {
		TerminateProcess(targetProcess_, 0);
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
		launchedByUs_ = false;
	}
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

	// StdioTransport::Start()는 블로킹이 아니므로 여기서 대기
	while (running_) {
		FlushEvents();
		Sleep(100);
	}

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

		// JSON-RPC 2.0: notification (no id) or request (has id)
		std::string method = msg.value("method", "");
		json params = msg.value("params", json::object());

		if (method == "initialize") {
			OnInitialize(id, params);
		} else if (method == "notifications/initialized") {
			// 클라이언트 초기화 완료 — 특별한 처리 없음
			LOG_INFO("Client initialized");
		} else if (method == "tools/list") {
			OnToolsList(id, params);
		} else if (method == "tools/call") {
			OnToolsCall(id, params);
		} else if (method == "ping") {
			SendResult(id, json::object());
		} else if (method == "resources/list" || method == "resources/templates/list" ||
		           method == "prompts/list") {
			// MCP optional capabilities -- return empty lists for compatibility
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
			{"version", "1.0.93"}
		}},
		{"instructions",
			"VEH Debugger - in-process debugger for Windows x86/x64 executables.\n"
			"\n"
			"## Typical workflow\n"
			"1. veh_launch(program, stopOnEntry=true) -- launch and pause at entry point\n"
			"2. veh_set_breakpoint / veh_set_source_breakpoint / veh_set_function_breakpoint -- set breakpoints\n"
			"3. veh_continue(wait=true) -- resume and BLOCK until breakpoint hit (returns stop info)\n"
			"4. veh_registers / veh_disassemble / veh_read_memory / veh_stack_trace -- inspect state\n"
			"5. veh_step_over / veh_step_in / veh_step_out -- step (synchronous, waits for completion)\n"
			"6. Repeat 3-5 as needed\n"
			"7. veh_detach -- detach when done\n"
			"\n"
			"## Key points\n"
			"- veh_continue(wait=true) blocks until stop event. Use this to detect breakpoint hits.\n"
			"- veh_continue(wait=true, timeout=N) sets custom timeout (default 10s, max 300s).\n"
			"- veh_step_in/veh_step_over/veh_step_out are synchronous (wait for completion automatically).\n"
			"- Most inspection tools (registers, stack_trace, disassemble, read_memory, enum_locals) require the target to be stopped.\n"
			"- veh_launch with stopOnEntry=true pauses at entry. First veh_continue resumes execution.\n"
			"- veh_attach auto-detaches previous session. Cannot attach to CREATE_SUSPENDED processes.\n"
		}
	};
	SendResult(id, result);
}

void McpServer::OnToolsList(const json& id, const json& params) {
	SendResult(id, {{"tools", GetToolsList()}});
}

void McpServer::OnToolsCall(const json& id, const json& params) {
	// Run in a separate thread so blocking tools (veh_continue wait=true, veh_launch, etc.)
	// don't block the reader thread and freeze the entire MCP server
	std::thread([this, id, params]() {
		std::string name = params.value("name", "");
		json args = params.value("arguments", json::object());

		LOG_INFO("Tool call: %s", name.c_str());

		try {
			json result;

		if      (name == "veh_attach")                result = ToolAttach(args);
		else if (name == "veh_launch")                result = ToolLaunch(args);
		else if (name == "veh_detach")                result = ToolDetach(args);
		else if (name == "veh_set_breakpoint")        result = ToolSetBreakpoint(args);
		else if (name == "veh_remove_breakpoint")     result = ToolRemoveBreakpoint(args);
		else if (name == "veh_set_data_breakpoint")   result = ToolSetDataBreakpoint(args);
		else if (name == "veh_remove_data_breakpoint") result = ToolRemoveDataBreakpoint(args);
		else if (name == "veh_continue")              result = ToolContinue(args);
		else if (name == "veh_step_in")               result = ToolStepIn(args);
		else if (name == "veh_step_over")             result = ToolStepOver(args);
		else if (name == "veh_step_out")              result = ToolStepOut(args);
		else if (name == "veh_pause")                 result = ToolPause(args);
		else if (name == "veh_threads")               result = ToolThreads(args);
		else if (name == "veh_stack_trace")           result = ToolStackTrace(args);
		else if (name == "veh_registers")             result = ToolRegisters(args);
		else if (name == "veh_read_memory")           result = ToolReadMemory(args);
		else if (name == "veh_write_memory")          result = ToolWriteMemory(args);
		else if (name == "veh_modules")               result = ToolModules(args);
		else if (name == "veh_disassemble")           result = ToolDisassemble(args);
		else if (name == "veh_enum_locals")           result = ToolEnumLocals(args);
		else if (name == "veh_set_source_breakpoint") result = ToolSetSourceBreakpoint(args);
		else if (name == "veh_set_function_breakpoint") result = ToolSetFunctionBreakpoint(args);
		else if (name == "veh_list_breakpoints")      result = ToolListBreakpoints(args);
		else if (name == "veh_evaluate")              result = ToolEvaluate(args);
		else if (name == "veh_set_register")          result = ToolSetRegister(args);
		else if (name == "veh_exception_info")        result = ToolExceptionInfo(args);
		else if (name == "veh_trace_callers")         result = ToolTraceCallers(args);
		else if (name == "veh_dump_memory")           result = ToolDumpMemory(args);
		else if (name == "veh_allocate_memory")       result = ToolAllocateMemory(args);
		else if (name == "veh_free_memory")           result = ToolFreeMemory(args);
		else if (name == "veh_execute_shellcode")     result = ToolExecuteShellcode(args);
		else {
			SendError(id, -32602, "Unknown tool: " + name);
			return;
		}

		// MCP tool result format
		SendResult(id, {
			{"content", json::array({
				{{"type", "text"}, {"text", result.dump(2)}}
			})}
		});
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

// --- Helper: Check if process is in CREATE_SUSPENDED state (loader not initialized) ---
// Distinguishes CREATE_SUSPENDED (can't inject) from SuspendThread (can inject):
//   CREATE_SUSPENDED: all threads suspended + very few modules (ntdll only or ~3)
//   SuspendThread: all threads suspended but loader initialized (many modules loaded)
static bool IsProcessUninitializedSuspended(uint32_t pid) {
	// Step 1: Check if all threads are suspended
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	bool foundAny = false;
	bool allSuspended = true;

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;
			foundAny = true;
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
			if (!hThread) { allSuspended = false; break; }
			DWORD prevCount = SuspendThread(hThread);
			if (prevCount == (DWORD)-1) {
				CloseHandle(hThread);
				allSuspended = false;
				break;
			}
			ResumeThread(hThread);  // Undo our suspend
			if (prevCount == 0) {
				allSuspended = false;
				CloseHandle(hThread);
				break;
			}
			CloseHandle(hThread);
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);

	if (!foundAny || !allSuspended) return false;

	// Step 2: Check module count - CREATE_SUSPENDED has very few modules (loader not run)
	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProc) return false;  // Can't determine, assume not suspended

	HMODULE modules[8];
	DWORD needed = 0;
	BOOL ok = EnumProcessModules(hProc, modules, sizeof(modules), &needed);
	CloseHandle(hProc);

	if (!ok) return true;  // EnumProcessModules fails on uninitialized process -> likely CREATE_SUSPENDED

	DWORD moduleCount = needed / sizeof(HMODULE);
	// CREATE_SUSPENDED: typically 1-3 modules (ntdll, possibly kernel32/kernelbase mapped but not init'd)
	// Normal suspended: 10+ modules (fully initialized)
	return moduleCount <= 4;
}

// --- Helper: Check if VEH pipe exists for target PID (re-attach scenario) ---
// Uses WaitNamedPipe with 0 timeout to probe without consuming the connection.
static bool IsPipeAvailable(uint32_t pid) {
	std::wstring pipeName = GetPipeName(pid);
	// WaitNamedPipe returns TRUE if an instance is available, FALSE otherwise
	// Timeout 0 = immediate check, does not consume the pipe instance
	return WaitNamedPipeW(pipeName.c_str(), 0) != 0;
}

// --- Tool Implementations ---

json McpServer::ToolAttach(const json& args) {
	if (attached_) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new attach", targetPid_);
		ToolDetach({});
	} else if (pipeClient_.IsConnected()) {
		// Process crashed/exited but pipe wasn't cleaned up
		LOG_WARN("Stale pipe connection detected, cleaning up");
		pipeClient_.StopHeartbeat();
		pipeClient_.StopEventListener();
		pipeClient_.Disconnect();
	}

	uint32_t pid = JsonUint32(args, "pid");
	if (pid == 0) return {{"error", "pid is required"}};

	// CREATE_SUSPENDED detection (uninitialized loader -> CreateRemoteThread hangs)
	if (IsProcessUninitializedSuspended(pid)) {
		return {{"error", "Process appears to be in CREATE_SUSPENDED state (loader not initialized). DLL injection requires a running process. Resume the process first or use veh_launch instead."}};
	}

	// DLL 경로 결정 (pid 기반 비트니스 감지)
	std::string dllPath = GetDllPath(pid);
	if (dllPath.empty()) {
		return {{"error", "VEH DLL not found. Ensure vcruntime_net.dll (x64) or vcruntime_net32.dll (x86) is in the same directory as veh-mcp-server.exe"}};
	}

	// Check if VEH pipe already exists (re-attach: DLL loaded, pipe server running)
	bool pipeExists = IsPipeAvailable(pid);

	if (pipeExists) {
		LOG_INFO("Pipe already exists for PID %u, skipping injection (re-attach)", pid);
	} else {
		// DLL injection
		LOG_INFO("Injecting into PID %u: %s", pid, dllPath.c_str());
		if (!Injector::InjectDll(pid, dllPath)) {
			return {{"error", "DLL injection failed. If you previously detached from this process, the DLL may already be loaded but the pipe server is no longer running. Restart the target process and try again."}};
		}
	}

	// Named Pipe connection
	if (!pipeClient_.Connect(pid, 3500)) {
		LOG_ERROR("Pipe connection failed (pid=%u)", pid);
		return {{"error", "Pipe connection failed (timeout). " +
			std::string(pipeExists ? "Pipe existed but connection failed - DLL may be in a stale state. " : "DLL was injected but pipe server did not start. ") +
			"Try restarting the target process."}};
	}

	// 이벤트 리스너 시작
	pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();

	targetPid_ = pid;
	targetProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
	if (!targetProcess_) {
		LOG_WARN("Cannot open process %u for monitoring, exit detection disabled", pid);
	}
	attached_ = true;
	StartProcessMonitor();

	// 타겟 비트니스에 맞게 디스어셈블러 재생성
	{
		BOOL isWow64 = FALSE;
		if (targetProcess_) {
			IsWow64Process(targetProcess_, &isWow64);
		} else {
			LOG_WARN("Cannot determine target bitness (OpenProcess failed), defaulting to x64");
		}
		bool is64 = (isWow64 == FALSE);
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	return {{"success", true}, {"pid", pid}, {"message", "Attached to process"}};
}

json McpServer::ToolLaunch(const json& args) {
	if (attached_) {
		LOG_INFO("Auto-detaching from previous session (pid=%u) before new launch", targetPid_);
		ToolDetach({});
	} else if (pipeClient_.IsConnected()) {
		// Process crashed/exited but pipe wasn't cleaned up
		LOG_WARN("Stale pipe connection detected, cleaning up");
		pipeClient_.StopHeartbeat();
		pipeClient_.StopEventListener();
		pipeClient_.Disconnect();
	}

	std::string program = args.value("program", "");
	if (program.empty()) return {{"error", "program is required"}};

	std::string argsStr;
	if (args.contains("args") && args["args"].is_array()) {
		for (auto& a : args["args"]) {
			if (!a.is_string()) continue;
			if (!argsStr.empty()) argsStr += " ";
			std::string arg = a.get<std::string>();
			if (arg.find_first_of(" \t\"") != std::string::npos) {
				// Windows CommandLineToArgvW 규칙에 따른 이스케이프
				std::string quoted = "\"";
				int numBackslashes = 0;
				for (char c : arg) {
					if (c == '\\') {
						numBackslashes++;
					} else if (c == '"') {
						for (int j = 0; j < numBackslashes; j++) quoted += "\\\\";
						quoted += "\\\"";
						numBackslashes = 0;
					} else {
						for (int j = 0; j < numBackslashes; j++) quoted += "\\";
						quoted += c;
						numBackslashes = 0;
					}
				}
				for (int j = 0; j < numBackslashes; j++) quoted += "\\\\";
				quoted += "\"";
				argsStr += quoted;
			} else {
				argsStr += arg;
			}
		}
	}

	bool stopOnEntry = JsonBool(args, "stopOnEntry", true);
	bool runAsInvoker = JsonBool(args, "runAsInvoker", false);
	InjectionMethod injMethod = ParseInjectionMethod(args.value("injectionMethod", "auto"));

	// Check if program file exists
	{
		std::error_code ec;
		if (!std::filesystem::exists(program, ec)) {
			return {{"error", "File not found: " + program}};
		}
	}

	// PE 헤더에서 비트니스 확인 (아직 프로세스가 없으므로 파일 기반)
	std::string dllPath = GetDllPathForExe(program);
	if (dllPath.empty()) {
		return {{"error", "VEH DLL not found. Ensure vcruntime_net.dll (x64) or vcruntime_net32.dll (x86) is in the same directory as veh-mcp-server.exe"}};
	}

	auto launchResult = Injector::LaunchAndInject(program, argsStr, "", dllPath, injMethod, runAsInvoker);
	uint32_t pid = launchResult.pid;
	if (pid == 0) {
		std::string msg = "Launch failed: " + program;
		if (!launchResult.error.empty()) msg += " - " + launchResult.error;
		return {{"error", msg}};
	}

	launchedMainThreadId_ = launchResult.mainThreadId;
	mainThreadResumed_ = false;

	targetProcess_ = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!targetProcess_) {
		LOG_WARN("OpenProcess(TERMINATE) failed for pid=%u, cannot terminate on cleanup", pid);
	}
	launchedByUs_ = true;

	// Named Pipe 연결
	if (!pipeClient_.Connect(pid, 3500)) {
		if (targetProcess_) {
			TerminateProcess(targetProcess_, 1);
			CloseHandle(targetProcess_);
			targetProcess_ = nullptr;
		}
		launchedByUs_ = false;
		launchedMainThreadId_ = 0;
		return {{"error", "Pipe connection failed after launch"}};
	}

	pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();

	targetPid_ = pid;
	attached_ = true;
	StartProcessMonitor();

	// 타겟 비트니스에 맞게 디스어셈블러 재생성
	{
		bool is64 = !Injector::IsExe32Bit(program);
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	// stopOnEntry=false: 즉시 메인 스레드 resume (DAP의 configurationDone과 동일)
	// stopOnEntry=true: 에이전트가 veh_continue 호출 시 resume
	if (!stopOnEntry) {
		ResumeMainThread();
	}

	return {{"success", true}, {"pid", pid}, {"message",
		stopOnEntry ? "Launched and attached (stopped on entry)" : "Launched and attached"}};
}

json McpServer::ToolDetach(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	// Set attached_ first to prevent ProcessMonitor from running cleanup concurrently
	attached_ = false;

	// 메인 스레드가 아직 suspended이면 resume (안 하면 프로세스가 좀비로 남음)
	ResumeMainThread();
	StopProcessMonitor();

	pipeClient_.StopHeartbeat();
	pipeClient_.StopEventListener();
	try {
		pipeClient_.SendCommand(IpcCommand::Detach);
	} catch (...) {
		// 파이프가 이미 끊어진 경우 무시 (소멸자와 동일 패턴)
	}
	pipeClient_.Disconnect();

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		swBreakpoints_.clear();
		hwBreakpoints_.clear();
	}
	targetPid_ = 0;
	launchedMainThreadId_ = 0;
	mainThreadResumed_ = false;

	if (targetProcess_) {
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
	}
	launchedByUs_ = false;

	return {{"success", true}, {"message", "Detached"}};
}

json McpServer::ToolSetBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}
	SetBreakpointRequest req;
	req.address = addr;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() >= sizeof(SetBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			{
				std::lock_guard<std::mutex> lock(bpMutex_);
				// 같은 id가 이미 있으면 조건만 업데이트 (DLL 측 dedup으로 기존 id 반환)
				bool found = false;
				for (auto& existing : swBreakpoints_) {
					if (existing.id == resp->id) {
						existing.condition = args.value("condition", "");
						existing.hitCondition = args.value("hitCondition", "");
						existing.logMessage = args.value("logMessage", "");
						found = true;
						break;
					}
				}
				if (!found) {
					BpMapping bp;
					bp.id = resp->id;
					bp.address = addr;
					bp.condition = args.value("condition", "");
					bp.hitCondition = args.value("hitCondition", "");
					bp.logMessage = args.value("logMessage", "");
					swBreakpoints_.push_back(bp);
				}
			}
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
			return {{"success", true}, {"id", resp->id}, {"address", buf}};
		}
	}
	return {{"error", "Failed to set breakpoint"}};
}

json McpServer::ToolRemoveBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t id = JsonUint32(args, "id");
	if (!args.contains("id") || id == 0) {
		return {{"error", "id is required (positive integer)"}};
	}

	RemoveBreakpointRequest req;
	req.id = id;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::RemoveBreakpoint, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) {
			return {{"error", "Breakpoint not found (id=" + std::to_string(id) + ")"}};
		}
	}

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		swBreakpoints_.erase(
			std::remove_if(swBreakpoints_.begin(), swBreakpoints_.end(),
				[id](const BpMapping& bp) { return bp.id == id; }),
			swBreakpoints_.end());
	}

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolSetSourceBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string source = args.value("source", "");
	uint32_t line = JsonUint32(args, "line");
	if (source.empty()) return {{"error", "source (file path) is required"}};
	if (line == 0) return {{"error", "line is required"}};

	// Resolve source line -> address via PDB
	ResolveSourceLineRequest resolveReq = {};
	strncpy_s(resolveReq.fileName, source.c_str(), sizeof(resolveReq.fileName) - 1);
	resolveReq.line = line;

	std::vector<uint8_t> resolveResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), resolveResp)) {
		return {{"error", "ResolveSourceLine IPC failed - " + IpcErrorMessage()}};
	}
	if (resolveResp.size() < sizeof(ResolveSourceLineResponse)) {
		return {{"error", "Invalid response from DLL"}};
	}
	auto* resolved = reinterpret_cast<const ResolveSourceLineResponse*>(resolveResp.data());
	if (resolved->status != IpcStatus::Ok || resolved->address == 0) {
		return {{"error", "Could not resolve source line (no PDB symbols or line not found)"}};
	}

	// Set breakpoint at resolved address
	SetBreakpointRequest bpReq;
	bpReq.address = resolved->address;
	std::vector<uint8_t> bpResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (bpResp.size() < sizeof(SetBreakpointResponse)) {
		return {{"error", "Invalid response from DLL"}};
	}
	auto* resp = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
	if (resp->status != IpcStatus::Ok) {
		return {{"error", "Failed to set breakpoint at resolved address"}};
	}

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		bool found = false;
		for (auto& existing : swBreakpoints_) {
			if (existing.id == resp->id) {
				existing.source = source;
				existing.line = line;
				existing.condition = args.value("condition", "");
				existing.hitCondition = args.value("hitCondition", "");
				existing.logMessage = args.value("logMessage", "");
				found = true;
				break;
			}
		}
		if (!found) {
			BpMapping bp;
			bp.id = resp->id;
			bp.address = resolved->address;
			bp.source = source;
			bp.line = line;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			swBreakpoints_.push_back(bp);
		}
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", resolved->address);
	return {{"success", true}, {"id", resp->id}, {"address", buf}, {"source", source}, {"line", line}};
}

json McpServer::ToolSetFunctionBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string name = args.value("name", "");
	if (name.empty()) return {{"error", "name (function name) is required"}};

	// Resolve function name -> address via PDB
	ResolveFunctionRequest resolveReq = {};
	strncpy_s(resolveReq.functionName, name.c_str(), sizeof(resolveReq.functionName) - 1);

	std::vector<uint8_t> resolveResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ResolveFunction, &resolveReq, sizeof(resolveReq), resolveResp)) {
		return {{"error", "ResolveFunction IPC failed - " + IpcErrorMessage()}};
	}
	if (resolveResp.size() < sizeof(ResolveFunctionResponse)) {
		return {{"error", "Invalid response from DLL"}};
	}
	auto* resolved = reinterpret_cast<const ResolveFunctionResponse*>(resolveResp.data());
	if (resolved->status != IpcStatus::Ok || resolved->address == 0) {
		return {{"error", "Could not resolve function '" + name + "' (no PDB symbols or not found)"}};
	}

	// Set breakpoint at resolved address
	SetBreakpointRequest bpReq;
	bpReq.address = resolved->address;
	std::vector<uint8_t> bpResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (bpResp.size() < sizeof(SetBreakpointResponse)) {
		return {{"error", "Invalid response from DLL"}};
	}
	auto* resp = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
	if (resp->status != IpcStatus::Ok) {
		return {{"error", "Failed to set breakpoint at resolved address"}};
	}

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		bool found = false;
		for (auto& existing : swBreakpoints_) {
			if (existing.id == resp->id) {
				existing.functionName = name;
				existing.condition = args.value("condition", "");
				existing.hitCondition = args.value("hitCondition", "");
				existing.logMessage = args.value("logMessage", "");
				found = true;
				break;
			}
		}
		if (!found) {
			BpMapping bp;
			bp.id = resp->id;
			bp.address = resolved->address;
			bp.functionName = name;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			swBreakpoints_.push_back(bp);
		}
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", resolved->address);
	return {{"success", true}, {"id", resp->id}, {"address", buf}, {"function", name}};
}

json McpServer::ToolListBreakpoints(const json& args) {
	json swList = json::array();
	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		for (auto& bp : swBreakpoints_) {
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", bp.address);
			json entry = {{"id", bp.id}, {"address", buf}};
			if (!bp.condition.empty()) entry["condition"] = bp.condition;
			if (!bp.hitCondition.empty()) entry["hitCondition"] = bp.hitCondition;
			if (!bp.logMessage.empty()) entry["logMessage"] = bp.logMessage;
			if (bp.hitCount > 0) entry["hitCount"] = bp.hitCount;
			if (!bp.source.empty()) { entry["source"] = bp.source; entry["line"] = bp.line; }
			if (!bp.functionName.empty()) entry["function"] = bp.functionName;
			swList.push_back(entry);
		}
	}
	json hwList = json::array();
	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		for (auto& bp : hwBreakpoints_) {
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", bp.address);
			const char* typeStr = bp.type == 0 ? "execute" : bp.type == 1 ? "write" : "readwrite";
			hwList.push_back({{"id", bp.id}, {"address", buf}, {"type", typeStr}, {"size", bp.size}});
		}
	}
	return {{"software", swList}, {"hardware", hwList}};
}

json McpServer::ToolEvaluate(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string expression = args.value("expression", "");
	uint32_t threadId = JsonUint32(args, "threadId");
	if (expression.empty()) return {{"error", "expression is required"}};

	// Trim
	while (!expression.empty() && expression.front() == ' ') expression.erase(expression.begin());
	while (!expression.empty() && expression.back() == ' ') expression.pop_back();

	// 1) Register name
	if (TryParseRegisterName(expression)) {
		if (threadId == 0) return {{"error", "threadId is required for register evaluation"}};
		GetRegistersRequest regReq;
		regReq.threadId = threadId;
		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)
			&& respData.size() >= sizeof(GetRegistersResponse)) {
			auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
			uint64_t val = ResolveRegisterByName(expression, regResp->regs);
			char buf[32];
			if (regResp->regs.is32bit)
				snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
			else
				snprintf(buf, sizeof(buf), "0x%016llX", val);
			return {{"value", buf}, {"type", regResp->regs.is32bit ? "uint32" : "uint64"}};
		}
		return {{"error", "Failed to read registers"}};
	}

	// 2) Hex address (0x...) -> memory preview
	if (expression.size() > 2 && expression[0] == '0' && (expression[1] == 'x' || expression[1] == 'X')) {
		try {
			uint64_t addr = std::stoull(expression, nullptr, 16);
			ReadMemoryRequest readReq;
			readReq.address = addr;
			readReq.size = 8;
			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)
				&& respData.size() >= sizeof(IpcStatus) + 8) {
				auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
				if (status == IpcStatus::Ok) {
					uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
					char buf[64];
					snprintf(buf, sizeof(buf), "[0x%llX] = 0x%016llX", addr, val);
					return {{"value", buf}, {"type", "memory"}};
				}
			}
		} catch (...) {}
		return {{"error", "Failed to read memory at " + expression}};
	}

	// 3) gs:[offset] or fs:[offset] -> segment register base + offset dereference
	//    x64: GS base = TEB address; x86: FS base = TEB address
	//    gs:[0x60] = PEB pointer, gs:[0x30] = TEB self-reference, etc.
	{
		std::string upper = expression;
		std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
		bool isGs = (upper.substr(0, 4) == "GS:[");
		bool isFs = (upper.substr(0, 4) == "FS:[");
		if (isGs || isFs) {
			std::string offsetStr = expression.substr(4);
			if (!offsetStr.empty() && offsetStr.back() == ']') offsetStr.pop_back();
			while (!offsetStr.empty() && offsetStr.front() == ' ') offsetStr.erase(offsetStr.begin());
			try {
				uint64_t offset = std::stoull(offsetStr, nullptr, 0);
				// Get TEB address via NtQueryInformationThread
				if (threadId == 0) return {{"error", "threadId is required for segment register evaluation"}};
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
				if (!hThread) return {{"error", "Failed to open thread"}};

				// THREAD_BASIC_INFORMATION contains TEB address
				typedef struct {
					LONG ExitStatus;
					PVOID TebBaseAddress;
					struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId;
					ULONG_PTR AffinityMask;
					LONG Priority;
					LONG BasePriority;
				} THREAD_BASIC_INFORMATION;

				typedef LONG(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
				auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
					GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
				if (!NtQueryInformationThread) { CloseHandle(hThread); return {{"error", "NtQueryInformationThread not found"}}; }

				// x64: gs=TEB, x86: fs=TEB. Reject wrong combination.
				BOOL isWow64 = FALSE;
				IsWow64Process(targetProcess_ ? targetProcess_ : GetCurrentProcess(), &isWow64);
				if ((!isWow64 && isFs) || (isWow64 && isGs)) {
					CloseHandle(hThread);
					return {{"error", isFs ? "fs:[] is x86 only (use gs:[] for x64)" : "gs:[] is x64 only (use fs:[] for x86)"}};
				}

				THREAD_BASIC_INFORMATION tbi = {};
				LONG ntStatus = NtQueryInformationThread(hThread, 0/*ThreadBasicInformation*/, &tbi, sizeof(tbi), nullptr);
				CloseHandle(hThread);

				if (ntStatus != 0) return {{"error", "NtQueryInformationThread failed"}};

				uint64_t tebAddr = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
				uint64_t targetAddr = tebAddr + offset;

				// Read pointer-sized value at TEB + offset
				ReadMemoryRequest readReq;
				readReq.address = targetAddr;
				readReq.size = 8;
				std::vector<uint8_t> respData;
				if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)
					&& respData.size() >= sizeof(IpcStatus) + 8) {
					auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
					if (status == IpcStatus::Ok) {
						uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
						char buf[80];
						snprintf(buf, sizeof(buf), "0x%016llX (TEB=0x%llX + 0x%llX)", val, tebAddr, offset);
						return {{"value", buf}, {"type", "segment"}, {"tebAddress", (std::ostringstream() << "0x" << std::hex << tebAddr).str()}};
					}
				}
				return {{"error", "Failed to read memory at segment base + offset"}};
			} catch (...) {}
			return {{"error", "Invalid offset in segment expression"}};
		}
	}

	// 4) *expr or [expr] -> pointer dereference with register+offset support
	//    Supported: *0x1234, [0x1234], [RAX], [RAX+0x10], [RAX-8], [RAX+RBX]
	if (!expression.empty() && (expression[0] == '*' || expression[0] == '[')) {
		std::string inner = expression.substr(1);
		if (!inner.empty() && inner.back() == ']') inner.pop_back();
		while (!inner.empty() && inner.front() == ' ') inner.erase(inner.begin());
		while (!inner.empty() && inner.back() == ' ') inner.pop_back();

		// Try to resolve as address expression (reg+offset, reg-offset, reg+reg, or plain value)
		uint64_t addr = 0;
		bool resolved = false;
		try {
			addr = std::stoull(inner, nullptr, 0);
			resolved = true;
		} catch (...) {}

		if (!resolved && threadId != 0) {
			// Parse reg+offset or reg-offset
			GetRegistersRequest regReq;
			regReq.threadId = threadId;
			std::vector<uint8_t> regResp;
			if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), regResp)
				&& regResp.size() >= sizeof(GetRegistersResponse)) {
				auto* rr = reinterpret_cast<const GetRegistersResponse*>(regResp.data());

				// Find + or - operator (skip leading chars that are part of register names)
				size_t opPos = std::string::npos;
				char opChar = 0;
				for (size_t i = 1; i < inner.size(); i++) {
					if (inner[i] == '+' || inner[i] == '-') {
						opPos = i;
						opChar = inner[i];
						break;
					}
				}

				if (opPos != std::string::npos) {
					std::string lhs = inner.substr(0, opPos);
					std::string rhs = inner.substr(opPos + 1);
					while (!lhs.empty() && lhs.back() == ' ') lhs.pop_back();
					while (!rhs.empty() && rhs.front() == ' ') rhs.erase(rhs.begin());

					uint64_t lhsVal = 0, rhsVal = 0;
					bool lhsOk = false, rhsOk = false;

					if (TryParseRegisterName(lhs)) {
						lhsVal = ResolveRegisterByName(lhs, rr->regs);
						lhsOk = true;
					} else {
						try { lhsVal = std::stoull(lhs, nullptr, 0); lhsOk = true; } catch (...) {}
					}

					if (TryParseRegisterName(rhs)) {
						rhsVal = ResolveRegisterByName(rhs, rr->regs);
						rhsOk = true;
					} else {
						try { rhsVal = std::stoull(rhs, nullptr, 0); rhsOk = true; } catch (...) {}
					}

					if (lhsOk && rhsOk) {
						addr = (opChar == '+') ? (lhsVal + rhsVal) : (lhsVal - rhsVal);
						resolved = true;
					}
				} else {
					// Single register name
					if (TryParseRegisterName(inner)) {
						addr = ResolveRegisterByName(inner, rr->regs);
						resolved = true;
					}
				}
			}
		}

		if (!resolved) return {{"error", "Cannot parse address expression: " + inner}};

		ReadMemoryRequest readReq;
		readReq.address = addr;
		readReq.size = 8;
		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)
			&& respData.size() >= sizeof(IpcStatus) + 8) {
			auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
			if (status == IpcStatus::Ok) {
				uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
				char buf[64];
				snprintf(buf, sizeof(buf), "0x%016llX", val);
				char addrBuf[32];
				snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);
				return {{"value", buf}, {"address", addrBuf}, {"type", "pointer"}};
			}
		}
		return {{"error", "Failed to read memory at computed address"}};
	}

	return {{"error", "Supported: register (RAX), 0x<addr>, [addr], [reg+offset], gs:[offset], fs:[offset]"}};
}

json McpServer::ToolSetRegister(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	std::string name = args.value("name", "");
	std::string valueStr = args.value("value", "");
	if (threadId == 0) return {{"error", "threadId is required"}};
	if (name.empty()) return {{"error", "name (register name) is required"}};
	if (valueStr.empty()) return {{"error", "value is required"}};

	uint32_t regIndex = GetRegisterIndex(name);
	if (regIndex == UINT32_MAX) {
		return {{"error", "Unknown register: " + name}};
	}

	uint64_t newVal;
	try {
		newVal = std::stoull(valueStr, nullptr, 0);
	} catch (...) {
		return {{"error", "Invalid value: " + valueStr}};
	}

	SetRegisterRequest req;
	req.threadId = threadId;
	req.regIndex = regIndex;
	req.value = newVal;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetRegister, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() >= sizeof(SetRegisterResponse)) {
		auto* resp = reinterpret_cast<const SetRegisterResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			char buf[32];
			snprintf(buf, sizeof(buf), "0x%llX", newVal);
			return {{"success", true}, {"name", name}, {"value", buf}};
		}
	}
	return {{"error", "Failed to set register"}};
}

json McpServer::ToolExceptionInfo(const json& args) {
	std::lock_guard<std::mutex> lock(exceptionMutex_);
	if (lastException_.code == 0) {
		return {{"error", "No exception recorded"}};
	}
	char codeBuf[32], addrBuf[32];
	snprintf(codeBuf, sizeof(codeBuf), "0x%08X", lastException_.code);
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", lastException_.address);
	return {
		{"exceptionCode", codeBuf},
		{"address", addrBuf},
		{"threadId", lastException_.threadId},
		{"description", lastException_.description}
	};
}

json McpServer::ToolTraceCallers(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	int durationSec = JsonInt(args, "duration_sec", 5);
	if (durationSec < 1) durationSec = 1;
	if (durationSec > 60) durationSec = 60;

	// Auto-resume: trace needs the process running to collect hits.
	// Resume all stopped threads before tracing, pause again after.
	ResumeMainThread();
	ContinueRequest contReq = {};
	contReq.threadId = 0;
	pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));

	// Build IPC request
	TraceCallersRequest req;
	req.address = addr;
	req.durationMs = static_cast<uint32_t>(durationSec) * 1000;

	// Send TraceCallers command (blocking - DLL will sleep for durationMs)
	std::vector<uint8_t> respData;
	int timeoutMs = (durationSec + 10) * 1000;
	if (!pipeClient_.SendAndReceive(IpcCommand::TraceCallers, &req, sizeof(req), respData, timeoutMs)) {
		// Pause before returning error
		PauseRequest pauseReq; pauseReq.threadId = 0;
		pipeClient_.SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));
		return {{"error", IpcErrorMessage()}};
	}

	// Auto-pause after collection
	PauseRequest pauseReq; pauseReq.threadId = 0;
	pipeClient_.SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));

	// Drain stale events from auto-resume period (BP hits during trace, pause event)
	{
		std::lock_guard<std::mutex> lock(bpHitMutex_);
		bpHitOccurred_ = false;
	}

	// Parse response: TraceCallersResponse header + TraceCallerEntry[] array
	if (respData.size() < sizeof(TraceCallersResponse)) {
		return {{"error", "Invalid response from DLL"}};
	}
	const auto* hdr = reinterpret_cast<const TraceCallersResponse*>(respData.data());
	if (hdr->status != IpcStatus::Ok) {
		return {{"error", "TraceCallers failed (breakpoint could not be set)"}};
	}

	// Build result
	json callers = json::array();
	const auto* entries = reinterpret_cast<const TraceCallerEntry*>(respData.data() + sizeof(TraceCallersResponse));
	size_t count = hdr->uniqueCallers;
	if (count > 100000) count = 100000; // sanity cap
	// Validate we have enough data
	if (respData.size() >= sizeof(TraceCallersResponse) + count * sizeof(TraceCallerEntry)) {
		for (size_t i = 0; i < count; i++) {
			char buf[32];
			snprintf(buf, sizeof(buf), "0x%llX", entries[i].callerAddress);
			callers.push_back({
				{"address", buf},
				{"hitCount", entries[i].hitCount}
			});
		}
	}

	return {
		{"totalHits", hdr->totalHits},
		{"uniqueCallers", hdr->uniqueCallers},
		{"durationSec", durationSec},
		{"callers", callers}
	};
}

json McpServer::ToolSetDataBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	std::string typeStr = args.value("type", "write");
	int size = JsonInt(args, "size", 4);

	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	SetHwBreakpointRequest req;
	req.address = addr;
	if (typeStr == "execute")        req.type = 0;
	else if (typeStr == "write")     req.type = 1;
	else if (typeStr == "readwrite") req.type = 3;
	else return {{"error", "type must be execute, write, or readwrite"}};
	if (size != 1 && size != 2 && size != 4 && size != 8) {
		return {{"error", "size must be 1, 2, 4, or 8"}};
	}
	req.size = static_cast<uint8_t>(size);

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetHwBreakpoint, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() >= sizeof(SetHwBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetHwBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			{
				std::lock_guard<std::mutex> lock(bpMutex_);
				hwBreakpoints_.push_back({resp->id, addr, req.type, req.size});
			}
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
			return {{"success", true}, {"id", resp->id}, {"slot", resp->slot},
			        {"address", buf}, {"type", typeStr}, {"size", size}};
		}
	}
	return {{"error", "Failed to set data breakpoint (max 4 HW slots)"}};
}

json McpServer::ToolRemoveDataBreakpoint(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t id = JsonUint32(args, "id");
	if (!args.contains("id") || id == 0) {
		return {{"error", "id is required (positive integer)"}};
	}

	RemoveHwBreakpointRequest req;
	req.id = id;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::RemoveHwBreakpoint, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) {
			return {{"error", "Data breakpoint not found (id=" + std::to_string(id) + ")"}};
		}
	}

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		hwBreakpoints_.erase(
			std::remove_if(hwBreakpoints_.begin(), hwBreakpoints_.end(),
				[id](const HwBpMapping& bp) { return bp.id == id; }),
			hwBreakpoints_.end());
	}

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolContinue(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	// stopOnEntry=true로 launch한 경우, 첫 continue에서 OS-level resume 수행
	ResumeMainThread();
	CleanupTempStepOverBp();

	uint32_t threadId = JsonUint32(args, "threadId");
	bool wait = JsonBool(args, "wait");
	bool passException = JsonBool(args, "pass_exception");
	int timeoutSec = JsonInt(args, "timeout", 10);
	if (timeoutSec < 1) timeoutSec = 1;
	if (timeoutSec > 300) timeoutSec = 300;

	// stopOnEntry=false 등에서 프로세스 실행 중 이벤트(exception/BP)가
	// veh_continue 호출 전에 발생할 수 있음. 캐시된 이벤트가 있으면 즉시 반환.
	if (wait && !passException) {
		std::lock_guard<std::mutex> lock(bpHitMutex_);
		if (bpHitOccurred_) {
			// 이미 발생한 이벤트 반환 (Continue 전송 안 함 - 스레드가 정지 상태)
			bpHitOccurred_ = false;  // 소비
			json ret = {
				{"stopped", true},
				{"reason", bpHitStopReason_},
				{"address", (std::ostringstream() << "0x" << std::hex << bpHitAddr_).str()},
				{"threadId", bpHitThread_},
				{"breakpointId", bpHitId_}
			};
			if (!bpHitType_.empty()) ret["breakpointType"] = bpHitType_;
			return ret;
		}
	}

	ContinueRequest req;
	req.threadId = threadId;
	req.passException = passException ? 1 : 0;

	if (!pipeClient_.SendCommand(IpcCommand::Continue, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}

	if (!wait) {
		return {{"success", true}, {"threadId", threadId}};
	}

	// Wait for breakpoint hit, step complete, pause, exception, or process exit
	{
		std::unique_lock<std::mutex> lock(bpHitMutex_);
		if (!bpHitCv_.wait_for(lock, std::chrono::seconds(timeoutSec),
				[this]{ return bpHitOccurred_ || !attached_; })) {
			return {{"timeout", true}, {"message", "No stop event within timeout. Process still running."}};
		}
		bpHitOccurred_ = false;  // 소비
		// Process exited but bpHitOccurred_ wasn't set (race with ProcessMonitor)
		if (!attached_ && bpHitStopReason_ != "exit") {
			return {
				{"stopped", true},
				{"reason", "exit"},
				{"address", "0x0"},
				{"threadId", 0},
				{"breakpointId", 0}
			};
		}
		json ret = {
			{"stopped", true},
			{"reason", bpHitStopReason_},
			{"address", (std::ostringstream() << "0x" << std::hex << bpHitAddr_).str()},
			{"threadId", bpHitThread_},
			{"breakpointId", bpHitId_}
		};
		if (!bpHitType_.empty()) ret["breakpointType"] = bpHitType_;
		return ret;
	}
}

json McpServer::ToolStepIn(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};
	ResumeMainThread();
	CleanupTempStepOverBp();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepInto, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) {
			return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
		}
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolStepOver(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};
	ResumeMainThread();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	// Clean up any stale temp BP from previous step-over
	CleanupTempStepOverBp();

	// Check if current instruction is CALL - if so, skip over it
	uint64_t nextAddr = 0;
	if (IsCallInstruction(threadId, nextAddr)) {
		// Set temp breakpoint at return address (instruction after CALL)
		if (SetTempBpAndContinue(nextAddr)) {
			return {{"success", true}, {"threadId", threadId}, {"skippedCall", true}};
		}
		// Temp BP failed - fall through to normal step
	}

	// Check if we're on a BP (rearm will execute 2 instructions)
	// If the NEXT instruction is CALL, we need to handle it preemptively
	uint64_t callAfterAddr = 0;
	if (IsNextInstructionCall(threadId, callAfterAddr)) {
		// Next instruction is CALL - set temp BP past the CALL and continue
		if (SetTempBpAndContinue(callAfterAddr)) {
			return {{"success", true}, {"threadId", threadId}, {"skippedCall", true}};
		}
	}

	// Normal single-step with synchronous wait
	{
		std::lock_guard<std::mutex> lock(stepMutex_);
		stepCompleted_ = false;
	}

	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> stepResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepOver, &req, sizeof(req), stepResp)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (stepResp.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(stepResp.data());
		if (status == IpcStatus::NotFound) {
			return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
		}
	}

	// Wait for StepCompleted event (up to 5s)
	{
		std::unique_lock<std::mutex> lock(stepMutex_);
		if (!stepCv_.wait_for(lock, std::chrono::seconds(5),
				[this]{ return stepCompleted_ || !attached_; })) {
			return {{"error", "Step timed out (threadId=" + std::to_string(threadId) + "). Thread may not be stopped or may be deadlocked."}};
		}
		if (!stepCompleted_ && !attached_) {
			return {{"error", "Target process exited during step"}};
		}
	}

	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolStepOut(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};
	ResumeMainThread();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepOut, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) {
			return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
		}
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolPause(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	PauseRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::Pause, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolThreads(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetThreads, nullptr, 0, respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(GetThreadsResponse)) {
		return {{"error", "Invalid response from DLL (truncated data)"}};
	}

	auto* resp = reinterpret_cast<const GetThreadsResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) {
		return {{"error", "GetThreads failed (CreateToolhelp32Snapshot error)"}};
	}
	auto* infos = reinterpret_cast<const ThreadInfo*>(respData.data() + sizeof(GetThreadsResponse));

	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetThreadsResponse))
		? (respData.size() - sizeof(GetThreadsResponse)) / sizeof(ThreadInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	json threads = json::array();
	for (uint32_t i = 0; i < count; i++) {
		threads.push_back({
			{"id", infos[i].id},
			{"name", infos[i].name}
		});
	}

	return {{"threads", threads}, {"count", count}};
}

json McpServer::ToolStackTrace(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	int maxFrames = JsonInt(args, "maxFrames", 20);
	if (maxFrames <= 0 || maxFrames > 200) maxFrames = 20;

	GetStackTraceRequest req;
	req.threadId = threadId;
	req.startFrame = 0;
	req.maxFrames = maxFrames;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(GetStackTraceResponse)) {
		return {{"error", "Invalid response from DLL (truncated data)"}};
	}

	auto* resp = reinterpret_cast<const GetStackTraceResponse*>(respData.data());
	auto* infos = reinterpret_cast<const StackFrameInfo*>(respData.data() + sizeof(GetStackTraceResponse));

	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetStackTraceResponse))
		? (respData.size() - sizeof(GetStackTraceResponse)) / sizeof(StackFrameInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	json frames = json::array();
	for (uint32_t i = 0; i < count; i++) {
		char addrBuf[20];
		snprintf(addrBuf, sizeof(addrBuf), "0x%llX", infos[i].address);

		json frame = {
			{"address", addrBuf},
			{"module", infos[i].moduleName},
			{"function", infos[i].functionName}
		};
		if (infos[i].sourceFile[0]) {
			frame["source"] = infos[i].sourceFile;
			frame["line"] = infos[i].line;
		}
		frames.push_back(frame);
	}

	return {{"frames", frames}, {"totalFrames", resp->totalFrames}};
}

json McpServer::ToolEnumLocals(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	// instructionAddress (RIP) and frameBase (RBP) for SymSetContext
	uint64_t instrAddr = 0, frameBase = 0;
	if (args.contains("instructionAddress")) {
		auto& v = args["instructionAddress"];
		if (v.is_string()) instrAddr = std::strtoull(v.get<std::string>().c_str(), nullptr, 0);
		else if (v.is_number()) instrAddr = v.get<uint64_t>();
	}
	if (args.contains("frameBase")) {
		auto& v = args["frameBase"];
		if (v.is_string()) frameBase = std::strtoull(v.get<std::string>().c_str(), nullptr, 0);
		else if (v.is_number()) frameBase = v.get<uint64_t>();
	}

	// If not provided, get from top frame of stack trace
	if (instrAddr == 0 || frameBase == 0) {
		GetStackTraceRequest stReq;
		stReq.threadId = threadId;
		stReq.startFrame = 0;
		stReq.maxFrames = 1;

		std::vector<uint8_t> stResp;
		if (pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp)
			&& stResp.size() >= sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo)) {
			auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + sizeof(GetStackTraceResponse));
			if (instrAddr == 0) instrAddr = frame->address;
			if (frameBase == 0) frameBase = frame->frameBase;
		}

		if (instrAddr == 0) return {{"error", "Could not determine instruction address. Provide instructionAddress or ensure target is stopped."}};
	}

	EnumLocalsRequest req;
	req.threadId = threadId;
	req.instructionAddress = instrAddr;
	req.frameBase = frameBase;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::EnumLocals, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(EnumLocalsResponse)) {
		return {{"error", "Invalid response from DLL (truncated data)"}};
	}

	auto* resp = reinterpret_cast<const EnumLocalsResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return {{"error", "Failed to enumerate locals (no PDB symbols or invalid frame)"}};

	auto* locals = reinterpret_cast<const LocalVariableInfo*>(respData.data() + sizeof(EnumLocalsResponse));
	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(EnumLocalsResponse))
		? (respData.size() - sizeof(EnumLocalsResponse)) / sizeof(LocalVariableInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	json vars = json::array();
	char buf[32];
	for (uint32_t i = 0; i < count; i++) {
		// Safe null-terminated copy
		char safeName[sizeof(LocalVariableInfo::name) + 1] = {};
		memcpy(safeName, locals[i].name, sizeof(locals[i].name));
		char safeType[sizeof(LocalVariableInfo::typeName) + 1] = {};
		memcpy(safeType, locals[i].typeName, sizeof(locals[i].typeName));

		snprintf(buf, sizeof(buf), "0x%llX", locals[i].address);

		// Format value based on type
		std::string valueStr;
		if (locals[i].valueSize >= 4 && (strstr(safeType, "float") != nullptr)) {
			float f;
			memcpy(&f, locals[i].value, sizeof(f));
			char fBuf[64];
			snprintf(fBuf, sizeof(fBuf), "%.6g", f);
			valueStr = fBuf;
		} else if (locals[i].valueSize >= 8 && (strstr(safeType, "double") != nullptr)) {
			double d;
			memcpy(&d, locals[i].value, sizeof(d));
			char dBuf[64];
			snprintf(dBuf, sizeof(dBuf), "%.10g", d);
			valueStr = dBuf;
		} else if (locals[i].valueSize >= 8 && (strstr(safeType, "*") != nullptr)) {
			uint64_t ptr;
			memcpy(&ptr, locals[i].value, sizeof(ptr));
			char pBuf[32];
			snprintf(pBuf, sizeof(pBuf), "0x%llX", ptr);
			valueStr = pBuf;
		} else if (locals[i].valueSize >= 4) {
			int32_t val;
			memcpy(&val, locals[i].value, sizeof(val));
			valueStr = std::to_string(val);
		} else {
			valueStr = "(unreadable)";
		}

		json var = {
			{"name", safeName},
			{"type", safeType},
			{"address", buf},
			{"value", valueStr},
			{"size", locals[i].size}
		};
		if (locals[i].flags & 0x100) var["isParameter"] = true;  // SYMFLAG_PARAMETER
		vars.push_back(var);
	}

	return {{"variables", vars}, {"count", count}};
}

json McpServer::ToolRegisters(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	GetRegistersRequest req;
	req.threadId = threadId;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(GetRegistersResponse)) {
		return {{"error", "Invalid response from DLL (truncated data)"}};
	}

	auto* resp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return {{"error", "Failed to get registers (thread may not exist or is not suspended)"}};

	const auto& r = resp->regs;
	char buf[20];

	json regs = json::object();
	auto hex = [&](uint64_t v) -> std::string {
		snprintf(buf, sizeof(buf), "0x%llX", v);
		return buf;
	};

	if (r.is32bit) {
		regs["eax"] = hex(r.rax); regs["ebx"] = hex(r.rbx);
		regs["ecx"] = hex(r.rcx); regs["edx"] = hex(r.rdx);
		regs["esi"] = hex(r.rsi); regs["edi"] = hex(r.rdi);
		regs["ebp"] = hex(r.rbp); regs["esp"] = hex(r.rsp);
		regs["eip"] = hex(r.rip);
	} else {
		regs["rax"] = hex(r.rax); regs["rbx"] = hex(r.rbx);
		regs["rcx"] = hex(r.rcx); regs["rdx"] = hex(r.rdx);
		regs["rsi"] = hex(r.rsi); regs["rdi"] = hex(r.rdi);
		regs["rbp"] = hex(r.rbp); regs["rsp"] = hex(r.rsp);
		regs["r8"]  = hex(r.r8);  regs["r9"]  = hex(r.r9);
		regs["r10"] = hex(r.r10); regs["r11"] = hex(r.r11);
		regs["r12"] = hex(r.r12); regs["r13"] = hex(r.r13);
		regs["r14"] = hex(r.r14); regs["r15"] = hex(r.r15);
		regs["rip"] = hex(r.rip);
	}
	regs["eflags"] = hex(r.rflags);
	regs["cs"] = hex(r.cs); regs["ss"] = hex(r.ss);
	// Debug registers
	regs["dr0"] = hex(r.dr0); regs["dr1"] = hex(r.dr1);
	regs["dr2"] = hex(r.dr2); regs["dr3"] = hex(r.dr3);
	regs["dr6"] = hex(r.dr6); regs["dr7"] = hex(r.dr7);
	regs["is32bit"] = (bool)r.is32bit;

	return {{"registers", regs}};
}

json McpServer::ToolReadMemory(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int size = JsonInt(args, "size", 64);
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (size <= 0 || size > 1048576) return {{"error", "size must be 1-1048576"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}
	ReadMemoryRequest req;
	req.address = addr;
	req.size = static_cast<uint32_t>(size);

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(IpcStatus)) return {{"error", "Invalid response from DLL (truncated data)"}};
	auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
	if (status != IpcStatus::Ok) return {{"error", "Memory read failed (address may be invalid or inaccessible)"}};

	const uint8_t* data = respData.data() + sizeof(IpcStatus);
	size_t dataLen = respData.size() - sizeof(IpcStatus);

	// hex string으로 변환
	std::ostringstream oss;
	for (size_t i = 0; i < dataLen; i++) {
		if (i > 0 && i % 16 == 0) oss << "\n";
		else if (i > 0) oss << " ";
		oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	return {{"address", addrBuf}, {"size", dataLen}, {"hex", oss.str()}};
}

// Helper: parse hex string to bytes
static bool ParseHexBytes(const std::string& hexStr, std::vector<uint8_t>& out) {
	std::string clean;
	for (char c : hexStr) {
		if (std::isxdigit(c)) clean += c;
	}
	if (clean.size() % 2 != 0) return false;
	out.clear();
	for (size_t i = 0; i < clean.size(); i += 2) {
		out.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	return true;
}

json McpServer::ToolWriteMemory(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	// Batch mode: patches array [{address, data}, ...]
	if (args.contains("patches") && args["patches"].is_array()) {
		const auto& patches = args["patches"];
		if (patches.size() > 1000) return {{"error", "Too many patches (max 1000)"}};
		int succeeded = 0, failed = 0;
		json errors = json::array();
		for (const auto& patch : patches) {
			std::string pAddr = patch.value("address", "");
			std::string pData = patch.value("data", "");
			uint64_t addr;
			if (pAddr.empty() || !ParseAddress(pAddr, addr)) {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "invalid address"}});
				continue;
			}
			std::vector<uint8_t> bytes;
			if (!ParseHexBytes(pData, bytes) || bytes.empty()) {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "invalid hex data"}});
				continue;
			}
			std::vector<uint8_t> payload(sizeof(WriteMemoryRequest) + bytes.size());
			auto* req = reinterpret_cast<WriteMemoryRequest*>(payload.data());
			req->address = addr;
			req->size = static_cast<uint32_t>(bytes.size());
			memcpy(payload.data() + sizeof(WriteMemoryRequest), bytes.data(), bytes.size());
			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::WriteMemory, payload.data(),
			                                static_cast<uint32_t>(payload.size()), respData)
				&& respData.size() >= sizeof(IpcStatus)
				&& *reinterpret_cast<const IpcStatus*>(respData.data()) == IpcStatus::Ok) {
				succeeded++;
			} else {
				failed++;
				errors.push_back({{"address", pAddr}, {"error", "write failed"}});
			}
		}
		json ret = {{"success", failed == 0}, {"succeeded", succeeded}, {"failed", failed}};
		if (!errors.empty()) ret["errors"] = errors;
		return ret;
	}

	// Single mode (existing behavior)
	std::string addrStr = args.value("address", "");
	std::string dataHex = args.value("data", "");
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (dataHex.empty()) return {{"error", "data is required (hex string)"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	std::vector<uint8_t> bytes;
	if (!ParseHexBytes(dataHex, bytes)) return {{"error", "Invalid hex string"}};
	if (bytes.size() > 1048576) {
		return {{"error", "data too large (max 1MB)"}};
	}

	std::vector<uint8_t> payload(sizeof(WriteMemoryRequest) + bytes.size());
	auto* req = reinterpret_cast<WriteMemoryRequest*>(payload.data());
	req->address = addr;
	req->size = static_cast<uint32_t>(bytes.size());
	memcpy(payload.data() + sizeof(WriteMemoryRequest), bytes.data(), bytes.size());

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::WriteMemory, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::Ok) {
			return {{"success", true}, {"bytesWritten", bytes.size()}};
		}
	}
	return {{"error", "Memory write failed (address may be invalid, read-only, or inaccessible)"}};
}

json McpServer::ToolDumpMemory(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int size = JsonInt(args, "size", 4096);
	std::string outputPath = args.value("output_path", "");
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (outputPath.empty()) return {{"error", "output_path is required"}};
	if (size <= 0 || size > 64 * 1024 * 1024) return {{"error", "size must be 1-67108864 (64MB)"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	// Open output file
	FILE* fp = fopen(outputPath.c_str(), "wb");
	if (!fp) {
		return {{"error", "Cannot open output file: " + outputPath}};
	}

	// Read in chunks of 1MB via IPC
	const uint32_t chunkSize = 1024 * 1024;
	uint64_t totalWritten = 0;
	uint64_t remaining = static_cast<uint64_t>(size);
	uint64_t currentAddr = addr;

	while (remaining > 0) {
		uint32_t toRead = static_cast<uint32_t>((remaining > chunkSize) ? chunkSize : remaining);
		ReadMemoryRequest req;
		req.address = currentAddr;
		req.size = toRead;

		std::vector<uint8_t> respData;
		if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &req, sizeof(req), respData)
			|| respData.size() < sizeof(IpcStatus)) {
			fclose(fp);
			return {{"error", "IPC error during read"}, {"bytesWritten", totalWritten}};
		}

		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status != IpcStatus::Ok) {
			fclose(fp);
			if (totalWritten > 0) {
				return {{"partial", true}, {"bytesWritten", totalWritten},
				        {"error", "Memory read failed at offset " + std::to_string(totalWritten)}};
			}
			return {{"error", "Memory read failed at starting address"}};
		}

		const uint8_t* data = respData.data() + sizeof(IpcStatus);
		size_t dataLen = respData.size() - sizeof(IpcStatus);
		fwrite(data, 1, dataLen, fp);
		totalWritten += dataLen;
		currentAddr += dataLen;
		if (dataLen > remaining) break;  // guard against unsigned underflow
		remaining -= dataLen;
	}

	fclose(fp);
	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	// Verify file: size + SHA256 checksum
	FILE* verify = fopen(outputPath.c_str(), "rb");
	uint64_t fileSize = 0;
	std::string sha256hex;
	if (verify) {
		// Compute SHA256 using Windows CryptoAPI
		_fseeki64(verify, 0, SEEK_END);
		fileSize = _ftelli64(verify);
		_fseeki64(verify, 0, SEEK_SET);

		HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
		if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
				uint8_t buf[65536];
				size_t bytesRead;
				while ((bytesRead = fread(buf, 1, sizeof(buf), verify)) > 0) {
					CryptHashData(hHash, buf, static_cast<DWORD>(bytesRead), 0);
				}
				DWORD hashLen = 32; uint8_t hash[32];
				if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
					char hex[65];
					for (DWORD i = 0; i < hashLen; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
					sha256hex = hex;
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hProv, 0);
		}
		fclose(verify);
	}

	json ret = {{"success", true}, {"address", addrBuf}, {"size", totalWritten},
	            {"output_path", outputPath}, {"fileSize", fileSize},
	            {"verified", fileSize == totalWritten}};
	if (!sha256hex.empty()) ret["sha256"] = sha256hex;
	return ret;
}

json McpServer::ToolAllocateMemory(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	int size = JsonInt(args, "size", 4096);
	std::string protStr = args.value("protection", "rwx");
	if (size <= 0 || size > 64 * 1024 * 1024) return {{"error", "size must be 1-67108864"}};

	uint32_t protection = PAGE_EXECUTE_READWRITE;
	if (protStr == "rw") protection = PAGE_READWRITE;
	else if (protStr == "rx") protection = PAGE_EXECUTE_READ;
	else if (protStr == "r") protection = PAGE_READONLY;

	AllocateMemoryRequest req;
	req.size = static_cast<uint32_t>(size);
	req.protection = protection;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::AllocateMemory, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() < sizeof(AllocateMemoryResponse)) return {{"error", "Invalid response"}};

	auto* resp = reinterpret_cast<const AllocateMemoryResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok || resp->address == 0) {
		return {{"error", "VirtualAlloc failed in target process"}};
	}

	char buf[20];
	snprintf(buf, sizeof(buf), "0x%llX", resp->address);
	return {{"success", true}, {"address", buf}, {"size", size}, {"protection", protStr}};
}

json McpServer::ToolFreeMemory(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) return {{"error", "invalid address format"}};

	FreeMemoryRequest req;
	req.address = addr;
	req.size = 0;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::FreeMemory, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::Ok) return {{"success", true}};
	}
	return {{"error", "VirtualFree failed"}};
}

json McpServer::ToolExecuteShellcode(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string codeHex = args.value("shellcode", "");
	if (codeHex.empty()) return {{"error", "shellcode (hex string) is required"}};
	int timeoutMs = JsonInt(args, "timeout_ms", 5000);
	if (timeoutMs < 0) timeoutMs = 0;
	if (timeoutMs > 60000) timeoutMs = 60000;

	// Parse hex
	std::vector<uint8_t> bytes;
	std::string clean;
	for (char c : codeHex) {
		if (std::isxdigit(c)) clean += c;
	}
	if (clean.size() % 2 != 0) return {{"error", "Invalid hex string (odd length)"}};
	for (size_t i = 0; i < clean.size(); i += 2) {
		bytes.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	if (bytes.empty()) return {{"error", "Empty shellcode"}};
	if (bytes.size() > 1024 * 1024) return {{"error", "Shellcode too large (max 1MB)"}};

	// Build IPC payload: ExecuteShellcodeRequest + code bytes
	std::vector<uint8_t> payload(sizeof(ExecuteShellcodeRequest) + bytes.size());
	auto* req = reinterpret_cast<ExecuteShellcodeRequest*>(payload.data());
	req->size = static_cast<uint32_t>(bytes.size());
	req->timeoutMs = static_cast<uint32_t>(timeoutMs);
	memcpy(payload.data() + sizeof(ExecuteShellcodeRequest), bytes.data(), bytes.size());

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::ExecuteShellcode, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData)) {
		return {{"error", IpcErrorMessage()}};
	}
	if (respData.size() < sizeof(ExecuteShellcodeResponse)) return {{"error", "Invalid response"}};

	auto* resp = reinterpret_cast<const ExecuteShellcodeResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) {
		return {{"error", "Shellcode execution failed (alloc or thread creation error)"}};
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", resp->allocatedAddress);
	json ret = {
		{"success", true},
		{"exitCode", resp->exitCode},
		{"allocatedAddress", addrBuf},
		{"fireAndForget", (timeoutMs == 0)}
	};
	if (resp->crashed) {
		char exAddrBuf[20];
		snprintf(exAddrBuf, sizeof(exAddrBuf), "0x%llX", resp->exceptionAddress);
		char exCodeBuf[12];
		snprintf(exCodeBuf, sizeof(exCodeBuf), "0x%08X", resp->exceptionCode);
		ret["crashed"] = true;
		ret["exceptionCode"] = exCodeBuf;
		ret["exceptionAddress"] = exAddrBuf;
	}
	return ret;
}

json McpServer::ToolModules(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetModules, nullptr, 0, respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(GetModulesResponse)) {
		return {{"error", "Invalid response from DLL (truncated data)"}};
	}

	auto* resp = reinterpret_cast<const GetModulesResponse*>(respData.data());
	auto* infos = reinterpret_cast<const ModuleInfo*>(respData.data() + sizeof(GetModulesResponse));

	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetModulesResponse))
		? (respData.size() - sizeof(GetModulesResponse)) / sizeof(ModuleInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	json modules = json::array();
	for (uint32_t i = 0; i < count; i++) {
		char baseBuf[20], sizeBuf[20];
		snprintf(baseBuf, sizeof(baseBuf), "0x%llX", infos[i].baseAddress);
		snprintf(sizeBuf, sizeof(sizeBuf), "0x%X", infos[i].size);
		modules.push_back({
			{"name", infos[i].name},
			{"path", infos[i].path},
			{"baseAddress", baseBuf},
			{"size", sizeBuf}
		});
	}

	return {{"modules", modules}, {"count", count}};
}

json McpServer::ToolDisassemble(const json& args) {
	if (!attached_) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int count = JsonInt(args, "count", 20);
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (count <= 0 || count > 500) count = 20;

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	// 충분한 바이트 읽기 (x86 명령어 최대 15바이트)
	uint32_t readSize = static_cast<uint32_t>(count) * 15;
	ReadMemoryRequest req;
	req.address = addr;
	req.size = readSize;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &req, sizeof(req), respData)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (respData.size() < sizeof(IpcStatus)) return {{"error", "Invalid response from DLL"}};
	auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
	if (status != IpcStatus::Ok) return {{"error", "Memory read failed for disassembly (address may be invalid or inaccessible)"}};

	const uint8_t* code = respData.data() + sizeof(IpcStatus);
	size_t codeLen = respData.size() - sizeof(IpcStatus);

	if (!disassembler_) {
		return {{"error", "Disassembler not available"}};
	}
	auto instructions = disassembler_->Disassemble(code, (uint32_t)codeLen, addr, count);

	json result = json::array();
	for (auto& insn : instructions) {
		char addrBuf[20];
		snprintf(addrBuf, sizeof(addrBuf), "0x%llX", insn.address);
		result.push_back({
			{"address", addrBuf},
			{"bytes", insn.bytes},
			{"mnemonic", insn.mnemonic}
		});
	}

	return {{"instructions", result}, {"count", result.size()}};
}

// --- Event Queue Flush ---

void McpServer::FlushEvents() {
	std::queue<std::pair<std::string, json>> events;
	std::queue<uint32_t> autoContinues;
	{
		std::lock_guard<std::mutex> lock(eventMutex_);
		std::swap(events, pendingEvents_);
		std::swap(autoContinues, pendingAutoContinue_);
	}
	while (!events.empty()) {
		auto& [method, params] = events.front();
		SendNotification(method, params);
		events.pop();
	}
	// Process queued auto-continues (from condition fail / logpoints)
	while (!autoContinues.empty()) {
		uint32_t tid = autoContinues.front();
		autoContinues.pop();
		ContinueRequest req = {};
		req.threadId = tid;
		if (!pipeClient_.SendCommand(IpcCommand::Continue, &req, sizeof(req))) {
			LOG_WARN("Auto-continue failed for thread %u", tid);
		}
	}
}

// --- Register/Condition/LogMessage helpers (ported from DAP adapter) ---

bool McpServer::TryParseRegisterName(const std::string& name) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	static const char* regNames[] = {
		"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
		"RIP", "RFLAGS",
		"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
		"EIP", "EFLAGS",
	};
	for (auto* rn : regNames) {
		if (upper == rn) return true;
	}
	return false;
}

uint64_t McpServer::ResolveRegisterByName(const std::string& name, const RegisterSet& regs) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	// RegisterSet layout: rax=0,rbx=1,rcx=2,rdx=3,rsi=4,rdi=5,rbp=6,rsp=7,
	//   r8-r15=8-15, rip=16, rflags=17
	const uint64_t* r = &regs.rax;
	static const std::pair<const char*, int> map[] = {
		{"RAX",0},{"EAX",0},{"RBX",1},{"EBX",1},{"RCX",2},{"ECX",2},{"RDX",3},{"EDX",3},
		{"RSI",4},{"ESI",4},{"RDI",5},{"EDI",5},{"RBP",6},{"EBP",6},{"RSP",7},{"ESP",7},
		{"R8",8},{"R9",9},{"R10",10},{"R11",11},{"R12",12},{"R13",13},{"R14",14},{"R15",15},
		{"RIP",16},{"EIP",16},{"RFLAGS",17},{"EFLAGS",17},
	};
	for (auto& [rn, idx] : map) {
		if (upper == rn) {
			uint64_t val = r[idx];
			if (upper[0] == 'E' && upper != "EFLAGS") val &= 0xFFFFFFFF;
			return val;
		}
	}
	return 0;
}

uint32_t McpServer::GetRegisterIndex(const std::string& name) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	static const std::pair<const char*, uint32_t> map[] = {
		{"RAX",0},{"EAX",0},{"RBX",1},{"EBX",1},{"RCX",2},{"ECX",2},{"RDX",3},{"EDX",3},
		{"RSI",4},{"ESI",4},{"RDI",5},{"EDI",5},{"RBP",6},{"EBP",6},{"RSP",7},{"ESP",7},
		{"R8",8},{"R9",9},{"R10",10},{"R11",11},{"R12",12},{"R13",13},{"R14",14},{"R15",15},
		{"RIP",16},{"EIP",16},{"RFLAGS",17},{"EFLAGS",17},
	};
	for (auto& [rn, idx] : map) {
		if (upper == rn) return idx;
	}
	return UINT32_MAX;
}

bool McpServer::EvaluateCondition(const std::string& condition, uint32_t threadId, const RegisterSet* cachedRegs) {
	// Condition syntax: LHS op RHS
	// LHS/RHS: register name, *addr (memory), or integer constant
	// Operators: ==, !=, >=, <=, >, <
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
	if (opStr.empty() || lhs.empty() || rhs.empty()) return true; // parse fail -> always stop

	// Trim whitespace
	auto trim = [](std::string& s) {
		while (!s.empty() && s.front() == ' ') s.erase(s.begin());
		while (!s.empty() && s.back() == ' ') s.pop_back();
	};
	trim(lhs); trim(rhs);

	// Resolve a value token (register, *memory, or constant)
	auto resolveVal = [&](const std::string& tok) -> uint64_t {
		if (tok.empty()) return 0;
		// Memory dereference: *addr or [addr]
		if (tok[0] == '*' || tok[0] == '[') {
			std::string addrStr = tok.substr(1);
			if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
			trim(addrStr);
			try {
				uint64_t addr = std::stoull(addrStr, nullptr, 0);
				uint64_t val = 0;
				SIZE_T bytesRead = 0;
				if (targetProcess_ && ReadProcessMemory(targetProcess_, (LPCVOID)addr, &val, 8, &bytesRead))
					return val;
			} catch (...) {}
			return 0;
		}
		// Register
		if (TryParseRegisterName(tok)) {
			if (cachedRegs) return ResolveRegisterByName(tok, *cachedRegs);
			return 0;
		}
		// Constant
		try { return std::stoull(tok, nullptr, 0); } catch (...) { return 0; }
	};

	uint64_t lhsVal = resolveVal(lhs);
	uint64_t rhsVal = resolveVal(rhs);

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
			// Trim
			while (!expr.empty() && expr.front() == ' ') expr.erase(expr.begin());
			while (!expr.empty() && expr.back() == ' ') expr.pop_back();

			char buf[32];
			if (TryParseRegisterName(expr) && cachedRegs) {
				uint64_t val = ResolveRegisterByName(expr, *cachedRegs);
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
					if (targetProcess_ && ReadProcessMemory(targetProcess_, (LPCVOID)addr, &val, 8, &bytesRead) && bytesRead >= 8) {
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
	SetBreakpointRequest bpReq;
	bpReq.address = address;
	std::vector<uint8_t> bpResp;
	if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)
		&& bpResp.size() >= sizeof(SetBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
		if (resp->status == IpcStatus::Ok) {
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				tempStepOverBpId_ = resp->id;
			}
			ContinueRequest contReq = {};
			contReq.threadId = 0;
			pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
			return true;
		}
	}
	return false;
}

bool McpServer::IsNextInstructionCall(uint32_t threadId, uint64_t& addrAfterCall) {
	// Get current RIP
	GetStackTraceRequest stReq;
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;
	std::vector<uint8_t> stResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
		return false;
	if (stResp.size() < sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo))
		return false;
	auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
	if (hdr->status != IpcStatus::Ok || hdr->count == 0) return false;
	auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + sizeof(GetStackTraceResponse));
	uint64_t rip = frame->address;

	// Check if this address has a BP (only relevant for BP rearm case)
	bool onBp = false;
	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		for (const auto& bp : swBreakpoints_) {
			if (bp.address == rip) { onBp = true; break; }
		}
	}
	if (!onBp) return false; // Not on a BP, no rearm issue

	// Read memory at RIP (BP-masked) and disassemble 2 instructions
	ReadMemoryRequest memReq;
	memReq.address = rip;
	memReq.size = 32; // enough for 2 instructions
	std::vector<uint8_t> memResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &memReq, sizeof(memReq), memResp))
		return false;
	if (memResp.size() < sizeof(IpcStatus) + 1) return false;
	auto status = *reinterpret_cast<const IpcStatus*>(memResp.data());
	if (status != IpcStatus::Ok) return false;
	const uint8_t* code = memResp.data() + sizeof(IpcStatus);
	size_t codeLen = memResp.size() - sizeof(IpcStatus);

	if (!disassembler_) return false;
	auto insns = disassembler_->Disassemble(code, (uint32_t)codeLen, rip, 2);
	if (insns.size() < 2) return false;

	// Check if the SECOND instruction is CALL
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
	// 1. Get current RIP via GetStackTrace IPC
	GetStackTraceRequest stReq;
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
		return false;
	if (stResp.size() < sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo))
		return false;
	auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
	if (hdr->status != IpcStatus::Ok || hdr->count == 0)
		return false;
	auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + sizeof(GetStackTraceResponse));
	uint64_t rip = frame->address;

	// 2. Read memory at RIP via IPC (BP-masked: sees original bytes, not INT3)
	ReadMemoryRequest memReq;
	memReq.address = rip;
	memReq.size = 16;
	std::vector<uint8_t> memResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &memReq, sizeof(memReq), memResp))
		return false;
	if (memResp.size() < sizeof(IpcStatus) + 1)
		return false;
	auto status = *reinterpret_cast<const IpcStatus*>(memResp.data());
	if (status != IpcStatus::Ok)
		return false;
	const uint8_t* code = memResp.data() + sizeof(IpcStatus);
	size_t codeLen = memResp.size() - sizeof(IpcStatus);

	// 3. Disassemble first instruction
	if (!disassembler_) return false;
	auto insns = disassembler_->Disassemble(code, (uint32_t)codeLen, rip, 1);
	if (insns.empty()) return false;

	const auto& insn = insns[0];
	// Check if mnemonic starts with "call"
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
		RemoveBreakpointRequest req;
		req.id = tempId;
		pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &req, sizeof(req));
		LOG_DEBUG("CleanupTempStepOverBp: removed temp BP #%u", tempId);
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
					// Keep tempStepOverBpId_ set - CleanupTempStepOverBp() will remove it
				}
			}

			if (isTempBp) {
				// Report as step completed (BP removal deferred to next tool call)
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
					std::lock_guard<std::mutex> lock(bpMutex_);
					for (auto& bp : swBreakpoints_) {
						if (bp.id == e->breakpointId) {
							bp.hitCount++;

							// Evaluate condition (using cached regs - no IPC deadlock)
							if (!bp.condition.empty()) {
								if (!EvaluateCondition(bp.condition, e->threadId, &e->regs)) {
									shouldStop = false;
									break;
								}
							}

							// Check hitCondition
							if (!bp.hitCondition.empty()) {
								try {
									uint32_t target = std::stoul(bp.hitCondition);
									if (bp.hitCount < target) {
										shouldStop = false;
										break;
									}
								} catch (...) {}
							}

							// Expand logMessage (logpoint = no stop)
							if (!bp.logMessage.empty()) {
								logOutput = ExpandLogMessage(bp.logMessage, e->threadId, &e->regs);
								shouldStop = false;
							}
							break;
						}
					}
				}

				if (!shouldStop) {
					// Log message output (if any)
					std::lock_guard<std::mutex> lock(eventMutex_);
					if (!logOutput.empty()) {
						pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "logpoint"}, {"data", logOutput}}});
					}
					// Queue auto-continue for main thread (avoid reader thread deadlock)
					pendingAutoContinue_.push(e->threadId);
				} else {
					char buf[128];
					snprintf(buf, sizeof(buf), "Breakpoint #%u hit at 0x%llX (thread %u)",
						e->breakpointId, e->address, e->threadId);
					{
						std::lock_guard<std::mutex> lock(eventMutex_);
						pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
					}
					// Determine BP type (SW IDs < 10001, HW IDs >= 10001)
					std::string bpType;
					if (e->breakpointId >= 10001) bpType = "hardware";
					else if (e->breakpointId > 0) bpType = "software";

					// Signal wait mode
					{
						std::lock_guard<std::mutex> lock(bpHitMutex_);
						bpHitOccurred_ = true;
						bpHitId_ = e->breakpointId;
						bpHitAddr_ = e->address;
						bpHitThread_ = e->threadId;
						bpHitStopReason_ = "breakpoint";
						bpHitType_ = bpType;
					}
					bpHitCv_.notify_all();
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
			// Signal synchronous waiters (ToolStepOver)
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
		break; // 무시
	case IpcEvent::Ready:
		LOG_INFO("VEH DLL ready");
		break;
	case IpcEvent::Paused: {
		{
			std::lock_guard<std::mutex> lock(eventMutex_);
			pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", "Target paused"}}});
		}
		{
			std::lock_guard<std::mutex> lock(bpHitMutex_);
			bpHitOccurred_ = true;
			bpHitId_ = 0;
			bpHitAddr_ = 0;
			bpHitThread_ = 0;
			bpHitStopReason_ = "pause";
		}
		bpHitCv_.notify_all();
		break;
	}
	case IpcEvent::ProcessExited: {
		if (size >= sizeof(ProcessExitEvent)) {
			auto* e = reinterpret_cast<const ProcessExitEvent*>(payload);
			char buf[64];
			snprintf(buf, sizeof(buf), "Process exited (code=%u)", e->exitCode);
			LOG_INFO("%s", buf);
			attached_ = false;
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			{
				std::lock_guard<std::mutex> lock(bpHitMutex_);
				bpHitOccurred_ = true;
				bpHitId_ = 0;
				bpHitAddr_ = 0;
				bpHitThread_ = 0;
				bpHitStopReason_ = "exit";
			}
			bpHitCv_.notify_all();
			stepCv_.notify_all(); // wake stepOver wait too
		}
		break;
	}
	case IpcEvent::ExceptionOccurred: {
		if (size >= sizeof(ExceptionEvent)) {
			auto* e = reinterpret_cast<const ExceptionEvent*>(payload);
			// Cache for veh_exception_info tool
			{
				std::lock_guard<std::mutex> lock(exceptionMutex_);
				lastException_.threadId = e->threadId;
				lastException_.code = e->exceptionCode;
				lastException_.address = e->address;
				lastException_.description = e->description;
			}
			char buf[384];
			snprintf(buf, sizeof(buf), "Exception 0x%08X at 0x%llX (thread %u): %s",
				e->exceptionCode, e->address, e->threadId, e->description);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/logging", {{"level", "warning"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
			{
				std::lock_guard<std::mutex> lock(bpHitMutex_);
				bpHitOccurred_ = true;
				bpHitId_ = 0;
				bpHitAddr_ = e->address;
				bpHitThread_ = e->threadId;
				bpHitStopReason_ = "exception";
			}
			bpHitCv_.notify_all();
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

std::string McpServer::GetExeDir() {
	wchar_t exePathW[MAX_PATH];
	DWORD exeLen = GetModuleFileNameW(nullptr, exePathW, MAX_PATH);
	if (exeLen == 0 || exeLen >= MAX_PATH) {
		LOG_ERROR("GetModuleFileName failed or path too long");
		return "";
	}
	std::filesystem::path exePath(exePathW);
	std::string dir = exePath.parent_path().string() + "\\";
	return dir;
}

std::string McpServer::ResolveDll(const std::string& dir, bool use32) {
	if (use32) {
		std::string path32 = dir + "vcruntime_net32.dll";
		if (std::filesystem::exists(path32)) return path32;
	}

	std::string path64 = dir + "vcruntime_net.dll";
	if (std::filesystem::exists(path64)) return path64;

	// 폴백
	if (!use32) {
		std::string path32 = dir + "vcruntime_net32.dll";
		if (std::filesystem::exists(path32)) return path32;
	}

	LOG_ERROR("DLL not found in %s (need %s)", dir.c_str(),
		use32 ? "vcruntime_net32.dll (x86)" : "vcruntime_net.dll (x64)");
	return "";
}

std::string McpServer::GetDllPath(uint32_t pid) {
	std::string dir = GetExeDir();
	if (dir.empty()) return "";

	// 타겟 비트니스 감지 (pid 기반)
	bool use32 = false;
	if (pid != 0) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProc) {
			BOOL isWow64 = FALSE;
			IsWow64Process(hProc, &isWow64);
			CloseHandle(hProc);
			use32 = (isWow64 != FALSE);
		}
	}

	return ResolveDll(dir, use32);
}

std::string McpServer::GetDllPathForExe(const std::string& exePath) {
	std::string dir = GetExeDir();
	if (dir.empty()) return "";

	bool use32 = Injector::IsExe32Bit(exePath);
	return ResolveDll(dir, use32);
}

bool McpServer::ParseAddress(const std::string& addrStr, uint64_t& out) {
	try {
		size_t pos;
		out = std::stoull(addrStr, &pos, 0);
		return pos == addrStr.size();
	} catch (...) {
		return false;
	}
}

// --- Tool List Definition ---

json McpServer::GetToolsList() {
	return json::array({
		{{"name", "veh_attach"}, {"description", "Attach to a running process by PID. Injects VEH debugger DLL. Auto-detaches if already attached. Target process must be running (not CREATE_SUSPENDED)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"pid", {{"type", "integer"}, {"description", "Process ID to attach to"}}}
		 }}, {"required", json::array({"pid"})}}}},

		{{"name", "veh_launch"}, {"description", "Launch a program and attach the debugger. Auto-detaches if already attached. Handles CREATE_SUSPENDED internally."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"program", {{"type", "string"}, {"description", "Path to executable"}}},
			{"args", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Command line arguments"}}},
			{"stopOnEntry", {{"type", "boolean"}, {"description", "Stop at entry point (default: true)"}}},
			{"runAsInvoker", {{"type", "boolean"}, {"description", "Bypass UAC elevation prompt by setting __COMPAT_LAYER=RunAsInvoker (default: false)"}}},
			{"injectionMethod", {{"type", "string"}, {"enum", json::array({"auto", "createRemoteThread", "ntCreateThreadEx", "threadHijack", "queueUserApc"})}, {"description", "DLL injection method (default: auto). Auto tries all methods in order."}}}
		 }}, {"required", json::array({"program"})}}}},

		{{"name", "veh_detach"}, {"description", "Detach debugger from the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_set_breakpoint"}, {"description", "Set a software breakpoint (INT3) at an address. If the target is running (not stopped at a breakpoint), the BP is still set but may not fire if execution already passed the address (timing-dependent). Duplicate address returns existing BP id."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address (e.g. 0x7FF600001000)"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression (e.g. 'RAX==0x1000', 'RCX>5'). Supports registers, *memory, hex/dec constants."}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold. BP fires only on Nth hit (e.g. '5' = fire on 5th hit)."}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint). Use {expr} for interpolation (e.g. 'x={RAX}'). Does NOT stop execution."}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_remove_breakpoint"}, {"description", "Remove a software breakpoint by ID."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"type", "integer"}, {"description", "Breakpoint ID from veh_set_breakpoint"}}}
		 }}, {"required", json::array({"id"})}}}},

		{{"name", "veh_set_source_breakpoint"}, {"description", "Set a breakpoint by source file and line number. Requires PDB symbols loaded."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"source", {{"type", "string"}, {"description", "Source file path (e.g. 'main.cpp', 'src/app.cpp')"}}},
			{"line", {{"type", "integer"}, {"description", "Line number in the source file"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression (e.g. 'RAX==0x1000')"}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold"}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint)"}}}
		 }}, {"required", json::array({"source", "line"})}}}},

		{{"name", "veh_set_function_breakpoint"}, {"description", "Set a breakpoint at the entry of a function by name. Requires PDB symbols loaded."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"name", {{"type", "string"}, {"description", "Function name (e.g. 'main', 'MyClass::DoSomething')"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression"}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold"}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint)"}}}
		 }}, {"required", json::array({"name"})}}}},

		{{"name", "veh_list_breakpoints"}, {"description", "List all active software and hardware breakpoints with their properties."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_set_data_breakpoint"}, {"description", "Set a hardware data breakpoint (DR0-DR3). Like Cheat Engine's 'Find out what writes/accesses'. Max 4 simultaneous."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address to watch"}}},
			{"type", {{"type", "string"}, {"enum", json::array({"write", "readwrite", "execute"})}, {"description", "Breakpoint type (default: write)"}}},
			{"size", {{"type", "integer"}, {"enum", json::array({1, 2, 4, 8})}, {"description", "Watch size in bytes (default: 4)"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_remove_data_breakpoint"}, {"description", "Remove a hardware data breakpoint by ID."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"type", "integer"}, {"description", "Data breakpoint ID"}}}
		 }}, {"required", json::array({"id"})}}}},

		{{"name", "veh_continue"}, {"description", "Continue execution. Use wait=true to block until a breakpoint hit, exception, pause, or process exit occurs (returns stop reason, address, threadId). Use pass_exception=true to forward the current exception to the process's own SEH handler (for CFF/obfuscated INT3, etc.). Default timeout 10s, configurable."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "Thread ID (0 = all, default: 0)"}}},
			{"wait", {{"type", "boolean"}, {"description", "If true, block until target stops (breakpoint/exception/pause/exit). Default: false"}}},
			{"timeout", {{"type", "integer"}, {"description", "Max seconds to wait when wait=true (1-300, default: 10)"}}},
			{"pass_exception", {{"type", "boolean"}, {"description", "If true, pass the current exception to the process's SEH handler instead of handling it. Use for CFF/obfuscated code with INT3. Default: false"}}}
		 }}}}},

		{{"name", "veh_step_in"}, {"description", "Single step into (execute one instruction, entering calls). Waits for completion and returns the new instruction pointer."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_step_over"}, {"description", "Step over (execute one instruction, skipping calls). Waits for completion and returns the new instruction pointer."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_step_out"}, {"description", "Step out (run until current function returns)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_pause"}, {"description", "Pause execution. threadId=0 pauses all threads."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "Thread ID (0 = all)"}}}
		 }}}}},

		{{"name", "veh_threads"}, {"description", "List all threads in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_stack_trace"}, {"description", "Get stack trace for a thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"maxFrames", {{"type", "integer"}, {"description", "Max frames to return (default: 20)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_registers"}, {"description", "Get CPU registers for a thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_read_memory"}, {"description", "Read memory from the target process. Returns hex dump."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address"}}},
			{"size", {{"type", "integer"}, {"description", "Bytes to read (default: 64, max: 1MB)"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_write_memory"}, {"description", "Write memory to the target process. Single mode: address+data. Batch mode: patches array for multi-address patching in one call."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address (single mode)"}}},
			{"data", {{"type", "string"}, {"description", "Hex bytes to write (single mode, e.g. '90 90 90')"}}},
			{"patches", {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {{"address", {{"type", "string"}}}, {"data", {{"type", "string"}}}}}}}, {"description", "Batch mode: [{address, data}, ...]. Overrides address/data if provided."}}}
		 }}}}},

		{{"name", "veh_modules"}, {"description", "List loaded modules (DLLs) in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_disassemble"}, {"description", "Disassemble instructions at an address."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address"}}},
			{"count", {{"type", "integer"}, {"description", "Number of instructions (default: 20)"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_enum_locals"}, {"description", "Enumerate local variables and parameters for a stopped thread's stack frame. Returns variable names, types, addresses, and values."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}},
			{"instructionAddress", {{"type", "string"}, {"description", "RIP/EIP hex address of the frame (auto-detected from top frame if omitted)"}}},
			{"frameBase", {{"type", "string"}, {"description", "RBP/EBP hex address (auto-detected from top frame if omitted)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_evaluate"}, {"description", "Evaluate an expression. Supports: register names (RAX, RBX, etc.), hex addresses (0x...), pointer dereference (*addr, [addr], [RAX+0x10], [RAX-8], [RAX+RBX]), and segment registers (gs:[0x60] for PEB, fs:[0x30] for TEB on x86)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"expression", {{"type", "string"}, {"description", "Expression to evaluate (register name, hex address, *addr for dereference)"}}},
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID for register context"}}}
		 }}, {"required", json::array({"expression", "threadId"})}}}},

		{{"name", "veh_set_register"}, {"description", "Set a CPU register value for a stopped thread."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID"}}},
			{"name", {{"type", "string"}, {"description", "Register name (e.g. RAX, RBX, RCX, RDX, RSP, RBP, RSI, RDI, R8-R15, RIP, RFLAGS)"}}},
			{"value", {{"type", "string"}, {"description", "New value (hex or decimal, e.g. '0x1000' or '4096')"}}}
		 }}, {"required", json::array({"threadId", "name", "value"})}}}},

		{{"name", "veh_exception_info"}, {"description", "Get information about the last exception that occurred in the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_trace_callers"}, {"description", "Profile who calls a function: sets BP at address, auto-resumes process, collects all unique callers with hit counts for duration_sec seconds, then pauses and returns results. Useful for call graph analysis and finding hot callers. x64: uses RtlVirtualUnwind for accurate caller resolution. x86: uses [ESP] (accurate only at function entry). Process is automatically resumed before tracing and paused after."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address to set breakpoint (e.g. '0x7FF600001000')"}}},
			{"duration_sec", {{"type", "integer"}, {"description", "How long to collect callers in seconds (default: 5, max: 60)"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_dump_memory"}, {"description", "Dump memory to a binary file. Reads in 1MB chunks, supports up to 64MB. Avoids token overhead of hex string encoding."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex start address"}}},
			{"size", {{"type", "integer"}, {"description", "Bytes to dump (default: 4096, max: 64MB)"}}},
			{"output_path", {{"type", "string"}, {"description", "Output file path for the binary dump"}}}
		 }}, {"required", json::array({"address", "output_path"})}}}},

		{{"name", "veh_allocate_memory"}, {"description", "Allocate memory pages in the target process via VirtualAlloc."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"size", {{"type", "integer"}, {"description", "Allocation size in bytes (default: 4096)"}}},
			{"protection", {{"type", "string"}, {"enum", json::array({"rwx", "rw", "rx", "r"})}, {"description", "Memory protection (default: rwx = PAGE_EXECUTE_READWRITE)"}}}
		 }}}}},

		{{"name", "veh_free_memory"}, {"description", "Free previously allocated memory pages in the target process via VirtualFree."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address of the allocation to free"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_execute_shellcode"}, {"description", "Execute shellcode in the target process. Allocates RWX page, copies code, creates thread, waits for completion, frees page. Set timeout_ms=0 for fire-and-forget (page not freed)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"shellcode", {{"type", "string"}, {"description", "Hex-encoded shellcode bytes (e.g. 'C3' for ret, '33C0C3' for xor eax,eax; ret)"}}},
			{"timeout_ms", {{"type", "integer"}, {"description", "Max wait time in ms (default: 5000, max: 60000). 0 = fire-and-forget (don't wait, don't free)."}}}
		 }}, {"required", json::array({"shellcode"})}}}}
	});
}

void McpServer::ResumeMainThread() {
	if (mainThreadResumed_ || launchedMainThreadId_ == 0) return;

	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, launchedMainThreadId_);
	if (hThread) {
		DWORD prevCount = ResumeThread(hThread);
		CloseHandle(hThread);
		mainThreadResumed_ = true;
		LOG_INFO("MCP: Resumed main thread %u (prev suspend count: %u)",
			launchedMainThreadId_, prevCount);
	} else {
		LOG_ERROR("MCP: Failed to open main thread %u for resume: %u",
			launchedMainThreadId_, GetLastError());
	}
}

void McpServer::StartProcessMonitor() {
	StopProcessMonitor(); // 이전 모니터 정리
	if (!targetProcess_) return;

	// PROCESS_SYNCHRONIZE 권한이 필요하지만 targetProcess_는 TERMINATE로 열림
	// 별도 핸들로 열어야 함
	HANDLE hWait = OpenProcess(SYNCHRONIZE, FALSE, targetPid_);
	if (!hWait) {
		LOG_WARN("Cannot open process %u for SYNCHRONIZE, exit monitor disabled", targetPid_);
		return;
	}

	monitorStopEvent_ = CreateEvent(nullptr, TRUE, FALSE, nullptr);

	processMonitorThread_ = std::thread([this, hWait, stopEv = monitorStopEvent_]() {
		HANDLE handles[2] = { hWait, stopEv };
		DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
		CloseHandle(hWait);

		// WAIT_OBJECT_0 = process exited, WAIT_OBJECT_0+1 = stop requested
		if (result == WAIT_OBJECT_0) {
			// Always signal condvar first (even if another path already set attached_=false)
			// This prevents continue(wait) from hanging until timeout
			attached_ = false;

			DWORD exitCode = 0;
			if (targetProcess_) {
				GetExitCodeProcess(targetProcess_, &exitCode);
			}

			LOG_INFO("MCP: Target process %u exited (code: %lu), cleaning up pipe/state", targetPid_, exitCode);

			// bpHit condvar signal first (unblock veh_continue wait before pipe cleanup)
			{
				std::lock_guard<std::mutex> lock(bpHitMutex_);
				bpHitOccurred_ = true;
				bpHitStopReason_ = "exit";
				bpHitThread_ = 0;
				bpHitAddr_ = 0;
				bpHitId_ = 0;
			}
			bpHitCv_.notify_all();
			stepCv_.notify_all(); // wake stepOver wait too

			// Pipe cleanup (dead process -> broken pipe, skip if already disconnected)
			pipeClient_.StopHeartbeat();
			pipeClient_.StopEventListener();
			pipeClient_.Disconnect();

			char buf[128];
			snprintf(buf, sizeof(buf), "Target process exited (exit code: %lu)", exitCode);

			// MCP notification
			json params = {
				{"event", "process_exited"},
				{"pid", targetPid_},
				{"exitCode", exitCode},
				{"message", buf}
			};

			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notification", params});
			}

			// State cleanup
			{
				std::lock_guard<std::mutex> lock(bpMutex_);
				swBreakpoints_.clear();
				hwBreakpoints_.clear();
			}
			if (targetProcess_) {
				CloseHandle(targetProcess_);
				targetProcess_ = nullptr;
			}
			targetPid_ = 0;
			launchedMainThreadId_ = 0;
			mainThreadResumed_ = false;
			launchedByUs_ = false;
		}
	});
}

void McpServer::StopProcessMonitor() {
	if (monitorStopEvent_) {
		SetEvent(monitorStopEvent_);
	}
	if (processMonitorThread_.joinable()) {
		processMonitorThread_.join();
	}
	if (monitorStopEvent_) {
		CloseHandle(monitorStopEvent_);
		monitorStopEvent_ = nullptr;
	}
}

std::string McpServer::NotAttachedMessage() {
	if (targetProcess_) {
		DWORD exitCode = 0;
		if (GetExitCodeProcess(targetProcess_, &exitCode) && exitCode != STILL_ACTIVE) {
			char buf[128];
			snprintf(buf, sizeof(buf), "Not attached - target process exited (code %lu)", exitCode);
			return buf;
		}
	}
	return "Not attached";
}

bool McpServer::IsTargetAlive() {
	if (!targetProcess_) return false;
	DWORD exitCode = 0;
	if (!GetExitCodeProcess(targetProcess_, &exitCode)) return false;
	return exitCode == STILL_ACTIVE;
}

std::string McpServer::IpcErrorMessage() {
	if (!attached_) return NotAttachedMessage();
	if (targetProcess_) {
		DWORD exitCode = 0;
		if (GetExitCodeProcess(targetProcess_, &exitCode) && exitCode != STILL_ACTIVE) {
			char buf[128];
			snprintf(buf, sizeof(buf), "Target process has exited (exit code: %lu)", exitCode);
			return buf;
		}
	}
	if (!pipeClient_.IsConnected()) return "Target pipe disconnected (process may have crashed)";
	return "IPC communication failed (timeout)";
}

} // namespace veh
