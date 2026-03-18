#include "mcp_server.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>

namespace veh {

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
			{"version", "1.0.2"}
		}}
	};
	SendResult(id, result);
}

void McpServer::OnToolsList(const json& id, const json& params) {
	SendResult(id, {{"tools", GetToolsList()}});
}

void McpServer::OnToolsCall(const json& id, const json& params) {
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
}

// --- Tool Implementations ---

json McpServer::ToolAttach(const json& args) {
	if (attached_) {
		return {{"error", "Already attached. Detach first."}};
	}

	uint32_t pid = args.value("pid", 0u);
	if (pid == 0) return {{"error", "pid is required"}};

	// DLL 경로 결정 (pid 기반 비트니스 감지)
	std::string dllPath = GetDllPath(pid);
	if (dllPath.empty()) return {{"error", "DLL not found"}};

	// DLL 인젝션
	LOG_INFO("Injecting into PID %u: %s", pid, dllPath.c_str());
	if (!Injector::InjectDll(pid, dllPath)) {
		return {{"error", "DLL injection failed"}};
	}

	// Named Pipe 연결
	if (!pipeClient_.Connect(pid, 7000)) {
		LOG_ERROR("Pipe connection failed after injection (pid=%u), DLL remains in target", pid);
		return {{"error", "Pipe connection failed (timeout). DLL was injected but could not connect."}};
	}

	// 이벤트 리스너 시작
	pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();

	targetPid_ = pid;
	attached_ = true;
	StartProcessMonitor();

	return {{"success", true}, {"pid", pid}, {"message", "Attached to process"}};
}

json McpServer::ToolLaunch(const json& args) {
	if (attached_) {
		return {{"error", "Already attached. Detach first."}};
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

	bool stopOnEntry = args.value("stopOnEntry", true);
	// PE 헤더에서 비트니스 확인 (아직 프로세스가 없으므로 파일 기반)
	std::string dllPath = GetDllPathForExe(program);
	if (dllPath.empty()) return {{"error", "DLL not found"}};

	auto launchResult = Injector::LaunchAndInject(program, argsStr, "", dllPath, InjectionMethod::CreateRemoteThread);
	uint32_t pid = launchResult.pid;
	if (pid == 0) return {{"error", "Launch failed"}};

	launchedMainThreadId_ = launchResult.mainThreadId;
	mainThreadResumed_ = false;

	targetProcess_ = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!targetProcess_) {
		LOG_WARN("OpenProcess(TERMINATE) failed for pid=%u, cannot terminate on cleanup", pid);
	}
	launchedByUs_ = true;

	// Named Pipe 연결
	if (!pipeClient_.Connect(pid, 7000)) {
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

	// stopOnEntry=false: 즉시 메인 스레드 resume (DAP의 configurationDone과 동일)
	// stopOnEntry=true: 에이전트가 veh_continue 호출 시 resume
	if (!stopOnEntry) {
		ResumeMainThread();
	}

	return {{"success", true}, {"pid", pid}, {"message",
		stopOnEntry ? "Launched and attached (stopped on entry)" : "Launched and attached"}};
}

json McpServer::ToolDetach(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

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

	swBreakpoints_.clear();
	hwBreakpoints_.clear();
	attached_ = false;
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
	if (!attached_) return {{"error", "Not attached"}};

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
			swBreakpoints_.push_back({resp->id, addr});
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
			return {{"success", true}, {"id", resp->id}, {"address", buf}};
		}
	}
	return {{"error", "Failed to set breakpoint"}};
}

json McpServer::ToolRemoveBreakpoint(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	if (!args.contains("id") || !args["id"].is_number_unsigned()) {
		return {{"error", "id must be a valid unsigned integer"}};
	}
	uint32_t id = args["id"].get<uint32_t>();

	RemoveBreakpointRequest req;
	req.id = id;
	if (!pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}

	swBreakpoints_.erase(
		std::remove_if(swBreakpoints_.begin(), swBreakpoints_.end(),
			[id](const BpMapping& bp) { return bp.id == id; }),
		swBreakpoints_.end());

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolSetDataBreakpoint(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	std::string addrStr = args.value("address", "");
	std::string typeStr = args.value("type", "write");
	int size = args.value("size", 4);

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
			hwBreakpoints_.push_back({resp->id, addr, req.type, req.size});
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
			return {{"success", true}, {"id", resp->id}, {"slot", resp->slot},
			        {"address", buf}, {"type", typeStr}, {"size", size}};
		}
	}
	return {{"error", "Failed to set data breakpoint (max 4 HW slots)"}};
}

json McpServer::ToolRemoveDataBreakpoint(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	if (!args.contains("id") || !args["id"].is_number_unsigned()) {
		return {{"error", "id must be a valid unsigned integer"}};
	}
	uint32_t id = args["id"].get<uint32_t>();

	RemoveHwBreakpointRequest req;
	req.id = id;
	if (!pipeClient_.SendCommand(IpcCommand::RemoveHwBreakpoint, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}

	hwBreakpoints_.erase(
		std::remove_if(hwBreakpoints_.begin(), hwBreakpoints_.end(),
			[id](const HwBpMapping& bp) { return bp.id == id; }),
		hwBreakpoints_.end());

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolContinue(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	// stopOnEntry=true로 launch한 경우, 첫 continue에서 OS-level resume 수행
	ResumeMainThread();

	uint32_t threadId = args.value("threadId", 0u);
	ContinueRequest req;
	req.threadId = threadId;

	if (!pipeClient_.SendCommand(IpcCommand::Continue, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolStepIn(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};
	ResumeMainThread();
	uint32_t threadId = args.value("threadId", 0u);
	if (threadId == 0) return {{"error", "threadId is required"}};

	StepRequest req;
	req.threadId = threadId;
	if (!pipeClient_.SendCommand(IpcCommand::StepInto, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolStepOver(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};
	ResumeMainThread();
	uint32_t threadId = args.value("threadId", 0u);
	if (threadId == 0) return {{"error", "threadId is required"}};

	StepRequest req;
	req.threadId = threadId;
	if (!pipeClient_.SendCommand(IpcCommand::StepOver, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolStepOut(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};
	ResumeMainThread();
	uint32_t threadId = args.value("threadId", 0u);
	if (threadId == 0) return {{"error", "threadId is required"}};

	StepRequest req;
	req.threadId = threadId;
	if (!pipeClient_.SendCommand(IpcCommand::StepOut, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolPause(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	uint32_t threadId = args.value("threadId", 0u);
	PauseRequest req;
	req.threadId = threadId;
	if (!pipeClient_.SendCommand(IpcCommand::Pause, &req, sizeof(req))) {
		return {{"error", IpcErrorMessage()}};
	}
	return {{"success", true}, {"threadId", threadId}};
}

json McpServer::ToolThreads(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

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
	if (!attached_) return {{"error", "Not attached"}};

	uint32_t threadId = args.value("threadId", 0u);
	if (threadId == 0) return {{"error", "threadId is required"}};

	int maxFrames = args.value("maxFrames", 20);
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
	if (!attached_) return {{"error", "Not attached"}};

	uint32_t threadId = args.value("threadId", 0u);
	if (threadId == 0) return {{"error", "threadId is required"}};

	// instructionAddress (RIP) and frameBase (RBP) for SymSetContext
	uint64_t instrAddr = 0, frameBase = 0;
	if (args.contains("instructionAddress")) {
		auto& v = args["instructionAddress"];
		if (v.is_string()) instrAddr = std::strtoull(v.get<std::string>().c_str(), nullptr, 16);
		else if (v.is_number()) instrAddr = v.get<uint64_t>();
	}
	if (args.contains("frameBase")) {
		auto& v = args["frameBase"];
		if (v.is_string()) frameBase = std::strtoull(v.get<std::string>().c_str(), nullptr, 16);
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
	if (!attached_) return {{"error", "Not attached"}};

	uint32_t threadId = args.value("threadId", 0u);
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
	if (!attached_) return {{"error", "Not attached"}};

	std::string addrStr = args.value("address", "");
	int size = args.value("size", 64);
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

json McpServer::ToolWriteMemory(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

	std::string addrStr = args.value("address", "");
	std::string dataHex = args.value("data", "");
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (dataHex.empty()) return {{"error", "data is required (hex string)"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	// hex 문자열 → 바이트 변환
	std::vector<uint8_t> bytes;
	std::string clean;
	for (char c : dataHex) {
		if (std::isxdigit(c)) clean += c;
	}
	if (clean.size() % 2 != 0) return {{"error", "Invalid hex string"}};
	for (size_t i = 0; i < clean.size(); i += 2) {
		bytes.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	if (bytes.size() > 1048576) {
		return {{"error", "data too large (max 1MB)"}};
	}

	// IPC 패킷: WriteMemoryRequest + data
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

json McpServer::ToolModules(const json& args) {
	if (!attached_) return {{"error", "Not attached"}};

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
	if (!attached_) return {{"error", "Not attached"}};

	std::string addrStr = args.value("address", "");
	int count = args.value("count", 20);
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
	{
		std::lock_guard<std::mutex> lock(eventMutex_);
		std::swap(events, pendingEvents_);
	}
	while (!events.empty()) {
		auto& [method, params] = events.front();
		SendNotification(method, params);
		events.pop();
	}
}

// --- IPC Event Handler ---

void McpServer::OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size) {
	auto evt = static_cast<IpcEvent>(eventId);

	switch (evt) {
	case IpcEvent::BreakpointHit: {
		if (size >= sizeof(BreakpointHitEvent)) {
			auto* e = reinterpret_cast<const BreakpointHitEvent*>(payload);
			char buf[128];
			snprintf(buf, sizeof(buf), "Breakpoint #%u hit at 0x%llX (thread %u)",
				e->breakpointId, e->address, e->threadId);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/message", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
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
				pendingEvents_.push({"notifications/message", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
		}
		break;
	}
	case IpcEvent::HeartbeatAck:
		break; // 무시
	case IpcEvent::Ready:
		LOG_INFO("VEH DLL ready");
		break;
	case IpcEvent::Paused: {
		std::lock_guard<std::mutex> lock(eventMutex_);
		pendingEvents_.push({"notifications/message", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", "Target paused"}}});
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
				pendingEvents_.push({"notifications/message", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
		}
		break;
	}
	case IpcEvent::ExceptionOccurred: {
		if (size >= sizeof(ExceptionEvent)) {
			auto* e = reinterpret_cast<const ExceptionEvent*>(payload);
			char buf[384];
			snprintf(buf, sizeof(buf), "Exception 0x%08X at 0x%llX (thread %u): %s",
				e->exceptionCode, e->address, e->threadId, e->description);
			{
				std::lock_guard<std::mutex> lock(eventMutex_);
				pendingEvents_.push({"notifications/message", {{"level", "warning"}, {"logger", "veh-debugger"}, {"data", buf}}});
			}
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
		if (GetFileAttributesA(path32.c_str()) != INVALID_FILE_ATTRIBUTES) return path32;
	}

	std::string path64 = dir + "vcruntime_net.dll";
	if (GetFileAttributesA(path64.c_str()) != INVALID_FILE_ATTRIBUTES) return path64;

	// 폴백
	if (!use32) {
		std::string path32 = dir + "vcruntime_net32.dll";
		if (GetFileAttributesA(path32.c_str()) != INVALID_FILE_ATTRIBUTES) return path32;
	}

	LOG_ERROR("DLL not found in %s", dir.c_str());
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

	// PE 헤더에서 비트니스 감지 (파일 기반)
	bool use32 = false;
	HANDLE hFile = CreateFileA(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
	                           OPEN_EXISTING, 0, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {
		IMAGE_DOS_HEADER dosHeader;
		DWORD bytesRead;
		if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) &&
		    bytesRead == sizeof(dosHeader) && dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
			if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
				DWORD ntSig;
				if (ReadFile(hFile, &ntSig, sizeof(ntSig), &bytesRead, nullptr) &&
				    bytesRead == sizeof(ntSig) && ntSig == IMAGE_NT_SIGNATURE) {
					IMAGE_FILE_HEADER fileHeader;
					if (ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr) &&
					    bytesRead == sizeof(fileHeader)) {
						use32 = (fileHeader.Machine == IMAGE_FILE_MACHINE_I386);
					}
				}
			}
		}
		CloseHandle(hFile);
	}

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
		{{"name", "veh_attach"}, {"description", "Attach to a running process by PID. Injects VEH debugger DLL."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"pid", {{"type", "integer"}, {"description", "Process ID to attach to"}}}
		 }}, {"required", json::array({"pid"})}}}},

		{{"name", "veh_launch"}, {"description", "Launch a program and attach the debugger."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"program", {{"type", "string"}, {"description", "Path to executable"}}},
			{"args", {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Command line arguments"}}},
			{"stopOnEntry", {{"type", "boolean"}, {"description", "Stop at entry point (default: true)"}}}
		 }}, {"required", json::array({"program"})}}}},

		{{"name", "veh_detach"}, {"description", "Detach debugger from the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

		{{"name", "veh_set_breakpoint"}, {"description", "Set a software breakpoint (INT3) at an address."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address (e.g. 0x7FF600001000)"}}}
		 }}, {"required", json::array({"address"})}}}},

		{{"name", "veh_remove_breakpoint"}, {"description", "Remove a software breakpoint by ID."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"id", {{"type", "integer"}, {"description", "Breakpoint ID from veh_set_breakpoint"}}}
		 }}, {"required", json::array({"id"})}}}},

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

		{{"name", "veh_continue"}, {"description", "Continue execution. If threadId=0 or omitted, resumes all stopped threads."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "Thread ID (0 = all)"}}}
		 }}}}},

		{{"name", "veh_step_in"}, {"description", "Single step into (execute one instruction, entering calls)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (from veh_threads)"}}}
		 }}, {"required", json::array({"threadId"})}}}},

		{{"name", "veh_step_over"}, {"description", "Step over (execute one instruction, skipping calls)."},
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

		{{"name", "veh_write_memory"}, {"description", "Write memory to the target process."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Hex address"}}},
			{"data", {{"type", "string"}, {"description", "Hex bytes to write (e.g. '90 90 90' or '909090')"}}}
		 }}, {"required", json::array({"address", "data"})}}}},

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
		 }}, {"required", json::array({"threadId"})}}}}
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

	processMonitorThread_ = std::thread([this, hWait]() {
		DWORD result = WaitForSingleObject(hWait, INFINITE);
		CloseHandle(hWait);

		if (result == WAIT_OBJECT_0 && attached_) {
			DWORD exitCode = 0;
			if (targetProcess_) {
				GetExitCodeProcess(targetProcess_, &exitCode);
			}

			LOG_INFO("MCP: Target process %u exited (code: %lu)", targetPid_, exitCode);

			char buf[128];
			snprintf(buf, sizeof(buf), "Target process exited (exit code: %lu)", exitCode);

			// MCP notification 전송
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

			attached_ = false;
		}
	});
}

void McpServer::StopProcessMonitor() {
	if (processMonitorThread_.joinable()) {
		// 스레드가 WaitForSingleObject 중이면 프로세스 종료 시 자동 해제
		// detach로 두면 됨 (프로세스가 이미 죽었거나 곧 죽을 거라)
		processMonitorThread_.detach();
	}
}

bool McpServer::IsTargetAlive() {
	if (!targetProcess_) return false;
	DWORD exitCode = 0;
	if (!GetExitCodeProcess(targetProcess_, &exitCode)) return false;
	return exitCode == STILL_ACTIVE;
}

std::string McpServer::IpcErrorMessage() {
	if (!attached_) return "Not attached";
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
