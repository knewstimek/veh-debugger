#include "mcp_server.h"
#include "batch_executor.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
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
			{"version", "1.0.97"}
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
		else if (name == "veh_batch")                 result = ToolBatch(args);
		else if (name == "veh_trace_register")        result = ToolTraceRegister(args);
		else if (name == "veh_trace_memory")          result = ToolTraceMemory(args);
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

// --- Tool Implementations ---

json McpServer::ToolAttach(const json& args) {
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
		return {{"error", "Attach failed for PID " + std::to_string(pid) + ". Check logs for details."}};
	}

	// Start event listener + heartbeat + process monitor
	session_.SetEventCallback([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
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
	opts.stopOnEntry = JsonBool(args, "stopOnEntry", true);
	opts.runAsInvoker = JsonBool(args, "runAsInvoker", false);
	opts.injectionMethod = args.value("injectionMethod", "auto");

	auto result = session_.Launch(opts);
	if (!result.ok) {
		return {{"error", result.error}};
	}

	// Start event listener + heartbeat + process monitor
	session_.SetEventCallback([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	session_.StartProcessMonitor();

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

	session_.Detach();
	return {{"success", true}, {"message", "Detached"}};
}

json McpServer::ToolSetBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	auto bpResult = session_.SetBreakpoint(addr);
	if (!bpResult.ok) {
		return {{"error", "Failed to set breakpoint"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bool found = false;
		for (auto& existing : bps) {
			if (existing.id == bpResult.id) {
				existing.condition = args.value("condition", "");
				existing.hitCondition = args.value("hitCondition", "");
				existing.logMessage = args.value("logMessage", "");
				found = true;
				break;
			}
		}
		if (!found) {
			SwBpInfo bp;
			bp.id = bpResult.id;
			bp.address = addr;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			bps.push_back(bp);
		}
	}

	// Store action if provided
	if (args.contains("action") && args["action"].is_array()) {
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		bpActions_[bpResult.id] = args["action"];
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
	json ret = {{"success", true}, {"id", bpResult.id}, {"address", buf}};
	if (args.contains("action")) ret["hasAction"] = true;
	return ret;
}

json McpServer::ToolRemoveBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t id = JsonUint32(args, "id");
	if (!args.contains("id") || id == 0) {
		return {{"error", "id is required (positive integer)"}};
	}

	if (!session_.RemoveBreakpoint(id)) {
		return {{"error", "Breakpoint not found (id=" + std::to_string(id) + ")"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bps.erase(
			std::remove_if(bps.begin(), bps.end(),
				[id](const SwBpInfo& bp) { return bp.id == id; }),
			bps.end());
		bpActions_.erase(id);
	}

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolSetSourceBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string source = args.value("source", "");
	uint32_t line = JsonUint32(args, "line");
	if (source.empty()) return {{"error", "source (file path) is required"}};
	if (line == 0) return {{"error", "line is required"}};

	uint64_t addr = session_.ResolveSourceLine(source, line);
	if (addr == 0) {
		return {{"error", "Could not resolve source line (no PDB symbols or line not found)"}};
	}

	auto bpResult = session_.SetBreakpoint(addr);
	if (!bpResult.ok) {
		return {{"error", "Failed to set breakpoint at resolved address"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bool found = false;
		for (auto& existing : bps) {
			if (existing.id == bpResult.id) {
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
			SwBpInfo bp;
			bp.id = bpResult.id;
			bp.address = addr;
			bp.source = source;
			bp.line = line;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			bps.push_back(bp);
		}
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
	return {{"success", true}, {"id", bpResult.id}, {"address", buf}, {"source", source}, {"line", line}};
}

json McpServer::ToolSetFunctionBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string name = args.value("name", "");
	if (name.empty()) return {{"error", "name (function name) is required"}};

	uint64_t addr = session_.ResolveFunction(name);
	if (addr == 0) {
		return {{"error", "Could not resolve function '" + name + "' (no PDB symbols or not found)"}};
	}

	auto bpResult = session_.SetBreakpoint(addr);
	if (!bpResult.ok) {
		return {{"error", "Failed to set breakpoint at resolved address"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bool found = false;
		for (auto& existing : bps) {
			if (existing.id == bpResult.id) {
				existing.functionName = name;
				existing.condition = args.value("condition", "");
				existing.hitCondition = args.value("hitCondition", "");
				existing.logMessage = args.value("logMessage", "");
				found = true;
				break;
			}
		}
		if (!found) {
			SwBpInfo bp;
			bp.id = bpResult.id;
			bp.address = addr;
			bp.functionName = name;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			bps.push_back(bp);
		}
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
	return {{"success", true}, {"id", bpResult.id}, {"address", buf}, {"function", name}};
}

json McpServer::ToolListBreakpoints(const json& args) {
	json swList = json::array();
	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		for (auto& bp : session_.GetSwBreakpoints()) {
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
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		for (auto& bp : session_.GetHwBreakpoints()) {
			char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", bp.address);
			const char* typeStr = bp.type == 0 ? "execute" : bp.type == 1 ? "write" : "readwrite";
			hwList.push_back({{"id", bp.id}, {"address", buf}, {"type", typeStr}, {"size", bp.size}});
		}
	}
	return {{"software", swList}, {"hardware", hwList}};
}

json McpServer::ToolEvaluate(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string expression = args.value("expression", "");
	uint32_t threadId = JsonUint32(args, "threadId");
	if (expression.empty()) return {{"error", "expression is required"}};

	auto result = session_.Evaluate(expression, threadId);
	if (!result.ok) {
		return {{"error", result.error}};
	}

	json ret = {{"value", result.value}, {"type", result.type}};
	if (!result.tebAddress.empty()) ret["tebAddress"] = result.tebAddress;
	if (result.address != 0) {
		char addrBuf[32];
		snprintf(addrBuf, sizeof(addrBuf), "0x%llX", result.address);
		ret["address"] = addrBuf;
	}
	return ret;
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
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	int durationSec = JsonInt(args, "duration_sec", 5);
	if (durationSec < 1) durationSec = 1;
	if (durationSec > 60) durationSec = 60;

	auto result = session_.TraceCallers(addr, static_cast<uint32_t>(durationSec));
	if (result.totalHits == 0 && result.callers.empty()) {
		return {{"error", IpcErrorMessage()}};
	}

	json callers = json::array();
	for (auto& c : result.callers) {
		char buf[32];
		snprintf(buf, sizeof(buf), "0x%llX", c.address);
		callers.push_back({{"address", buf}, {"hitCount", c.hitCount}});
	}

	return {
		{"totalHits", result.totalHits},
		{"uniqueCallers", result.uniqueCallers},
		{"durationSec", durationSec},
		{"callers", callers}
	};
}

json McpServer::ToolSetDataBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	std::string typeStr = args.value("type", "write");
	int size = JsonInt(args, "size", 4);

	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	uint8_t type;
	if (typeStr == "execute")        type = 0;
	else if (typeStr == "write")     type = 1;
	else if (typeStr == "readwrite") type = 3;
	else return {{"error", "type must be execute, write, or readwrite"}};
	if (size != 1 && size != 2 && size != 4 && size != 8) {
		return {{"error", "size must be 1, 2, 4, or 8"}};
	}

	auto result = session_.SetHwBreakpoint(addr, type, static_cast<uint8_t>(size));
	if (!result.ok) {
		return {{"error", "Failed to set data breakpoint (max 4 HW slots)"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		session_.GetHwBreakpoints().push_back({result.id, addr, type, static_cast<uint8_t>(size)});
	}

	char buf[32]; snprintf(buf, sizeof(buf), "0x%llX", addr);
	return {{"success", true}, {"id", result.id}, {"slot", result.slot},
	        {"address", buf}, {"type", typeStr}, {"size", size}};
}

json McpServer::ToolRemoveDataBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t id = JsonUint32(args, "id");
	if (!args.contains("id") || id == 0) {
		return {{"error", "id is required (positive integer)"}};
	}

	if (!session_.RemoveHwBreakpoint(id)) {
		return {{"error", "Data breakpoint not found (id=" + std::to_string(id) + ")"}};
	}

	{
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetHwBreakpoints();
		bps.erase(
			std::remove_if(bps.begin(), bps.end(),
				[id](const HwBpInfo& bp) { return bp.id == id; }),
			bps.end());
	}

	return {{"success", true}, {"id", id}};
}

json McpServer::ToolContinue(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	session_.ResumeMainThread();
	CleanupTempStepOverBp();

	uint32_t threadId = JsonUint32(args, "threadId");
	bool wait = JsonBool(args, "wait");
	bool passException = JsonBool(args, "pass_exception");
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
		if (cached) {
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

	if (!session_.Continue(threadId, passException)) {
		return {{"error", IpcErrorMessage()}};
	}

	if (!wait) {
		return {{"success", true}, {"threadId", threadId}};
	}

	// Wait for stop event
	auto stopEvent = session_.WaitForStop(timeoutSec);
	if (stopEvent.timeout) {
		return {{"timeout", true}, {"message", "No stop event within timeout. Process still running."}};
	}

	json ret = {
		{"stopped", true},
		{"reason", stopEvent.reason},
		{"address", (std::ostringstream() << "0x" << std::hex << stopEvent.address).str()},
		{"threadId", stopEvent.threadId},
		{"breakpointId", stopEvent.breakpointId}
	};
	if (!stopEvent.bpType.empty()) ret["breakpointType"] = stopEvent.bpType;
	return ret;
}

json McpServer::ToolStepIn(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	session_.ResumeMainThread();
	CleanupTempStepOverBp();
	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	if (!session_.StepIn(threadId)) {
		return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
	}
	return {{"success", true}, {"threadId", threadId}};
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
	}

	if (!session_.StepOver(threadId)) {
		return {{"error", "Thread " + std::to_string(threadId) + " is not stopped (not found or already running)"}};
	}

	// Wait for StepCompleted event (up to 5s)
	{
		std::unique_lock<std::mutex> lock(stepMutex_);
		if (!stepCv_.wait_for(lock, std::chrono::seconds(5),
				[this]{ return stepCompleted_ || !session_.IsAttached(); })) {
			return {{"error", "Step timed out (threadId=" + std::to_string(threadId) + "). Thread may not be stopped or may be deadlocked."}};
		}
		if (!stepCompleted_ && !session_.IsAttached()) {
			return {{"error", "Target process exited during step"}};
		}
	}

	return {{"success", true}, {"threadId", threadId}};
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
	json arr = json::array();
	for (auto& t : threads) {
		arr.push_back({{"id", t.id}, {"name", t.name}});
	}
	return {{"threads", arr}, {"count", threads.size()}};
}

json McpServer::ToolStackTrace(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	int maxFrames = JsonInt(args, "maxFrames", 20);
	if (maxFrames <= 0 || maxFrames > 200) maxFrames = 20;

	auto frames = session_.GetStackTrace(threadId, maxFrames);
	json arr = json::array();
	for (auto& f : frames) {
		char addrBuf[20];
		snprintf(addrBuf, sizeof(addrBuf), "0x%llX", f.address);

		json frame = {
			{"address", addrBuf},
			{"module", f.moduleName},
			{"function", f.functionName}
		};
		if (!f.sourceFile.empty()) {
			frame["source"] = f.sourceFile;
			frame["line"] = f.line;
		}
		arr.push_back(frame);
	}

	return {{"frames", arr}, {"totalFrames", arr.size()}};
}

json McpServer::ToolEnumLocals(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

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

	auto locals = session_.EnumLocals(threadId, instrAddr, frameBase);
	if (locals.empty() && instrAddr == 0) {
		return {{"error", "Could not determine instruction address. Provide instructionAddress or ensure target is stopped."}};
	}

	json vars = json::array();
	char buf[32];
	for (auto& var : locals) {
		snprintf(buf, sizeof(buf), "0x%llX", var.address);

		// Format value based on type
		std::string valueStr;
		if (var.value.size() >= 4 && (var.typeName.find("float") != std::string::npos)) {
			float f;
			memcpy(&f, var.value.data(), sizeof(f));
			char fBuf[64];
			snprintf(fBuf, sizeof(fBuf), "%.6g", f);
			valueStr = fBuf;
		} else if (var.value.size() >= 8 && (var.typeName.find("double") != std::string::npos)) {
			double d;
			memcpy(&d, var.value.data(), sizeof(d));
			char dBuf[64];
			snprintf(dBuf, sizeof(dBuf), "%.10g", d);
			valueStr = dBuf;
		} else if (var.value.size() >= 8 && (var.typeName.find('*') != std::string::npos)) {
			uint64_t ptr;
			memcpy(&ptr, var.value.data(), sizeof(ptr));
			char pBuf[32];
			snprintf(pBuf, sizeof(pBuf), "0x%llX", ptr);
			valueStr = pBuf;
		} else if (var.value.size() >= 4) {
			int32_t val;
			memcpy(&val, var.value.data(), sizeof(val));
			valueStr = std::to_string(val);
		} else {
			valueStr = "(unreadable)";
		}

		json v = {
			{"name", var.name},
			{"type", var.typeName},
			{"address", buf},
			{"value", valueStr},
			{"size", var.size}
		};
		if (var.flags & 0x100) v["isParameter"] = true;
		vars.push_back(v);
	}

	return {{"variables", vars}, {"count", vars.size()}};
}

json McpServer::ToolRegisters(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required"}};

	auto regsOpt = session_.GetRegisters(threadId);
	if (!regsOpt) {
		return {{"error", "Failed to get registers (thread may not exist or is not suspended)"}};
	}

	const auto& r = *regsOpt;
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
	regs["dr0"] = hex(r.dr0); regs["dr1"] = hex(r.dr1);
	regs["dr2"] = hex(r.dr2); regs["dr3"] = hex(r.dr3);
	regs["dr6"] = hex(r.dr6); regs["dr7"] = hex(r.dr7);
	regs["is32bit"] = (bool)r.is32bit;

	return {{"registers", regs}};
}

json McpServer::ToolReadMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int size = JsonInt(args, "size", 64);
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (size <= 0 || size > 1048576) return {{"error", "size must be 1-1048576"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	auto data = session_.ReadMemory(addr, static_cast<uint32_t>(size));
	if (data.empty()) {
		return {{"error", "Memory read failed (address may be invalid or inaccessible)"}};
	}

	std::ostringstream oss;
	for (size_t i = 0; i < data.size(); i++) {
		if (i > 0 && i % 16 == 0) oss << "\n";
		else if (i > 0) oss << " ";
		oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	return {{"address", addrBuf}, {"size", data.size()}, {"hex", oss.str()}};
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
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

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
			if (session_.WriteMemory(addr, bytes.data(), static_cast<uint32_t>(bytes.size()))) {
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

	// Single mode
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

	if (!session_.WriteMemory(addr, bytes.data(), static_cast<uint32_t>(bytes.size()))) {
		return {{"error", "Memory write failed (address may be invalid, read-only, or inaccessible)"}};
	}

	return {{"success", true}, {"bytesWritten", bytes.size()}};
}

json McpServer::ToolDumpMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

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

	FILE* fp = fopen(outputPath.c_str(), "wb");
	if (!fp) {
		return {{"error", "Cannot open output file: " + outputPath}};
	}

	const uint32_t chunkSize = 1024 * 1024;
	uint64_t totalWritten = 0;
	uint64_t remaining = static_cast<uint64_t>(size);
	uint64_t currentAddr = addr;

	while (remaining > 0) {
		uint32_t toRead = static_cast<uint32_t>((remaining > chunkSize) ? chunkSize : remaining);
		auto data = session_.ReadMemory(currentAddr, toRead);
		if (data.empty()) {
			fclose(fp);
			if (totalWritten > 0) {
				return {{"partial", true}, {"bytesWritten", totalWritten},
				        {"error", "Memory read failed at offset " + std::to_string(totalWritten)}};
			}
			return {{"error", "Memory read failed at starting address"}};
		}

		fwrite(data.data(), 1, data.size(), fp);
		totalWritten += data.size();
		currentAddr += data.size();
		if (data.size() > remaining) break;
		remaining -= data.size();
	}

	fclose(fp);
	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", addr);

	// Verify file: size + SHA256 checksum
	FILE* verify = fopen(outputPath.c_str(), "rb");
	uint64_t fileSize = 0;
	std::string sha256hex;
	if (verify) {
		HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
		_fseeki64(verify, 0, SEEK_END);
		fileSize = _ftelli64(verify);
		_fseeki64(verify, 0, SEEK_SET);

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
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	int size = JsonInt(args, "size", 4096);
	std::string protStr = args.value("protection", "rwx");
	if (size <= 0 || size > 64 * 1024 * 1024) return {{"error", "size must be 1-67108864"}};

	uint32_t protection = PAGE_EXECUTE_READWRITE;
	if (protStr == "rw") protection = PAGE_READWRITE;
	else if (protStr == "rx") protection = PAGE_EXECUTE_READ;
	else if (protStr == "r") protection = PAGE_READONLY;

	uint64_t addr = session_.AllocateMemory(static_cast<uint32_t>(size), protection);
	if (addr == 0) {
		return {{"error", "VirtualAlloc failed in target process"}};
	}

	char buf[20];
	snprintf(buf, sizeof(buf), "0x%llX", addr);
	return {{"success", true}, {"address", buf}, {"size", size}, {"protection", protStr}};
}

json McpServer::ToolFreeMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) return {{"error", "invalid address format"}};

	if (!session_.FreeMemory(addr)) {
		return {{"error", "VirtualFree failed"}};
	}
	return {{"success", true}};
}

json McpServer::ToolExecuteShellcode(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string codeHex = args.value("shellcode", "");
	if (codeHex.empty()) return {{"error", "shellcode (hex string) is required"}};
	int timeoutMs = JsonInt(args, "timeout_ms", 5000);
	if (timeoutMs < 0) timeoutMs = 0;
	if (timeoutMs > 60000) timeoutMs = 60000;

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

	auto result = session_.ExecuteShellcode(bytes.data(), static_cast<uint32_t>(bytes.size()),
	                                         static_cast<uint32_t>(timeoutMs));
	if (!result.ok) {
		return {{"error", "Shellcode execution failed (alloc or thread creation error)"}};
	}

	char addrBuf[20];
	snprintf(addrBuf, sizeof(addrBuf), "0x%llX", result.allocatedAddress);
	json ret = {
		{"success", true},
		{"exitCode", result.exitCode},
		{"allocatedAddress", addrBuf},
		{"fireAndForget", (timeoutMs == 0)}
	};
	if (result.crashed) {
		char exAddrBuf[20];
		snprintf(exAddrBuf, sizeof(exAddrBuf), "0x%llX", result.exceptionAddress);
		char exCodeBuf[12];
		snprintf(exCodeBuf, sizeof(exCodeBuf), "0x%08X", result.exceptionCode);
		ret["crashed"] = true;
		ret["exceptionCode"] = exCodeBuf;
		ret["exceptionAddress"] = exAddrBuf;
	}
	return ret;
}

json McpServer::ToolBatch(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	json steps;

	// File mode: load steps from JSON file
	if (args.contains("file") && args["file"].is_string()) {
		std::string filePath = args["file"].get<std::string>();
		// Basic path validation: block ".." segments
		if (filePath.find("..") != std::string::npos) {
			return {{"error", "Path must not contain '..' segments"}};
		}
		FILE* fp = fopen(filePath.c_str(), "rb");
		if (!fp) return {{"error", "Cannot open file: " + filePath}};
		fseek(fp, 0, SEEK_END);
		long sz = ftell(fp);
		if (sz < 0) { fclose(fp); return {{"error", "Failed to read file size"}}; }
		fseek(fp, 0, SEEK_SET);
		if (sz > 10 * 1024 * 1024) { fclose(fp); return {{"error", "File too large (max 10MB)"}}; }
		std::string content(sz, '\0');
		size_t nread = fread(&content[0], 1, sz, fp);
		fclose(fp);
		if (nread != static_cast<size_t>(sz)) {
			return {{"error", "Failed to read file (partial read)"}};
		}
		try {
			json fileJson = json::parse(content);
			if (fileJson.is_array()) {
				steps = fileJson;
			} else if (fileJson.is_object() && fileJson.contains("steps") && fileJson["steps"].is_array()) {
				steps = fileJson["steps"];
			} else {
				return {{"error", "File must contain a JSON array of steps, or {\"steps\": [...]}"}};
			}
		} catch (const std::exception& e) {
			return {{"error", std::string("JSON parse error: ") + e.what()}};
		}
	} else {
		steps = args.value("steps", json::array());
	}

	if (!steps.is_array() || steps.empty()) {
		return {{"error", "steps (array) is required, or provide file path"}};
	}

	BatchExecutor executor(session_);
	return executor.Execute(steps);
}

json McpServer::ToolTraceRegister(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	std::string regName = args.value("register", "");
	int maxSteps = JsonInt(args, "max_steps", 10000);
	std::string modeStr = args.value("mode", "changed");
	std::string compStr = args.value("value", "");

	if (threadId == 0) return {{"error", "threadId is required"}};
	if (regName.empty()) return {{"error", "register name is required"}};
	if (maxSteps < 1) maxSteps = 1;
	if (maxSteps > 100000) maxSteps = 100000;

	uint32_t regIndex = DebugSession::GetRegisterIndex(regName);
	if (regIndex == UINT32_MAX) return {{"error", "Unknown register: " + regName}};

	uint8_t mode = 0;
	if (modeStr == "equals") mode = 1;
	else if (modeStr == "not_equals") mode = 2;

	uint64_t compareValue = 0;
	if (!compStr.empty()) {
		try { compareValue = std::stoull(compStr, nullptr, 0); } catch (...) {}
	}

	auto r = session_.TraceRegister(threadId, regIndex, maxSteps, mode, compareValue);
	if (!r.ok) return {{"error", "TraceRegister failed (thread may not be stopped)"}};

	char addrBuf[20]; snprintf(addrBuf, sizeof(addrBuf), "0x%llX", r.address);
	char oldBuf[20]; snprintf(oldBuf, sizeof(oldBuf), "0x%llX", r.oldValue);
	char newBuf[20]; snprintf(newBuf, sizeof(newBuf), "0x%llX", r.newValue);

	json ret = {
		{"found", r.found},
		{"stepsExecuted", r.stepsExecuted},
		{"address", addrBuf},
		{"register", regName},
		{"oldValue", oldBuf},
		{"newValue", newBuf}
	};

	// Add disassembly of the instruction that caused the change
	if (r.found && r.address) {
		auto insns = session_.Disassemble(r.address, 1);
		if (!insns.empty()) {
			ret["instruction"] = insns[0].mnemonic;
		}
	}

	return ret;
}

json McpServer::ToolTraceMemory(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) return {{"error", "invalid address format"}};

	int size = JsonInt(args, "size", 4);
	if (size != 1 && size != 2 && size != 4 && size != 8) return {{"error", "size must be 1, 2, 4, or 8"}};

	int timeoutMs = JsonInt(args, "timeout_ms", 10000);
	if (timeoutMs < 100) timeoutMs = 100;
	if (timeoutMs > 60000) timeoutMs = 60000;

	auto r = session_.TraceMemoryWrite(addr, size, timeoutMs);
	if (!r.ok) return {{"error", "TraceMemory failed"}};

	char instrBuf[20]; snprintf(instrBuf, sizeof(instrBuf), "0x%llX", r.instructionAddress);
	char oldBuf[20]; snprintf(oldBuf, sizeof(oldBuf), "0x%llX", r.oldValue);
	char newBuf[20]; snprintf(newBuf, sizeof(newBuf), "0x%llX", r.newValue);
	char addrBuf2[20]; snprintf(addrBuf2, sizeof(addrBuf2), "0x%llX", addr);

	json ret = {
		{"found", r.found},
		{"address", addrBuf2},
		{"threadId", r.threadId}
	};

	if (r.found) {
		ret["instructionAddress"] = instrBuf;
		ret["oldValue"] = oldBuf;
		ret["newValue"] = newBuf;
		// Disassemble the writing instruction
		if (r.instructionAddress) {
			auto insns = session_.Disassemble(r.instructionAddress, 1);
			if (!insns.empty()) ret["instruction"] = insns[0].mnemonic;
		}
	} else {
		ret["timeout"] = true;
	}

	return ret;
}

json McpServer::ToolModules(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	auto modules = session_.GetModules();
	json arr = json::array();
	for (auto& m : modules) {
		char baseBuf[20], sizeBuf[20];
		snprintf(baseBuf, sizeof(baseBuf), "0x%llX", m.baseAddress);
		snprintf(sizeBuf, sizeof(sizeBuf), "0x%X", m.size);
		arr.push_back({
			{"name", m.name},
			{"path", m.path},
			{"baseAddress", baseBuf},
			{"size", sizeBuf}
		});
	}
	return {{"modules", arr}, {"count", arr.size()}};
}

json McpServer::ToolDisassemble(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	int count = JsonInt(args, "count", 20);
	if (addrStr.empty()) return {{"error", "address is required"}};
	if (count <= 0 || count > 500) count = 20;

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}

	auto insns = session_.Disassemble(addr, static_cast<uint32_t>(count));
	if (insns.empty()) {
		return {{"error", "Disassembly failed (address may be invalid or inaccessible)"}};
	}

	json result = json::array();
	for (auto& insn : insns) {
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
	while (!autoContinues.empty()) {
		uint32_t tid = autoContinues.front();
		autoContinues.pop();
		if (!session_.Continue(tid)) {
			LOG_WARN("Auto-continue failed for thread %u", tid);
		}
	}
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

	auto resolveVal = [&](const std::string& tok) -> uint64_t {
		if (tok.empty()) return 0;
		if (tok[0] == '*' || tok[0] == '[') {
			std::string addrStr = tok.substr(1);
			if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
			trim(addrStr);
			try {
				uint64_t addr = std::stoull(addrStr, nullptr, 0);
				uint64_t val = 0;
				SIZE_T bytesRead = 0;
				HANDLE hProc = session_.GetTargetProcess();
				if (hProc && ReadProcessMemory(hProc, (LPCVOID)addr, &val, 8, &bytesRead))
					return val;
			} catch (...) {}
			return 0;
		}
		if (DebugSession::TryParseRegisterName(tok)) {
			if (cachedRegs) return DebugSession::ResolveRegisterByName(tok, *cachedRegs);
			return 0;
		}
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
						// Execute action via BatchExecutor, then auto-continue
						char buf[128];
						snprintf(buf, sizeof(buf), "BP #%u action executing at 0x%llX (thread %u)",
							e->breakpointId, e->address, e->threadId);
						{
							std::lock_guard<std::mutex> lock(eventMutex_);
							pendingEvents_.push({"notifications/logging", {{"level", "info"}, {"logger", "veh-debugger"}, {"data", buf}}});
						}
						BatchExecutor executor(session_);
						executor.Execute(action);
						// Auto-continue after action
						{
							std::lock_guard<std::mutex> lock(eventMutex_);
							pendingAutoContinue_.push(e->threadId);
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
	// Module+RVA syntax: "crackme.exe+0x1000" or "ntdll.dll+0x5000"
	auto plusPos = addrStr.find('+');
	if (plusPos != std::string::npos && plusPos > 0) {
		std::string modulePart = addrStr.substr(0, plusPos);
		std::string offsetPart = addrStr.substr(plusPos + 1);

		// Check if the part before '+' looks like a module name (contains '.' or non-hex chars)
		bool looksLikeModule = false;
		for (char c : modulePart) {
			if (c == '.' || c == '_' || c == '-') { looksLikeModule = true; break; }
			if (std::isalpha(c) && !std::isxdigit(c)) { looksLikeModule = true; break; }
		}

		if (looksLikeModule && session_.IsAttached()) {
			// Resolve module base
			auto modules = session_.GetModules();
			// Case-insensitive match
			std::string modLower = modulePart;
			std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);

			for (auto& m : modules) {
				std::string nameLower = m.name;
				std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
				if (nameLower == modLower) {
					try {
						uint64_t offset = std::stoull(offsetPart, nullptr, 0);
						out = m.baseAddress + offset;
						return true;
					} catch (...) { return false; }
				}
			}
			return false;  // module not found
		}
	}

	// Plain hex/decimal address
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

		{{"name", "veh_set_breakpoint"}, {"description", "Set a software breakpoint (INT3) at an address. Supports module+RVA (e.g. 'crackme.exe+0x1000'). Duplicate address returns existing BP id. Use 'action' to auto-execute commands on hit (no agent intervention needed)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Address: hex (0x7FF600001000) or module+RVA (crackme.exe+0x1000)"}}},
			{"condition", {{"type", "string"}, {"description", "Condition expression (e.g. 'RAX==0x1000', 'RCX>5'). BP only fires when true."}}},
			{"hitCondition", {{"type", "string"}, {"description", "Hit count threshold. BP fires only on Nth hit (e.g. '5' = fire on 5th hit)."}}},
			{"logMessage", {{"type", "string"}, {"description", "Log message template (logpoint). Use {expr} for interpolation (e.g. 'x={RAX}'). Does NOT stop execution."}}},
			{"action", {{"type", "array"}, {"description", "Auto-execute on BP hit (same format as veh_batch steps). After action, auto-continues. Example: [{\"tool\":\"veh_set_register\",\"args\":{\"threadId\":0,\"name\":\"RAX\",\"value\":\"1\"}},{\"tool\":\"veh_continue\"}]"}}}
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
			{"pass_exception", {{"type", "boolean"}, {"description", "If true, pass the current exception to the process's SEH handler instead of handling it. Use for CFF/obfuscated code with INT3. Default: false"}}},
			{"ignore_exceptions", {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Exception codes to auto-pass to SEH (persistent until changed). E.g. [2147483651] for INT3 (0x80000003). Filters exceptions while catching real crashes."}}}
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
		 }}, {"required", json::array({"shellcode"})}}}},

		{{"name", "veh_batch"}, {"description",
			"Execute multiple debugger commands in a single call, reducing round-trips. "
			"Supports sequential execution, variable references ($N for step N result, $N.key for nested access), "
			"and control flow (if/loop/for_each). Uses existing tool names and args format.\n"
			"\nExamples:\n"
			"  Sequential: {steps: [{tool: \"veh_registers\", args: {threadId: 1234}}, {tool: \"veh_read_memory\", args: {address: \"$0.registers.rsp\", size: 8}}]}\n"
			"  Batch patch: {steps: [{tool: \"veh_write_memory\", args: {patches: [{address: \"0x1000\", data: \"90\"}, {address: \"0x2000\", data: \"90\"}]}}]}\n"
			"  Loop: {steps: [{loop: [{tool: \"veh_step_over\", args: {threadId: 1}}, {tool: \"veh_registers\", args: {threadId: 1}}], until: \"$registers.rax!=0\", max: 100}]}\n"
			"  If: {steps: [{tool: \"veh_registers\", args: {threadId: 1}}, {if: \"$0.registers.rax==0\", then: [{tool: \"veh_write_memory\", args: {address: \"0x1000\", data: \"90\"}}]}]}\n"
			"  For-each: {steps: [{for_each: [\"0x1000\",\"0x2000\",\"0x3000\"], as: \"$addr\", do: [{tool: \"veh_write_memory\", args: {address: \"$addr\", data: \"90\"}}]}]}"
		},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"steps", {{"type", "array"}, {"description", "Array of steps. Each step is {tool, args} or {if, then, else} or {loop, until, max} or {for_each, as, do}"}}},
			{"file", {{"type", "string"}, {"description", "Load steps from a JSON file instead of inline. File can be a JSON array of steps or {\"steps\": [...]}. Example: veh_batch({file: \"patch_sequence.json\"})"}}}
		 }}}}},

		{{"name", "veh_trace_register"}, {"description", "Trace a register: single-steps internally (inside DLL, zero IPC overhead per step) until the register meets a condition. Returns the instruction that caused the change. Thread must be stopped at a breakpoint (not via veh_pause). Much faster than manual step+check loops."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"threadId", {{"type", "integer"}, {"description", "OS thread ID (must be stopped)"}}},
			{"register", {{"type", "string"}, {"description", "Register name (RAX, RBX, RCX, etc.)"}}},
			{"mode", {{"type", "string"}, {"enum", json::array({"changed", "equals", "not_equals"})}, {"description", "Condition: 'changed' (any change), 'equals' (== value), 'not_equals' (!= value). Default: changed"}}},
			{"value", {{"type", "string"}, {"description", "Compare value for equals/not_equals mode (hex or decimal)"}}},
			{"max_steps", {{"type", "integer"}, {"description", "Max instructions to step (default: 10000, max: 100000)"}}}
		 }}, {"required", json::array({"threadId", "register"})}}}},

		{{"name", "veh_trace_memory"}, {"description", "Trace memory writes: sets a temporary hardware data breakpoint, resumes the process, and waits for any thread to write to the address. Returns the writing instruction, thread ID, and old/new values. Uses DR0-DR3 (1 slot occupied during trace)."},
		 {"inputSchema", {{"type", "object"}, {"properties", {
			{"address", {{"type", "string"}, {"description", "Memory address to watch (hex or module+RVA)"}}},
			{"size", {{"type", "integer"}, {"enum", json::array({1, 2, 4, 8})}, {"description", "Watch size in bytes (default: 4)"}}},
			{"timeout_ms", {{"type", "integer"}, {"description", "Max wait time in ms (default: 10000, max: 60000)"}}}
		 }}, {"required", json::array({"address"})}}}}
	});
}

std::string McpServer::NotAttachedMessage() {
	HANDLE hProc = session_.GetTargetProcess();
	if (hProc) {
		DWORD exitCode = 0;
		if (GetExitCodeProcess(hProc, &exitCode) && exitCode != STILL_ACTIVE) {
			char buf[128];
			snprintf(buf, sizeof(buf), "Not attached - target process exited (code %lu)", exitCode);
			return buf;
		}
	}
	return "Not attached";
}

std::string McpServer::IpcErrorMessage() {
	if (!session_.IsAttached()) return NotAttachedMessage();
	HANDLE hProc = session_.GetTargetProcess();
	if (hProc) {
		DWORD exitCode = 0;
		if (GetExitCodeProcess(hProc, &exitCode) && exitCode != STILL_ACTIVE) {
			char buf[128];
			snprintf(buf, sizeof(buf), "Target process has exited (exit code: %lu)", exitCode);
			return buf;
		}
	}
	if (!session_.GetPipeClient().IsConnected()) return "Target pipe disconnected (process may have crashed)";
	return "IPC communication failed (timeout)";
}

} // namespace veh
