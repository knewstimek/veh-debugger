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

json McpServer::ToolSetModuleBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	if (args.value("clear", false)) {
		bool ok = session_.SetModuleLoadStop("", 2);
		return {{"success", ok}, {"cleared", true}};
	}

	std::string module = args.value("module", "");
	if (module.empty()) return {{"error", "module is required (or pass clear=true)"}};

	bool enabled = args.value("enabled", true);
	bool ok = session_.SetModuleLoadStop(module, enabled ? 0 : 1);
	if (!ok) return {{"error", "Failed to update module-load breakpoint"}};
	return {{"success", true}, {"module", module}, {"action", enabled ? "add" : "remove"}};
}

json McpServer::ToolSetBreakpoint(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	std::string addrStr = args.value("address", "");
	if (addrStr.empty()) return {{"error", "address is required"}};

	uint64_t addr;
	if (!ParseAddress(addrStr, addr)) {
		return {{"error", "invalid address format"}};
	}
	if (args.contains("action") && !args["action"].is_array()) {
		return {{"error", "action must be an array of batch steps"}};
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
		StoreBreakpointAction(bpResult.id, args["action"]);
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
		// deferred: 모듈 미로드일 수 있으므로 pending으로 보관. 모듈 로드 시 워커가 재해석.
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bool exists = false;
		for (auto& ex : bps) {
			if (ex.pending && ex.source == source && ex.line == line) { exists = true; break; }
		}
		if (!exists) {
			SwBpInfo bp;
			bp.id = 0;
			bp.address = 0;
			bp.source = source;
			bp.line = line;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			bp.pending = true;
			bps.push_back(bp);
		}
		return {{"pending", true}, {"source", source}, {"line", line},
		        {"message", "Symbol not loaded yet; breakpoint is pending and will bind when the module loads. Poll veh_list_breakpoints (status) to confirm."}};
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
			// 같은 vehId, 또는 같은 source/line의 미해결 pending 엔트리를 재사용한다.
			// (모듈 로드 후 워커가 바인딩하기 전에 같은 BP를 재설정하면 중복 active 발생 -> 방지)
			if (existing.id == bpResult.id ||
			    (existing.pending && existing.source == source && existing.line == line)) {
				existing.id = bpResult.id;
				existing.address = addr;
				existing.pending = false;
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
		// deferred: 함수 심볼 미해결 -> pending으로 보관. 모듈 로드 시 워커가 재해석.
		std::lock_guard<std::mutex> lock(session_.GetBpMutex());
		auto& bps = session_.GetSwBreakpoints();
		bool exists = false;
		for (auto& ex : bps) {
			if (ex.pending && ex.functionName == name) { exists = true; break; }
		}
		if (!exists) {
			SwBpInfo bp;
			bp.id = 0;
			bp.address = 0;
			bp.functionName = name;
			bp.condition = args.value("condition", "");
			bp.hitCondition = args.value("hitCondition", "");
			bp.logMessage = args.value("logMessage", "");
			bp.pending = true;
			bps.push_back(bp);
		}
		return {{"pending", true}, {"function", name},
		        {"message", "Symbol not loaded yet; breakpoint is pending and will bind when the module loads. Poll veh_list_breakpoints (status) to confirm."}};
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
			// 같은 vehId, 또는 같은 functionName의 미해결 pending 엔트리를 재사용한다.
			// (모듈 로드 후 워커가 바인딩하기 전에 같은 BP를 재설정하면 중복 active 발생 -> 방지)
			if (existing.id == bpResult.id ||
			    (existing.pending && existing.functionName == name)) {
				existing.id = bpResult.id;
				existing.address = addr;
				existing.pending = false;
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
			json entry = {{"id", bp.id}, {"address", buf}, {"status", bp.pending ? "pending" : "active"}};
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
		HwBpInfo info{result.id, addr, type, static_cast<uint8_t>(size)};
		info.condition = args.value("condition", "");
		info.hitCondition = args.value("hitCondition", "");
		session_.GetHwBreakpoints().push_back(std::move(info));
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

} // namespace veh
