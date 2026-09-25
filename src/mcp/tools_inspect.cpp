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

json McpServer::ToolSymbolize(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	json inputs = json::array();
	if (args.contains("addresses") && args["addresses"].is_array()) inputs = args["addresses"];
	if (args.contains("address")) inputs.push_back(args["address"]);
	if (inputs.empty()) return {{"error", "address or addresses is required"}};
	if (inputs.size() > kSymbolizeMaxAddresses)
		return {{"error", "at most " + std::to_string(kSymbolizeMaxAddresses) + " addresses per call"}};

	std::vector<uint64_t> addresses;
	for (auto& input : inputs) {
		uint64_t value = 0;
		if (input.is_number_unsigned()) value = input.get<uint64_t>();
		else if (!input.is_string() || !ParseAddress(input.get<std::string>(), value))
			return {{"error", "invalid address: " + input.dump()}};
		addresses.push_back(value);
	}

	auto entries = session_.Symbolize(addresses);
	if (entries.size() != addresses.size()) return {{"error", "symbolize failed in target"}};

	json symbols = json::array();
	for (auto& e : entries) {
		char buf[32];
		json item = {{"address", HexAddr(e.address)}};
		std::string module = e.moduleName;
		std::string function = e.functionName;
		if (!function.empty()) {
			snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(e.displacement));
			item["symbol"] = (module.empty() ? "" : module + "!") + function + (e.displacement ? buf : "");
			item["function"] = function;
			item["offset"] = HexAddr(e.displacement);
		} else if (e.moduleBase) {
			snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(e.address - e.moduleBase));
			item["symbol"] = module + buf;
		}
		if (!module.empty()) item["module"] = module;
		if (e.line) {
			item["file"] = e.sourceFile;
			item["line"] = e.line;
		}
		symbols.push_back(std::move(item));
	}
	return {{"symbols", symbols}, {"count", symbols.size()}};
}

static json TypeMemberValue(const DisplayTypeMember& m) {
	uint64_t raw = 0;
	memcpy(&raw, m.value, sizeof(raw));
	if (m.bitLength) return raw;
	switch (m.kind) {
	case TypeMemberKind::Pointer: return HexAddr(raw);
	case TypeMemberKind::Bool: return raw != 0;
	case TypeMemberKind::Float:
		if (m.valueSize == 4) { float f; memcpy(&f, m.value, 4); return f; }
		if (m.valueSize == 8) { double d; memcpy(&d, m.value, 8); return d; }
		break;
	case TypeMemberKind::Int: {
		const unsigned bits = m.valueSize * 8;
		int64_t v = static_cast<int64_t>(raw);
		if (bits < 64) v = static_cast<int64_t>(raw << (64 - bits)) >> (64 - bits);  // sign-extend
		return v;
	}
	default: break;
	}
	return raw;
}

json McpServer::ToolDisplayType(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	std::string type = args.value("type", "");
	if (type.empty() || type.size() >= sizeof(DisplayTypeRequest::typeName)) return {{"error", "type is required (\"Type\" or \"module!Type\")"}};

	DisplayTypeRequest req{};
	strncpy_s(req.typeName, type.c_str(), _TRUNCATE);
	std::string addrStr = args.value("address", "");
	if (!addrStr.empty() && !ParseAddress(addrStr, req.address)) return {{"error", "invalid address format"}};
	int depth = JsonInt(args, "depth", 1);
	if (depth < 0 || depth > 4) return {{"error", "depth must be 0-4"}};
	req.maxDepth = static_cast<uint8_t>(depth);
	req.maxMembers = JsonUint32(args, "max_members", 200);
	if (req.maxMembers == 0 || req.maxMembers > kDisplayTypeMaxMembers) return {{"error", "max_members must be 1-1024"}};

	DisplayTypeResponse header{};
	std::vector<DisplayTypeMember> members;
	if (!session_.DisplayType(req, header, members))
		return {{"error", "type not found in loaded PDB symbols: " + type}};

	json list = json::array();
	for (auto& m : members) {
		json item = {{"offset", HexAddr(m.offset)}, {"name", m.name}, {"type", m.typeName}, {"size", m.size}};
		if (m.depth) item["depth"] = m.depth;
		if (m.bitLength) item["bits"] = std::to_string(m.bitPosition) + ":" + std::to_string(m.bitLength);
		if (m.valueSize) item["value"] = TypeMemberValue(m);
		list.push_back(std::move(item));
	}
	json result = {{"type", type}, {"module", header.moduleName}, {"size", header.typeSize},
	               {"members", list}, {"count", list.size()}, {"truncated", header.truncated != 0}};
	if (req.address) result["address"] = HexAddr(req.address);
	return result;
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

	if (args.contains("fields") && args["fields"].is_array() && !args["fields"].empty()) {
		json selected = {{"is32bit", regs["is32bit"]}};
		for (const auto& field : args["fields"]) {
			if (field.is_string() && regs.contains(field.get<std::string>()))
				selected[field.get<std::string>()] = regs[field.get<std::string>()];
		}
		return {{"registers", std::move(selected)}};
	}
	return {{"registers", regs}};
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

} // namespace veh
