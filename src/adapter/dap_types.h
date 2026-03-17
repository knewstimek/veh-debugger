#pragma once
#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

namespace veh::dap {

using json = nlohmann::json;

// DAP Base Protocol
struct ProtocolMessage {
	int seq = 0;
	std::string type; // "request", "response", "event"
};

struct Request : ProtocolMessage {
	std::string command;
	json arguments = json::object();
};

struct Response : ProtocolMessage {
	int request_seq = 0;
	bool success = true;
	std::string command;
	std::string message;
	json body = json::object();
};

struct Event : ProtocolMessage {
	std::string event;
	json body = json::object();
};

// --- Capabilities ---
inline json MakeCapabilities() {
	return {
		{"supportsConfigurationDoneRequest", true},
		{"supportsEvaluateForHovers", true},
		{"supportsConditionalBreakpoints", true},
		{"supportsHitConditionalBreakpoints", true},
		{"supportsLogPoints", true},
		{"supportsFunctionBreakpoints", true},
		{"supportsExceptionInfoRequest", true},
		{"supportsReadMemoryRequest", true},
		{"supportsWriteMemoryRequest", true},
		{"supportsDisassembleRequest", true},
		{"supportsModulesRequest", true},
		{"supportsLoadedSourcesRequest", true},
		{"supportsTerminateRequest", true},
		{"supportsSetVariable", true},
		{"supportsSetExpression", false},
		{"supportsStepBack", false},
		{"supportsRestartRequest", true},
		{"supportsGotoTargetsRequest", true},
		{"supportsStepInTargetsRequest", false},
		{"supportsCompletionsRequest", true},
		{"supportsDataBreakpoints", true},
		{"supportsCancelRequest", true},
		{"supportsTerminateThreadsRequest", true},
		{"supportsInstructionBreakpoints", true},
		{"supportsBreakpointLocationsRequest", false},
		{"exceptionBreakpointFilters", json::array({
			{{"filter", "all"}, {"label", "All Exceptions"}, {"default_", false}},
			{{"filter", "uncaught"}, {"label", "Uncaught Exceptions"}, {"default_", true}},
		})},
	};
}

// --- DAP Types ---
struct Source {
	std::string name;
	std::string path;

	json ToJson() const {
		json j;
		if (!name.empty()) j["name"] = name;
		if (!path.empty()) j["path"] = path;
		return j;
	}
};

struct Breakpoint {
	int id = 0;
	bool verified = false;
	std::string message;
	uint64_t instructionReference = 0;

	json ToJson() const {
		json j = {
			{"id", id},
			{"verified", verified},
		};
		if (!message.empty()) j["message"] = message;
		if (instructionReference) {
			char buf[32];
			snprintf(buf, sizeof(buf), "0x%llX", instructionReference);
			j["instructionReference"] = buf;
		}
		return j;
	}
};

struct StackFrameDap {
	int id = 0;
	std::string name;
	int line = 0;
	int column = 0;
	Source source;
	std::string instructionPointerReference;
	std::string moduleId;

	json ToJson() const {
		json j = {
			{"id", id},
			{"name", name},
			{"line", line},
			{"column", column},
		};
		if (!source.path.empty()) j["source"] = source.ToJson();
		if (!instructionPointerReference.empty())
			j["instructionPointerReference"] = instructionPointerReference;
		if (!moduleId.empty()) j["moduleId"] = moduleId;
		return j;
	}
};

struct Scope {
	std::string name;
	int variablesReference = 0;
	int namedVariables = 0;    // VSCode는 이 값이 0이면 scope를 빈 것으로 판단하여 펼침 불가
	bool expensive = false;

	json ToJson() const {
		json j = {
			{"name", name},
			{"variablesReference", variablesReference},
			{"expensive", expensive},
		};
		if (namedVariables > 0) {
			j["namedVariables"] = namedVariables;
		}
		return j;
	}
};

struct Variable {
	std::string name;
	std::string value;
	std::string type;
	int variablesReference = 0;
	std::string memoryReference;

	json ToJson() const {
		json j = {
			{"name", name},
			{"value", value},
			{"variablesReference", variablesReference},
		};
		if (!type.empty()) j["type"] = type;
		if (!memoryReference.empty()) j["memoryReference"] = memoryReference;
		return j;
	}
};

struct Thread {
	int id = 0;
	std::string name;

	json ToJson() const {
		return {{"id", id}, {"name", name}};
	}
};

struct Module {
	std::string id;
	std::string name;
	std::string path;
	std::string addressRange;

	json ToJson() const {
		json j = {
			{"id", id},
			{"name", name},
		};
		if (!path.empty()) j["path"] = path;
		if (!addressRange.empty()) j["addressRange"] = addressRange;
		return j;
	}
};

struct DisassembledInstruction {
	std::string address;
	std::string instructionBytes;
	std::string instruction;

	json ToJson() const {
		return {
			{"address", address},
			{"instructionBytes", instructionBytes},
			{"instruction", instruction},
		};
	}
};

// --- Helper: parse hex address ---
inline bool ParseAddress(const std::string& s, uint64_t& out) {
	if (s.empty()) return false;
	try {
		size_t pos = 0;
		out = std::stoull(s, &pos, 0);
		return pos > 0; // 최소 1자 이상 파싱 성공
	} catch (...) {
		return false;
	}
}

// 하위 호환: 기존 코드에서 ParseAddress(str)로 호출하는 곳
inline uint64_t ParseAddress(const std::string& s) {
	uint64_t addr = 0;
	ParseAddress(s, addr);
	return addr;
}

inline std::string FormatAddress(uint64_t addr) {
	char buf[32];
	snprintf(buf, sizeof(buf), "0x%llX", addr);
	return buf;
}

} // namespace veh::dap
