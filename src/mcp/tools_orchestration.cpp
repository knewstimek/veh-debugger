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
			json fileJson = json::parse(content, nullptr, true, true);  // allow_comments (JSONC)
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
	if (args.contains("stop_on_error") && !args["stop_on_error"].is_boolean())
		return {{"error", "stop_on_error must be a boolean"}};
	const bool stopOnError = args.value("stop_on_error", false);

	auto run = [&](const json* input, const std::string& inputVariable) {
		BatchExecutor executor = NewBatchExecutor();
		executor.SetStopOnError(stopOnError);
		if (input) executor.SetVariable(inputVariable, *input);
		return executor.Execute(steps);
	};
	if (!args.contains("inputs")) return run(nullptr, "");
	if (!args["inputs"].is_array() || args["inputs"].empty() || args["inputs"].size() > 256)
		return {{"error", "inputs must be an array with 1-256 items"}};
	if (args.contains("input_variable") && !args["input_variable"].is_string())
		return {{"error", "input_variable must be a string"}};
	std::string inputVariable = args.value("input_variable", "$input");
	if (inputVariable.empty()) inputVariable = "$input";
	if (inputVariable[0] != '$') inputVariable.insert(inputVariable.begin(), '$');
	json inputReports = json::array();
	uint32_t succeeded = 0, failed = 0;
	int64_t firstFailedInput = -1;
	for (size_t index = 0; index < args["inputs"].size(); ++index) {
		const auto& input = args["inputs"][index];
		json execution = run(&input, inputVariable);
		bool inputFailed = execution.value("failed", 0) != 0;
		json report = {{"index", index}, {"status", inputFailed ? "failed" : "ok"},
			{"steps", execution.value("results", json::array())},
			{"succeeded", execution.value("succeeded", 0)}, {"failed", execution.value("failed", 0)},
			{"first_failed_step", execution.value("first_failed_step", json(nullptr))},
			{"trace_summary", execution.value("trace_summary", json::array())},
			{"artifacts", execution.value("artifacts", json::array())}};
		if (input.is_object() && input.contains("name")) report["name"] = input["name"];
		inputReports.push_back(std::move(report));
		if (inputFailed) {
			++failed; if (firstFailedInput < 0) firstFailedInput = static_cast<int64_t>(index);
			if (stopOnError) break;
		} else ++succeeded;
	}
	return {{"mode", "inputs"}, {"input_variable", inputVariable},
		{"inputs", std::move(inputReports)}, {"succeeded", succeeded}, {"failed", failed},
		{"first_failed_input", firstFailedInput < 0 ? json(nullptr) : json(firstFailedInput)},
		{"stopped_on_error", stopOnError && failed != 0}};
}

static std::string CompactToolSummary(const std::string& description) {
	size_t end = description.find('.');
	if (end == std::string::npos || end > 180) end = std::min<size_t>(description.size(), 180);
	else ++end;
	return description.substr(0, end);
}

static std::string ToolSchemaHandle(const json& definition) {
	const std::string bytes = definition.dump();
	uint64_t hash = 1469598103934665603ULL;
	for (unsigned char value : bytes) {
		hash ^= value;
		hash *= 1099511628211ULL;
	}
	char buffer[32];
	snprintf(buffer, sizeof(buffer), "veh_%016llx", static_cast<unsigned long long>(hash));
	return buffer;
}

json McpServer::ToolToolbox(const json& args) {
	const std::string operation = args.value("operation", "list");
	if (operation == "profiles") {
		json profiles = json::array();
		for (const char* profile : {"lite", "interactive", "capture", "full"}) {
			const unsigned mask = ProfileMask(profile);
			profiles.push_back({{"name", profile}, {"eager_tools", std::count_if(tools_.begin(), tools_.end(),
				[mask](const ToolDef& tool) { return tool.InProfile(mask); })}});
		}
		return {{"active", toolProfile_}, {"profiles", std::move(profiles)}};
	}

	if (operation == "list") {
		const std::string profile = args.value("profile", "full");
		const unsigned mask = ProfileMask(profile);
		if (!mask) return {{"error", "profile must be lite, interactive, capture, or full"}};
		std::string query = args.value("query", "");
		std::transform(query.begin(), query.end(), query.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		json matches = json::array();
		for (const auto& tool : tools_) {
			if (!tool.InProfile(mask)) continue;
			const std::string summary = CompactToolSummary(tool.definition.value("description", ""));
			std::string haystack = tool.name + " " + summary + " " + tool.category;
			std::transform(haystack.begin(), haystack.end(), haystack.begin(),
				[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			if (!query.empty() && haystack.find(query) == std::string::npos) continue;
			matches.push_back({{"name", tool.name}, {"category", tool.category}, {"summary", summary}});
		}
		return {{"active_profile", toolProfile_}, {"filter_profile", profile},
			{"count", matches.size()}, {"tools", std::move(matches)}};
	}

	const std::string name = args.value("tool", "");
	if (name.empty()) return {{"error", "tool is required for describe or call"}};
	if (operation == "describe") {
		const ToolDef* tool = FindTool(name);
		if (!tool) return {{"error", "Unknown tool: " + name}};
		const std::string handle = ToolSchemaHandle(tool->definition);
		if (args.value("schema_handle", "") == handle)
			return {{"tool", name}, {"schema_handle", handle}, {"unchanged", true}};
		return {{"tool", name}, {"category", tool->category}, {"schema_handle", handle},
			{"description", tool->definition.value("description", "")},
			{"inputSchema", tool->definition.value("inputSchema", json::object())}};
	}
	if (operation == "call") {
		if (name == "veh_toolbox") return {{"error", "veh_toolbox cannot call itself"}};
		if (args.contains("arguments") && !args["arguments"].is_object())
			return {{"error", "arguments must be an object"}};
		bool known = false;
		json result = DispatchTool(name, args.value("arguments", json::object()), &known);
		if (!known) return {{"error", "Unknown tool: " + name}};
		json wrapped = {{"tool", name}};
		if (result.is_object() && result.contains("error")) wrapped["error"] = result["error"];
		wrapped["result"] = std::move(result);
		return wrapped;
	}
	return {{"error", "operation must be list, describe, call, or profiles"}};
}

} // namespace veh
