#include "mcp_server.h"
#include "tools_common.h"
#include "batch_executor.h"
#include "trace_basic_blocks_tool.h"
#include "trace_output_file.h"
#include "assembler.h"
#include "adapter/disassembler.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <set>
#include <stdexcept>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

struct BatchSessionOperation {
	std::string name;
	size_t topIndex = 0;
	unsigned depth = 0;
};

static void CollectBatchSessionOperations(const json& steps, unsigned depth,
		std::vector<BatchSessionOperation>& operations, size_t inheritedTop = 0) {
	if (!steps.is_array()) return;
	for (size_t index = 0; index < steps.size(); ++index) {
		json decoded;
		const json* step = &steps[index];
		if (step->is_string()) {
			try { decoded = json::parse(step->get<std::string>()); step = &decoded; }
			catch (...) { continue; }
		}
		if (!step->is_object()) continue;
		const size_t topIndex = depth == 0 ? index : inheritedTop;
		if (step->contains("tool") && (*step)["tool"].is_string()) {
			const std::string name = (*step)["tool"].get<std::string>();
			if (name == "veh_attach" || name == "veh_launch" ||
				name == "veh_detach" || name == "veh_terminate")
				operations.push_back({name, topIndex, depth});
		}
		for (const char* child : {"then", "else", "loop", "do"})
			if (step->contains(child))
				CollectBatchSessionOperations((*step)[child], depth + 1, operations, topIndex);
	}
}

static size_t BatchReportCount(const json& report) {
	if (report.value("mode", "") == "inputs" && report.contains("inputs") && report["inputs"].is_array())
		return report["inputs"].size();
	return report.value("totalSteps", static_cast<size_t>(0));
}

static bool BatchOutputLimit(const json& args, uint64_t& limit, std::string& error) {
	limit = 0;
	if (!args.contains("max_output_bytes")) return true;
	if (!args["max_output_bytes"].is_number_integer()) {
		error = "max_output_bytes must be an integer from 1024 through 67108864"; return false;
	}
	try {
		if (args["max_output_bytes"].is_number_unsigned())
			limit = args["max_output_bytes"].get<uint64_t>();
		else {
			const int64_t signedLimit = args["max_output_bytes"].get<int64_t>();
			if (signedLimit < 0) { error = "max_output_bytes must be an integer from 1024 through 67108864"; return false; }
			limit = static_cast<uint64_t>(signedLimit);
		}
	} catch (...) {
		error = "max_output_bytes must be an integer from 1024 through 67108864"; return false;
	}
	if (limit < 1024 || limit > 64ULL * 1024 * 1024) {
		error = "max_output_bytes must be an integer from 1024 through 67108864"; return false;
	}
	return true;
}

static json ApplyBatchOutputBudget(json report, const json& args) {
	if (!args.contains("max_output_bytes")) return report;
	uint64_t requested = 0;
	std::string error;
	if (!BatchOutputLimit(args, requested, error)) return {{"error", error}};
	const std::string serialized = report.dump();
	if (serialized.size() <= requested) return report;

	const size_t count = BatchReportCount(report);
	auto written = WriteJsonArtifactInDirectory(args.value("artifact_directory", ""),
		"veh-batch-result", report);
	json compact = {
		{"partial", true}, {"truncated", true}, {"partial_reason", "max_output_bytes"},
		{"max_output_bytes", requested}, {"original_bytes", serialized.size()}, {"count", count}
	};
	for (const char* key : {"mode", "input_variable", "totalSteps", "succeeded", "failed",
		"first_failed_step", "first_failed_input", "stopped_on_error"})
		if (report.contains(key)) compact[key] = report[key];
	if (written.success) compact["artifact"] = {
		{"path", written.path}, {"format", written.format}, {"sha256", written.sha256},
		{"size", written.size}, {"count", count}, {"complete", true}, {"truncated", false}
	};
	else compact["artifact"] = {{"complete", false}, {"error", written.error}};
	return compact;
}

json McpServer::ToolBatch(const json& args) {
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
	std::vector<BatchSessionOperation> sessionOperations;
	CollectBatchSessionOperations(steps, 0, sessionOperations);
	if (!sessionOperations.empty()) {
		if (sessionOperations.size() != 1 || sessionOperations[0].topIndex != 0 ||
			sessionOperations[0].depth != 0 ||
			(sessionOperations[0].name != "veh_launch" && sessionOperations[0].name != "veh_attach"))
			return {{"error", "Only one top-level first-step veh_launch or veh_attach is allowed; detach/terminate and nested session operations remain unavailable"}};
		if (session_.IsAttached())
			return {{"error", "veh_launch/veh_attach can start a batch only when no session is attached"}};
		if (args.contains("inputs"))
			return {{"error", "veh_launch/veh_attach cannot be repeated with batch inputs"}};
	} else if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	if (args.contains("stop_on_error") && !args["stop_on_error"].is_boolean())
		return {{"error", "stop_on_error must be a boolean"}};
	uint64_t outputLimit = 0;
	std::string outputError;
	if (!BatchOutputLimit(args, outputLimit, outputError)) return {{"error", outputError}};
	(void)outputLimit;
	if (args.contains("artifact_directory")) {
		if (!args["artifact_directory"].is_string()) return {{"error", "artifact_directory must be a string"}};
		if (args["artifact_directory"].get<std::string>().empty())
			return {{"error", "artifact_directory must not be empty; omit it to use the host temporary directory"}};
		try {
			const auto directory = std::filesystem::absolute(
				std::filesystem::u8path(args["artifact_directory"].get<std::string>()));
			if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory))
				return {{"error", "artifact_directory does not exist or is not a directory"}};
		} catch (const std::exception& error) {
			return {{"error", std::string("invalid artifact_directory: ") + error.what()}};
		}
	}
	const bool stopOnError = args.value("stop_on_error", false);

	auto run = [&](const json* input, const std::string& inputVariable) {
		BatchExecutor executor = NewBatchExecutor(!sessionOperations.empty());
		executor.SetStopOnError(stopOnError);
		if (input) executor.SetVariable(inputVariable, *input);
		return executor.Execute(steps);
	};
	if (!args.contains("inputs")) return ApplyBatchOutputBudget(run(nullptr, ""), args);
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
	return ApplyBatchOutputBudget({{"mode", "inputs"}, {"input_variable", inputVariable},
		{"inputs", std::move(inputReports)}, {"succeeded", succeeded}, {"failed", failed},
		{"first_failed_input", firstFailedInput < 0 ? json(nullptr) : json(firstFailedInput)},
		{"stopped_on_error", stopOnError && failed != 0}}, args);
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
		for (const char* profile : {"lite", "interactive", "capture", "analysis", "vmguest", "full"}) {
			const unsigned mask = ProfileMask(profile);
			profiles.push_back({{"name", profile}, {"eager_tools", std::count_if(tools_.begin(), tools_.end(),
				[mask](const ToolDef& tool) { return tool.InProfile(mask); })}});
		}
		return {{"active", toolProfile_}, {"profiles", std::move(profiles)}};
	}

	if (operation == "list") {
		const std::string profile = args.value("profile", "full");
		const unsigned mask = ProfileMask(profile);
		if (!mask) return {{"error", "profile must be lite, interactive, capture, analysis, vmguest, or full"}};
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
	if (operation == "manifest") {
		if (args.contains("compact") && !args["compact"].is_boolean())
			return {{"error", "compact must be a boolean"}};
		const bool compact = args.value("compact", true);
		std::vector<const ToolDef*> selected;
		std::set<std::string> seen;
		if (args.contains("tools")) {
			if (!args["tools"].is_array() || args["tools"].empty() || args["tools"].size() > 64)
				return {{"error", "tools must be an array with 1-64 tool names"}};
			for (const auto& value : args["tools"]) {
				if (!value.is_string()) return {{"error", "tools must contain only tool names"}};
				const std::string name = value.get<std::string>();
				const ToolDef* tool = FindTool(name);
				if (!tool) return {{"error", "Unknown tool: " + name}};
				if (seen.insert(name).second) selected.push_back(tool);
			}
		} else {
			const std::string profile = args.value("profile", "full");
			const unsigned mask = ProfileMask(profile);
			if (!mask) return {{"error", "profile must be lite, interactive, capture, analysis, vmguest, or full"}};
			std::string query = args.value("query", "");
			std::transform(query.begin(), query.end(), query.begin(),
				[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			for (const auto& tool : tools_) {
				if (!tool.InProfile(mask)) continue;
				const std::string summary = CompactToolSummary(tool.definition.value("description", ""));
				std::string haystack = tool.name + " " + summary + " " + tool.category;
				std::transform(haystack.begin(), haystack.end(), haystack.begin(),
					[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
				if (!query.empty() && haystack.find(query) == std::string::npos) continue;
				selected.push_back(&tool);
				if (selected.size() > 64)
					return {{"error", "manifest matches more than 64 tools; narrow query or pass tools"}};
			}
		}

		json schemaHandles = json::array();
		for (const ToolDef* tool : selected)
			schemaHandles.push_back({{"name", tool->name}, {"schema_handle", ToolSchemaHandle(tool->definition)}});
		json handleInput = {{"compact", compact}, {"tools", std::move(schemaHandles)}};
		const std::string manifestHandle = ToolSchemaHandle(handleInput);
		if (args.value("manifest_handle", "") == manifestHandle)
			return {{"manifest_handle", manifestHandle}, {"count", selected.size()}, {"unchanged", true}};
		json definitions = json::array();
		for (const ToolDef* tool : selected) {
			const std::string description = tool->definition.value("description", "");
			definitions.push_back({{"name", tool->name}, {"category", tool->category},
				{"schema_handle", ToolSchemaHandle(tool->definition)},
				{"description", compact ? CompactToolSummary(description) : description},
				{"inputSchema", tool->definition.value("inputSchema", json::object())}});
		}
		return {{"active_profile", toolProfile_}, {"manifest_handle", manifestHandle},
			{"count", definitions.size()}, {"tools", std::move(definitions)}};
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
	return {{"error", "operation must be list, manifest, describe, call, or profiles"}};
}

} // namespace veh
