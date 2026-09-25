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

	return {{"frames", arr}, {"count", arr.size()}, {"totalFrames", arr.size()}};
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

json McpServer::ToolResolveImports(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	uint32_t threadId = JsonUint32(args, "threadId");
	if (threadId == 0) return {{"error", "threadId is required (must be stopped at breakpoint)"}};

	int maxSteps = JsonInt(args, "max_steps", 1000);
	if (maxSteps < 1) maxSteps = 1;
	if (maxSteps > 10000) maxSteps = 10000;

	// Parse addresses array
	std::vector<uint64_t> thunks;
	if (args.contains("addresses") && args["addresses"].is_array()) {
		for (auto& a : args["addresses"]) {
			uint64_t addr = 0;
			if (a.is_string()) {
				std::string s = a.get<std::string>();
				ParseAddress(s, addr);
			} else if (a.is_number()) {
				addr = a.get<uint64_t>();
			}
			if (addr) thunks.push_back(addr);
		}
	}
	if (thunks.empty()) return {{"error", "addresses (array) is required"}};
	if (thunks.size() > 2000) return {{"error", "Too many addresses (max 2000)"}};

	bool followExceptions = false;
	if (args.contains("follow_exceptions") && args["follow_exceptions"].is_boolean())
		followExceptions = args["follow_exceptions"].get<bool>();

	bool systemOnly = false;
	if (args.contains("system_only") && args["system_only"].is_boolean())
		systemOnly = args["system_only"].get<bool>();

	std::vector<std::string> targetModules;
	if (args.contains("target_modules") && args["target_modules"].is_array()) {
		for (auto& m : args["target_modules"]) {
			if (m.is_string()) targetModules.push_back(m.get<std::string>());
		}
	}

	auto results = session_.ResolveImports(threadId, thunks, maxSteps,
		followExceptions, systemOnly, targetModules);

	json arr = json::array();
	int resolved = 0;
	for (auto& e : results) {
		char thunkBuf[20]; snprintf(thunkBuf, sizeof(thunkBuf), "0x%llX", e.thunkAddress);
		char targetBuf[20]; snprintf(targetBuf, sizeof(targetBuf), "0x%llX", e.targetAddress);
		json entry = {{"thunk", thunkBuf}, {"resolved", e.resolved}};
		if (e.resolved) {
			std::string api = e.moduleName;
			if (!e.functionName.empty()) api += "!" + e.functionName;
			entry["target"] = targetBuf;
			entry["api"] = api;
			entry["module"] = e.moduleName;
			entry["function"] = e.functionName;
			resolved++;
		}
		// Diagnostic info (always included, most useful for failed entries)
		entry["steps"] = e.stepsExecuted;
		if (e.exceptionsPassed > 0)
			entry["exceptions_passed"] = e.exceptionsPassed;
		if (!e.trace.empty()) {
			json traceArr = json::array();
			for (auto& t : e.trace) {
				char addrBuf[20]; snprintf(addrBuf, sizeof(addrBuf), "0x%llX", t.address);
				json te = {{"addr", addrBuf}};
				if (t.excCode != 0) {
					char excBuf[12]; snprintf(excBuf, sizeof(excBuf), "0x%08X", t.excCode);
					te["exc"] = excBuf;
				}
				traceArr.push_back(te);
			}
			entry["trace"] = traceArr;
		}
		arr.push_back(entry);
	}

	return {{"imports", arr}, {"total", thunks.size()}, {"resolved", resolved}};
}

json McpServer::ToolTraceCalls(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};

	// Parse addresses
	std::vector<uint64_t> addresses;
	if (args.contains("addresses") && args["addresses"].is_array()) {
		for (auto& a : args["addresses"]) {
			uint64_t addr = 0;
			if (a.is_string()) { std::string s = a.get<std::string>(); ParseAddress(s, addr); }
			else if (a.is_number()) { addr = a.get<uint64_t>(); }
			if (addr) addresses.push_back(addr);
		}
	}
	if (addresses.empty()) return {{"error", "addresses (array of call/jmp site addresses) is required"}};
	if (addresses.size() > 4000) return {{"error", "Too many addresses (max 4000)"}};

	int durationSec = JsonInt(args, "duration_sec", 5);
	if (durationSec < 1) durationSec = 1;
	if (durationSec > 60) durationSec = 60;

	bool resolve = false;
	if (args.contains("resolve") && args["resolve"].is_boolean())
		resolve = args["resolve"].get<bool>();
	bool systemOnly = false;
	if (args.contains("system_only") && args["system_only"].is_boolean())
		systemOnly = args["system_only"].get<bool>();

	auto result = session_.TraceCalls(addresses, static_cast<uint32_t>(durationSec) * 1000,
		resolve, systemOnly);

	json arr = json::array();
	for (auto& e : result.entries) {
		char siteBuf[20]; snprintf(siteBuf, sizeof(siteBuf), "0x%llX", e.callSite);
		char targetBuf[20]; snprintf(targetBuf, sizeof(targetBuf), "0x%llX", e.target);
		std::string api = e.moduleName;
		if (!e.functionName.empty()) api += "!" + e.functionName;
		json entry = {
			{"call_site", siteBuf}, {"target", targetBuf},
			{"hits", e.hitCount}
		};
		if (!api.empty()) entry["api"] = api;
		if (!e.moduleName.empty()) entry["module"] = e.moduleName;
		if (!e.functionName.empty()) entry["function"] = e.functionName;
		arr.push_back(entry);
	}

	return {{"calls", arr}, {"total_sites", addresses.size()},
	        {"resolved", result.entries.size()}, {"total_hits", result.totalHits}};
}

json McpServer::ToolTraceBasicBlocks(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	return ExecuteTraceBasicBlocksTool(session_, args,
		[this](const std::string& text, uint64_t& value) { return ParseAddress(text, value); });
}

json McpServer::ToolTargetedCapture(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	if (!args.contains("inputs") || !args["inputs"].is_array() || args["inputs"].empty() ||
		args["inputs"].size() > 256)
		return {{"error", "inputs must be an array with 1-256 items"}};
	if (!args.contains("trace") || !args["trace"].is_object())
		return {{"error", "trace object is required"}};
	if (!args.contains("trigger") || !args["trigger"].is_object())
		return {{"error", "trigger object is required"}};
	if (!args.contains("window") || !args["window"].is_object())
		return {{"error", "window object is required"}};
	json setupSteps = args.value("steps", json::array());
	if (!setupSteps.is_array() || setupSteps.size() > 500)
		return {{"error", "steps must be an array with at most 500 items"}};
	if (!args.contains("output_directory") || !args["output_directory"].is_string() ||
		args["output_directory"].get<std::string>().empty())
		return {{"error", "output_directory is required"}};
	if (args.contains("stop_on_error") && !args["stop_on_error"].is_boolean())
		return {{"error", "stop_on_error must be a boolean"}};
	if (args.contains("environment") && !args["environment"].is_object())
		return {{"error", "environment must be an object"}};

	auto bounded = [](const json& object, const char* key, uint32_t minimum,
		uint32_t maximum, uint32_t defaultValue, uint32_t& output) {
		if (!object.contains(key)) { output = defaultValue; return true; }
		const auto& value = object[key];
		uint64_t parsed = 0;
		if (value.is_number_unsigned()) parsed = value.get<uint64_t>();
		else if (value.is_number_integer() && value.get<int64_t>() >= 0)
			parsed = static_cast<uint64_t>(value.get<int64_t>());
		else return false;
		if (parsed < minimum || parsed > maximum) return false;
		output = static_cast<uint32_t>(parsed);
		return true;
	};
	uint32_t occurrence = 0, beforeSteps = 0, afterSteps = 0;
	if (!bounded(args["trigger"], "occurrence", 1, UINT32_MAX, 1, occurrence) ||
		!bounded(args["window"], "before_steps", 0, 100000, 0, beforeSteps) ||
		!bounded(args["window"], "after_steps", 1, 100000, 1, afterSteps))
		return {{"error", "trigger.occurrence must be >= 1 and window before/after_steps must be 0-100000/1-100000"}};
	if (!args["trigger"].contains("address"))
		return {{"error", "trigger.address is required"}};

	std::filesystem::path directory(args["output_directory"].get<std::string>());
	std::error_code pathError;
	std::filesystem::create_directories(directory, pathError);
	if (pathError || !std::filesystem::is_directory(directory, pathError))
		return {{"error", "cannot create or access output_directory"}};
	directory = std::filesystem::absolute(directory, pathError);
	if (pathError) return {{"error", "cannot resolve output_directory"}};

	std::string inputVariable = args.value("input_variable", "$input");
	if (inputVariable.empty()) inputVariable = "$input";
	if (inputVariable[0] != '$') inputVariable.insert(inputVariable.begin(), '$');
	const bool stopOnError = args.value("stop_on_error", true);
	const json environmentArgs = args.value("environment", json::object());
	static std::atomic<uint64_t> captureSerial{0};
	const uint64_t runToken = GetTickCount64() ^ (static_cast<uint64_t>(GetCurrentProcessId()) << 32) ^
		captureSerial.fetch_add(1, std::memory_order_relaxed);
	json reports = json::array();
	uint32_t succeeded = 0, failed = 0;
	int64_t firstFailedInput = -1;

	for (size_t index = 0; index < args["inputs"].size(); ++index) {
		const auto& input = args["inputs"][index];
		BatchExecutor executor = NewBatchExecutor();
		executor.SetStopOnError(true);
		executor.SetVariable(inputVariable, input);
		json setup = setupSteps.empty() ? json{{"results", json::array()}, {"failed", 0}, {"succeeded", 0}}
			: executor.Execute(setupSteps);
		json setupSummary = {{"succeeded", setup.value("succeeded", 0)},
			{"failed", setup.value("failed", 0)},
			{"first_failed_step", setup.value("first_failed_step", json(nullptr))}};
		json report = {{"index", index}, {"setup", std::move(setupSummary)}};
		if (input.is_object() && input.contains("name")) report["name"] = input["name"];
		if (setup.value("failed", 0u) != 0) {
			report["status"] = "failed";
			report["error"] = "input setup failed";
			reports.push_back(std::move(report));
			++failed; if (firstFailedInput < 0) firstFailedInput = static_cast<int64_t>(index);
			if (stopOnError) break;
			continue;
		}

		json traceArgs = executor.ResolveArguments(args["trace"]);
		json trigger = executor.ResolveArguments(args["trigger"]);
		traceArgs["target_window"] = {{"address", trigger["address"]}, {"occurrence", occurrence},
			{"before_steps", beforeSteps}, {"after_steps", afterSteps}};
		traceArgs["collect_events"] = true;
		if (!traceArgs.contains("collect_memory_events")) traceArgs["collect_memory_events"] = true;
		if (!traceArgs.contains("collect_register_events")) traceArgs["collect_register_events"] = true;
		if (!traceArgs.contains("collect_code")) traceArgs["collect_code"] = true;
		traceArgs["code_output"] = "inline";
		const uint64_t windowEvents = static_cast<uint64_t>(beforeSteps) + afterSteps + 16;
		if (!traceArgs.contains("max_events")) traceArgs["max_events"] = std::min<uint64_t>(windowEvents, 32768);
		if (!traceArgs.contains("max_register_events")) traceArgs["max_register_events"] = std::min<uint64_t>(windowEvents, 65536);
		if (!traceArgs.contains("max_memory_events")) traceArgs["max_memory_events"] =
			std::min<uint64_t>(windowEvents * 4, 65536);
		if (!traceArgs.contains("max_code_bytes")) traceArgs["max_code_bytes"] = 16 * 1024 * 1024;
		std::filesystem::path artifact = directory /
			("targeted-" + std::to_string(runToken) + "-" + std::to_string(index) + ".json");
		traceArgs["output_file"] = artifact.string();
		traceArgs["output_format"] = "json";

		json checkpointArgs = environmentArgs;
		checkpointArgs["threadId"] = traceArgs.value("threadId", json(0));
		if (!checkpointArgs.contains("capture_teb")) checkpointArgs["capture_teb"] = true;
		json environment = ToolCheckpointCreate(checkpointArgs);
		if (environment.contains("error")) {
			report["status"] = "failed";
			report["error"] = environment["error"];
			reports.push_back(std::move(report));
			++failed; if (firstFailedInput < 0) firstFailedInput = static_cast<int64_t>(index);
			if (stopOnError) break;
			continue;
		}
		const json checkpointId = environment["id"];
		{
			std::lock_guard<std::mutex> lock(checkpointMutex_);
			auto saved = checkpoints_.find(checkpointId.get<uint64_t>());
			if (saved != checkpoints_.end()) {
				for (size_t regionIndex = 0; regionIndex < saved->second.regions.size(); ++regionIndex) {
					const auto& bytes = saved->second.regions[regionIndex].bytes;
					static constexpr char digits[] = "0123456789abcdef";
					std::string encoded(bytes.size() * 2, '0');
					for (size_t byteIndex = 0; byteIndex < bytes.size(); ++byteIndex) {
						encoded[byteIndex * 2] = digits[bytes[byteIndex] >> 4];
						encoded[byteIndex * 2 + 1] = digits[bytes[byteIndex] & 0x0f];
					}
					environment["regions"][regionIndex]["encoding"] = "hex";
					environment["regions"][regionIndex]["data"] = std::move(encoded);
				}
			}
		}
		environment.erase("id");
		environment["scope"] = "immediately_before_targeted_trace";
		json traceResult;
		try {
			traceResult = ExecuteTraceBasicBlocksTool(session_, traceArgs,
				[this](const std::string& text, uint64_t& value) { return ParseAddress(text, value); }, environment);
		} catch (const std::exception& e) {
			traceResult = {{"error", std::string("targeted trace failed: ") + e.what()}};
		}
		ToolCheckpointDelete({{"id", checkpointId}});
		const bool hasTraceError = traceResult.contains("error");
		const bool targetMatched = !hasTraceError &&
			traceResult.value("target_window", json::object()).value("matched", false);
		const uint64_t stepsExecuted = !hasTraceError ?
			traceResult.value("steps_executed", uint64_t{0}) : 0;
		const std::string stopReason = !hasTraceError ?
			traceResult.value("stop_reason", std::string{}) : std::string{};
		// A match at the initial IP has sequence zero.  It is only a trigger
		// observation, not a completed capture: the requested post window must run
		// and terminate through the dedicated target-window stop path.
		const bool captureSucceeded = !hasTraceError && targetMatched &&
			stepsExecuted != 0 && stopReason == "target_window";
		if (traceResult.contains("output_file")) report["artifact"] = traceResult["output_file"];
		if (traceResult.contains("counts")) report["counts"] = traceResult["counts"];
		if (traceResult.contains("truncation")) report["truncation"] = traceResult["truncation"];
		if (traceResult.contains("drop_counts")) report["drop_counts"] = traceResult["drop_counts"];
		if (traceResult.contains("target_window")) report["target_window"] = traceResult["target_window"];
		if (traceResult.contains("steps_executed")) report["steps_executed"] = traceResult["steps_executed"];
		if (traceResult.contains("stop_reason")) report["stop_reason"] = traceResult["stop_reason"];
		if (report.contains("artifact") && report["artifact"].is_object())
			report["artifact"]["complete"] = captureSucceeded;
		report["capture_complete"] = captureSucceeded;
		if (!captureSucceeded) {
			report["status"] = "failed";
			if (hasTraceError) report["error"] = traceResult["error"];
			else if (!targetMatched) report["error"] = "target occurrence was not reached";
			else if (stepsExecuted == 0) report["error"] = "trace executed zero instructions";
			else if (stopReason == "exception")
				report["error"] = "trace stopped by exception before target window completed";
			else report["error"] = "target window did not complete (stop_reason: " + stopReason + ")";
			++failed; if (firstFailedInput < 0) firstFailedInput = static_cast<int64_t>(index);
		} else {
			report["status"] = "ok";
			++succeeded;
		}
		reports.push_back(std::move(report));
		if (stopOnError && failed != 0) break;
	}
	return {{"mode", "targeted_inputs"}, {"input_variable", inputVariable},
		{"inputs", std::move(reports)}, {"succeeded", succeeded}, {"failed", failed},
		{"first_failed_input", firstFailedInput < 0 ? json(nullptr) : json(firstFailedInput)},
		{"stopped_on_error", stopOnError && failed != 0},
		{"artifact_directory", directory.string()}};
}

} // namespace veh
