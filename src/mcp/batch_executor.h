#pragma once
#include "debug_session.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>

namespace veh {

using json = nlohmann::json;

// BatchExecutor: executes a sequence of debugger commands with variable references.
//
// Step format:
//   {tool: "veh_registers", args: {threadId: 1234}}
//   {tool: "veh_read_memory", args: {address: "$0.registers.rsp", size: 8}}
//
// Control flow:
//   {if: "RAX==0", then: [...steps...], else: [...steps...]}
//   {loop: [...steps...], until: "RAX!=0", max: 100}
//   {for_each: ["0x1000","0x2000"], as: "$addr", do: [...steps...]}
//
// Variable references:
//   $N        -> result of step N (0-based, absolute index across the whole batch)
//   $N.key    -> result["key"]
//   $last     -> most recent step result; $prev -> the one before it.
//               Use these in loop `until` conditions -- the latest step's absolute
//               index changes each iteration and cannot be written statically.
//   $var      -> named variable (from a step's "as", for_each "as", or user-defined)
//
// Notes:
//   veh_registers returns 32-bit names (eax/esp/eip) for 32-bit targets, 64-bit
//   otherwise, plus is32bit. Pass args.fields (e.g. ["esp","eip"]) to trim output.

class BatchExecutor {
public:
	explicit BatchExecutor(DebugSession& session);

	// Execute a batch of steps. Returns array of step results.
	json Execute(const json& steps);

private:
	// Execute a single step (tool call or control flow)
	json ExecuteStep(const json& step);

	// Execute a tool call via DebugSession
	json CallTool(const std::string& toolName, const json& args);

	// Variable resolution
	std::string ResolveString(const std::string& str);
	json ResolveArgs(const json& args);
	json ResolveValue(const std::string& ref);

	// Condition evaluation (delegates to DebugSession or simple comparison)
	bool EvaluateCondition(const std::string& condition);

	// Map tool name -> DebugSession method call -> json result
	json DispatchTool(const std::string& name, const json& args);

	// Resolve address string with module+RVA support
	uint64_t ResolveAddress(const std::string& addrStr);

	DebugSession& session_;
	std::vector<json> results_;  // step results indexed by step number
	std::unordered_map<std::string, json> namedVars_;  // named variables ($addr, etc.)
	int depth_ = 0;  // nesting depth (max 20)
};

} // namespace veh
