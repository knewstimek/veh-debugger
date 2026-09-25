#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace veh {

using json = nlohmann::json;

// BatchExecutor: executes a sequence of debugger commands with variable references.
// It owns only $ref resolution and flow control; every tool call goes through the
// ToolRunner, so batch steps share the direct MCP tool implementations.
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
	using ToolRunner = std::function<json(const std::string&, const json&)>;
	explicit BatchExecutor(ToolRunner runTool);

	// Execute a batch of steps. Returns array of step results.
	json Execute(const json& steps);
	void SetVariable(const std::string& name, const json& value);
	void SetStopOnError(bool value) { stopOnError_ = value; }
	json ResolveArguments(const json& args) { return ResolveArgs(args); }

private:
	// Execute a single step (tool call or control flow)
	json ExecuteStep(const json& step);

	// Variable resolution
	std::string ResolveString(const std::string& str);
	json ResolveArgs(const json& args);
	json ResolveValue(const std::string& ref);

	// Condition evaluation (simple comparison)
	bool EvaluateCondition(const std::string& condition);

	// Sub-executor for a nested block, inheriting results and variables
	BatchExecutor Nested() const;

	ToolRunner runTool_;
	std::vector<json> results_;  // step results indexed by step number
	std::unordered_map<std::string, json> namedVars_;  // named variables ($addr, etc.)
	int depth_ = 0;  // nesting depth (max 20)
	bool stopOnError_ = false;
};

} // namespace veh
