#include "batch_executor.h"
#include <cstdio>

namespace veh {

// --- Helpers ---

static uint64_t ParseHexOrDec(const std::string& s) {
	if (s.empty()) return 0;
	if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		return std::stoull(s, nullptr, 16);
	return std::stoull(s, nullptr, 0);
}

static std::string ToHex(uint64_t v) {
	char buf[20];
	snprintf(buf, sizeof(buf), "0x%llX", v);
	return buf;
}

// --- BatchExecutor ---

BatchExecutor::BatchExecutor(ToolRunner runTool) : runTool_(std::move(runTool)) {}

BatchExecutor BatchExecutor::Nested() const {
	BatchExecutor sub(runTool_);
	sub.depth_ = depth_ + 1;
	sub.stopOnError_ = stopOnError_;
	sub.results_ = results_;
	sub.namedVars_ = namedVars_;
	return sub;
}

static bool BatchResultFailed(const json& value) {
	if (value.is_object()) {
		if (value.contains("error")) return true;
		if (value.contains("success") && value["success"].is_boolean() && !value["success"].get<bool>())
			return true;
		for (const char* child : {"result", "results"})
			if (value.contains(child) && BatchResultFailed(value[child])) return true;
	} else if (value.is_array()) {
		for (const auto& item : value) if (BatchResultFailed(item)) return true;
	}
	return false;
}

static void CollectBatchTraceMetadata(const json& value, json& summaries, json& artifacts) {
	if (value.is_object()) {
		if (value.contains("stop_reason") && value.contains("steps_executed")) {
			json summary = {{"stop_reason", value["stop_reason"]}, {"steps_executed", value["steps_executed"]}};
			for (const char* key : {"thread_id", "counts", "occurrence_window", "truncation"})
				if (value.contains(key)) summary[key] = value[key];
			summaries.push_back(std::move(summary));
		}
		if (value.contains("output_file") && value["output_file"].is_object() &&
			value["output_file"].contains("path")) artifacts.push_back(value["output_file"]);
		if (value.contains("code_artifact") && value["code_artifact"].is_object() &&
			value["code_artifact"].contains("path")) artifacts.push_back(value["code_artifact"]);
		if (value.contains("event_file") && value["event_file"].is_object() &&
			value["event_file"].contains("path")) artifacts.push_back(value["event_file"]);
		for (const auto& [key, child] : value.items())
			if (key != "output_file" && key != "code_artifact" && key != "event_file")
				CollectBatchTraceMetadata(child, summaries, artifacts);
	} else if (value.is_array()) {
		for (const auto& child : value) CollectBatchTraceMetadata(child, summaries, artifacts);
	}
}

void BatchExecutor::SetVariable(const std::string& name, const json& value) {
	namedVars_[name.empty() || name[0] == '$' ? name : "$" + name] = value;
}

json BatchExecutor::Execute(const json& steps) {
	if (!steps.is_array()) {
		return {{"error", "steps must be an array"}};
	}
	if (steps.size() > 500) {
		return {{"error", "Too many steps (max 500)"}};
	}

	// Don't clear results_/namedVars_ -- sub-executors inherit parent context
	json allResults = json::array();
	uint32_t succeeded = 0, failed = 0;
	int64_t firstFailedStep = -1;

	for (size_t i = 0; i < steps.size(); i++) {
		try {
			json result = ExecuteStep(steps[i]);
			results_.push_back(result);
			bool stepFailed = BatchResultFailed(result);
			allResults.push_back({{"step", i}, {"status", stepFailed ? "failed" : "ok"}, {"result", result}});
			if (stepFailed) { ++failed; if (firstFailedStep < 0) firstFailedStep = static_cast<int64_t>(i); }
			else ++succeeded;

			// Check for fatal error
			if (result.contains("error") && result.contains("fatal") && result["fatal"].get<bool>()) {
				allResults.push_back({{"step", i}, {"aborted", true}, {"reason", result["error"]}});
				break;
			}
			if (stepFailed && stopOnError_) break;
		} catch (const std::exception& e) {
			json err = {{"error", std::string("Step ") + std::to_string(i) + ": " + e.what()}};
			results_.push_back(err);
			allResults.push_back({{"step", i}, {"status", "failed"}, {"result", err}});
			++failed; if (firstFailedStep < 0) firstFailedStep = static_cast<int64_t>(i);
			if (stopOnError_) break;
		}
	}

	json traceSummaries = json::array(), artifacts = json::array();
	CollectBatchTraceMetadata(allResults, traceSummaries, artifacts);
	json report = {{"results", allResults}, {"totalSteps", results_.size()},
		{"succeeded", succeeded}, {"failed", failed},
		{"first_failed_step", firstFailedStep < 0 ? json(nullptr) : json(firstFailedStep)},
		{"stopped_on_error", stopOnError_ && failed != 0},
		{"trace_summary", std::move(traceSummaries)}, {"artifacts", std::move(artifacts)}};
	return report;
}

json BatchExecutor::ExecuteStep(const json& step) {
	if (depth_ > 20) {
		return {{"error", "Maximum nesting depth (20) exceeded"}};
	}

	// Some MCP schema consumers expose an unconstrained array as string[]. Accept a
	// JSON-encoded object for backward compatibility, while keeping object-form as
	// the canonical representation.
	if (step.is_string()) {
		try {
			json decoded = json::parse(step.get<std::string>());
			if (!decoded.is_object()) {
				return {{"error", "String step must decode to a JSON object"}};
			}
			return ExecuteStep(decoded);
		} catch (const std::exception& e) {
			return {{"error", std::string("Invalid JSON string step: ") + e.what()}};
		}
	}
	if (!step.is_object()) {
		return {{"error", "Step must be an object or a JSON-encoded object string"}};
	}

	// Control flow: if
	if (step.contains("if")) {
		std::string condition = ResolveString(step["if"].get<std::string>());
		bool result = EvaluateCondition(condition);
		if (result && step.contains("then") && step["then"].is_array()) {
			BatchExecutor sub = Nested();
			size_t parentSize = results_.size();
			json r = sub.Execute(step["then"]);
			// Merge only new results (avoid duplicating inherited parent results)
			for (size_t j = parentSize; j < sub.results_.size(); j++)
				results_.push_back(sub.results_[j]);
			return {{"type", "if"}, {"condition", condition}, {"branch", "then"}, {"result", r}};
		} else if (!result && step.contains("else") && step["else"].is_array()) {
			BatchExecutor sub = Nested();
			size_t parentSize = results_.size();
			json r = sub.Execute(step["else"]);
			for (size_t j = parentSize; j < sub.results_.size(); j++)
				results_.push_back(sub.results_[j]);
			return {{"type", "if"}, {"condition", condition}, {"branch", "else"}, {"result", r}};
		}
		return {{"type", "if"}, {"condition", condition}, {"branch", result ? "then" : "else"}, {"skipped", true}};
	}

	// Control flow: loop
	if (step.contains("loop") && step["loop"].is_array()) {
		std::string untilCond = step.value("until", "");
		int maxIter = step.value("max", 100);
		if (maxIter > 10000) maxIter = 10000;

		json loopResults = json::array();
		int iterations = 0;
		for (int i = 0; i < maxIter; i++) {
			BatchExecutor sub = Nested();
			json r = sub.Execute(step["loop"]);
			// Update our results with sub-results
			results_ = sub.results_;
			namedVars_ = sub.namedVars_;
			loopResults.push_back(r);
			iterations++;
			if (stopOnError_ && BatchResultFailed(r)) break;

			if (!untilCond.empty()) {
				std::string resolved = ResolveString(untilCond);
				if (EvaluateCondition(resolved)) break;
			}
		}
		return {{"type", "loop"}, {"iterations", iterations}, {"results", loopResults}};
	}

	// Control flow: for_each
	if (step.contains("for_each") && step.contains("do") && step["do"].is_array()) {
		std::string varName = step.value("as", "$item");
		json items = step["for_each"];
		// If items is a string starting with $, resolve it
		if (items.is_string()) {
			items = ResolveValue(items.get<std::string>());
		}
		if (!items.is_array()) {
			return {{"error", "for_each value must be an array"}};
		}
		if (items.size() > 1000) {
			return {{"error", "for_each array too large (max 1000)"}};
		}

		// Resolve $refs in array elements
		for (size_t i = 0; i < items.size(); i++) {
			if (items[i].is_string()) {
				std::string s = items[i].get<std::string>();
				if (!s.empty() && s[0] == '$') {
					json resolved = ResolveValue(s);
					if (resolved != json(s)) items[i] = resolved;
				}
			}
		}

		json foreachResults = json::array();
		for (size_t i = 0; i < items.size(); i++) {
			namedVars_[varName] = items[i];
			BatchExecutor sub = Nested();
			json r = sub.Execute(step["do"]);
			results_ = sub.results_;
			namedVars_ = sub.namedVars_;
			foreachResults.push_back(r);
			if (stopOnError_ && BatchResultFailed(r)) break;
		}
		return {{"type", "for_each"}, {"count", foreachResults.size()}, {"results", foreachResults}};
	}

	// Tool call
	if (step.contains("tool")) {
		std::string toolName = step["tool"].get<std::string>();
		json args = step.value("args", json::object());
		json resolvedArgs = ResolveArgs(args);

		// Store result with optional name
		json result = runTool_(toolName, resolvedArgs);
		if (step.contains("as")) {
			namedVars_[step["as"].get<std::string>()] = result;
		}
		return result;
	}

	return {{"error", "Unknown step format. Expected: {tool, args} or {if} or {loop} or {for_each}"}};
}

// --- Variable Resolution ---

json BatchExecutor::ResolveValue(const std::string& ref) {
	if (ref.empty() || ref[0] != '$') return json(ref);

	// Parse $N or $name, then optional .key.subkey chain
	std::string path = ref.substr(1);  // remove $
	std::vector<std::string> parts;
	std::string current;
	for (char c : path) {
		if (c == '.') {
			if (!current.empty()) { parts.push_back(current); current.clear(); }
		} else {
			current += c;
		}
	}
	if (!current.empty()) parts.push_back(current);

	if (parts.empty()) return json(ref);

	// Root: $last/$prev sentinels -> most recent result(s), then named vars, then numeric index.
	// These make loop `until` conditions writable (the latest step index is not known statically).
	json root;
	if (parts[0] == "last" || parts[0] == "prev") {
		if (results_.empty()) return json(ref);
		size_t n = results_.size();
		size_t idx = (parts[0] == "last") ? n - 1 : (n >= 2 ? n - 2 : 0);
		root = results_[idx];
	} else if (auto it = namedVars_.find("$" + parts[0]); it != namedVars_.end()) {
		root = it->second;
	} else {
		try {
			size_t idx = std::stoull(parts[0]);
			if (idx < results_.size()) {
				root = results_[idx];
			} else {
				return json(ref);  // unresolved
			}
		} catch (...) {
			// Try full name ($varname)
			auto it2 = namedVars_.find(ref);
			if (it2 != namedVars_.end()) return it2->second;
			return json(ref);  // unresolved
		}
	}

	// Walk the path
	for (size_t i = 1; i < parts.size(); i++) {
		if (root.is_object() && root.contains(parts[i])) {
			root = root[parts[i]];
		} else if (root.is_array()) {
			try {
				size_t idx = std::stoull(parts[i]);
				if (idx < root.size()) root = root[idx];
				else return json(ref);
			} catch (...) { return json(ref); }
		} else {
			return json(ref);  // can't traverse further
		}
	}

	return root;
}

std::string BatchExecutor::ResolveString(const std::string& str) {
	// Find all $N.key.subkey references and replace with resolved values
	std::string result;
	size_t i = 0;
	while (i < str.size()) {
		if (str[i] == '$') {
			// Extract the reference (until space, comma, or comparison operator)
			size_t start = i;
			i++;
			while (i < str.size() && str[i] != ' ' && str[i] != ',' &&
			       str[i] != '=' && str[i] != '!' && str[i] != '<' && str[i] != '>') {
				i++;
			}
			std::string ref = str.substr(start, i - start);
			json val = ResolveValue(ref);
			if (val.is_string()) {
				result += val.get<std::string>();
			} else if (val.is_number()) {
				// Format numbers as hex for addresses
				if (val.is_number_unsigned()) {
					result += ToHex(val.get<uint64_t>());
				} else {
					result += std::to_string(val.get<int64_t>());
				}
			} else {
				result += val.dump();
			}
		} else {
			result += str[i];
			i++;
		}
	}
	return result;
}

json BatchExecutor::ResolveArgs(const json& args) {
	if (args.is_string()) {
		std::string s = args.get<std::string>();
		if (!s.empty() && s[0] == '$') {
			json resolved = ResolveValue(s);
			if (resolved != json(s)) return resolved;  // successfully resolved
		}
		return json(ResolveString(s));
	}
	if (args.is_object()) {
		json resolved = json::object();
		for (auto& [key, val] : args.items()) {
			resolved[key] = ResolveArgs(val);
		}
		return resolved;
	}
	if (args.is_array()) {
		json resolved = json::array();
		for (auto& val : args) {
			resolved.push_back(ResolveArgs(val));
		}
		return resolved;
	}
	return args;  // number, bool, null - return as-is
}

// --- Condition Evaluation ---

bool BatchExecutor::EvaluateCondition(const std::string& condition) {
	// Parse: LHS op RHS (==, !=, >=, <=, >, <)
	struct { const char* op; size_t len; } ops[] = {
		{"==", 2}, {"!=", 2}, {">=", 2}, {"<=", 2}, {">", 1}, {"<", 1},
	};

	for (auto& [op, len] : ops) {
		auto pos = condition.find(op);
		if (pos != std::string::npos) {
			std::string lhs = condition.substr(0, pos);
			std::string rhs = condition.substr(pos + len);
			// Trim
			while (!lhs.empty() && lhs.back() == ' ') lhs.pop_back();
			while (!rhs.empty() && rhs.front() == ' ') rhs.erase(rhs.begin());

			// Resolve variables
			lhs = ResolveString(lhs);
			rhs = ResolveString(rhs);

			// Try numeric comparison
			try {
				uint64_t lv = ParseHexOrDec(lhs);
				uint64_t rv = ParseHexOrDec(rhs);
				if (std::string(op) == "==") return lv == rv;
				if (std::string(op) == "!=") return lv != rv;
				if (std::string(op) == ">=") return lv >= rv;
				if (std::string(op) == "<=") return lv <= rv;
				if (std::string(op) == ">")  return lv > rv;
				if (std::string(op) == "<")  return lv < rv;
			} catch (...) {
				// String comparison fallback
				if (std::string(op) == "==") return lhs == rhs;
				if (std::string(op) == "!=") return lhs != rhs;
			}
		}
	}

	// No operator found - treat as truthy check
	if (condition == "true" || condition == "1") return true;
	if (condition == "false" || condition == "0" || condition.empty()) return false;
	return !condition.empty();
}


} // namespace veh
