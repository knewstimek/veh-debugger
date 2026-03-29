#include "batch_executor.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>

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

static std::vector<uint8_t> ParseHexBytes(const std::string& hexStr) {
	std::string clean;
	for (char c : hexStr) {
		if (std::isxdigit(static_cast<unsigned char>(c))) clean += c;
	}
	std::vector<uint8_t> out;
	if (clean.size() % 2 != 0) return out;
	for (size_t i = 0; i < clean.size(); i += 2) {
		out.push_back(static_cast<uint8_t>(std::stoi(clean.substr(i, 2), nullptr, 16)));
	}
	return out;
}

// --- BatchExecutor ---

BatchExecutor::BatchExecutor(DebugSession& session) : session_(session) {}

json BatchExecutor::Execute(const json& steps) {
	if (!steps.is_array()) {
		return {{"error", "steps must be an array"}};
	}
	if (steps.size() > 500) {
		return {{"error", "Too many steps (max 500)"}};
	}

	// Don't clear results_/namedVars_ -- sub-executors inherit parent context
	json allResults = json::array();

	for (size_t i = 0; i < steps.size(); i++) {
		try {
			json result = ExecuteStep(steps[i]);
			results_.push_back(result);
			allResults.push_back({{"step", i}, {"result", result}});

			// Check for fatal error
			if (result.contains("error") && result.contains("fatal") && result["fatal"].get<bool>()) {
				allResults.push_back({{"step", i}, {"aborted", true}, {"reason", result["error"]}});
				break;
			}
		} catch (const std::exception& e) {
			json err = {{"error", std::string("Step ") + std::to_string(i) + ": " + e.what()}};
			results_.push_back(err);
			allResults.push_back({{"step", i}, {"result", err}});
		}
	}

	return {{"results", allResults}, {"totalSteps", results_.size()}};
}

json BatchExecutor::ExecuteStep(const json& step) {
	if (depth_ > 20) {
		return {{"error", "Maximum nesting depth (20) exceeded"}};
	}

	// Control flow: if
	if (step.contains("if")) {
		std::string condition = ResolveString(step["if"].get<std::string>());
		bool result = EvaluateCondition(condition);
		if (result && step.contains("then") && step["then"].is_array()) {
			BatchExecutor sub(session_);
			sub.depth_ = depth_ + 1;
			sub.results_ = results_;
			sub.namedVars_ = namedVars_;
			size_t parentSize = results_.size();
			json r = sub.Execute(step["then"]);
			// Merge only new results (avoid duplicating inherited parent results)
			for (size_t j = parentSize; j < sub.results_.size(); j++)
				results_.push_back(sub.results_[j]);
			return {{"type", "if"}, {"condition", condition}, {"branch", "then"}, {"result", r}};
		} else if (!result && step.contains("else") && step["else"].is_array()) {
			BatchExecutor sub(session_);
			sub.depth_ = depth_ + 1;
			sub.results_ = results_;
			sub.namedVars_ = namedVars_;
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
			BatchExecutor sub(session_);
			sub.depth_ = depth_ + 1;
			sub.results_ = results_;
			sub.namedVars_ = namedVars_;
			json r = sub.Execute(step["loop"]);
			// Update our results with sub-results
			results_ = sub.results_;
			namedVars_ = sub.namedVars_;
			loopResults.push_back(r);
			iterations++;

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
			BatchExecutor sub(session_);
			sub.depth_ = depth_ + 1;
			sub.results_ = results_;
			sub.namedVars_ = namedVars_;
			json r = sub.Execute(step["do"]);
			results_ = sub.results_;
			namedVars_ = sub.namedVars_;
			foreachResults.push_back(r);
		}
		return {{"type", "for_each"}, {"count", items.size()}, {"results", foreachResults}};
	}

	// Tool call
	if (step.contains("tool")) {
		std::string toolName = step["tool"].get<std::string>();
		json args = step.value("args", json::object());
		json resolvedArgs = ResolveArgs(args);

		// Store result with optional name
		json result = DispatchTool(toolName, resolvedArgs);
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

	// Root: check named vars first, then numeric index
	json root;
	auto it = namedVars_.find("$" + parts[0]);
	if (it != namedVars_.end()) {
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

// --- Tool Dispatch ---

json BatchExecutor::DispatchTool(const std::string& name, const json& args) {
	if (!session_.IsAttached()) {
		return {{"error", "Not attached to any process"}};
	}

	auto hexArg = [&](const std::string& key) -> uint64_t {
		std::string s = args.value(key, "");
		if (s.empty()) return 0;
		// Module+RVA: "crackme.exe+0x1000"
		auto plusPos = s.find('+');
		if (plusPos != std::string::npos && plusPos > 0) {
			std::string mod = s.substr(0, plusPos);
			bool isModule = false;
			for (char c : mod) {
				if (c == '.' || c == '_' || c == '-') { isModule = true; break; }
				if (std::isalpha(c) && !std::isxdigit(c)) { isModule = true; break; }
			}
			if (isModule) {
				auto modules = session_.GetModules();
				std::string modLower = mod;
				std::transform(modLower.begin(), modLower.end(), modLower.begin(), ::tolower);
				for (auto& m : modules) {
					std::string nl = m.name;
					std::transform(nl.begin(), nl.end(), nl.begin(), ::tolower);
					if (nl == modLower) {
						return m.baseAddress + ParseHexOrDec(s.substr(plusPos + 1));
					}
				}
				return 0;
			}
		}
		return ParseHexOrDec(s);
	};
	auto intArg = [&](const std::string& key, int def) -> int {
		if (!args.contains(key)) return def;
		auto& v = args[key];
		if (v.is_number()) return v.get<int>();
		if (v.is_string()) { try { return std::stoi(v.get<std::string>()); } catch (...) {} }
		return def;
	};
	auto uint32Arg = [&](const std::string& key) -> uint32_t {
		if (!args.contains(key)) return 0;
		auto& v = args[key];
		if (v.is_number()) return v.get<uint32_t>();
		if (v.is_string()) { try { return static_cast<uint32_t>(ParseHexOrDec(v.get<std::string>())); } catch (...) {} }
		return 0;
	};
	auto boolArg = [&](const std::string& key) -> bool {
		if (!args.contains(key)) return false;
		auto& v = args[key];
		if (v.is_boolean()) return v.get<bool>();
		if (v.is_string()) return v.get<std::string>() == "true";
		return false;
	};

	// --- Execution control ---
	if (name == "veh_continue") {
		bool passEx = boolArg("pass_exception");
		uint32_t tid = uint32Arg("threadId");
		bool wait = boolArg("wait");
		int timeout = intArg("timeout", 10);

		if (wait) {
			auto cached = session_.ConsumeCachedStop();
			if (cached && !passEx) {
				return {{"stopped", true}, {"reason", cached->reason},
				        {"address", ToHex(cached->address)}, {"threadId", cached->threadId},
				        {"breakpointId", cached->breakpointId}};
			}
		}

		if (!session_.Continue(tid, passEx)) {
			return {{"error", "Continue failed"}};
		}
		if (!wait) return {{"success", true}};

		auto stop = session_.WaitForStop(timeout);
		if (stop.timeout) return {{"timeout", true}};
		return {{"stopped", true}, {"reason", stop.reason},
		        {"address", ToHex(stop.address)}, {"threadId", stop.threadId},
		        {"breakpointId", stop.breakpointId}};
	}

	if (name == "veh_step_in") {
		uint32_t tid = uint32Arg("threadId");
		if (!session_.StepIn(tid)) return {{"error", "StepIn failed"}};
		return {{"success", true}, {"threadId", tid}};
	}
	if (name == "veh_step_over") {
		uint32_t tid = uint32Arg("threadId");
		if (!session_.StepOver(tid)) return {{"error", "StepOver failed"}};
		return {{"success", true}, {"threadId", tid}};
	}
	if (name == "veh_step_out") {
		uint32_t tid = uint32Arg("threadId");
		if (!session_.StepOut(tid)) return {{"error", "StepOut failed"}};
		return {{"success", true}, {"threadId", tid}};
	}
	if (name == "veh_pause") {
		uint32_t tid = uint32Arg("threadId");
		if (!session_.Pause(tid)) return {{"error", "Pause failed"}};
		return {{"success", true}};
	}

	// --- Breakpoints ---
	if (name == "veh_set_breakpoint") {
		uint64_t addr = hexArg("address");
		auto r = session_.SetBreakpoint(addr);
		if (!r.ok) return {{"error", "SetBreakpoint failed"}};
		return {{"success", true}, {"id", r.id}, {"address", ToHex(addr)}};
	}
	if (name == "veh_remove_breakpoint") {
		uint32_t id = uint32Arg("id");
		if (!session_.RemoveBreakpoint(id)) return {{"error", "RemoveBreakpoint failed"}};
		return {{"success", true}, {"id", id}};
	}
	if (name == "veh_set_data_breakpoint") {
		uint64_t addr = hexArg("address");
		std::string typeStr = args.value("type", "write");
		uint8_t type = 1; // write
		if (typeStr == "execute") type = 0;
		else if (typeStr == "readwrite") type = 3;
		uint8_t sz = static_cast<uint8_t>(intArg("size", 4));
		auto r = session_.SetHwBreakpoint(addr, type, sz);
		if (!r.ok) return {{"error", "SetHwBreakpoint failed"}};
		return {{"success", true}, {"id", r.id}, {"slot", r.slot}};
	}
	if (name == "veh_remove_data_breakpoint") {
		uint32_t id = uint32Arg("id");
		if (!session_.RemoveHwBreakpoint(id)) return {{"error", "RemoveHwBreakpoint failed"}};
		return {{"success", true}, {"id", id}};
	}

	// --- State queries ---
	if (name == "veh_threads") {
		auto threads = session_.GetThreads();
		json arr = json::array();
		for (auto& t : threads) arr.push_back({{"id", t.id}, {"name", t.name}});
		return {{"threads", arr}, {"count", threads.size()}};
	}
	if (name == "veh_registers") {
		uint32_t tid = uint32Arg("threadId");
		auto regs = session_.GetRegisters(tid);
		if (!regs) return {{"error", "GetRegisters failed"}};
		auto hex = [](uint64_t v) { char b[20]; snprintf(b, sizeof(b), "0x%llX", v); return std::string(b); };
		json r;
		r["rax"] = hex(regs->rax); r["rbx"] = hex(regs->rbx);
		r["rcx"] = hex(regs->rcx); r["rdx"] = hex(regs->rdx);
		r["rsi"] = hex(regs->rsi); r["rdi"] = hex(regs->rdi);
		r["rbp"] = hex(regs->rbp); r["rsp"] = hex(regs->rsp);
		r["r8"] = hex(regs->r8); r["r9"] = hex(regs->r9);
		r["r10"] = hex(regs->r10); r["r11"] = hex(regs->r11);
		r["r12"] = hex(regs->r12); r["r13"] = hex(regs->r13);
		r["r14"] = hex(regs->r14); r["r15"] = hex(regs->r15);
		r["rip"] = hex(regs->rip); r["rflags"] = hex(regs->rflags);
		r["is32bit"] = (bool)regs->is32bit;
		return {{"registers", r}};
	}
	if (name == "veh_stack_trace") {
		uint32_t tid = uint32Arg("threadId");
		int maxFrames = intArg("maxFrames", 20);
		auto frames = session_.GetStackTrace(tid, maxFrames);
		json arr = json::array();
		for (auto& f : frames) {
			arr.push_back({{"address", ToHex(f.address)}, {"module", f.moduleName},
			               {"function", f.functionName}, {"source", f.sourceFile}, {"line", f.line}});
		}
		return {{"frames", arr}, {"count", frames.size()}};
	}
	if (name == "veh_modules") {
		auto mods = session_.GetModules();
		json arr = json::array();
		for (auto& m : mods) {
			arr.push_back({{"name", m.name}, {"path", m.path},
			               {"baseAddress", ToHex(m.baseAddress)}, {"size", m.size}});
		}
		return {{"modules", arr}, {"count", mods.size()}};
	}

	// --- Memory ---
	if (name == "veh_read_memory") {
		uint64_t addr = hexArg("address");
		int size = intArg("size", 64);
		auto data = session_.ReadMemory(addr, size);
		if (data.empty()) return {{"error", "ReadMemory failed"}};
		std::ostringstream oss;
		for (size_t i = 0; i < data.size(); i++) {
			if (i > 0 && i % 16 == 0) oss << "\n";
			else if (i > 0) oss << " ";
			oss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
		}
		return {{"address", ToHex(addr)}, {"size", data.size()}, {"hex", oss.str()}};
	}
	if (name == "veh_write_memory") {
		// Batch patches mode
		if (args.contains("patches") && args["patches"].is_array()) {
			int ok = 0, fail = 0;
			for (auto& p : args["patches"]) {
				uint64_t a = ParseHexOrDec(p.value("address", "0"));
				auto bytes = ParseHexBytes(p.value("data", ""));
				if (!bytes.empty() && session_.WriteMemory(a, bytes.data(), static_cast<uint32_t>(bytes.size()))) ok++;
				else fail++;
			}
			return {{"success", fail == 0}, {"succeeded", ok}, {"failed", fail}};
		}
		// Single mode
		uint64_t addr = hexArg("address");
		auto bytes = ParseHexBytes(args.value("data", ""));
		if (bytes.empty()) return {{"error", "No data"}};
		if (!session_.WriteMemory(addr, bytes.data(), static_cast<uint32_t>(bytes.size())))
			return {{"error", "WriteMemory failed"}};
		return {{"success", true}, {"bytesWritten", bytes.size()}};
	}
	if (name == "veh_allocate_memory") {
		int size = intArg("size", 4096);
		std::string prot = args.value("protection", "rwx");
		uint32_t p = 0x40; // PAGE_EXECUTE_READWRITE
		if (prot == "rw") p = 0x04;
		else if (prot == "rx") p = 0x20;
		else if (prot == "r") p = 0x02;
		uint64_t addr = session_.AllocateMemory(size, p);
		if (!addr) return {{"error", "AllocateMemory failed"}};
		return {{"success", true}, {"address", ToHex(addr)}, {"size", size}};
	}
	if (name == "veh_free_memory") {
		uint64_t addr = hexArg("address");
		if (!session_.FreeMemory(addr)) return {{"error", "FreeMemory failed"}};
		return {{"success", true}};
	}
	if (name == "veh_execute_shellcode") {
		auto bytes = ParseHexBytes(args.value("shellcode", ""));
		if (bytes.empty()) return {{"error", "No shellcode"}};
		int timeout = intArg("timeout_ms", 5000);
		auto r = session_.ExecuteShellcode(bytes.data(), static_cast<uint32_t>(bytes.size()), timeout);
		json ret = {{"success", r.ok}, {"exitCode", r.exitCode}};
		if (r.crashed) {
			char codeBuf[12]; snprintf(codeBuf, sizeof(codeBuf), "0x%08X", r.exceptionCode);
			ret["crashed"] = true;
			ret["exceptionCode"] = codeBuf;
			ret["exceptionAddress"] = ToHex(r.exceptionAddress);
		}
		return ret;
	}

	// --- Analysis ---
	if (name == "veh_evaluate") {
		std::string expr = args.value("expression", "");
		uint32_t tid = uint32Arg("threadId");
		auto r = session_.Evaluate(expr, tid);
		if (!r.ok) return {{"error", r.error}};
		json ret = {{"value", r.value}, {"type", r.type}};
		if (r.address) ret["address"] = ToHex(r.address);
		if (!r.tebAddress.empty()) ret["tebAddress"] = r.tebAddress;
		return ret;
	}
	if (name == "veh_disassemble") {
		uint64_t addr = hexArg("address");
		int count = intArg("count", 20);
		auto insns = session_.Disassemble(addr, count);
		json arr = json::array();
		for (auto& i : insns) arr.push_back({{"address", i.address}, {"bytes", i.bytes}, {"mnemonic", i.mnemonic}});
		return {{"instructions", arr}, {"count", insns.size()}};
	}
	if (name == "veh_set_register") {
		uint32_t tid = uint32Arg("threadId");
		std::string regName = args.value("name", "");
		uint32_t idx = DebugSession::GetRegisterIndex(regName);
		if (idx == UINT32_MAX) return {{"error", "Unknown register: " + regName}};
		uint64_t val = ParseHexOrDec(args.value("value", "0"));
		if (!session_.SetRegister(tid, idx, val)) return {{"error", "SetRegister failed"}};
		return {{"success", true}, {"name", regName}, {"value", ToHex(val)}};
	}

	if (name == "veh_list_breakpoints") {
		json sw = json::array(), hw = json::array();
		{
			std::lock_guard<std::mutex> lock(session_.GetBpMutex());
			for (auto& bp : session_.GetSwBreakpoints())
				sw.push_back({{"id", bp.id}, {"address", ToHex(bp.address)}});
			for (auto& bp : session_.GetHwBreakpoints())
				hw.push_back({{"id", bp.id}, {"address", ToHex(bp.address)}});
		}
		return {{"software", sw}, {"hardware", hw}};
	}

	if (name == "veh_enum_locals") {
		uint32_t tid = uint32Arg("threadId");
		uint64_t ip = hexArg("instructionAddress");
		uint64_t fb = hexArg("frameBase");
		auto locals = session_.EnumLocals(tid, ip, fb);
		json arr = json::array();
		for (auto& l : locals) {
			std::ostringstream oss;
			for (size_t i = 0; i < l.value.size(); i++) {
				if (i > 0) oss << " ";
				oss << std::hex << std::setfill('0') << std::setw(2) << (int)l.value[i];
			}
			arr.push_back({{"name", l.name}, {"type", l.typeName}, {"address", ToHex(l.address)},
			               {"size", l.size}, {"value", oss.str()}});
		}
		return {{"locals", arr}, {"count", locals.size()}};
	}
	if (name == "veh_exception_info") {
		// Exception info is MCP-level cached state, not available in batch directly
		return {{"error", "veh_exception_info not available in batch mode (use directly)"}};
	}
	if (name == "veh_trace_callers") {
		uint64_t addr = hexArg("address");
		int dur = intArg("duration_sec", 5);
		auto r = session_.TraceCallers(addr, dur);
		json arr = json::array();
		for (auto& c : r.callers) arr.push_back({{"address", ToHex(c.address)}, {"hitCount", c.hitCount}});
		return {{"totalHits", r.totalHits}, {"uniqueCallers", r.uniqueCallers}, {"callers", arr}};
	}
	if (name == "veh_dump_memory") {
		uint64_t addr = hexArg("address");
		int size = intArg("size", 4096);
		std::string path = args.value("output_path", "");
		if (path.empty()) return {{"error", "output_path is required"}};
		// Read in chunks and write to file
		FILE* fp = fopen(path.c_str(), "wb");
		if (!fp) return {{"error", "Cannot open file: " + path}};
		uint64_t written = 0, remaining = size;
		uint64_t cur = addr;
		while (remaining > 0) {
			uint32_t chunk = static_cast<uint32_t>((remaining > 1048576) ? 1048576 : remaining);
			auto data = session_.ReadMemory(cur, chunk);
			if (data.empty()) break;
			fwrite(data.data(), 1, data.size(), fp);
			written += data.size();
			cur += data.size();
			if (data.size() > remaining) break;
			remaining -= data.size();
		}
		fclose(fp);
		return {{"success", true}, {"size", written}, {"output_path", path}};
	}
	if (name == "veh_set_source_breakpoint") {
		std::string src = args.value("source", "");
		int line = intArg("line", 0);
		uint64_t addr = session_.ResolveSourceLine(src, line);
		if (!addr) return {{"error", "Cannot resolve " + src + ":" + std::to_string(line)}};
		auto r = session_.SetBreakpoint(addr);
		if (!r.ok) return {{"error", "SetBreakpoint failed"}};
		return {{"success", true}, {"id", r.id}, {"address", ToHex(addr)}};
	}
	if (name == "veh_set_function_breakpoint") {
		std::string fname = args.value("name", "");
		uint64_t addr = session_.ResolveFunction(fname);
		if (!addr) return {{"error", "Cannot resolve function: " + fname}};
		auto r = session_.SetBreakpoint(addr);
		if (!r.ok) return {{"error", "SetBreakpoint failed"}};
		return {{"success", true}, {"id", r.id}, {"address", ToHex(addr)}};
	}
	if (name == "veh_trace_register") {
		uint32_t tid = uint32Arg("threadId");
		std::string regName = args.value("register", "");
		uint32_t regIdx = DebugSession::GetRegisterIndex(regName);
		if (regIdx == UINT32_MAX) return {{"error", "Unknown register: " + regName}};
		int maxSteps = intArg("max_steps", 10000);
		std::string modeStr = args.value("mode", "changed");
		uint8_t mode = 0;
		if (modeStr == "equals") mode = 1;
		else if (modeStr == "not_equals") mode = 2;
		uint64_t cmpVal = 0;
		std::string valStr = args.value("value", "");
		if (!valStr.empty()) { try { cmpVal = ParseHexOrDec(valStr); } catch (...) {} }
		auto r = session_.TraceRegister(tid, regIdx, maxSteps, mode, cmpVal);
		if (!r.ok) return {{"error", "TraceRegister failed"}};
		json ret = {{"found", r.found}, {"stepsExecuted", r.stepsExecuted},
		            {"address", ToHex(r.address)}, {"oldValue", ToHex(r.oldValue)}, {"newValue", ToHex(r.newValue)}};
		if (r.found && r.address) {
			auto insns = session_.Disassemble(r.address, 1);
			if (!insns.empty()) ret["instruction"] = insns[0].mnemonic;
		}
		return ret;
	}
	if (name == "veh_trace_memory") {
		uint64_t addr = hexArg("address");
		int sz = intArg("size", 4);
		int tms = intArg("timeout_ms", 10000);
		auto r = session_.TraceMemoryWrite(addr, sz, tms);
		if (!r.ok) return {{"error", "TraceMemory failed"}};
		json ret = {{"found", r.found}, {"address", ToHex(addr)}, {"threadId", r.threadId}};
		if (r.found) {
			ret["instructionAddress"] = ToHex(r.instructionAddress);
			ret["oldValue"] = ToHex(r.oldValue);
			ret["newValue"] = ToHex(r.newValue);
			if (r.instructionAddress) {
				auto insns = session_.Disassemble(r.instructionAddress, 1);
				if (!insns.empty()) ret["instruction"] = insns[0].mnemonic;
			}
		}
		return ret;
	}
	if (name == "veh_attach" || name == "veh_launch" || name == "veh_detach") {
		return {{"error", name + " is not available in batch mode (session lifecycle)"}};
	}

	return {{"error", "Unknown tool: " + name}};
}

json BatchExecutor::CallTool(const std::string& toolName, const json& args) {
	return DispatchTool(toolName, ResolveArgs(args));
}

} // namespace veh
