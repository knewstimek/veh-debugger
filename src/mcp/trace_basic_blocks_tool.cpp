#include "trace_basic_blocks_tool.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <unordered_map>

namespace veh {

using json = nlohmann::json;

class TraceRegionClassifier {
public:
	explicit TraceRegionClassifier(HANDLE process) : process_(process) {}

	json Describe(uint64_t address, uint64_t stackPointer = 0) {
		const auto* region = Query(address);
		if (!region || region->state != MEM_COMMIT) return json();
		std::string type = "private";
		if (region->type == MEM_IMAGE) type = "image";
		else if (region->type == MEM_MAPPED) type = "mapped";
		if (stackPointer) {
			const auto* stack = Query(stackPointer);
			if (stack && stack->allocationBase == region->allocationBase) type = "stack";
		}
		json value = {{"type", type}, {"base", Hex(region->base)},
			{"size", region->end - region->base}, {"protection", Protection(region->protect)}};
		if (region->protect & PAGE_GUARD) value["guard"] = true;
		return value;
	}

private:
	struct Region {
		uint64_t base = 0;
		uint64_t end = 0;
		uint64_t allocationBase = 0;
		DWORD state = 0;
		DWORD type = 0;
		DWORD protect = 0;
	};

	static std::string Hex(uint64_t value) {
		char buffer[24]; snprintf(buffer, sizeof(buffer), "0x%llX", value);
		return buffer;
	}

	static std::string Protection(DWORD protect) {
		DWORD base = protect & 0xFF;
		switch (base) {
		case PAGE_NOACCESS: return "none";
		case PAGE_READONLY: return "r";
		case PAGE_READWRITE: return "rw";
		case PAGE_WRITECOPY: return "rw-copy";
		case PAGE_EXECUTE: return "x";
		case PAGE_EXECUTE_READ: return "rx";
		case PAGE_EXECUTE_READWRITE: return "rwx";
		case PAGE_EXECUTE_WRITECOPY: return "rwx-copy";
		default: return "unknown";
		}
	}

	const Region* Query(uint64_t address) {
		if (!process_ || !address) return nullptr;
		auto upper = regions_.upper_bound(address);
		if (upper != regions_.begin()) {
			auto cached = std::prev(upper);
			if (address >= cached->second.base && address < cached->second.end)
				return &cached->second;
		}
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
				&mbi, sizeof(mbi))) return nullptr;
		Region region;
		region.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		region.end = region.base + mbi.RegionSize;
		region.allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
		region.state = mbi.State;
		region.type = mbi.Type;
		region.protect = mbi.Protect;
		auto inserted = regions_.insert_or_assign(region.base, region);
		return &inserted.first->second;
	}

	HANDLE process_ = nullptr;
	std::map<uint64_t, Region> regions_;
};

static int TraceJsonInt(const json& args, const char* key, int defaultValue) {
	if (!args.contains(key)) return defaultValue;
	const auto& value = args[key];
	if (value.is_number()) return value.get<int>();
	if (value.is_string()) {
		try { return std::stoi(value.get<std::string>(), nullptr, 0); }
		catch (...) {}
	}
	return defaultValue;
}

static uint32_t TraceJsonUint32(const json& args, const char* key, uint32_t defaultValue = 0) {
	if (!args.contains(key)) return defaultValue;
	const auto& value = args[key];
	if (value.is_number_unsigned()) return value.get<uint32_t>();
	if (value.is_number_integer()) {
		auto number = value.get<int64_t>();
		return number >= 0 && number <= UINT32_MAX ? static_cast<uint32_t>(number) : defaultValue;
	}
	if (value.is_string()) {
		const auto& text = value.get_ref<const std::string&>();
		if (text.empty() || text.front() == '-') return defaultValue;
		try {
			size_t consumed = 0;
			auto number = std::stoull(text, &consumed, 0);
			if (consumed == text.size() && number <= UINT32_MAX) return static_cast<uint32_t>(number);
		} catch (...) {}
	}
	return defaultValue;
}

static bool TraceJsonBool(const json& args, const char* key, bool defaultValue) {
	if (!args.contains(key)) return defaultValue;
	const auto& value = args[key];
	if (value.is_boolean()) return value.get<bool>();
	if (value.is_string()) {
		const auto text = value.get<std::string>();
		return text == "true" || text == "1";
	}
	if (value.is_number_integer()) return value.get<int>() != 0;
	if (value.is_number()) return value.get<double>() != 0.0;
	return defaultValue;
}

static std::string TraceTrim(std::string value) {
	auto space = [](unsigned char c) { return std::isspace(c) != 0; };
	value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](char c) { return !space(c); }));
	value.erase(std::find_if(value.rbegin(), value.rend(), [&](char c) { return !space(c); }).base(), value.end());
	return value;
}

static bool TraceRegisterIndex(std::string name, uint8_t& index) {
	std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return char(std::tolower(c)); });
	static const std::pair<const char*, uint8_t> names[] = {
		{"rax",0},{"eax",0},{"rbx",1},{"ebx",1},{"rcx",2},{"ecx",2},{"rdx",3},{"edx",3},
		{"rsi",4},{"esi",4},{"rdi",5},{"edi",5},{"rbp",6},{"ebp",6},{"rsp",7},{"esp",7},
		{"r8",8},{"r9",9},{"r10",10},{"r11",11},{"r12",12},{"r13",13},{"r14",14},{"r15",15},
		{"rip",16},{"eip",16},{"eflags",17}
	};
	for (const auto& item : names) if (name == item.first) { index = item.second; return true; }
	return false;
}

static bool ParseTraceConditionOperand(std::string text, TraceConditionOperand& operand) {
	text = TraceTrim(text);
	std::string lower = text;
	std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return char(std::tolower(c)); });
	uint8_t memorySize = static_cast<uint8_t>(sizeof(void*));
	for (const auto& prefix : {std::pair<const char*, uint8_t>{"byte ",1}, {"word ",2},
			{"dword ",4}, {"qword ",8}}) {
		if (lower.rfind(prefix.first, 0) == 0) {
			memorySize = prefix.second;
			text = TraceTrim(text.substr(strlen(prefix.first)));
			lower = TraceTrim(lower.substr(strlen(prefix.first)));
			break;
		}
	}
	if (text.size() >= 3 && text.front() == '[' && text.back() == ']') {
		std::string inner = TraceTrim(text.substr(1, text.size() - 2));
		size_t split = inner.find_first_of("+-", 1);
		std::string registerName = TraceTrim(inner.substr(0, split));
		uint8_t reg = 0;
		if (!TraceRegisterIndex(registerName, reg) || reg >= 16) return false;
		int64_t offset = 0;
		if (split != std::string::npos) {
			try {
				auto magnitude = std::stoull(TraceTrim(inner.substr(split + 1)), nullptr, 0);
				if (magnitude > static_cast<uint64_t>(INT64_MAX)) return false;
				offset = inner[split] == '-' ? -static_cast<int64_t>(magnitude) : static_cast<int64_t>(magnitude);
			} catch (...) { return false; }
		}
		operand.kind = TraceConditionOperandKind::MemoryAtRegister;
		operand.registerIndex = reg;
		operand.offset = offset;
		operand.size = memorySize;
		return true;
	}
	uint8_t reg = 0;
	if (TraceRegisterIndex(text, reg)) {
		operand.kind = TraceConditionOperandKind::Register;
		operand.registerIndex = reg;
		return true;
	}
	try {
		size_t consumed = 0;
		uint64_t value = std::stoull(text, &consumed, 0);
		if (consumed != text.size()) return false;
		operand.kind = TraceConditionOperandKind::Immediate;
		operand.immediate = value;
		return true;
	} catch (...) { return false; }
}

static bool ParseTraceCondition(const json& args, const char* key, TraceCondition& result,
		std::string& error) {
	if (!args.contains(key)) return true;
	if (!args[key].is_string()) { error = std::string(key) + " must be a string"; return false; }
	std::string expression = TraceTrim(args[key].get<std::string>());
	if (expression.empty()) return true;
	bool hasOr = expression.find("||") != std::string::npos;
	bool hasAnd = expression.find("&&") != std::string::npos;
	if (hasOr && hasAnd) { error = std::string(key) + " cannot mix && and ||"; return false; }
	std::string delimiter = hasOr ? "||" : (hasAnd ? "&&" : "");
	result.matchAny = hasOr ? 1 : 0;
	size_t cursor = 0;
	while (cursor <= expression.size()) {
		size_t next = delimiter.empty() ? std::string::npos : expression.find(delimiter, cursor);
		std::string clauseText = TraceTrim(expression.substr(cursor,
			next == std::string::npos ? std::string::npos : next - cursor));
		if (result.clauseCount >= kTraceConditionMaxClauses) {
			error = std::string(key) + " supports at most 4 clauses"; return false;
		}
		const std::pair<const char*, TraceConditionComparison> operators[] = {
			{"==",TraceConditionComparison::Equal},{"!=",TraceConditionComparison::NotEqual},
			{"<=",TraceConditionComparison::LessEqual},{">=",TraceConditionComparison::GreaterEqual},
			{"<",TraceConditionComparison::Less},{">",TraceConditionComparison::Greater}
		};
		size_t operatorAt = std::string::npos;
		const char* operatorText = nullptr;
		TraceConditionComparison comparison{};
		for (const auto& candidate : operators) {
			operatorAt = clauseText.find(candidate.first);
			if (operatorAt != std::string::npos) { operatorText = candidate.first; comparison = candidate.second; break; }
		}
		if (!operatorText) { error = std::string("invalid ") + key + " clause: " + clauseText; return false; }
		auto& clause = result.clauses[result.clauseCount];
		if (!ParseTraceConditionOperand(clauseText.substr(0, operatorAt), clause.lhs) ||
			!ParseTraceConditionOperand(clauseText.substr(operatorAt + strlen(operatorText)), clause.rhs)) {
			error = std::string("invalid operand in ") + key + ": " + clauseText; return false;
		}
		clause.comparison = comparison;
		result.clauseCount++;
		if (next == std::string::npos) break;
		cursor = next + delimiter.size();
	}
	return result.clauseCount != 0;
}

json ExecuteTraceBasicBlocksTool(DebugSession& session, const json& args,
		const TraceAddressResolver& resolveAddress) {
	uint32_t threadId = TraceJsonUint32(args, "threadId");
	if (!threadId) return {{"error", "threadId is required"}};

	auto parseAddress = [&](const char* name, uint64_t& value) -> bool {
		if (!args.contains(name)) return false;
		const auto& item = args[name];
		if (item.is_string()) return resolveAddress(item.get<std::string>(), value);
		if (item.is_number_unsigned() || item.is_number_integer()) {
			value = item.get<uint64_t>();
			return true;
		}
		return false;
	};
	uint64_t start = 0, end = 0;
	if (!parseAddress("start", start) || !parseAddress("end", end) || start >= end)
		return {{"error", "start and end are required and must define a non-empty address range"}};
	if (end - start > 4ULL * 1024 * 1024)
		return {{"error", "trace range is too large (max 4 MiB)"}};

	int maxBlocks = TraceJsonInt(args, "max_blocks", 4096);
	int maxEdges = TraceJsonInt(args, "max_edges", 8192);
	int maxSteps = TraceJsonInt(args, "max_steps", 100000);
	int timeoutMs = TraceJsonInt(args, "timeout_ms", 10000);
	int stackBytes = TraceJsonInt(args, "stack_bytes", 128);
	bool collectMemoryWrites = TraceJsonBool(args, "collect_memory_writes", false);
	int maxMemoryWrites = TraceJsonInt(args, "max_memory_writes", 4096);
	bool collectMemoryReads = TraceJsonBool(args, "collect_memory_reads", false);
	int maxMemoryReads = TraceJsonInt(args, "max_memory_reads", 4096);
	bool collectEvents = TraceJsonBool(args, "collect_events", false);
	int maxEvents = TraceJsonInt(args, "max_events", 8192);
	if (maxBlocks < 1 || maxBlocks > 16384) return {{"error", "max_blocks must be 1-16384"}};
	if (maxEdges < 1 || maxEdges > 32768) return {{"error", "max_edges must be 1-32768"}};
	if (maxSteps < 1 || maxSteps > 5000000) return {{"error", "max_steps must be 1-5000000"}};
	if (timeoutMs < 100 || timeoutMs > 60000) return {{"error", "timeout_ms must be 100-60000"}};
	if (stackBytes < 0 || stackBytes > static_cast<int>(kTraceBasicBlockMaxStackBytes))
		return {{"error", "stack_bytes must be 0-256"}};
	if (maxMemoryWrites < 1 || maxMemoryWrites > 16384)
		return {{"error", "max_memory_writes must be 1-16384"}};
	if (maxMemoryReads < 1 || maxMemoryReads > 16384)
		return {{"error", "max_memory_reads must be 1-16384"}};
	if (maxEvents < 1 || maxEvents > 32768)
		return {{"error", "max_events must be 1-32768"}};
	std::vector<TraceDependencySource> dependencySources;
	std::vector<std::string> dependencyLabels;
	if (args.contains("dependency_sources")) {
		if (!args["dependency_sources"].is_array() || args["dependency_sources"].size() > kTraceDependencyMaxSources)
			return {{"error", "dependency_sources must be an array with at most 32 items"}};
		for (const auto& item : args["dependency_sources"]) {
			TraceDependencySource source{}; std::string label;
			if (item.is_string()) {
				label = item.get<std::string>(); uint8_t reg = 0xFF;
				if (!TraceRegisterIndex(label, reg) || reg >= 16)
					return {{"error", "dependency register source is invalid: " + label}};
				source.kind = TraceDependencySourceKind::Register; source.registerIndex = reg;
			} else if (item.is_object() && item.contains("address") && item.contains("size")) {
				const auto& address = item["address"];
				if (address.is_string()) { if (!resolveAddress(address.get<std::string>(), source.address)) return {{"error", "dependency memory address could not be resolved"}}; }
				else if (address.is_number()) source.address = address.get<uint64_t>();
				else return {{"error", "dependency memory address is invalid"}};
				source.size = item["size"].get<uint64_t>();
				if (!source.size || source.size > 1048576) return {{"error", "dependency memory source size must be 1-1048576"}};
				source.kind = TraceDependencySourceKind::Memory;
				if (item.contains("label") && item["label"].is_string()) label = item["label"].get<std::string>();
				else { char buffer[24]; snprintf(buffer, sizeof(buffer), "0x%llX", source.address); label = buffer; }
			} else return {{"error", "dependency source must be a register name or {address,size,label?}"}};
			dependencySources.push_back(source); dependencyLabels.push_back(label);
		}
	}
	bool followExceptions = TraceJsonBool(args, "follow_exceptions", true);
	TraceCondition startCondition{}, stopCondition{}, collectCondition{};
	std::string conditionError;
	if (!ParseTraceCondition(args, "start_condition", startCondition, conditionError) ||
		!ParseTraceCondition(args, "stop_condition", stopCondition, conditionError) ||
		!ParseTraceCondition(args, "collect_condition", collectCondition, conditionError))
		return {{"error", conditionError}};

	auto result = session.TraceBasicBlocks(threadId, start, end,
		static_cast<uint32_t>(maxBlocks), static_cast<uint32_t>(maxEdges),
		static_cast<uint32_t>(maxSteps), static_cast<uint32_t>(timeoutMs),
		static_cast<uint16_t>(stackBytes), followExceptions,
		collectMemoryWrites, static_cast<uint32_t>(maxMemoryWrites),
		collectMemoryReads, static_cast<uint32_t>(maxMemoryReads),
		collectEvents, static_cast<uint32_t>(maxEvents), dependencySources,
		startCondition, stopCondition, collectCondition);
	if (!result.ok)
		return {{"error", "TraceBasicBlocks failed (thread must be VEH-stopped and RIP must be inside the range)"}};

	auto hex = [](uint64_t value) {
		char buffer[24]; snprintf(buffer, sizeof(buffer), "0x%llX", value);
		return std::string(buffer);
	};
	TraceRegionClassifier regions(session.GetTargetProcess());
	auto stopReason = [](TraceBasicBlockStopReason reason) {
		switch (reason) {
		case TraceBasicBlockStopReason::LeftRange: return "left_range";
		case TraceBasicBlockStopReason::MaxSteps: return "max_steps";
		case TraceBasicBlockStopReason::MaxBlocks: return "max_blocks";
		case TraceBasicBlockStopReason::MaxEdges: return "max_edges";
		case TraceBasicBlockStopReason::Timeout: return "timeout";
		case TraceBasicBlockStopReason::Exception: return "exception";
		case TraceBasicBlockStopReason::Cancelled: return "cancelled";
		case TraceBasicBlockStopReason::Condition: return "condition";
		default: return "completed";
		}
	};
	auto edgeKind = [](TraceBasicBlockEdgeKind kind) {
		switch (kind) {
		case TraceBasicBlockEdgeKind::Branch: return "branch";
		case TraceBasicBlockEdgeKind::Call: return "call";
		case TraceBasicBlockEdgeKind::Return: return "return";
		case TraceBasicBlockEdgeKind::Exception: return "exception";
		case TraceBasicBlockEdgeKind::RangeExit: return "range_exit";
		default: return "fallthrough";
		}
	};
	auto dependencies = [&](uint32_t mask) {
		json values = json::array();
		for (size_t i = 0; i < dependencyLabels.size(); ++i) if (mask & (1u << i)) values.push_back(dependencyLabels[i]);
		return values;
	};

	json blocks = json::array();
	for (const auto& block : result.blocks) {
		json value = {{"start", hex(block.start)}, {"end", hex(block.end)}, {"hits", block.hitCount}};
		if (block.firstSnapshot != UINT32_MAX) value["first_snapshot"] = block.firstSnapshot;
		blocks.push_back(std::move(value));
	}
	json edges = json::array();
	for (const auto& edge : result.edges) {
		json value = {{"source", hex(edge.source)}, {"target", hex(edge.target)},
			{"source_instruction", hex(edge.sourceInstruction)},
			{"hits", edge.hitCount}, {"kind", edgeKind(edge.kind)}};
		if (edge.indirect) value["indirect"] = true;
		if (edge.snapshot != UINT32_MAX) value["snapshot"] = edge.snapshot;
		if (edge.exceptionCode) value["exception_code"] = hex(edge.exceptionCode);
		if (edge.dependencyMask) value["dependencies"] = dependencies(edge.dependencyMask);
		edges.push_back(std::move(value));
	}

	static const char* registerNames64[kTraceBasicBlockRegisterCount] = {
		"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"
	};
	static const char* registerNames32[10] = {
		"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags"
	};
	bool snapshotsAre32Bit = !result.snapshots.empty() && result.snapshots.front().is32bit != 0;
	json registerOrder = json::array();
	if (snapshotsAre32Bit) {
		for (const char* name : registerNames32) registerOrder.push_back(name);
	} else {
		for (const char* name : registerNames64) registerOrder.push_back(name);
	}
	json snapshots = json::array();
	for (size_t index = 0; index < result.snapshots.size(); ++index) {
		const auto& snapshot = result.snapshots[index];
		json registers = json::array();
		if (snapshot.is32bit) {
			for (uint32_t i = 0; i < 8; ++i) registers.push_back(hex(snapshot.registers[i]));
			registers.push_back(hex(snapshot.registers[16]));
			registers.push_back(hex(snapshot.registers[17]));
		} else {
			for (uint32_t i = 0; i < kTraceBasicBlockRegisterCount; ++i)
				registers.push_back(hex(snapshot.registers[i]));
		}
		std::ostringstream stack;
		for (uint16_t i = 0; i < snapshot.stackSize; ++i) {
			if (i) stack << ' ';
			stack << std::hex << std::setfill('0') << std::setw(2)
				<< static_cast<unsigned>(snapshot.stack[i]);
		}
		snapshots.push_back({{"id", index}, {"instruction_pointer", hex(snapshot.instructionPointer)},
			{"stack_pointer", hex(snapshot.stackPointer)}, {"registers", std::move(registers)},
			{"stack", stack.str()}});
	}

	// A block's first snapshot is its entry state; an edge snapshot is the
	// destination state on that edge's first observation. Their difference is a
	// compact, block-level state transition without adding work to the VEH path.
	std::unordered_map<uint64_t, uint32_t> blockEntrySnapshots;
	for (const auto& block : result.blocks)
		blockEntrySnapshots.emplace(block.start, block.firstSnapshot);
	for (size_t edgeIndex = 0; edgeIndex < result.edges.size(); ++edgeIndex) {
		const auto& edge = result.edges[edgeIndex];
		auto source = blockEntrySnapshots.find(edge.source);
		if (source == blockEntrySnapshots.end() || source->second >= result.snapshots.size() ||
			edge.snapshot >= result.snapshots.size()) continue;
		const auto& before = result.snapshots[source->second];
		const auto& after = result.snapshots[edge.snapshot];
		if (before.is32bit != after.is32bit) continue;
		json delta = json::object();
		if (before.is32bit) {
			for (uint32_t i = 0; i < 8; ++i) {
				if (before.registers[i] != after.registers[i]) {
					json change = {{"before", hex(before.registers[i])}, {"after", hex(after.registers[i])}};
					auto region = regions.Describe(after.registers[i], after.stackPointer);
					if (!region.is_null()) change["after_region"] = std::move(region);
					delta[registerNames32[i]] = std::move(change);
				}
			}
			if (before.registers[17] != after.registers[17])
				delta["eflags"] = {{"before", hex(before.registers[17])},
					{"after", hex(after.registers[17])}};
		} else {
			for (uint32_t i = 0; i < 16; ++i) {
				if (before.registers[i] != after.registers[i]) {
					json change = {{"before", hex(before.registers[i])}, {"after", hex(after.registers[i])}};
					auto region = regions.Describe(after.registers[i], after.stackPointer);
					if (!region.is_null()) change["after_region"] = std::move(region);
					delta[registerNames64[i]] = std::move(change);
				}
			}
			if (before.registers[17] != after.registers[17])
				delta["eflags"] = {{"before", hex(before.registers[17])},
					{"after", hex(after.registers[17])}};
		}
		if (!delta.empty()) edges[edgeIndex]["register_delta"] = std::move(delta);
	}

	json hotBlocks = json::array();
	auto rankedBlocks = result.blocks;
	std::sort(rankedBlocks.begin(), rankedBlocks.end(), [](const auto& a, const auto& b) {
		return a.hitCount != b.hitCount ? a.hitCount > b.hitCount : a.start < b.start;
	});
	for (size_t i = 0; i < std::min<size_t>(16, rankedBlocks.size()); ++i)
		hotBlocks.push_back({{"start", hex(rankedBlocks[i].start)}, {"hits", rankedBlocks[i].hitCount}});

	json hotEdges = json::array();
	auto rankedEdges = result.edges;
	std::sort(rankedEdges.begin(), rankedEdges.end(), [](const auto& a, const auto& b) {
		if (a.hitCount != b.hitCount) return a.hitCount > b.hitCount;
		if (a.source != b.source) return a.source < b.source;
		return a.target < b.target;
	});
	for (size_t i = 0; i < std::min<size_t>(16, rankedEdges.size()); ++i)
		hotEdges.push_back({{"source", hex(rankedEdges[i].source)},
			{"target", hex(rankedEdges[i].target)}, {"hits", rankedEdges[i].hitCount}});

	// The DLL deliberately reports observations rather than VM semantics. This
	// analyzer-side fold identifies dominant re-entry blocks from measured hit
	// counts, leaving dispatcher interpretation to the caller.
	json loopFolds = json::array();
	for (const auto& block : rankedBlocks) {
		if (block.hitCount < 2) continue;
		json inbound = json::array();
		uint64_t reentryHits = 0;
		for (const auto& edge : result.edges) {
			if (edge.target != block.start || edge.kind == TraceBasicBlockEdgeKind::RangeExit) continue;
			inbound.push_back({{"source", hex(edge.source)}, {"hits", edge.hitCount}});
			reentryHits += edge.hitCount;
		}
		if (!inbound.empty()) {
			loopFolds.push_back({{"reentry_block", hex(block.start)}, {"block_hits", block.hitCount},
				{"reentry_hits", reentryHits}, {"inbound", std::move(inbound)}});
		}
		if (loopFolds.size() == 16) break;
	}

	std::map<uint64_t, std::vector<const TraceBasicBlockEdgeEntry*>> indirectBySite;
	for (const auto& edge : result.edges)
		if (edge.indirect) indirectBySite[edge.sourceInstruction].push_back(&edge);
	json indirectBranches = json::array();
	for (const auto& [site, targets] : indirectBySite) {
		json values = json::array();
		uint64_t totalHits = 0;
		for (const auto* target : targets) {
			json targetValue = {{"address", hex(target->target)}, {"hits", target->hitCount}};
			auto region = regions.Describe(target->target);
			if (!region.is_null()) targetValue["region"] = std::move(region);
			values.push_back(std::move(targetValue));
			totalHits += target->hitCount;
		}
		indirectBranches.push_back({{"instruction", hex(site)}, {"total_hits", totalHits},
			{"unique_targets", targets.size()}, {"targets", std::move(values)}});
	}

	auto bytes = [](const uint8_t* value, uint8_t size) {
		std::ostringstream stream;
		for (uint8_t i = 0; i < size; ++i) {
			if (i) stream << ' ';
			stream << std::hex << std::setfill('0') << std::setw(2)
				<< static_cast<unsigned>(value[i]);
		}
		return stream.str();
	};
	json memoryWrites = json::array();
	json executableWrites = json::array();
	for (const auto& write : result.memoryWrites) {
		json value = {{"instruction", hex(write.instruction)}, {"address", hex(write.address)},
			{"size", write.size}, {"hits", write.hitCount},
			{"first_step", write.firstStep},
			{"before", bytes(write.before, write.size)}, {"after", bytes(write.after, write.size)}};
		auto region = regions.Describe(write.address);
		if (!region.is_null()) value["region"] = std::move(region);
		if (write.flags & kTraceMemoryExecutable) {
			value["executable"] = true;
			if (write.flags & kTraceMemoryExecutedAfterWrite) {
				value["executed_after_write"] = true;
				value["executed_address"] = hex(write.executedAddress);
			}
			executableWrites.push_back(value);
		}
		if (write.dependencyMask) value["dependencies"] = dependencies(write.dependencyMask);
		memoryWrites.push_back(std::move(value));
	}
	json memoryReads = json::array();
	for (const auto& read : result.memoryReads) {
		json value = {{"instruction", hex(read.instruction)}, {"address", hex(read.address)},
			{"size", read.size}, {"hits", read.hitCount}, {"value", bytes(read.value, read.size)}};
		auto region = regions.Describe(read.address); if (!region.is_null()) value["region"] = std::move(region);
		if (read.dependencyMask) value["dependencies"] = dependencies(read.dependencyMask);
		memoryReads.push_back(std::move(value));
	}
	json finalDependencies = json::object();
	const char** dependencyRegisterNames = snapshotsAre32Bit ? registerNames32 : registerNames64;
	size_t dependencyRegisterCount = snapshotsAre32Bit ? 8 : 16;
	for (size_t i = 0; i < dependencyRegisterCount; ++i)
		if (result.finalRegisterDependencies[i]) finalDependencies[dependencyRegisterNames[i]] = dependencies(result.finalRegisterDependencies[i]);
	if (result.finalFlagsDependencies) finalDependencies["eflags"] = dependencies(result.finalFlagsDependencies);

	auto exceptionType = [](uint32_t code) {
		switch (code) {
		case EXCEPTION_ACCESS_VIOLATION: return "access_violation";
		case EXCEPTION_BREAKPOINT: return "breakpoint";
		case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal_instruction";
		case EXCEPTION_INT_DIVIDE_BY_ZERO: return "integer_divide_by_zero";
		case EXCEPTION_STACK_OVERFLOW: return "stack_overflow";
		default: return "exception";
		}
	};
	json exceptions = json::array();
	for (const auto& event : result.exceptionEvents) {
		json value = {{"type", exceptionType(event.code)}, {"code", hex(event.code)},
			{"fault_rip", hex(event.faultRip)}, {"continuation", hex(event.continuation)},
			{"hits", event.hitCount}};
		if (event.faultAddress) value["fault_address"] = hex(event.faultAddress);
		if (event.faultSnapshot != UINT32_MAX) value["fault_snapshot"] = event.faultSnapshot;
		if (event.continuationSnapshot != UINT32_MAX)
			value["continuation_snapshot"] = event.continuationSnapshot;
		auto faultRegion = regions.Describe(event.faultAddress);
		if (!faultRegion.is_null()) value["fault_region"] = std::move(faultRegion);
		auto continuationRegion = regions.Describe(event.continuation);
		if (!continuationRegion.is_null()) value["continuation_region"] = std::move(continuationRegion);
		exceptions.push_back(std::move(value));
	}
	json events = json::array();
	for (const auto& event : result.events) {
		json value = {{"sequence", event.sequence}, {"thread_id", event.threadId}};
		if (event.type == TraceBasicBlockEventType::BlockEntry) {
			value["type"] = "block_entry";
			value["block"] = hex(event.target);
		} else {
			value["type"] = "edge";
			value["source"] = hex(event.source);
			value["source_instruction"] = hex(event.sourceInstruction);
			value["target"] = hex(event.target);
			value["kind"] = edgeKind(event.edgeKind);
			if (event.indirect) value["indirect"] = true;
			if (event.exceptionCode) value["exception_code"] = hex(event.exceptionCode);
		}
		events.push_back(std::move(value));
	}
	json ordering = {{"available", result.eventCollectionEnabled},
		{"granularity", "basic_block_transitions"},
		{"event_schema_version", result.eventSchemaVersion},
		{"complete", result.eventCollectionEnabled && !result.eventsTruncated}};

	return {{"schema_version", 2}, {"mode", "aggregated"},
		{"thread_id", result.threadId}, {"ordering", std::move(ordering)},
		{"events", std::move(events)}, {"events_truncated", result.eventsTruncated},
		{"stop_reason", stopReason(result.stopReason)}, {"truncated", result.truncated},
		{"steps_executed", result.stepsExecuted}, {"elapsed_ms", result.elapsedMs},
		{"filtered_steps", result.filteredSteps}, {"start_condition_met", result.startConditionMet},
		{"final_address", hex(result.finalAddress)}, {"exceptions_followed", result.exceptionsFollowed},
		{"blocks", std::move(blocks)}, {"edges", std::move(edges)},
		{"hot_blocks", std::move(hotBlocks)}, {"hot_edges", std::move(hotEdges)},
		{"loop_folds", std::move(loopFolds)},
		{"indirect_branches", std::move(indirectBranches)},
		{"memory_writes", std::move(memoryWrites)},
		{"memory_reads", std::move(memoryReads)},
		{"executable_writes", std::move(executableWrites)},
		{"memory_writes_truncated", result.memoryWritesTruncated},
		{"unsupported_memory_writes", result.unsupportedMemoryWrites},
		{"memory_reads_truncated", result.memoryReadsTruncated},
		{"unsupported_memory_reads", result.unsupportedMemoryReads},
		{"dependency_incomplete", result.dependencyIncomplete},
		{"final_dependencies", std::move(finalDependencies)},
		{"exceptions", std::move(exceptions)},
		{"register_order", std::move(registerOrder)}, {"snapshots", std::move(snapshots)}};
}

} // namespace veh
