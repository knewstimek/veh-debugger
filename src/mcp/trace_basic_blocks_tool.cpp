#include "trace_basic_blocks_tool.h"
#include <iomanip>
#include <sstream>

namespace veh {

using json = nlohmann::json;

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
	if (maxBlocks < 1 || maxBlocks > 16384) return {{"error", "max_blocks must be 1-16384"}};
	if (maxEdges < 1 || maxEdges > 32768) return {{"error", "max_edges must be 1-32768"}};
	if (maxSteps < 1 || maxSteps > 5000000) return {{"error", "max_steps must be 1-5000000"}};
	if (timeoutMs < 100 || timeoutMs > 60000) return {{"error", "timeout_ms must be 100-60000"}};
	if (stackBytes < 0 || stackBytes > static_cast<int>(kTraceBasicBlockMaxStackBytes))
		return {{"error", "stack_bytes must be 0-256"}};
	bool followExceptions = TraceJsonBool(args, "follow_exceptions", true);

	auto result = session.TraceBasicBlocks(threadId, start, end,
		static_cast<uint32_t>(maxBlocks), static_cast<uint32_t>(maxEdges),
		static_cast<uint32_t>(maxSteps), static_cast<uint32_t>(timeoutMs),
		static_cast<uint16_t>(stackBytes), followExceptions);
	if (!result.ok)
		return {{"error", "TraceBasicBlocks failed (thread must be VEH-stopped and RIP must be inside the range)"}};

	auto hex = [](uint64_t value) {
		char buffer[24]; snprintf(buffer, sizeof(buffer), "0x%llX", value);
		return std::string(buffer);
	};
	auto stopReason = [](TraceBasicBlockStopReason reason) {
		switch (reason) {
		case TraceBasicBlockStopReason::LeftRange: return "left_range";
		case TraceBasicBlockStopReason::MaxSteps: return "max_steps";
		case TraceBasicBlockStopReason::MaxBlocks: return "max_blocks";
		case TraceBasicBlockStopReason::MaxEdges: return "max_edges";
		case TraceBasicBlockStopReason::Timeout: return "timeout";
		case TraceBasicBlockStopReason::Exception: return "exception";
		case TraceBasicBlockStopReason::Cancelled: return "cancelled";
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

	json blocks = json::array();
	for (const auto& block : result.blocks) {
		json value = {{"start", hex(block.start)}, {"end", hex(block.end)}, {"hits", block.hitCount}};
		if (block.firstSnapshot != UINT32_MAX) value["first_snapshot"] = block.firstSnapshot;
		blocks.push_back(std::move(value));
	}
	json edges = json::array();
	for (const auto& edge : result.edges) {
		json value = {{"source", hex(edge.source)}, {"target", hex(edge.target)},
			{"hits", edge.hitCount}, {"kind", edgeKind(edge.kind)}};
		if (edge.snapshot != UINT32_MAX) value["snapshot"] = edge.snapshot;
		if (edge.exceptionCode) value["exception_code"] = hex(edge.exceptionCode);
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

	return {{"stop_reason", stopReason(result.stopReason)}, {"truncated", result.truncated},
		{"steps_executed", result.stepsExecuted}, {"elapsed_ms", result.elapsedMs},
		{"final_address", hex(result.finalAddress)}, {"exceptions_followed", result.exceptionsFollowed},
		{"blocks", std::move(blocks)}, {"edges", std::move(edges)},
		{"register_order", std::move(registerOrder)}, {"snapshots", std::move(snapshots)}};
}

} // namespace veh
