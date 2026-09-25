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

static std::string CheckpointHex(uint64_t value) {
	char buffer[24]; snprintf(buffer, sizeof(buffer), "0x%llX", value);
	return buffer;
}

static bool CheckpointId(const json& args, const char* key, uint64_t& value) {
	if (!args.contains(key)) return false;
	const auto& item = args[key];
	if (item.is_number_unsigned()) { value = item.get<uint64_t>(); return value != 0; }
	if (item.is_number_integer()) {
		auto signedValue = item.get<int64_t>(); value = signedValue > 0 ? uint64_t(signedValue) : 0; return value != 0;
	}
	if (item.is_string()) {
		try { size_t used = 0; value = std::stoull(item.get<std::string>(), &used, 0);
			return value != 0 && used == item.get_ref<const std::string&>().size(); }
		catch (...) { return false; }
	}
	return false;
}

static std::vector<std::pair<const char*, uint64_t>> CheckpointRegisters(const RegisterSet& r) {
	if (r.is32bit) return {{"eax",r.rax},{"ebx",r.rbx},{"ecx",r.rcx},{"edx",r.rdx},
		{"esi",r.rsi},{"edi",r.rdi},{"ebp",r.rbp},{"esp",r.rsp},
		{"eip",r.rip},{"eflags",r.rflags}};
	return {{"rax",r.rax},{"rbx",r.rbx},{"rcx",r.rcx},{"rdx",r.rdx},
		{"rsi",r.rsi},{"rdi",r.rdi},{"rbp",r.rbp},{"rsp",r.rsp},
		{"r8",r.r8},{"r9",r.r9},{"r10",r.r10},{"r11",r.r11},
		{"r12",r.r12},{"r13",r.r13},{"r14",r.r14},{"r15",r.r15},
		{"rip",r.rip},{"eflags",r.rflags}};
}

json McpServer::ToolCheckpointCreate(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	uint32_t threadId = JsonUint32(args, "threadId");
	if (!threadId) return {{"error", "threadId is required"}};
	if (!session_.IsThreadStopped(threadId))
		return {{"error", "checkpoint requires a VEH-stopped thread"}};
	auto registers = session_.GetRegisters(threadId);
	if (!registers) return {{"error", "failed to capture thread context"}};
	auto queryEnvironment = [&](CheckpointThreadEnvironment& environment) -> bool {
		HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
		if (!thread) return false;
		using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
		auto query = reinterpret_cast<NtQueryInformationThreadFn>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
		struct ThreadBasicInformationLocal {
			LONG exitStatus; PVOID tebBase; HANDLE processId; HANDLE threadId;
			ULONG_PTR affinityMask; LONG priority; LONG basePriority;
		};
		ThreadBasicInformationLocal basic{};
		bool ok = query && query(thread, 0, &basic, sizeof(basic), nullptr) >= 0;
		if (ok) environment.nativeTeb = reinterpret_cast<uint64_t>(basic.tebBase);
		BOOL wow64 = FALSE;
		IsWow64Process(session_.GetTargetProcess(), &wow64);
		environment.wow64 = wow64 != FALSE;
		ULONG_PTR wow64Teb = 0;
		if (query && environment.wow64 && query(thread, 17, &wow64Teb, sizeof(wow64Teb), nullptr) >= 0)
			environment.teb = wow64Teb;
		if (!environment.teb) environment.teb = environment.nativeTeb;
		auto selectorBase = [&](uint64_t selector) -> uint64_t {
			LDT_ENTRY entry{};
			if (!selector || !GetThreadSelectorEntry(thread, static_cast<DWORD>(selector), &entry)) return 0;
			return static_cast<uint64_t>(entry.BaseLow) |
				(static_cast<uint64_t>(entry.HighWord.Bytes.BaseMid) << 16) |
				(static_cast<uint64_t>(entry.HighWord.Bytes.BaseHi) << 24);
		};
		environment.fsBase = selectorBase(registers->fs);
		environment.gsBase = selectorBase(registers->gs);
		if (registers->is32bit && !environment.fsBase) environment.fsBase = environment.teb;
		if (!registers->is32bit && !environment.gsBase) environment.gsBase = environment.nativeTeb;
		CloseHandle(thread);
		return ok && environment.teb != 0;
	};
	if (args.contains("regions") && !args["regions"].is_array())
		return {{"error", "regions must be an array"}};
	json regionsArg = args.value("regions", json::array());
	CheckpointThreadEnvironment environment{};
	if (!queryEnvironment(environment))
		return {{"error", "failed to query thread TEB/segment environment"}};
	if (args.contains("capture_teb") && !args["capture_teb"].is_boolean())
		return {{"error", "capture_teb must be a boolean"}};
	bool captureTeb = args.value("capture_teb", false);
	const size_t explicitRegionCount = regionsArg.size();
	if (captureTeb) {
		uint32_t tebSize = JsonUint32(args, "teb_size", 4096);
		if (tebSize < 256 || tebSize > 1024 * 1024)
			return {{"error", "teb_size must be 256-1048576"}};
		regionsArg.push_back({{"address", environment.teb}, {"size", tebSize}, {"kind", "teb"}});
	}
	if (regionsArg.size() > 16) return {{"error", "at most 16 memory regions are allowed"}};

	Checkpoint checkpoint;
	checkpoint.sessionGeneration = session_.GetSessionGeneration();
	checkpoint.threadId = threadId;
	checkpoint.registers = *registers;
	checkpoint.environment = environment;
	const uint64_t checkpointStackPointer = registers->rsp;
	MEMORY_BASIC_INFORMATION stackMbi{};
	const bool hasStackMapping = checkpointStackPointer &&
		VirtualQueryEx(session_.GetTargetProcess(),
			reinterpret_cast<LPCVOID>(uintptr_t(checkpointStackPointer)),
			&stackMbi, sizeof(stackMbi)) && stackMbi.State == MEM_COMMIT;
	size_t totalBytes = 0;
	for (size_t requestedIndex = 0; requestedIndex < regionsArg.size(); ++requestedIndex) {
		const auto& requested = regionsArg[requestedIndex];
		if (!requested.is_object() || !requested.contains("address") || !requested.contains("size"))
			return {{"error", "each region requires address and size"}};
		uint64_t address = 0;
		if (requested["address"].is_string()) {
			if (!ParseAddress(requested["address"].get<std::string>(), address))
				return {{"error", "invalid checkpoint region address"}};
		} else if (requested["address"].is_number_unsigned() || requested["address"].is_number_integer()) {
			address = requested["address"].get<uint64_t>();
		} else return {{"error", "invalid checkpoint region address"}};
		uint64_t size = 0;
		if (requested["size"].is_number_unsigned() || requested["size"].is_number_integer())
			size = requested["size"].get<uint64_t>();
		else if (requested["size"].is_string()) {
			try { size_t used=0; size=std::stoull(requested["size"].get<std::string>(), &used, 0);
				if (used != requested["size"].get_ref<const std::string&>().size()) size=0; }
			catch (...) { size=0; }
		}
		if (!address || !size || size > 4ULL * 1024 * 1024 || totalBytes + size > 16ULL * 1024 * 1024)
			return {{"error", "each region must be 1-4 MiB and total captured memory must not exceed 16 MiB"}};
		if (address + size < address) return {{"error", "checkpoint region overflows address space"}};
		for (const auto& existing : checkpoint.regions) {
			uint64_t existingEnd = existing.address + existing.bytes.size();
			if (address < existingEnd && existing.address < address + size)
				return {{"error", "checkpoint regions must not overlap"}};
		}
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQueryEx(session_.GetTargetProcess(), reinterpret_cast<LPCVOID>(uintptr_t(address)),
				&mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
			return {{"error", "checkpoint region is not committed memory"}};
		uint64_t regionBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);
		if (address + size > regionBase + mbi.RegionSize)
			return {{"error", "a checkpoint range may not cross a VirtualQuery region boundary"}};
		auto bytes = session_.ReadMemory(address, static_cast<uint32_t>(size));
		if (bytes.size() != size) return {{"error", "failed to read checkpoint region"}};
		CheckpointRegion region;
		region.address = address;
		region.allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
		region.regionBase = regionBase;
		region.regionSize = mbi.RegionSize;
		region.type = mbi.Type;
		region.protection = mbi.Protect;
		const bool isStack = requestedIndex < explicitRegionCount && hasStackMapping &&
			mbi.AllocationBase == stackMbi.AllocationBase;
		region.kind = requestedIndex >= explicitRegionCount ? "teb" : (isStack ? "stack" : "memory");
		// The stopped thread is currently executing the VEH exception/wait machinery
		// below its saved application SP.  Replacing that live prefix makes the
		// checkpoint command appear successful but corrupts the resume path.  Restore
		// the logical application stack (saved SP..end) and leave the live VEH frames
		// below SP untouched.
		if (isStack && address < checkpointStackPointer)
			region.restoreOffset = static_cast<size_t>(std::min<uint64_t>(
				checkpointStackPointer - address, size));
		region.restorable = region.kind != "teb";
		region.bytes = std::move(bytes);
		checkpoint.regions.push_back(std::move(region));
		totalBytes += size;
	}
	checkpoint.byteSize = totalBytes;
	{
		std::lock_guard<std::mutex> lock(checkpointMutex_);
		if (checkpoints_.size() >= 16) return {{"error", "checkpoint limit reached (16)"}};
		if (checkpointBytes_ + totalBytes > 64ULL * 1024 * 1024)
			return {{"error", "checkpoint memory budget exceeded (64 MiB)"}};
		checkpoint.id = nextCheckpointId_++;
		checkpointBytes_ += totalBytes;
		checkpoints_.emplace(checkpoint.id, checkpoint);
	}
	json regions = json::array();
	for (const auto& region : checkpoint.regions) {
		json item = {{"address",CheckpointHex(region.address)}, {"size",region.bytes.size()},
			{"allocation_base",CheckpointHex(region.allocationBase)}, {"kind", region.kind},
			{"restorable", region.restorable}};
		if (region.kind == "stack") {
			item["restore_start"] = CheckpointHex(region.address + region.restoreOffset);
			item["live_prefix_skipped"] = region.restoreOffset;
		}
		regions.push_back(std::move(item));
	}
	auto architecture = registers->is32bit ? (environment.wow64 ? "wow64" : "x86") : "x64";
	json threadEnvironment = {{"architecture", architecture}, {"wow64", environment.wow64},
		{"teb", CheckpointHex(environment.teb)},
		{"fs", {{"selector", CheckpointHex(registers->fs)}, {"base", CheckpointHex(environment.fsBase)}}},
		{"gs", {{"selector", CheckpointHex(registers->gs)}, {"base", CheckpointHex(environment.gsBase)}}}};
	if (environment.nativeTeb && environment.nativeTeb != environment.teb)
		threadEnvironment["native_teb"] = CheckpointHex(environment.nativeTeb);
	return {{"id",checkpoint.id}, {"threadId",threadId}, {"memory_bytes",totalBytes},
		{"regions",std::move(regions)},
		{"thread_environment", std::move(threadEnvironment)}, {"teb_captured", captureTeb},
		{"context_scope",registers->is32bit ? "x86-gpr-flags" : "x64-gpr-flags-xmm"},
		{"limitations",json::array({"selected memory only","live VEH stack below the saved SP is not restored",
			"TEB bytes and segment bases are observed but not restored",
			"no heap metadata, handles, kernel state, or other threads"})}};
}

json McpServer::ToolCheckpointRestore(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	uint64_t id = 0;
	if (!CheckpointId(args, "id", id)) return {{"error", "valid checkpoint id is required"}};
	Checkpoint checkpoint;
	{
		std::lock_guard<std::mutex> lock(checkpointMutex_);
		auto found = checkpoints_.find(id);
		if (found == checkpoints_.end()) return {{"error", "checkpoint not found"}};
		checkpoint = found->second;
	}
	if (checkpoint.sessionGeneration != session_.GetSessionGeneration())
		return {{"error", "checkpoint belongs to a previous debug session"}};
	if (!session_.IsThreadStopped(checkpoint.threadId))
		return {{"error", "checkpoint thread must be VEH-stopped before restore"}};

	std::vector<std::vector<uint8_t>> rollback;
	rollback.reserve(checkpoint.regions.size());
	for (const auto& region : checkpoint.regions) {
		if (!region.restorable) { rollback.emplace_back(); continue; }
		const uint64_t restoreAddress = region.address + region.restoreOffset;
		const size_t restoreSize = region.bytes.size() - region.restoreOffset;
		if (!restoreSize) { rollback.emplace_back(); continue; }
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQueryEx(session_.GetTargetProcess(), reinterpret_cast<LPCVOID>(uintptr_t(restoreAddress)),
				&mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
			reinterpret_cast<uint64_t>(mbi.AllocationBase) != region.allocationBase ||
			mbi.Type != region.type || restoreAddress + restoreSize >
				reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize)
			return {{"error", "memory mapping changed since checkpoint; restore refused"},
				{"address",CheckpointHex(restoreAddress)}};
		auto current = session_.ReadMemory(restoreAddress, static_cast<uint32_t>(restoreSize));
		if (current.size() != restoreSize)
			return {{"error", "failed to prepare restore rollback image"}};
		rollback.push_back(std::move(current));
	}
	size_t written = 0;
	for (; written < checkpoint.regions.size(); ++written) {
		const auto& region = checkpoint.regions[written];
		const size_t restoreSize = region.bytes.size() - region.restoreOffset;
		if (!region.restorable || !restoreSize) continue;
		const uint64_t restoreAddress = region.address + region.restoreOffset;
		if (!session_.WriteMemory(restoreAddress, region.bytes.data() + region.restoreOffset,
				static_cast<uint32_t>(restoreSize))) {
			for (size_t i = 0; i <= written && i < rollback.size(); ++i)
				if (!rollback[i].empty()) session_.WriteMemory(
					checkpoint.regions[i].address + checkpoint.regions[i].restoreOffset, rollback[i].data(),
					static_cast<uint32_t>(rollback[i].size()));
			return {{"error", "memory restore failed; rollback attempted"}, {"failed_region",written}};
		}
	}
	if (!session_.SetRegisters(checkpoint.threadId, checkpoint.registers)) {
		for (size_t i = 0; i < rollback.size(); ++i)
			if (!rollback[i].empty()) session_.WriteMemory(
				checkpoint.regions[i].address + checkpoint.regions[i].restoreOffset, rollback[i].data(),
				static_cast<uint32_t>(rollback[i].size()));
		return {{"error", "context restore failed; memory rollback attempted"}};
	}
	size_t liveStackBytesSkipped = 0;
	for (const auto& region : checkpoint.regions)
		if (region.kind == "stack") liveStackBytesSkipped += region.restoreOffset;
	return {{"restored",true}, {"id",id}, {"threadId",checkpoint.threadId},
		{"regions",checkpoint.regions.size()}, {"memory_bytes",checkpoint.byteSize},
		{"live_stack_bytes_skipped",liveStackBytesSkipped},
		{"warning","external process state (other threads, handles, allocations, files, sockets) was not restored"}};
}

json McpServer::ToolCheckpointDiff(const json& args) {
	if (!session_.IsAttached()) return {{"error", NotAttachedMessage()}};
	uint64_t id = 0;
	if (!CheckpointId(args, "id", id)) return {{"error", "valid checkpoint id is required"}};
	Checkpoint before, after;
	bool compareCurrent = !args.contains("other_id");
	{
		std::lock_guard<std::mutex> lock(checkpointMutex_);
		auto found = checkpoints_.find(id);
		if (found == checkpoints_.end()) return {{"error", "checkpoint not found"}};
		before = found->second;
		if (!compareCurrent) {
			uint64_t otherId = 0;
			if (!CheckpointId(args, "other_id", otherId)) return {{"error", "invalid other_id"}};
			auto other = checkpoints_.find(otherId);
			if (other == checkpoints_.end()) return {{"error", "other checkpoint not found"}};
			after = other->second;
		}
	}
	if (before.sessionGeneration != session_.GetSessionGeneration() ||
		(!compareCurrent && after.sessionGeneration != before.sessionGeneration))
		return {{"error", "checkpoint session mismatch"}};
	if (compareCurrent) {
		if (!session_.IsThreadStopped(before.threadId))
			return {{"error", "checkpoint thread must be VEH-stopped to diff current state"}};
		auto registers = session_.GetRegisters(before.threadId);
		if (!registers) return {{"error", "failed to read current context"}};
		after.threadId = before.threadId;
		after.registers = *registers;
		for (const auto& region : before.regions) {
			CheckpointRegion current = region;
			current.bytes = session_.ReadMemory(region.address, static_cast<uint32_t>(region.bytes.size()));
			if (current.bytes.size() != region.bytes.size())
				return {{"error", "failed to read current memory for diff"}, {"address",CheckpointHex(region.address)}};
			after.regions.push_back(std::move(current));
		}
	}
	if (before.threadId != after.threadId || before.regions.size() != after.regions.size())
		return {{"error", "checkpoints have incompatible thread or region layouts"}};
	json registerChanges = json::object();
	auto beforeRegs = CheckpointRegisters(before.registers);
	auto afterRegs = CheckpointRegisters(after.registers);
	for (size_t i = 0; i < beforeRegs.size(); ++i)
		if (beforeRegs[i].second != afterRegs[i].second)
			registerChanges[beforeRegs[i].first] = {{"before",CheckpointHex(beforeRegs[i].second)},
				{"after",CheckpointHex(afterRegs[i].second)}};
	json xmmChanges = json::array();
	if (!before.registers.is32bit) for (size_t i = 0; i < 16; ++i)
		if (memcmp(before.registers.xmm[i], after.registers.xmm[i], 16) != 0) xmmChanges.push_back(i);
	json memoryChanges = json::array();
	bool truncated = false;
	for (size_t regionIndex = 0; regionIndex < before.regions.size(); ++regionIndex) {
		const auto& left = before.regions[regionIndex];
		const auto& right = after.regions[regionIndex];
		if (left.address != right.address || left.bytes.size() != right.bytes.size())
			return {{"error", "checkpoints have incompatible region layouts"}};
		for (size_t offset = 0; offset < left.bytes.size();) {
			if (left.bytes[offset] == right.bytes[offset]) { ++offset; continue; }
			size_t start = offset;
			while (offset < left.bytes.size() && left.bytes[offset] != right.bytes[offset]) ++offset;
			if (memoryChanges.size() == 1024) { truncated = true; break; }
			memoryChanges.push_back({{"address",CheckpointHex(left.address + start)},
				{"offset",start}, {"size",offset-start}});
		}
		if (truncated) break;
	}
	return {{"id",id}, {"against",compareCurrent ? json("current") : args["other_id"]},
		{"register_delta",std::move(registerChanges)}, {"xmm_changed",std::move(xmmChanges)},
		{"memory_changes",std::move(memoryChanges)}, {"truncated",truncated}};
}

json McpServer::ToolCheckpointDelete(const json& args) {
	uint64_t id = 0;
	if (!CheckpointId(args, "id", id)) return {{"error", "valid checkpoint id is required"}};
	std::lock_guard<std::mutex> lock(checkpointMutex_);
	auto found = checkpoints_.find(id);
	if (found == checkpoints_.end()) return {{"deleted",false}, {"id",id}};
	checkpointBytes_ -= found->second.byteSize;
	checkpoints_.erase(found);
	return {{"deleted",true}, {"id",id}};
}

} // namespace veh
