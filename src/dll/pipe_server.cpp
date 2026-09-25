#include <windows.h>
#include <algorithm>
#include "pipe_server.h"
#include "veh_handler.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "threads.h"
#include "stack_walk.h"
#include "memory.h"
#include "value_scan.h"
#include "syscall_resolver.h"
#include "../common/ipc_protocol.h"
#include "../common/logger.h"

#include <tlhelp32.h>
#include <dbghelp.h>
#include <Zydis/Zydis.h>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>
#pragma comment(lib, "dbghelp.lib")

// ---------------------------------------------------------------------------
// Import resolve: static instruction flow analysis (no Zydis needed)
// ---------------------------------------------------------------------------

// Safe memory read (__try must be in function without C++ destructors)
static bool SafeReadMem(uint64_t addr, void* buf, size_t len) {
	__try {
		memcpy(buf, reinterpret_cast<const void*>(addr), len);
		return true;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

static uint64_t ReadPtr(uint64_t addr) {
#ifdef _WIN64
	uint64_t val = 0;
	if (SafeReadMem(addr, &val, 8)) return val;
#else
	uint32_t val = 0;
	if (SafeReadMem(addr, &val, 4)) return val;
#endif
	return 0;
}

// Register IDs stored in trace metadata match TraceBasicBlockSnapshot's GPR
// order. Segment/vector registers are intentionally unsupported here.
static uint8_t BasicTraceRegisterIndex(ZydisMachineMode mode, ZydisRegister reg) {
	if (reg == ZYDIS_REGISTER_NONE) return 0xFF;
	reg = ZydisRegisterGetLargestEnclosing(mode, reg);
	switch (reg) {
#ifdef _WIN64
	case ZYDIS_REGISTER_RAX: return 0; case ZYDIS_REGISTER_RBX: return 1;
	case ZYDIS_REGISTER_RCX: return 2; case ZYDIS_REGISTER_RDX: return 3;
	case ZYDIS_REGISTER_RSI: return 4; case ZYDIS_REGISTER_RDI: return 5;
	case ZYDIS_REGISTER_RBP: return 6; case ZYDIS_REGISTER_RSP: return 7;
	case ZYDIS_REGISTER_R8: return 8; case ZYDIS_REGISTER_R9: return 9;
	case ZYDIS_REGISTER_R10: return 10; case ZYDIS_REGISTER_R11: return 11;
	case ZYDIS_REGISTER_R12: return 12; case ZYDIS_REGISTER_R13: return 13;
	case ZYDIS_REGISTER_R14: return 14; case ZYDIS_REGISTER_R15: return 15;
#else
	case ZYDIS_REGISTER_EAX: return 0; case ZYDIS_REGISTER_EBX: return 1;
	case ZYDIS_REGISTER_ECX: return 2; case ZYDIS_REGISTER_EDX: return 3;
	case ZYDIS_REGISTER_ESI: return 4; case ZYDIS_REGISTER_EDI: return 5;
	case ZYDIS_REGISTER_EBP: return 6; case ZYDIS_REGISTER_ESP: return 7;
#endif
	default: return 0xFF;
	}
}

static bool InitTraceDecoder(ZydisDecoder& decoder, ZydisMachineMode& machineMode) {
#ifdef _WIN64
	machineMode = ZYDIS_MACHINE_MODE_LONG_64;
	return ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machineMode, ZYDIS_STACK_WIDTH_64));
#else
	machineMode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
	return ZYAN_SUCCESS(ZydisDecoderInit(&decoder, machineMode, ZYDIS_STACK_WIDTH_32));
#endif
}

// Decodes one instruction into trace metadata and returns its length (1 for
// undecodable bytes). With starts, also records the sweep's block starts.
static uint8_t DecodeTraceInstruction(const ZydisDecoder& decoder, ZydisMachineMode machineMode,
		uint64_t address, const uint8_t* bytes, size_t available,
		veh::VehHandler::TraceBasicBlocksState::Instruction& meta, bool& decodedOk,
		std::set<uint64_t>* starts, uint64_t start, uint64_t end) {
	decodedOk = false;
	ZydisDecodedInstruction decoded{};
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};
	uint8_t length = 1;
	bool terminal = false;
	bool indirect = false;
	meta.address = address;
	veh::TraceBasicBlockEdgeKind kind = veh::TraceBasicBlockEdgeKind::Fallthrough;
	if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, bytes, available, &decoded, operands))) {
		decodedOk = true;
		length = decoded.length;
		switch (decoded.meta.category) {
		case ZYDIS_CATEGORY_CALL:
			terminal = true; kind = veh::TraceBasicBlockEdgeKind::Call; break;
		case ZYDIS_CATEGORY_RET:
			terminal = true; kind = veh::TraceBasicBlockEdgeKind::Return; break;
		case ZYDIS_CATEGORY_COND_BR:
		case ZYDIS_CATEGORY_UNCOND_BR:
		case ZYDIS_CATEGORY_INTERRUPT:
		case ZYDIS_CATEGORY_SYSCALL:
		case ZYDIS_CATEGORY_SYSRET:
			terminal = true; kind = veh::TraceBasicBlockEdgeKind::Branch; break;
		default:
			break;
		}
		if (terminal && (decoded.meta.category == ZYDIS_CATEGORY_CALL ||
				decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR) &&
				decoded.operand_count_visible > 0) {
			indirect = operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE;
		}
		if (terminal) {
			uint64_t next = address + length;
			if (starts && next < end) starts->insert(next);
			for (uint8_t i = 0; i < decoded.operand_count_visible; ++i) {
				if (operands[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operands[i].imm.is_relative)
					continue;
				ZyanU64 target = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&decoded, &operands[i], address, &target)) &&
					starts && target >= start && target < end) starts->insert(target);
			}
		}

		bool repeated = (decoded.attributes & (ZYDIS_ATTRIB_HAS_REP |
			ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) != 0;
		if (decoded.cpu_flags) {
			meta.readsFlags = decoded.cpu_flags->tested != 0;
			meta.writesFlags = (decoded.cpu_flags->modified | decoded.cpu_flags->set_0 |
				decoded.cpu_flags->set_1 | decoded.cpu_flags->undefined) != 0;
		}
		if ((decoded.mnemonic == ZYDIS_MNEMONIC_XOR || decoded.mnemonic == ZYDIS_MNEMONIC_SUB) &&
			decoded.operand_count_visible >= 2 && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			ZydisRegisterGetLargestEnclosing(machineMode, operands[0].reg.value) ==
			ZydisRegisterGetLargestEnclosing(machineMode, operands[1].reg.value))
			meta.clearsDependencies = 1;
		for (uint8_t i = 0; i < decoded.operand_count; ++i) {
			const auto& operand = operands[i];
			if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
				uint8_t reg = BasicTraceRegisterIndex(machineMode, operand.reg.value);
				if (reg < 16) {
					if (operand.actions & ZYDIS_OPERAND_ACTION_READ) meta.readRegisterMask |= 1u << reg;
					if (operand.actions & ZYDIS_OPERAND_ACTION_WRITE) meta.writeRegisterMask |= 1u << reg;
				}
				continue;
			}
			if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
			// LEA consumes the address expression, not memory at that address. Zydis
			// represents the source as a memory-form operand, so carry its base/index
			// register origins into the enclosing destination register explicitly and
			// do not emit a synthetic memory-read observation.
			if (decoded.mnemonic == ZYDIS_MNEMONIC_LEA) {
				uint8_t base = BasicTraceRegisterIndex(machineMode, operand.mem.base);
				uint8_t index = BasicTraceRegisterIndex(machineMode, operand.mem.index);
				if (base < 16) meta.readRegisterMask |= 1u << base;
				if (index < 16) meta.readRegisterMask |= 1u << index;
				continue;
			}
			// Intel multi-byte NOP encodings carry a memory-form operand for
			// instruction length, but they neither calculate an effective address
			// nor access memory. Treating NOP [reg] as a read creates a false
			// unsupported access when the decorative register value is unmapped.
			if (decoded.mnemonic == ZYDIS_MNEMONIC_NOP) continue;
			bool readable = (operand.actions & ZYDIS_OPERAND_ACTION_READ) != 0;
			bool writable = (operand.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
			if (!readable && !writable) continue;
			bool unsupported = repeated || operand.size == 0 ||
				operand.size > veh::kTraceMemoryMaxValueBytes * 8 ||
				operand.mem.segment == ZYDIS_REGISTER_FS || operand.mem.segment == ZYDIS_REGISTER_GS ||
				(writable && meta.writeOperandCount >= veh::VehHandler::TraceBasicBlocksState::kMaxWriteOperands) ||
				(readable && meta.readOperandCount >= veh::VehHandler::TraceBasicBlocksState::kMaxReadOperands);
			if (unsupported) {
				if (writable) meta.unsupportedWrites++;
				if (readable) meta.unsupportedReads++;
				continue;
			}
			veh::VehHandler::TraceBasicBlocksState::WriteOperand parsed{};
			parsed.size = static_cast<uint8_t>((operand.size + 7) / 8);
			parsed.scale = operand.mem.scale;
			parsed.displacement = operand.mem.disp.has_displacement ? operand.mem.disp.value : 0;
			parsed.ripRelative = operand.mem.base == ZYDIS_REGISTER_RIP ? 1 : 0;
			parsed.base = parsed.ripRelative ? 0xFF : BasicTraceRegisterIndex(machineMode, operand.mem.base);
			parsed.index = BasicTraceRegisterIndex(machineMode, operand.mem.index);
			// PUSH and CALL decrement SP before storing; Zydis reports the stack
			// operand relative to the pre-instruction SP.
			parsed.preDecrementStack = writable && (decoded.meta.category == ZYDIS_CATEGORY_PUSH ||
				decoded.meta.category == ZYDIS_CATEGORY_CALL) && parsed.base == 7 ? 1 : 0;
			if ((!parsed.ripRelative && operand.mem.base != ZYDIS_REGISTER_NONE && parsed.base == 0xFF) ||
				(operand.mem.index != ZYDIS_REGISTER_NONE && parsed.index == 0xFF)) {
				if (writable) meta.unsupportedWrites++;
				if (readable) meta.unsupportedReads++;
				continue;
			}
			if (writable) meta.writeOperands[meta.writeOperandCount++] = parsed;
			if (readable) meta.readOperands[meta.readOperandCount++] = parsed;
		}
	}

	meta.next = address + length;
	meta.terminal = terminal ? 1 : 0;
	meta.indirect = indirect ? 1 : 0;
	meta.kind = kind;
	return length;
}

static bool DecodeBasicTraceRange(uint64_t start, uint64_t end,
		std::vector<veh::VehHandler::TraceBasicBlocksState::Instruction>& instructions,
		std::vector<uint64_t>& blockStarts) {
	if (start >= end) return false;
	ZydisDecoder decoder;
	ZydisMachineMode machineMode;
	if (!InitTraceDecoder(decoder, machineMode)) return false;

	std::set<uint64_t> starts;
	starts.insert(start);
	uint64_t address = start;
	while (address < end) {
		MEMORY_BASIC_INFORMATION region{};
		if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(address)),
				&region, sizeof(region))) {
			return false;
		}
		const uint64_t regionBase = reinterpret_cast<uint64_t>(region.BaseAddress);
		const uint64_t regionEnd = regionBase + static_cast<uint64_t>(region.RegionSize);
		if (regionEnd <= address) return false;
		const bool readable = region.State == MEM_COMMIT &&
			(region.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
		if (!readable) {
			// PE image ranges may contain reserved or inaccessible gaps between
			// executable sections. They cannot contain an executed instruction, so
			// skip the whole region without turning a valid trace into decode failure.
			address = std::min(end, regionEnd);
			continue;
		}
		uint8_t bytes[ZYDIS_MAX_INSTRUCTION_LENGTH] = {};
		const uint64_t readableEnd = std::min(end, regionEnd);
		size_t available = static_cast<size_t>(std::min<uint64_t>(
			readableEnd - address, sizeof(bytes)));
		if (!SafeReadMem(address, bytes, available)) return false;
		veh::VehHandler::TraceBasicBlocksState::Instruction meta;
		bool decodedOk = false;
		uint8_t length = DecodeTraceInstruction(decoder, machineMode, address, bytes, available,
			meta, decodedOk, &starts, start, end);
		instructions.push_back(meta);
		if (instructions.size() > 1000000) return false;
		address += length;
	}

	blockStarts.assign(starts.begin(), starts.end());
	size_t blockIndex = 0;
	for (auto& instruction : instructions) {
		while (blockIndex + 1 < blockStarts.size() && blockStarts[blockIndex + 1] <= instruction.address)
			++blockIndex;
		instruction.staticBlockStart = blockStarts[blockIndex];
	}
	return !instructions.empty();
}

// Single-instruction decode used by the exception handler for addresses the
// sweep did not produce. Reads only the committed, readable part of the page
// run (no SEH inside the handler) and never allocates.
bool veh::DecodeTraceInstructionAt(uint64_t address, uint64_t limit,
		veh::VehHandler::TraceBasicBlocksState::Instruction& out) {
	if (address >= limit) return false;
	size_t available = static_cast<size_t>(std::min<uint64_t>(limit - address, ZYDIS_MAX_INSTRUCTION_LENGTH));
	for (uint64_t cursor = address; cursor < address + available;) {
		MEMORY_BASIC_INFORMATION region{};
		if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(cursor)), &region, sizeof(region)) ||
				region.State != MEM_COMMIT || (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
			available = static_cast<size_t>(cursor - address);
			break;
		}
		cursor = reinterpret_cast<uint64_t>(region.BaseAddress) + static_cast<uint64_t>(region.RegionSize);
	}
	if (!available) return false;
	uint8_t bytes[ZYDIS_MAX_INSTRUCTION_LENGTH] = {};
	memcpy(bytes, reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), available);
	ZydisDecoder decoder;
	ZydisMachineMode machineMode;
	if (!InitTraceDecoder(decoder, machineMode)) return false;
	out = {};
	bool decodedOk = false;
	DecodeTraceInstruction(decoder, machineMode, address, bytes, available, out, decodedOk, nullptr, 0, 0);
	out.staticBlockStart = 0;  // dynamic: no static block boundary
	return decodedOk;
}

static uint64_t RegFromCtx(const CONTEXT& ctx, uint8_t idx) {
#ifdef _WIN64
	switch (idx) {
		case 0: return ctx.Rax; case 1: return ctx.Rcx; case 2: return ctx.Rdx; case 3: return ctx.Rbx;
		case 4: return ctx.Rsp; case 5: return ctx.Rbp; case 6: return ctx.Rsi; case 7: return ctx.Rdi;
		case 8: return ctx.R8;  case 9: return ctx.R9;  case 10: return ctx.R10; case 11: return ctx.R11;
		case 12: return ctx.R12; case 13: return ctx.R13; case 14: return ctx.R14; case 15: return ctx.R15;
	}
#else
	switch (idx) {
		case 0: return ctx.Eax; case 1: return ctx.Ecx; case 2: return ctx.Edx; case 3: return ctx.Ebx;
		case 4: return ctx.Esp; case 5: return ctx.Ebp; case 6: return ctx.Esi; case 7: return ctx.Edi;
	}
#endif
	return 0;
}

enum class FlowType { DirectJump, DirectCall, IndirectBranch, Return, Conditional, Unknown };

struct InsnFlow {
	FlowType type = FlowType::Unknown;
	uint8_t  length = 0;
	uint64_t target = 0;
	bool     resolved = false;
	uint16_t retImm = 0;  // for ret imm16
};

static InsnFlow AnalyzeFlow(uint64_t rip, const CONTEXT& ctx) {
	InsnFlow f;
	uint8_t code[16] = {};
	if (!SafeReadMem(rip, code, 16)) return f;

	uint8_t* p = code;
	uint8_t rex = 0;

	// Skip legacy prefixes first (Intel SDM Vol.2 order: legacy -> REX -> opcode)
	while (p < code + 14 &&
	       (*p == 0x66 || *p == 0x67 || *p == 0xF2 || *p == 0xF3 ||
	        *p == 0x2E || *p == 0x3E || *p == 0x26 || *p == 0x36 ||
	        *p == 0x64 || *p == 0x65)) p++;
#ifdef _WIN64
	// REX prefix comes after legacy prefixes
	if (p < code + 15 && *p >= 0x40 && *p <= 0x4F) rex = *p++;
#endif
	if (p >= code + 16) return f;  // malformed (all prefixes, no opcode)

	uint8_t op = *p++;

	if (op == 0xE9) { // jmp rel32
		int32_t rel; memcpy(&rel, p, 4);
		f.type = FlowType::DirectJump; f.length = (uint8_t)(p - code) + 4;
		f.target = rip + f.length + rel; f.resolved = true;
	}
	else if (op == 0xEB) { // jmp rel8
		int8_t rel = (int8_t)*p;
		f.type = FlowType::DirectJump; f.length = (uint8_t)(p - code) + 1;
		f.target = rip + f.length + rel; f.resolved = true;
	}
	else if (op == 0xE8) { // call rel32
		int32_t rel; memcpy(&rel, p, 4);
		f.type = FlowType::DirectCall; f.length = (uint8_t)(p - code) + 4;
		f.target = rip + f.length + rel; f.resolved = true;
	}
	else if (op == 0xC3) { // ret
		f.type = FlowType::Return; f.length = (uint8_t)(p - code);
#ifdef _WIN64
		f.target = ReadPtr(ctx.Rsp);
#else
		f.target = ReadPtr(ctx.Esp);
#endif
		f.resolved = (f.target != 0);
	}
	else if (op == 0xC2) { // ret imm16
		uint16_t imm; memcpy(&imm, p, 2);
		f.type = FlowType::Return; f.length = (uint8_t)(p - code) + 2; f.retImm = imm;
#ifdef _WIN64
		f.target = ReadPtr(ctx.Rsp);
#else
		f.target = ReadPtr(ctx.Esp);
#endif
		f.resolved = (f.target != 0);
	}
	else if (op == 0xFF) { // indirect jmp/call
		uint8_t modrm = *p++;
		uint8_t mod = (modrm >> 6) & 3, reg = (modrm >> 3) & 7, rm = modrm & 7;
		if (reg != 2 && reg != 4) { f.type = FlowType::Unknown; return f; } // not call/jmp
		f.type = FlowType::IndirectBranch;

		if (mod == 3) { // register direct: jmp rax, call rbx
			uint8_t ri = rm | ((rex & 1) << 3);
			f.target = RegFromCtx(ctx, ri); f.resolved = true;
			f.length = (uint8_t)(p - code);
		}
#ifdef _WIN64
		else if (mod == 0 && rm == 5) { // [rip+disp32]
			int32_t disp; memcpy(&disp, p, 4); p += 4;
			f.length = (uint8_t)(p - code);
			f.target = ReadPtr(rip + f.length + disp); f.resolved = (f.target != 0);
		}
#else
		else if (mod == 0 && rm == 5) { // [disp32]
			uint32_t addr32; memcpy(&addr32, p, 4); p += 4;
			f.length = (uint8_t)(p - code);
			f.target = ReadPtr(addr32); f.resolved = (f.target != 0);
		}
#endif
		else if (rm == 4 && mod != 3) { // SIB byte - too complex
			f.type = FlowType::Unknown;
		}
		else if (mod == 0) { // [reg]
			uint8_t ri = rm | ((rex & 1) << 3);
			f.length = (uint8_t)(p - code);
			f.target = ReadPtr(RegFromCtx(ctx, ri)); f.resolved = (f.target != 0);
		}
		else if (mod == 1) { // [reg+disp8]
			uint8_t ri = rm | ((rex & 1) << 3);
			int8_t disp = (int8_t)*p++;
			f.length = (uint8_t)(p - code);
			f.target = ReadPtr(RegFromCtx(ctx, ri) + disp); f.resolved = (f.target != 0);
		}
		else if (mod == 2) { // [reg+disp32]
			uint8_t ri = rm | ((rex & 1) << 3);
			int32_t disp; memcpy(&disp, p, 4); p += 4;
			f.length = (uint8_t)(p - code);
			f.target = ReadPtr(RegFromCtx(ctx, ri) + disp); f.resolved = (f.target != 0);
		}
	}
	else if ((op >= 0x70 && op <= 0x7F) || (op == 0x0F)) { // conditional jmp
		f.type = FlowType::Conditional; // don't follow statically -- use TF
	}
	// else: non-branch instruction -> Unknown (use INT3/TF)

	return f;
}

// Verify address is in executable memory (prevents following into garbage)
static bool IsExecutableAddr(uint64_t addr) {
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) return false;
	return (mbi.State == MEM_COMMIT) &&
	       (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

static bool IsInTargetModule(uint64_t rip, const veh::VehHandler::ImportResolveState& ir) {
	for (auto& mr : ir.moduleRanges) {
		if (rip >= mr.base && rip < mr.end && mr.isTarget) return true;
	}
	return false;
}

// UEF safety net for follow_exceptions import resolution
// Called when SEH doesn't handle an exception during thunk tracing.
// Redirects thread to parkStub (NOP) with TF set -> SINGLE_STEP -> NotifyAndWait -> thread stops.
static LONG WINAPI ImportResolveUEF(PEXCEPTION_POINTERS info) {
	auto& ir = veh::VehHandler::Instance().importResolve_;
	if (ir.active.load(std::memory_order_acquire) && ir.parkStub) {
		ir.found = false;
		ir.targetAddress = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
		ir.active.store(false, std::memory_order_relaxed);
		ir.done.store(true, std::memory_order_release);
		// Redirect to parkStub (NOP) with TF -> SINGLE_STEP -> VEH NotifyAndWait
		info->ContextRecord->EFlags &= ~0x100; // clear TF first
		info->ContextRecord->EFlags |= 0x100;  // set TF for one SINGLE_STEP after NOP
#ifdef _WIN64
		info->ContextRecord->Rip = reinterpret_cast<DWORD64>(ir.parkStub);
#else
		info->ContextRecord->Eip = reinterpret_cast<DWORD>(ir.parkStub);
#endif
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

namespace veh {

PipeServer& PipeServer::Instance() {
	static PipeServer instance;
	return instance;
}

// --- Overlapped I/O helpers ---

bool PipeServer::AsyncReadExact(void* buf, DWORD size, DWORD timeoutMs) {
	DWORD totalRead = 0;
	while (totalRead < size) {
		OVERLAPPED ov = {};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;

		DWORD bytesRead = 0;
		BOOL ok = ReadFile(pipe_, static_cast<uint8_t*>(buf) + totalRead,
		                   size - totalRead, &bytesRead, &ov);

		if (!ok && GetLastError() != ERROR_IO_PENDING) {
			DWORD error = GetLastError();
			CloseHandle(ov.hEvent);
			SetLastError(error);
			return false;
		}

		if (ok) {
			CloseHandle(ov.hEvent);
			if (bytesRead == 0) return false;
			totalRead += bytesRead;
			continue;
		}

		HANDLE events[] = { ov.hEvent, stopEvent_ };
		DWORD nEvents = stopEvent_ ? 2 : 1;
		DWORD wait = WaitForMultipleObjects(nEvents, events, FALSE, timeoutMs);

		if (wait == WAIT_OBJECT_0) {
			BOOL completed = GetOverlappedResult(pipe_, &ov, &bytesRead, FALSE);
			DWORD error = completed ? ERROR_SUCCESS : GetLastError();
			CloseHandle(ov.hEvent);
			if (!completed || bytesRead == 0) {
				SetLastError(completed ? ERROR_BROKEN_PIPE : error);
				return false;
			}
			totalRead += bytesRead;
		} else {
			CancelIoEx(pipe_, &ov);
			CloseHandle(ov.hEvent);
			SetLastError(wait == WAIT_TIMEOUT ? WAIT_TIMEOUT : ERROR_OPERATION_ABORTED);
			return false;  // 타임아웃 or stop
		}
	}
	return true;
}

bool PipeServer::AsyncWriteExact(const void* buf, DWORD size, DWORD timeoutMs) {
	DWORD totalWritten = 0;
	while (totalWritten < size) {
		OVERLAPPED ov = {};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;

		DWORD bytesWritten = 0;
		BOOL ok = WriteFile(pipe_, static_cast<const uint8_t*>(buf) + totalWritten,
		                    size - totalWritten, &bytesWritten, &ov);

		if (!ok && GetLastError() != ERROR_IO_PENDING) {
			CloseHandle(ov.hEvent);
			return false;
		}

		if (ok) {
			CloseHandle(ov.hEvent);
			if (bytesWritten == 0) return false;
			totalWritten += bytesWritten;
			continue;
		}

		HANDLE events[] = { ov.hEvent, stopEvent_ };
		DWORD nEvents = stopEvent_ ? 2 : 1;
		DWORD wait = WaitForMultipleObjects(nEvents, events, FALSE, timeoutMs);

		if (wait == WAIT_OBJECT_0) {
			GetOverlappedResult(pipe_, &ov, &bytesWritten, FALSE);
			CloseHandle(ov.hEvent);
			if (bytesWritten == 0) return false;
			totalWritten += bytesWritten;
		} else {
			CancelIoEx(pipe_, &ov);
			CloseHandle(ov.hEvent);
			return false;
		}
	}
	return true;
}

// --- Lifecycle ---

bool PipeServer::Start(uint32_t targetPid) {
	if (running_) {
		LOG_WARN("PipeServer already running");
		return true;
	}

	targetPid_ = targetPid;
	std::wstring pipeName = GetPipeName(targetPid);

	stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!stopEvent_) {
		LOG_ERROR("CreateEventW for stopEvent_ failed: %lu", GetLastError());
		return false;
	}

	// Overlapped Named pipe
	pipe_ = CreateNamedPipeW(
		pipeName.c_str(),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1, 64 * 1024, 64 * 1024, 0, NULL
	);

	if (pipe_ == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateNamedPipeW failed: %lu", GetLastError());
		return false;
	}

	running_ = true;
	serverThread_ = std::thread(&PipeServer::ServerThread, this);

	// 스레드 ID가 확정될 때까지 대기 후 등록 (race 방지)
	// ServerThread 진입 시 serverTid_에 기록하고 serverTidReady_ 시그널
	{
		std::unique_lock<std::mutex> lk(serverTidMutex_);
		serverTidCv_.wait(lk, [this] { return serverTid_ != 0; });
		ThreadManager::Instance().RegisterInternalThread(serverTid_);
		VehHandler::Instance().SetInternalThread(serverTid_);
	}

	LOG_INFO("PipeServer started: %ls [overlapped]", pipeName.c_str());
	return true;
}

void PipeServer::Stop() {
	if (!running_) return;
	running_ = false;

	if (stopEvent_) SetEvent(stopEvent_);
	if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);

	if (serverThread_.joinable()) {
		serverThread_.join();
	}
	serverTid_ = 0;

	if (connected_) {
		DisconnectNamedPipe(pipe_);
		connected_ = false;
	}
	if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
	if (stopEvent_) { CloseHandle(stopEvent_); stopEvent_ = nullptr; }

	LOG_INFO("PipeServer stopped");
}

void PipeServer::EmergencyCleanup() {
	LOG_WARN("Emergency cleanup: adapter presumed dead");
	ValueScanner::Instance().Reset();
	BreakpointManager::Instance().RemoveAll();
	HwBreakpointManager::Instance().RemoveAll();
	VehHandler::Instance().Uninstall();
	ThreadManager::Instance().ResumeAll();
	ThreadManager::Instance().ThawAll();
	LOG_INFO("Emergency cleanup done: VEH uninstalled, all BPs removed, threads resumed");
}

void PipeServer::ServerThread() {
	LOG_INFO("Server thread started (tid=%u)", GetCurrentThreadId());

	// 스레드 이름 설정 (필터링 우회 시에도 식별 가능)
	typedef HRESULT(WINAPI* SetThreadDescription_t)(HANDLE, PCWSTR);
	static auto pSetDesc = reinterpret_cast<SetThreadDescription_t>(
		GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetThreadDescription"));
	if (pSetDesc) pSetDesc(GetCurrentThread(), L"VEH IPC");

	// Start()에 스레드 ID 전달 (RegisterInternalThread race 방지)
	{
		std::lock_guard<std::mutex> lk(serverTidMutex_);
		serverTid_ = GetCurrentThreadId();
	}
	serverTidCv_.notify_one();

	// DbgHelp 심볼 엔진 초기화
	StackWalker::Instance().Initialize();

	// 외부 루프: running_ 동안 클라이언트 연결을 반복 수락한다.
	// Detach 시 내부 커맨드 루프만 탈출하고 여기서 새 클라이언트를 기다린다.
	// Shutdown 시 running_=false가 되어 외부 루프도 종료된다.
	while (running_) {
		LOG_INFO("Waiting for client connection...");

		// Overlapped ConnectNamedPipe
		{
			OVERLAPPED ov = {};
			ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			BOOL ok = ConnectNamedPipe(pipe_, &ov);
			if (!ok) {
				DWORD err = GetLastError();
				if (err == ERROR_PIPE_CONNECTED) {
					// 이미 연결됨 — 정상
				} else if (err == ERROR_IO_PENDING) {
					HANDLE events[] = { ov.hEvent, stopEvent_ };
					// 재연결 대기: 타임아웃 없이 무한 대기 (stopEvent_로 깨움)
					DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
					if (wait != WAIT_OBJECT_0) {
						CloseHandle(ov.hEvent);
						if (running_) LOG_ERROR("ConnectNamedPipe stopped");
						break;
					}
					DWORD dummy;
					GetOverlappedResult(pipe_, &ov, &dummy, FALSE);
				} else {
					CloseHandle(ov.hEvent);
					LOG_ERROR("ConnectNamedPipe failed: %lu", err);
					break;
				}
			}
			CloseHandle(ov.hEvent);
		}

		if (!running_) break;

		connected_ = true;
		lastCommandTime_ = GetTickCount64();
		LOG_INFO("Client connected");

		// Detach 후 재연결 시 VEH 재설치 (최초 연결은 InitThread가 처리)
		if (!VehHandler::Instance().IsInstalled()) {
			VehHandler::Instance().Install();
			LOG_INFO("VEH handler re-installed for new session");
		}

		// Ready 이벤트 전송
		SendEvent(static_cast<uint32_t>(IpcEvent::Ready));

		// 내부 커맨드 루프: running_ && connected_ 동안 명령 처리
		// Detach 시 connected_=false로 내부 루프만 탈출
		// Shutdown 시 running_=false로 양쪽 루프 모두 탈출
		while (running_ && connected_) {
			IpcHeader hdr;
			if (!AsyncReadExact(&hdr, sizeof(hdr), READ_TIMEOUT_MS)) {
				if (!running_ || !connected_) break;
				DWORD readError = GetLastError();
				if (readError != WAIT_TIMEOUT && readError != ERROR_OPERATION_ABORTED &&
					readError != ERROR_IO_PENDING) {
					LOG_WARN("Control pipe disconnected: %lu", readError);
					connected_ = false;
					break;
				}

				// 하트비트 타임아웃 체크
				uint64_t elapsed = GetTickCount64() - lastCommandTime_;
				if (elapsed >= HEARTBEAT_TIMEOUT_MS) {
					LOG_ERROR("Heartbeat timeout: no command for %llu ms", elapsed);
					EmergencyCleanup();
					connected_ = false;
					break;
				}
				// 타임아웃이면 재시도 (정상 — READ_TIMEOUT_MS마다 체크)
				continue;
			}

			lastCommandTime_ = GetTickCount64();

			std::vector<uint8_t> payload;
			if (hdr.payloadSize > 0) {
				if (hdr.payloadSize > 16 * 1024 * 1024) {
					LOG_ERROR("Payload too large: %u", hdr.payloadSize);
					connected_ = false;
					break;
				}
				payload.resize(hdr.payloadSize);
				if (!AsyncReadExact(payload.data(), hdr.payloadSize, 3000)) {
					LOG_ERROR("AsyncReadExact(payload) failed");
					connected_ = false;
					break;
				}
			}

			LOG_DEBUG("IPC cmd=0x%04X size=%u", hdr.command, hdr.payloadSize);
			HandleCommand(hdr.command, payload.data(), hdr.payloadSize);
			// A long command (memory search, trace) is activity too; do not let its
			// duration count toward the idle heartbeat timeout.
			lastCommandTime_ = GetTickCount64();
		}

		// Detach 후: 파이프 연결만 끊고 외부 루프에서 새 클라이언트 대기
		// Shutdown 후: running_=false이므로 외부 루프도 종료
		if (running_) {
			DisconnectNamedPipe(pipe_);
			LOG_INFO("Client disconnected, ready for re-connection");
		}
	}

	connected_ = false;
	ThreadManager::Instance().UnregisterInternalThread(GetCurrentThreadId());
	LOG_INFO("Server thread exiting");
}

void PipeServer::HandleCommand(uint32_t command, const uint8_t* payload, uint32_t payloadSize) {
	auto cmd = static_cast<IpcCommand>(command);

	switch (cmd) {

	case IpcCommand::Heartbeat: {
		// 하트비트 응답 — HeartbeatAck 이벤트 전송
		SendEvent(static_cast<uint32_t>(IpcEvent::HeartbeatAck));
		break;
	}

	case IpcCommand::SetBreakpoint: {
		if (payloadSize < sizeof(SetBreakpointRequest)) {
			SetBreakpointResponse resp{IpcStatus::InvalidArgs, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetBreakpointRequest*>(payload);
		LOG_INFO("SetBreakpoint: addr=0x%llX", req->address);
		uint32_t id = BreakpointManager::Instance().Add(req->address);

		SetBreakpointResponse resp;
		resp.status = id ? IpcStatus::Ok : IpcStatus::Error;
		resp.id = id;
		SendResponse(command, &resp, sizeof(resp));
		LOG_INFO("SetBreakpoint: addr=0x%llX -> id=%u status=%d", req->address, id, (int)resp.status);
		break;
	}

	case IpcCommand::SetModuleLoadStop: {
		if (payloadSize < sizeof(SetModuleLoadStopRequest)) {
			SetModuleLoadStopResponse resp{IpcStatus::InvalidArgs};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetModuleLoadStopRequest*>(payload);
		// The wire buffer is exactly payloadSize; a sender that fills all 256 name
		// bytes leaves no NUL. Force-terminate a local copy before any strlen use.
		char name[sizeof(req->name) + 1];
		memcpy(name, req->name, sizeof(req->name));
		name[sizeof(req->name)] = '\0';
		auto& veh = VehHandler::Instance();
		if (req->action == 2)      veh.ClearModuleLoadPatterns();
		else if (req->action == 1) veh.RemoveModuleLoadPattern(name);
		else                       veh.AddModuleLoadPattern(name);
		LOG_INFO("SetModuleLoadStop: action=%u name=%s", req->action, name);
		SetModuleLoadStopResponse resp{IpcStatus::Ok};
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::RemoveBreakpoint: {
		if (payloadSize < sizeof(RemoveBreakpointRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const RemoveBreakpointRequest*>(payload);
		bool ok = BreakpointManager::Instance().Remove(req->id);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::NotFound;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::RemoveBreakpointByAddr: {
		if (payloadSize < sizeof(RemoveBreakpointByAddrRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const RemoveBreakpointByAddrRequest*>(payload);
		bool ok = BreakpointManager::Instance().RemoveByAddress(req->address);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::NotFound;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::SetHwBreakpoint: {
		if (payloadSize < sizeof(SetHwBreakpointRequest)) {
			SetHwBreakpointResponse resp{IpcStatus::InvalidArgs, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetHwBreakpointRequest*>(payload);
		auto type = static_cast<HwBreakType>(req->type);
		HwBreakSize bpSize;
		switch (req->size) {
		case 1: bpSize = HwBreakSize::Byte;  break;
		case 2: bpSize = HwBreakSize::Word;  break;
		case 4: bpSize = HwBreakSize::Dword; break;
		case 8: bpSize = HwBreakSize::Qword; break;
		default:
			SetHwBreakpointResponse resp{IpcStatus::InvalidArgs, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}

		uint32_t id = HwBreakpointManager::Instance().Add(req->address, type, bpSize);
		SetHwBreakpointResponse resp;
		resp.status = id ? IpcStatus::Ok : IpcStatus::Error;
		resp.id = id;
		resp.slot = 0;
		if (id) {
			auto hwbp = HwBreakpointManager::Instance().FindById(id);
			if (hwbp) resp.slot = hwbp->slot;

			// 모든 스레드의 DR 레지스터에 즉시 적용
			ApplyHwBreakpointsToAllThreads();
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::RemoveHwBreakpoint: {
		if (payloadSize < sizeof(RemoveHwBreakpointRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const RemoveHwBreakpointRequest*>(payload);
		bool ok = HwBreakpointManager::Instance().Remove(req->id);
		if (ok) {
			// 제거된 HW BP를 모든 스레드에서 반영
			ApplyHwBreakpointsToAllThreads();
		}
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::NotFound;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::Continue: {
		if (payloadSize < sizeof(uint32_t)) {  // backward compat: at least threadId
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ContinueRequest*>(payload);
		bool passEx = payloadSize >= sizeof(uint32_t) + sizeof(uint8_t)
			? (req->passException != 0) : false;
		bool wantDetails = payloadSize >= sizeof(ContinueRequest) && req->wantDetails != 0;
		auto stoppedThreadIds = []() {
			std::set<uint32_t> ids;
			for (uint32_t tid : VehHandler::Instance().GetStoppedThreadIds()) ids.insert(tid);
			for (uint32_t tid : ThreadManager::Instance().GetSuspendedThreadIds()) ids.insert(tid);
			return ids;
		};
		const auto stoppedBefore = wantDetails ? stoppedThreadIds() : std::set<uint32_t>{};
		// VEH 핸들러에서 대기 중인 스레드를 깨운다
		if (req->threadId == 0) {
			VehHandler::Instance().ResumeAllStoppedThreads();
		} else {
			VehHandler::Instance().ResumeStoppedThread(req->threadId, false, passEx);
		}
		// Pause (OS SuspendThread) 로 정지된 스레드도 resume
		// (VEH resume과 별개 -- Pause는 OS-level, Continue는 양쪽 모두 해제)
		if (req->threadId == 0) {
			ThreadManager::Instance().ResumeAll();
		} else {
			ThreadManager::Instance().ResumeThread(req->threadId);
		}
		if (!wantDetails) break;
		const auto stillStopped = stoppedThreadIds();
		std::vector<uint32_t> resumed;
		for (uint32_t tid : stoppedBefore) {
			if (stillStopped.find(tid) == stillStopped.end()) resumed.push_back(tid);
		}

		ContinueResponse resp{};
		resp.status = IpcStatus::Ok;
		resp.resumedCount = static_cast<uint32_t>(resumed.size());
		resp.stillStoppedCount = static_cast<uint32_t>(stillStopped.size());
		std::vector<uint8_t> response(sizeof(resp) +
			(resumed.size() + stillStopped.size()) * sizeof(uint32_t));
		memcpy(response.data(), &resp, sizeof(resp));
		uint8_t* out = response.data() + sizeof(resp);
		if (!resumed.empty()) {
			memcpy(out, resumed.data(), resumed.size() * sizeof(uint32_t));
			out += resumed.size() * sizeof(uint32_t);
		}
		for (uint32_t tid : stillStopped) {
			memcpy(out, &tid, sizeof(tid));
			out += sizeof(tid);
		}
		SendResponse(command, response.data(), static_cast<uint32_t>(response.size()));
		break;
	}

	case IpcCommand::StepOver:
	case IpcCommand::StepInto: {
		if (payloadSize < sizeof(StepRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const StepRequest*>(payload);
		if (!VehHandler::Instance().IsThreadStopped(req->threadId)) {
			IpcStatus status = IpcStatus::NotFound;
			SendResponse(command, &status, sizeof(status));
			break;
		}
		// step=true: BP rearm 후 다시 TF 설정하여 StepCompleted 이벤트 발생
		VehHandler::Instance().ResumeStoppedThread(req->threadId, /*step=*/true);
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::StepOut: {
		if (payloadSize < sizeof(StepRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const StepRequest*>(payload);
		if (!VehHandler::Instance().IsThreadStopped(req->threadId)) {
			IpcStatus status = IpcStatus::NotFound;
			SendResponse(command, &status, sizeof(status));
			break;
		}
		// StepOut도 step=true (함수 리턴까지는 어댑터에서 반복 step으로 구현)
		VehHandler::Instance().ResumeStoppedThread(req->threadId, /*step=*/true);
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::TerminateThread: {
		if (payloadSize < sizeof(TerminateThreadRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const TerminateThreadRequest*>(payload);
		HANDLE hThread = ::OpenThread(THREAD_TERMINATE, FALSE, req->threadId);
		IpcStatus status = IpcStatus::Error;
		if (hThread) {
			if (::TerminateThread(hThread, 0)) status = IpcStatus::Ok;
			CloseHandle(hThread);
		}
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::SetInstructionPointer: {
		if (payloadSize < sizeof(SetInstructionPointerRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const SetInstructionPointerRequest*>(payload);
		CONTEXT ctx;
		IpcStatus status = IpcStatus::Error;
		if (ThreadManager::Instance().GetContext(req->threadId, ctx)) {
#ifdef _WIN64
			ctx.Rip = req->address;
#else
			ctx.Eip = static_cast<DWORD>(req->address);
#endif
			if (ThreadManager::Instance().SetContext(req->threadId, ctx)) {
				status = IpcStatus::Ok;
			}
		}
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::SetRegister: {
		if (payloadSize < sizeof(SetRegisterRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const SetRegisterRequest*>(payload);
		CONTEXT ctx;
		SetRegisterResponse resp;
		resp.status = IpcStatus::Error;

		// VEH stopped context first, then fallback to ThreadManager
		bool isVehStopped = VehHandler::Instance().GetStoppedContext(req->threadId, ctx);
		bool gotContext = isVehStopped || ThreadManager::Instance().GetContext(req->threadId, ctx);
		if (gotContext && req->regIndex <= 17) {
			// Map regIndex to CONTEXT field (same order as RegisterSet: rax=0..rflags=17)
#ifdef _WIN64
			DWORD64* regMap[] = {
				&ctx.Rax, &ctx.Rbx, &ctx.Rcx, &ctx.Rdx,
				&ctx.Rsi, &ctx.Rdi, &ctx.Rbp, &ctx.Rsp,
				&ctx.R8,  &ctx.R9,  &ctx.R10, &ctx.R11,
				&ctx.R12, &ctx.R13, &ctx.R14, &ctx.R15,
				&ctx.Rip, (DWORD64*)&ctx.EFlags,
			};
			*regMap[req->regIndex] = req->value;
#else
			DWORD* regMap[] = {
				&ctx.Eax, &ctx.Ebx, &ctx.Ecx, &ctx.Edx,
				&ctx.Esi, &ctx.Edi, &ctx.Ebp, &ctx.Esp,
				nullptr,  nullptr,  nullptr,  nullptr,
				nullptr,  nullptr,  nullptr,  nullptr,
				&ctx.Eip, &ctx.EFlags,
			};
			if (regMap[req->regIndex]) {
				*regMap[req->regIndex] = static_cast<DWORD>(req->value);
			}
#endif
			// VEH stopped: update stoppedContexts_ (applied on resume)
			// Otherwise: direct SetContext
			if (isVehStopped) {
				if (VehHandler::Instance().SetStoppedContext(req->threadId, ctx)) {
					resp.status = IpcStatus::Ok;
				}
			} else {
				if (ThreadManager::Instance().SetContext(req->threadId, ctx)) {
					resp.status = IpcStatus::Ok;
				}
			}
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::SetRegisters: {
		SetRegistersResponse resp{IpcStatus::InvalidArgs};
		if (payloadSize < sizeof(SetRegistersRequest)) {
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetRegistersRequest*>(payload);
		CONTEXT ctx{};
		// Checkpoint restore is intentionally restricted to a VEH-stopped context;
		// applying a whole context to a running/suspended thread is not atomic with
		// respect to the debugger's stop lifecycle.
		if (!VehHandler::Instance().GetStoppedContext(req->threadId, ctx)) {
			resp.status = IpcStatus::NotFound;
			SendResponse(command, &resp, sizeof(resp));
			break;
		}
#ifdef _WIN64
		ctx.Rax=req->regs.rax; ctx.Rbx=req->regs.rbx; ctx.Rcx=req->regs.rcx; ctx.Rdx=req->regs.rdx;
		ctx.Rsi=req->regs.rsi; ctx.Rdi=req->regs.rdi; ctx.Rbp=req->regs.rbp; ctx.Rsp=req->regs.rsp;
		ctx.R8=req->regs.r8; ctx.R9=req->regs.r9; ctx.R10=req->regs.r10; ctx.R11=req->regs.r11;
		ctx.R12=req->regs.r12; ctx.R13=req->regs.r13; ctx.R14=req->regs.r14; ctx.R15=req->regs.r15;
		ctx.Rip=req->regs.rip; ctx.EFlags=static_cast<DWORD>(req->regs.rflags);
		memcpy(ctx.FltSave.XmmRegisters, req->regs.xmm, sizeof(req->regs.xmm));
#else
		ctx.Eax=static_cast<DWORD>(req->regs.rax); ctx.Ebx=static_cast<DWORD>(req->regs.rbx);
		ctx.Ecx=static_cast<DWORD>(req->regs.rcx); ctx.Edx=static_cast<DWORD>(req->regs.rdx);
		ctx.Esi=static_cast<DWORD>(req->regs.rsi); ctx.Edi=static_cast<DWORD>(req->regs.rdi);
		ctx.Ebp=static_cast<DWORD>(req->regs.rbp); ctx.Esp=static_cast<DWORD>(req->regs.rsp);
		ctx.Eip=static_cast<DWORD>(req->regs.rip); ctx.EFlags=static_cast<DWORD>(req->regs.rflags);
#endif
		resp.status = VehHandler::Instance().SetStoppedContext(req->threadId, ctx)
			? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::IsThreadStopped: {
		IsThreadStoppedResponse resp{IpcStatus::InvalidArgs, 0};
		if (payloadSize >= sizeof(IsThreadStoppedRequest)) {
			auto* req = reinterpret_cast<const IsThreadStoppedRequest*>(payload);
			resp.status = IpcStatus::Ok;
			resp.stopped = VehHandler::Instance().IsThreadStopped(req->threadId) ? 1 : 0;
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::Pause: {
		if (payloadSize < sizeof(PauseRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const PauseRequest*>(payload);
		if (req->threadId == 0) {
			ThreadManager::Instance().SuspendAllExcept(GetCurrentThreadId());
		} else {
			ThreadManager::Instance().SuspendThread(req->threadId);
		}
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::FreezeThread: {
		if (payloadSize < sizeof(FreezeThreadRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const FreezeThreadRequest*>(payload);
		auto& threads = ThreadManager::Instance();
		bool ok = true;
		switch (req->op) {
		case FreezeOp::List: break;
		case FreezeOp::Freeze: ok = req->threadId != 0 && threads.FreezeThread(req->threadId); break;
		case FreezeOp::Thaw:
			if (req->threadId == 0) threads.ThawAll();
			else ok = threads.ThawThread(req->threadId);
			break;
		default: ok = false; break;
		}
		auto frozen = threads.GetFrozenThreadIds();
		std::vector<uint8_t> buf(sizeof(FreezeThreadResponse) + frozen.size() * sizeof(uint32_t));
		auto* resp = reinterpret_cast<FreezeThreadResponse*>(buf.data());
		resp->status = ok ? IpcStatus::Ok : IpcStatus::Error;
		resp->count = static_cast<uint32_t>(frozen.size());
		if (!frozen.empty()) memcpy(buf.data() + sizeof(FreezeThreadResponse), frozen.data(), frozen.size() * sizeof(uint32_t));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetThreads: {
		auto threads = ThreadManager::Instance().EnumerateThreads();
		GetThreadsResponse resp;
		resp.status = IpcStatus::Ok;
		resp.count = static_cast<uint32_t>(threads.size());

		std::vector<uint8_t> buf(sizeof(resp) + threads.size() * sizeof(ThreadInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		auto* infos = reinterpret_cast<ThreadInfo*>(buf.data() + sizeof(resp));
		for (size_t i = 0; i < threads.size(); ++i) {
			infos[i].id = threads[i].id;
			memset(infos[i].name, 0, sizeof(infos[i].name));
			strncpy_s(infos[i].name, threads[i].name.c_str(), sizeof(infos[i].name) - 1);
		}
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetStackTrace: {
		if (payloadSize < sizeof(GetStackTraceRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const GetStackTraceRequest*>(payload);
		auto frames = StackWalker::Instance().Walk(req->threadId, req->startFrame, req->maxFrames);

		// StackWalk64 스택 바닥에서 address=0 프레임을 반환할 수 있다 — 필터링
		frames.erase(std::remove_if(frames.begin(), frames.end(),
			[](const auto& f) { return f.address == 0; }), frames.end());

		GetStackTraceResponse resp;
		resp.status = IpcStatus::Ok;
		resp.totalFrames = static_cast<uint32_t>(frames.size());
		resp.count = static_cast<uint32_t>(frames.size());

		std::vector<uint8_t> buf(sizeof(resp) + frames.size() * sizeof(StackFrameInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		auto* infos = reinterpret_cast<StackFrameInfo*>(buf.data() + sizeof(resp));
		for (size_t i = 0; i < frames.size(); ++i) {
			infos[i].address       = frames[i].address;
			infos[i].returnAddress = frames[i].returnAddress;
			infos[i].frameBase     = frames[i].frameBase;
			infos[i].moduleBase    = frames[i].moduleBase;
			infos[i].line          = frames[i].line;
			memset(infos[i].moduleName, 0, sizeof(infos[i].moduleName));
			strncpy_s(infos[i].moduleName, frames[i].moduleName.c_str(), sizeof(infos[i].moduleName) - 1);
			memset(infos[i].functionName, 0, sizeof(infos[i].functionName));
			strncpy_s(infos[i].functionName, frames[i].functionName.c_str(), sizeof(infos[i].functionName) - 1);
			memset(infos[i].sourceFile, 0, sizeof(infos[i].sourceFile));
			strncpy_s(infos[i].sourceFile, frames[i].sourceFile.c_str(), sizeof(infos[i].sourceFile) - 1);
		}
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetRegisters: {
		if (payloadSize < sizeof(GetRegistersRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const GetRegistersRequest*>(payload);
		CONTEXT ctx;
		GetRegistersResponse resp;
		memset(&resp, 0, sizeof(resp));

		// VEH 정지 컨텍스트를 먼저 시도, 실패 시 ThreadManager::GetContext fallback
		bool gotContext = VehHandler::Instance().GetStoppedContext(req->threadId, ctx)
			|| ThreadManager::Instance().GetContext(req->threadId, ctx);
		if (gotContext) {
			resp.status = IpcStatus::Ok;
#ifdef _WIN64
			resp.regs.is32bit = 0;
			resp.regs.rax = ctx.Rax; resp.regs.rbx = ctx.Rbx;
			resp.regs.rcx = ctx.Rcx; resp.regs.rdx = ctx.Rdx;
			resp.regs.rsi = ctx.Rsi; resp.regs.rdi = ctx.Rdi;
			resp.regs.rbp = ctx.Rbp; resp.regs.rsp = ctx.Rsp;
			resp.regs.r8  = ctx.R8;  resp.regs.r9  = ctx.R9;
			resp.regs.r10 = ctx.R10; resp.regs.r11 = ctx.R11;
			resp.regs.r12 = ctx.R12; resp.regs.r13 = ctx.R13;
			resp.regs.r14 = ctx.R14; resp.regs.r15 = ctx.R15;
			resp.regs.rip = ctx.Rip;
			resp.regs.rflags = ctx.EFlags;
			resp.regs.cs = ctx.SegCs; resp.regs.ss = ctx.SegSs;
			resp.regs.ds = ctx.SegDs; resp.regs.es = ctx.SegEs;
			resp.regs.fs = ctx.SegFs; resp.regs.gs = ctx.SegGs;
			// Debug registers
			resp.regs.dr0 = ctx.Dr0; resp.regs.dr1 = ctx.Dr1;
			resp.regs.dr2 = ctx.Dr2; resp.regs.dr3 = ctx.Dr3;
			resp.regs.dr6 = ctx.Dr6; resp.regs.dr7 = ctx.Dr7;
			static_assert(sizeof(ctx.FltSave.XmmRegisters) >= sizeof(resp.regs.xmm),
				"XMM register size mismatch");
			memcpy(resp.regs.xmm, ctx.FltSave.XmmRegisters, sizeof(resp.regs.xmm));
#else
			resp.regs.is32bit = 1;
			resp.regs.rax = ctx.Eax; resp.regs.rbx = ctx.Ebx;
			resp.regs.rcx = ctx.Ecx; resp.regs.rdx = ctx.Edx;
			resp.regs.rsi = ctx.Esi; resp.regs.rdi = ctx.Edi;
			resp.regs.rbp = ctx.Ebp; resp.regs.rsp = ctx.Esp;
			resp.regs.r8 = 0;  resp.regs.r9 = 0;
			resp.regs.r10 = 0; resp.regs.r11 = 0;
			resp.regs.r12 = 0; resp.regs.r13 = 0;
			resp.regs.r14 = 0; resp.regs.r15 = 0;
			resp.regs.rip = ctx.Eip;
			resp.regs.rflags = ctx.EFlags;
			resp.regs.cs = ctx.SegCs; resp.regs.ss = ctx.SegSs;
			resp.regs.ds = ctx.SegDs; resp.regs.es = ctx.SegEs;
			resp.regs.fs = ctx.SegFs; resp.regs.gs = ctx.SegGs;
			// Debug registers (x86도 동일한 CONTEXT 필드)
			resp.regs.dr0 = ctx.Dr0; resp.regs.dr1 = ctx.Dr1;
			resp.regs.dr2 = ctx.Dr2; resp.regs.dr3 = ctx.Dr3;
			resp.regs.dr6 = ctx.Dr6; resp.regs.dr7 = ctx.Dr7;
			// x86에는 XMM이 FloatSave에 포함되지 않음 — 0으로 초기화
			memset(resp.regs.xmm, 0, sizeof(resp.regs.xmm));
#endif
		} else {
			resp.status = IpcStatus::Error;
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::ReadMemory: {
		if (payloadSize < sizeof(ReadMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ReadMemoryRequest*>(payload);
		if (req->size > 16 * 1024 * 1024) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto data = MemoryManager::Instance().Read(req->address, req->size);

		// 활성 BP의 INT3(0xCC)를 원본 바이트로 치환 — 디스어셈블리/메모리 뷰에서
		// BP 유무와 관계없이 원본 명령어를 표시. 실제 메모리는 변경하지 않음.
		if (!data.empty()) {
			BreakpointManager::Instance().MaskBreakpointsInBuffer(req->address, data.data(), data.size());
		}

		IpcStatus status = data.empty() ? IpcStatus::Error : IpcStatus::Ok;
		std::vector<uint8_t> buf(sizeof(IpcStatus) + data.size());
		memcpy(buf.data(), &status, sizeof(status));
		if (!data.empty()) memcpy(buf.data() + sizeof(status), data.data(), data.size());
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::WriteMemory: {
		if (payloadSize < sizeof(WriteMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const WriteMemoryRequest*>(payload);
		const uint8_t* data = payload + sizeof(WriteMemoryRequest);
		uint32_t dataSize = payloadSize - sizeof(WriteMemoryRequest);
		if (dataSize != req->size) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		bool ok = MemoryManager::Instance().Write(req->address, data, dataSize);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::ResolveSourceLine: {
		if (payloadSize < sizeof(ResolveSourceLineRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ResolveSourceLineRequest*>(payload);

		// 안전한 복사본 생성 — null 종단 강제
		ResolveSourceLineRequest safeReq = *req;
		safeReq.fileName[sizeof(safeReq.fileName) - 1] = '\0';

		ResolveSourceLineResponse resp;
		resp.status = IpcStatus::Error;
		resp.address = 0;

		IMAGEHLP_LINE64 lineInfo = {};
		lineInfo.SizeOfStruct = sizeof(lineInfo);
		LONG displacement = 0;

		HANDLE hProcess = GetCurrentProcess();

		// 모듈 목록 갱신 (detach/재연결 시 스테일 방지)
		SymRefreshModuleList(hProcess);

		if (SymGetLineFromName64(hProcess, NULL, safeReq.fileName, safeReq.line, &displacement, &lineInfo)) {
			resp.status = IpcStatus::Ok;
			resp.address = lineInfo.Address;
			LOG_INFO("ResolveSourceLine: %s:%u -> 0x%llX", safeReq.fileName, safeReq.line, resp.address);
		} else {
			DWORD err = GetLastError();
			LOG_WARN("ResolveSourceLine failed: %s:%u (error=%lu)", safeReq.fileName, safeReq.line, err);

			// 풀 경로 실패 시 파일명만으로 재시도
			const char* baseName = strrchr(safeReq.fileName, '\\');
			if (!baseName) baseName = strrchr(safeReq.fileName, '/');
			if (baseName) {
				baseName++; // 구분자 건너뛰기
				lineInfo = {};
				lineInfo.SizeOfStruct = sizeof(lineInfo);
				displacement = 0;
				if (SymGetLineFromName64(hProcess, NULL, baseName, safeReq.line, &displacement, &lineInfo)) {
					resp.status = IpcStatus::Ok;
					resp.address = lineInfo.Address;
					LOG_INFO("ResolveSourceLine (basename retry): %s:%u -> 0x%llX", baseName, safeReq.line, resp.address);
				} else {
					LOG_WARN("ResolveSourceLine basename retry also failed: %s:%u (error=%lu)", baseName, safeReq.line, GetLastError());
				}
			}
		}

		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::ResolveFunction: {
		if (payloadSize < sizeof(ResolveFunctionRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ResolveFunctionRequest*>(payload);

		// 안전한 복사본 생성 — null 종단 강제
		ResolveFunctionRequest safeReq = *req;
		safeReq.functionName[sizeof(safeReq.functionName) - 1] = '\0';

		ResolveFunctionResponse resp;
		resp.status = IpcStatus::Error;
		resp.address = 0;

		constexpr size_t kSymBufSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME;
		uint8_t symBuf[kSymBufSize];
		auto* symInfo = reinterpret_cast<SYMBOL_INFO*>(symBuf);
		symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		symInfo->MaxNameLen = MAX_SYM_NAME;

		HANDLE hProcess = GetCurrentProcess();
		if (SymFromName(hProcess, safeReq.functionName, symInfo)) {
			resp.status = IpcStatus::Ok;
			resp.address = symInfo->Address;
			LOG_INFO("ResolveFunction: %s -> 0x%llX", safeReq.functionName, resp.address);
		} else {
			LOG_WARN("ResolveFunction failed: %s (error=%lu)", safeReq.functionName, GetLastError());
		}

		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::EnumLocals: {
		if (payloadSize < sizeof(EnumLocalsRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const EnumLocalsRequest*>(payload);

		auto locals = StackWalker::Instance().EnumLocals(
			req->threadId, req->instructionAddress, req->frameBase);

		// Build variable-length response
		size_t respSize = sizeof(EnumLocalsResponse) + locals.size() * sizeof(LocalVariableInfo);
		std::vector<uint8_t> respBuf(respSize, 0);
		auto* resp2 = reinterpret_cast<EnumLocalsResponse*>(respBuf.data());
		resp2->status = IpcStatus::Ok;
		resp2->count = static_cast<uint32_t>(locals.size());
		if (!locals.empty()) {
			memcpy(respBuf.data() + sizeof(EnumLocalsResponse),
			       locals.data(), locals.size() * sizeof(LocalVariableInfo));
		}

		SendResponse(command, respBuf.data(), static_cast<uint32_t>(respSize));
		break;
	}

	case IpcCommand::Symbolize: {
		auto* req = reinterpret_cast<const SymbolizeRequest*>(payload);
		if (payloadSize < sizeof(SymbolizeRequest) || req->count == 0 || req->count > kSymbolizeMaxAddresses
			|| payloadSize != sizeof(SymbolizeRequest) + req->count * sizeof(uint64_t)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		std::vector<uint64_t> addresses(req->count);
		memcpy(addresses.data(), payload + sizeof(SymbolizeRequest), req->count * sizeof(uint64_t));
		auto symbols = StackWalker::Instance().Symbolize(addresses);

		std::vector<uint8_t> respBuf(sizeof(SymbolizeResponse) + symbols.size() * sizeof(SymbolizeEntry), 0);
		auto* resp = reinterpret_cast<SymbolizeResponse*>(respBuf.data());
		resp->status = IpcStatus::Ok;
		resp->count = static_cast<uint32_t>(symbols.size());
		auto* entries = reinterpret_cast<SymbolizeEntry*>(respBuf.data() + sizeof(SymbolizeResponse));
		for (size_t i = 0; i < symbols.size(); ++i) {
			auto& e = entries[i];
			e.address = addresses[i];
			e.moduleBase = symbols[i].moduleBase;
			e.displacement = symbols[i].displacement;
			e.line = symbols[i].line;
			strncpy_s(e.moduleName, symbols[i].moduleName.c_str(), _TRUNCATE);
			strncpy_s(e.functionName, symbols[i].functionName.c_str(), _TRUNCATE);
			strncpy_s(e.sourceFile, symbols[i].sourceFile.c_str(), _TRUNCATE);
		}
		SendResponse(command, respBuf.data(), static_cast<uint32_t>(respBuf.size()));
		break;
	}

	case IpcCommand::DisplayType: {
		if (payloadSize < sizeof(DisplayTypeRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		DisplayTypeRequest req;
		memcpy(&req, payload, sizeof(req));
		req.typeName[sizeof(req.typeName) - 1] = '\0';
		if (req.maxMembers == 0 || req.maxMembers > kDisplayTypeMaxMembers) req.maxMembers = kDisplayTypeMaxMembers;
		DisplayTypeResponse resp{};
		std::vector<DisplayTypeMember> members;
		resp.status = StackWalker::Instance().DisplayType(req, resp, members) ? IpcStatus::Ok : IpcStatus::NotFound;
		resp.count = static_cast<uint32_t>(members.size());
		std::vector<uint8_t> buf(sizeof(resp) + members.size() * sizeof(DisplayTypeMember));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (!members.empty())
			memcpy(buf.data() + sizeof(resp), members.data(), members.size() * sizeof(DisplayTypeMember));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetModules: {
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid_);
		if (snap == INVALID_HANDLE_VALUE) {
			GetModulesResponse resp{IpcStatus::Error, 0};
			SendResponse(command, &resp, sizeof(resp));
			break;
		}
		std::vector<ModuleInfo> modules;
		MODULEENTRY32W me;
		me.dwSize = sizeof(me);
		if (Module32FirstW(snap, &me)) {
			do {
				ModuleInfo mi = {};
				mi.baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
				mi.size = me.modBaseSize;
				WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, mi.name, sizeof(mi.name), NULL, NULL);
				mi.name[sizeof(mi.name) - 1] = '\0';
				WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, mi.path, sizeof(mi.path), NULL, NULL);
				mi.path[sizeof(mi.path) - 1] = '\0';
				modules.push_back(mi);
			} while (Module32NextW(snap, &me));
		}
		CloseHandle(snap);

		GetModulesResponse resp;
		resp.status = IpcStatus::Ok;
		resp.count = static_cast<uint32_t>(modules.size());
		std::vector<uint8_t> buf(sizeof(resp) + modules.size() * sizeof(ModuleInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (!modules.empty()) memcpy(buf.data() + sizeof(resp), modules.data(), modules.size() * sizeof(ModuleInfo));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::TraceCallers: {
		if (payloadSize < sizeof(TraceCallersRequest)) {
			TraceCallersResponse resp{IpcStatus::InvalidArgs, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const TraceCallersRequest*>(payload);
		LOG_INFO("TraceCallers: addr=0x%llX duration=%ums", req->address, req->durationMs);

		// 기존 BP가 이 주소에 있는지 확인
		auto& bpMgr = BreakpointManager::Instance();
		bool wasExistingBp = bpMgr.FindByAddress(req->address).has_value();

		// BP 설정 (기존 BP가 있으면 그 id를 재사용)
		uint32_t bpId = bpMgr.Add(req->address);
		if (!bpId) {
			TraceCallersResponse resp{IpcStatus::Error, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}

		// Trace 시작
		auto& veh = VehHandler::Instance();
		veh.StartTrace(req->address);

		// duration 대기 (스레드가 이미 실행 중이면 BP 히트됨)
		Sleep(req->durationMs);

		// 1) 먼저 trace 모드 종료 (새 히트가 일반 BP 경로로 빠지지 않도록)
		// 2) 그 다음 BP 제거 (기존 사용자 BP면 보존)
		veh.StopTrace();
		Sleep(10); // 진행 중인 VEH 핸들러 완료 대기
		if (!wasExistingBp) {
			bpMgr.Remove(bpId);
		}

		// 결과 수집
		uint32_t totalHits = 0;
		auto callers = veh.GetTraceResults(totalHits);

		// 응답 구성
		TraceCallersResponse resp;
		resp.status = IpcStatus::Ok;
		resp.totalHits = totalHits;
		resp.uniqueCallers = static_cast<uint32_t>(callers.size());

		std::vector<uint8_t> buf(sizeof(resp) + callers.size() * sizeof(TraceCallerEntry));
		memcpy(buf.data(), &resp, sizeof(resp));

		size_t idx = 0;
		auto* entries = reinterpret_cast<TraceCallerEntry*>(buf.data() + sizeof(resp));
		for (const auto& [caller, count] : callers) {
			entries[idx].callerAddress = caller;
			entries[idx].hitCount = count;
			idx++;
		}

		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		LOG_INFO("TraceCallers: %u hits, %u unique callers", totalHits, resp.uniqueCallers);
		break;
	}

	case IpcCommand::AllocateMemory: {
		if (payloadSize < sizeof(AllocateMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const AllocateMemoryRequest*>(payload);
		AllocateMemoryResponse resp;
		resp.address = MemoryManager::Instance().Allocate(req->size, req->protection);
		resp.status = resp.address ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::FreeMemory: {
		if (payloadSize < sizeof(FreeMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const FreeMemoryRequest*>(payload);
		bool ok = MemoryManager::Instance().Free(req->address, req->size);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::QueryMemoryMap: {
		if (payloadSize < sizeof(QueryMemoryMapRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const QueryMemoryMapRequest*>(payload);
		const uint32_t maxRegions = (req->maxRegions == 0 || req->maxRegions > 65536) ? 65536 : req->maxRegions;
		std::vector<MemoryRegionEntry> regions;
		QueryMemoryMapResponse resp{};
		resp.nextAddress = MemoryManager::Instance().QueryMap(
			req->startAddress, req->endAddress, maxRegions, req->includeFree != 0, regions);
		resp.status = IpcStatus::Ok;
		resp.count = static_cast<uint32_t>(regions.size());
		resp.truncated = resp.nextAddress ? 1 : 0;
		std::vector<uint8_t> buf(sizeof(resp) + regions.size() * sizeof(MemoryRegionEntry));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (!regions.empty())
			memcpy(buf.data() + sizeof(resp), regions.data(), regions.size() * sizeof(MemoryRegionEntry));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::SearchMemory: {
		auto* req = reinterpret_cast<const SearchMemoryRequest*>(payload);
		if (payloadSize < sizeof(SearchMemoryRequest) || req->patternSize == 0 || req->patternSize > 4096
			|| payloadSize != sizeof(SearchMemoryRequest) + 2ull * req->patternSize
			|| req->maxResults == 0 || req->maxResults > 100000 || req->alignment > 4096) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		const uint8_t* pattern = payload + sizeof(SearchMemoryRequest);
		const uint8_t* mask = pattern + req->patternSize;
		MemoryManager::SearchResult result;
		const uint64_t payloadStart = reinterpret_cast<uint64_t>(payload);
		bool ok = MemoryManager::Instance().Search(*req, pattern, mask,
			payloadStart, payloadStart + payloadSize, result);
		// The request buffer is freed after this handler; wipe it so a later
		// search cannot find the stale pattern in freed heap memory.
		SecureZeroMemory(const_cast<uint8_t*>(payload), payloadSize);

		SearchMemoryResponse resp{};
		resp.status = ok ? IpcStatus::Ok : IpcStatus::Error;
		resp.count = static_cast<uint32_t>(result.hits.size());
		resp.truncated = result.nextAddress ? 1 : 0;
		resp.regionsScanned = result.regionsScanned;
		resp.scannedBytes = result.scannedBytes;
		resp.nextAddress = result.nextAddress;
		std::vector<uint8_t> buf(sizeof(resp) + result.hits.size() * sizeof(uint64_t));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (!result.hits.empty())
			memcpy(buf.data() + sizeof(resp), result.hits.data(), result.hits.size() * sizeof(uint64_t));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::ValueScan: {
		ValueScanResponse resp{};
		if (payloadSize != sizeof(ValueScanRequest)) {
			resp.status = IpcStatus::InvalidArgs;
			resp.failure = ValueScanFailure::InvalidRequest;
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const ValueScanRequest*>(payload);
		if (req->operation > ValueScanOperation::Reset || req->valueType > ValueScanType::F64
			|| req->compare > ValueScanCompare::DecreasedBy || req->maxResults == 0
			|| req->maxResults > 1000 || req->alignment > 4096) {
			resp.status = IpcStatus::InvalidArgs;
			resp.failure = ValueScanFailure::InvalidRequest;
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		std::vector<ValueScanEntry> entries(req->maxResults);
		const uint64_t payloadStart = reinterpret_cast<uint64_t>(payload);
		ValueScanner::Instance().Scan(*req, resp, entries.data(),
			payloadStart, payloadStart + payloadSize);
		std::vector<uint8_t> buf(sizeof(resp) + static_cast<size_t>(resp.count) * sizeof(ValueScanEntry));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (resp.count)
			memcpy(buf.data() + sizeof(resp), entries.data(), static_cast<size_t>(resp.count) * sizeof(ValueScanEntry));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::ExecuteShellcode: {
		if (payloadSize < sizeof(ExecuteShellcodeRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ExecuteShellcodeRequest*>(payload);
		const uint8_t* code = payload + sizeof(ExecuteShellcodeRequest);
		uint32_t codeSize = payloadSize - sizeof(ExecuteShellcodeRequest);
		if (codeSize != req->size) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		ExecuteShellcodeResponse resp = {};
		bool crashed = false;
		uint32_t exCode = 0;
		uint64_t exAddr = 0;
		bool ok = MemoryManager::Instance().ExecuteShellcode(
			code, codeSize, req->timeoutMs, resp.allocatedAddress, resp.exitCode,
			crashed, exCode, exAddr);
		resp.status = ok ? IpcStatus::Ok : IpcStatus::Error;
		resp.crashed = crashed ? 1 : 0;
		resp.exceptionCode = exCode;
		resp.exceptionAddress = exAddr;
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::TraceRegister: {
		if (payloadSize < sizeof(TraceRegisterRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const TraceRegisterRequest*>(payload);
		if (req->maxSteps == 0 || req->maxSteps > 100000 || req->regIndex > 17) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}

		// Start trace (VEH handler does the stepping loop internally)
		VehHandler::Instance().StartTraceRegister(
			req->threadId, req->regIndex, req->maxSteps, req->mode, req->compareValue);

		// Wait for VEH handler to signal completion
		auto& state = VehHandler::Instance().traceReg_;
		int waitMs = 0;
		int maxWaitMs = static_cast<int>(req->maxSteps) * 10 + 5000; // generous timeout
		while (!state.done.load(std::memory_order_acquire) && waitMs < maxWaitMs) {
			Sleep(10);
			waitMs += 10;
		}

		TraceRegisterResponse resp;
		if (state.done.load(std::memory_order_acquire)) {
			resp.status = IpcStatus::Ok;
			resp.found = state.found ? 1 : 0;
			resp.stepsExecuted = state.stepsExecuted;
			resp.address = state.resultAddress;
			resp.oldValue = state.oldValue;
			resp.newValue = state.newValue;
		} else {
			resp.status = IpcStatus::Error;
			resp.found = 0;
			resp.stepsExecuted = 0;  // don't read non-atomic from racing VEH thread
			resp.address = 0;
			resp.oldValue = 0;
			resp.newValue = 0;
			state.active.store(false, std::memory_order_relaxed);
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::TraceMemory: {
		if (payloadSize < sizeof(TraceMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const TraceMemoryRequest*>(payload);

		// Read initial value
		uint64_t oldVal = 0;
		auto initData = MemoryManager::Instance().Read(req->address, req->size);
		if (!initData.empty()) {
			memcpy(&oldVal, initData.data(), (req->size > 8) ? 8 : req->size);
		}

		// Set temp HW data breakpoint (write)
		HwBreakSize bpSize = HwBreakSize::Dword;
		switch (req->size) {
			case 1: bpSize = HwBreakSize::Byte; break;
			case 2: bpSize = HwBreakSize::Word; break;
			case 4: bpSize = HwBreakSize::Dword; break;
			case 8: bpSize = HwBreakSize::Qword; break;
		}
		uint32_t bpId = HwBreakpointManager::Instance().Add(req->address, HwBreakType::Write, bpSize);
		if (bpId == 0) {
			TraceMemoryResponse resp = {};
			resp.status = IpcStatus::Error;
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		ApplyHwBreakpointsToAllThreads();

		// Setup VEH trace state (VEH handler checks this on HW BP hit)
		auto& tm = VehHandler::Instance().traceMem_;
		tm.hwBpId = bpId;
		tm.watchAddress = req->address;
		tm.watchSize = req->size;
		tm.oldValue = oldVal;
		tm.found = false;
		tm.done.store(false, std::memory_order_relaxed);
		tm.active.store(true, std::memory_order_release);

		// Resume all stopped threads
		VehHandler::Instance().ResumeAllStoppedThreads();
		ThreadManager::Instance().ResumeAll();

		// Poll done flag (VEH handler sets it on HW BP hit)
		uint32_t timeoutMs = req->timeoutMs;
		if (timeoutMs == 0) timeoutMs = 10000;
		if (timeoutMs > 60000) timeoutMs = 60000;
		int elapsed = 0;
		while (!tm.done.load(std::memory_order_acquire) && elapsed < (int)timeoutMs) {
			Sleep(10);
			elapsed += 10;
		}

		TraceMemoryResponse resp = {};
		if (tm.done.load(std::memory_order_acquire)) {
			resp.status = IpcStatus::Ok;
			resp.found = tm.found ? 1 : 0;
			resp.threadId = tm.threadId;
			resp.instructionAddress = tm.instructionAddress;
			resp.oldValue = tm.oldValue;
			resp.newValue = tm.newValue;
		} else {
			// Timeout: cleanup
			tm.active.store(false, std::memory_order_relaxed);
			HwBreakpointManager::Instance().Remove(bpId);
			ApplyHwBreakpointsToAllThreads();
			resp.status = IpcStatus::Ok;
			resp.found = 0;
		}

		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::ResolveImport: {
		if (payloadSize < sizeof(ResolveImportRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ResolveImportRequest*>(payload);
		uint32_t count = req->count;
		if (count == 0 || count > 2000) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		uint32_t maxSteps = req->maxStepsPerThunk;
		if (maxSteps == 0) maxSteps = 1000;
		if (maxSteps > 10000) maxSteps = 10000;
		bool followExceptions = (req->followExceptions != 0);
		bool systemOnly = (req->systemOnly != 0);

		const uint64_t* thunks = reinterpret_cast<const uint64_t*>(
			payload + sizeof(ResolveImportRequest));
		if (payloadSize < sizeof(ResolveImportRequest) + count * sizeof(uint64_t)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}

		// Parse target module names (after thunk addresses)
		std::vector<std::string> targetModules;
		if (req->targetModuleCount > 0) {
			const char* modData = reinterpret_cast<const char*>(
				payload + sizeof(ResolveImportRequest) + count * sizeof(uint64_t));
			size_t modDataSize = payloadSize - sizeof(ResolveImportRequest) - count * sizeof(uint64_t);
			for (uint8_t m = 0; m < req->targetModuleCount && modDataSize >= 64; m++) {
				char buf[65] = {};
				memcpy(buf, modData + m * 64, 64);
				// Lowercase for case-insensitive matching
				for (char* p = buf; *p; p++) *p = static_cast<char>(tolower(*p));
				targetModules.push_back(buf);
			}
		}

		// Get Windows system directory for system_only filter
		wchar_t sysDir[MAX_PATH] = {};
		if (systemOnly) {
			GetSystemDirectoryW(sysDir, MAX_PATH);
			// Ensure lowercase for comparison
			for (wchar_t* p = sysDir; *p; p++) *p = towlower(*p);
		}

		// Build module range table with isTarget filter
		auto& ir = VehHandler::Instance().importResolve_;
		ir.moduleRanges.clear();
		{
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
			if (snap != INVALID_HANDLE_VALUE) {
				MODULEENTRY32W me; me.dwSize = sizeof(me);
				bool first = true;
				if (Module32FirstW(snap, &me)) {
					do {
						uint64_t base = reinterpret_cast<uint64_t>(me.modBaseAddr);
						uint64_t end = base + me.modBaseSize;

						bool isTarget = true;  // default: all non-exe modules
						if (first) {
							ir.exeBase = base;
							ir.exeEnd = end;
							isTarget = false;  // main exe is never a target
							first = false;
						} else if (!targetModules.empty()) {
							// Filter: only modules in target list
							char modName[256] = {};
							WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, modName, sizeof(modName), nullptr, nullptr);
							for (char* p = modName; *p; p++) *p = static_cast<char>(tolower(*p));
							// Remove .dll extension for matching
							char* dot = strrchr(modName, '.');
							std::string nameNoExt(modName, dot ? dot : modName + strlen(modName));
							isTarget = false;
							for (auto& tm : targetModules) {
								if (tm == modName || tm == nameNoExt) { isTarget = true; break; }
							}
						} else if (systemOnly) {
							// Filter: only system DLLs (path under Windows system dir)
							wchar_t modPath[MAX_PATH];
							wcscpy_s(modPath, me.szExePath);
							for (wchar_t* p = modPath; *p; p++) *p = towlower(*p);
							isTarget = (wcsstr(modPath, sysDir) == modPath);
						}

						ir.moduleRanges.push_back({base, end, isTarget});
					} while (Module32NextW(snap, &me));
				}
				CloseHandle(snap);
			}
		}

		// Allocate parkStub + install UEF safety net if follow_exceptions
		LPTOP_LEVEL_EXCEPTION_FILTER prevUEF = nullptr;
		if (followExceptions) {
			// NOP sled (0x90) - UEF redirects here on unhandled exception
			ir.parkStub = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (ir.parkStub) {
				memset(ir.parkStub, 0x90, 4096);  // fill with NOPs
				prevUEF = SetUnhandledExceptionFilter(ImportResolveUEF);
			}
			// If VirtualAlloc failed, parkStub=NULL -> UEF not installed -> follow_exceptions
			// still works (SEH pass-through) but unhandled exceptions will crash as before
		}

		// Save original context
		CONTEXT origCtx;
		if (!VehHandler::Instance().GetStoppedContext(req->threadId, origCtx)) {
			if (followExceptions && ir.parkStub) {
				SetUnhandledExceptionFilter(prevUEF);
				VirtualFree(ir.parkStub, 0, MEM_RELEASE); ir.parkStub = nullptr;
			}
			IpcStatus status = IpcStatus::Error;
			SendResponse(command, &status, sizeof(status));
			return;
		}

		// Process each thunk
		std::vector<uint8_t> respBuf(sizeof(ResolveImportResponse) + count * sizeof(ResolveImportEntry));
		auto* resp = reinterpret_cast<ResolveImportResponse*>(respBuf.data());
		auto* entries = reinterpret_cast<ResolveImportEntry*>(respBuf.data() + sizeof(ResolveImportResponse));
		resp->status = IpcStatus::Ok;
		resp->count = count;

		for (uint32_t i = 0; i < count; i++) {
			memset(&entries[i], 0, sizeof(ResolveImportEntry));
			entries[i].thunkAddress = thunks[i];

			// Call stub: proper calling convention + DR cleanup
			CONTEXT tmpCtx = origCtx;
			{
				bool stackOk = true;
#ifdef _WIN64
				uint64_t fakeRet = ir.parkStub ? reinterpret_cast<uint64_t>(ir.parkStub) : origCtx.Rip;
				tmpCtx.Rsp = (tmpCtx.Rsp & ~0xFULL);
				tmpCtx.Rsp -= 0x28;
				if (IsBadWritePtr(reinterpret_cast<LPVOID>(tmpCtx.Rsp), 0x28)) {
					stackOk = false;
				} else {
					memset(reinterpret_cast<void*>(tmpCtx.Rsp), 0, 0x28);
					*reinterpret_cast<uint64_t*>(tmpCtx.Rsp) = fakeRet;
				}
				tmpCtx.Rip = thunks[i];
#else
				uint32_t fakeRet = ir.parkStub ? reinterpret_cast<uint32_t>(ir.parkStub) : origCtx.Eip;
				tmpCtx.Esp = (tmpCtx.Esp & ~0xFU);
				tmpCtx.Esp -= 4;
				if (IsBadWritePtr(reinterpret_cast<LPVOID>(tmpCtx.Esp), 4)) {
					stackOk = false;
				} else {
					*reinterpret_cast<uint32_t*>(tmpCtx.Esp) = static_cast<uint32_t>(fakeRet);
				}
				tmpCtx.Eip = static_cast<DWORD>(thunks[i]);
#endif
				if (!stackOk) { entries[i].resolved = 0; continue; }
			}
			// DR register cleanup: prevent anti-debug detection
			tmpCtx.Dr0 = tmpCtx.Dr1 = tmpCtx.Dr2 = tmpCtx.Dr3 = 0;
			tmpCtx.Dr6 = 0; tmpCtx.Dr7 = 0;
			VehHandler::Instance().SetStoppedContext(req->threadId, tmpCtx);

			// Init trace state
			ir.threadId = req->threadId;
			ir.maxSteps = maxSteps;
			ir.followExceptions = followExceptions;
			ir.exceptionsPassed = 0;
			ir.stepsExecuted = 0;
			ir.traceLogIdx = 0;
			ir.pendingInt3Addr.store(0, std::memory_order_relaxed);
			ir.pendingInt3Byte.store(0, std::memory_order_relaxed);
			memset(ir.traceLog, 0, sizeof(ir.traceLog));
			ir.found = false;
			ir.targetAddress = 0;

			// === Static analysis + INT3/TF hybrid loop ===
			uint32_t stepCount = 0;
			bool resolved = false;

			while (stepCount < maxSteps) {
				CONTEXT curCtx;
				if (!VehHandler::Instance().GetStoppedContext(req->threadId, curCtx)) break;
#ifdef _WIN64
				uint64_t rip = curCtx.Rip;
#else
				uint64_t rip = curCtx.Eip;
#endif
				// Check if in target module
				if (IsInTargetModule(rip, ir)) {
					// SymFromAddr validation: check if at/near function entry
					DWORD64 displacement = 0;
					char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
					SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
					sym->SizeOfStruct = sizeof(SYMBOL_INFO);
					sym->MaxNameLen = MAX_SYM_NAME;
					bool hasSym = SymFromAddr(GetCurrentProcess(), rip, &displacement, sym);
					if (hasSym && displacement <= 0x100) {
						// Valid function entry -- resolved!
						entries[i].resolved = 1;
						entries[i].targetAddress = rip;
						strncpy_s(entries[i].functionName, sym->Name, sizeof(entries[i].functionName) - 1);
						IMAGEHLP_MODULE64 modInfo = {}; modInfo.SizeOfStruct = sizeof(modInfo);
						if (SymGetModuleInfo64(GetCurrentProcess(), rip, &modInfo))
							strncpy_s(entries[i].moduleName, modInfo.ModuleName, sizeof(entries[i].moduleName) - 1);
						resolved = true;
						break;
					}
					// No symbol or large displacement -- might be trampoline, continue
					// But accept after 50 extra steps to avoid infinite loop
					if (stepCount > 0 && !hasSym) {
						// In target module but no symbol -- still report as resolved (best effort)
						entries[i].resolved = 1;
						entries[i].targetAddress = rip;
						IMAGEHLP_MODULE64 modInfo = {}; modInfo.SizeOfStruct = sizeof(modInfo);
						if (SymGetModuleInfo64(GetCurrentProcess(), rip, &modInfo))
							strncpy_s(entries[i].moduleName, modInfo.ModuleName, sizeof(entries[i].moduleName) - 1);
						resolved = true;
						break;
					}
				}

				// Record trace
				ir.traceLog[ir.traceLogIdx % VehHandler::ImportResolveState::kTraceLogSize] = {rip, 0};
				ir.traceLogIdx++;
				ir.stepsExecuted = stepCount;

				// Analyze instruction flow
				InsnFlow flow = AnalyzeFlow(rip, curCtx);

				// Validate: target must be in executable memory
				// Prevents false follows from coincidental opcode matches in encrypted/SMC code
				if (flow.resolved && flow.target != 0 && !IsExecutableAddr(flow.target)) {
					flow.resolved = false;
				}

				if (flow.resolved && flow.type == FlowType::DirectJump) {
					// Static follow: just update RIP
#ifdef _WIN64
					curCtx.Rip = flow.target;
#else
					curCtx.Eip = static_cast<DWORD>(flow.target);
#endif
					VehHandler::Instance().SetStoppedContext(req->threadId, curCtx);
					stepCount++;
					continue;
				}

				if (flow.resolved && flow.type == FlowType::DirectCall) {
					// Static follow: push return addr, set RIP
#ifdef _WIN64
					curCtx.Rsp -= 8;
					uint64_t retAddr = rip + flow.length;
					if (!IsBadWritePtr(reinterpret_cast<LPVOID>(curCtx.Rsp), 8))
						*reinterpret_cast<uint64_t*>(curCtx.Rsp) = retAddr;
					curCtx.Rip = flow.target;
#else
					curCtx.Esp -= 4;
					uint32_t retAddr = static_cast<uint32_t>(rip + flow.length);
					if (!IsBadWritePtr(reinterpret_cast<LPVOID>(curCtx.Esp), 4))
						*reinterpret_cast<uint32_t*>(curCtx.Esp) = retAddr;
					curCtx.Eip = static_cast<DWORD>(flow.target);
#endif
					VehHandler::Instance().SetStoppedContext(req->threadId, curCtx);
					stepCount++;
					continue;
				}

				if (flow.resolved && flow.type == FlowType::IndirectBranch) {
					// Static follow: set RIP to resolved target
#ifdef _WIN64
					curCtx.Rip = flow.target;
#else
					curCtx.Eip = static_cast<DWORD>(flow.target);
#endif
					VehHandler::Instance().SetStoppedContext(req->threadId, curCtx);
					stepCount++;
					continue;
				}

				if (flow.resolved && flow.type == FlowType::Return) {
					// Static follow: pop return addr
#ifdef _WIN64
					curCtx.Rsp += 8 + flow.retImm;
					curCtx.Rip = flow.target;
#else
					curCtx.Esp += 4 + flow.retImm;
					curCtx.Eip = static_cast<DWORD>(flow.target);
#endif
					VehHandler::Instance().SetStoppedContext(req->threadId, curCtx);
					stepCount++;
					continue;
				}

				// === Need actual execution ===
				// Default: TF for one step (always correct, minimal exposure since
				// most branches are already handled by static analysis above).
				// INT3 mode is available but risky with obfuscated code (DecodeInsn
				// may return wrong length for unusual opcodes -> code corruption).
				bool useInt3 = false;
				// (INT3 mode reserved for future opt-in parameter)

				// Resume thread with TF for one step
				ir.done.store(false, std::memory_order_relaxed);
				ir.active.store(true, std::memory_order_release);
				VehHandler::Instance().ResumeStoppedThread(req->threadId, true); // TF

				// Wait for step completion
				int waitMs = 0;
				while (!ir.done.load(std::memory_order_acquire) && waitMs < 10000) {
					Sleep(1);
					waitMs++;
				}
				ir.active.store(false, std::memory_order_relaxed);

				// Wait for thread to stop (NotifyAndWait)
				for (int w = 0; w < 5000; w++) {
					if (VehHandler::Instance().IsThreadStopped(req->threadId)) break;
					Sleep(1);
				}

				if (!ir.done.load(std::memory_order_acquire)) {
					break; // Timeout
				}

				stepCount++;
			}

			if (!resolved) {
				entries[i].resolved = 0;
			}

			// Copy diagnostic trace log
			entries[i].stepsExecuted = stepCount;
			entries[i].exceptionsPassed = static_cast<uint8_t>(
				ir.exceptionsPassed > 255 ? 255 : ir.exceptionsPassed);
			{
				uint32_t total = ir.traceLogIdx;
				uint32_t copyCount = (total < 16) ? total : 16;
				entries[i].traceCount = static_cast<uint8_t>(copyCount);
				for (uint32_t t = 0; t < copyCount; t++) {
					uint32_t srcIdx = (total - copyCount + t) % VehHandler::ImportResolveState::kTraceLogSize;
					entries[i].traceAddresses[t] = ir.traceLog[srcIdx].address;
					entries[i].traceExcCodes[t] = ir.traceLog[srcIdx].exceptionCode;
				}
			}

			// Restore original context
			VehHandler::Instance().SetStoppedContext(req->threadId, origCtx);
		}

		// Cleanup UEF + parkStub
		if (followExceptions && ir.parkStub) {
			SetUnhandledExceptionFilter(prevUEF);
			VirtualFree(ir.parkStub, 0, MEM_RELEASE); ir.parkStub = nullptr;
		}

		SendResponse(command, respBuf.data(), static_cast<uint32_t>(respBuf.size()));
		break;
	}

	case IpcCommand::TraceCalls: {
		if (payloadSize < sizeof(TraceCallsRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status)); return;
		}
		auto* req = reinterpret_cast<const TraceCallsRequest*>(payload);
		uint32_t count = req->count;
		if (count == 0 || count > 4000) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status)); return;
		}
		uint32_t durationMs = req->durationMs;
		if (durationMs == 0) durationMs = 5000;
		if (durationMs > 60000) durationMs = 60000;

		const uint64_t* addrs = reinterpret_cast<const uint64_t*>(payload + sizeof(TraceCallsRequest));
		if (payloadSize < sizeof(TraceCallsRequest) + count * sizeof(uint64_t)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status)); return;
		}

		bool resolveMode = (req->resolve != 0);
		bool sysOnly = (req->systemOnly != 0);
		uint32_t resolveMaxSteps = req->resolveMaxSteps;
		if (resolveMaxSteps == 0) resolveMaxSteps = 2000;
		if (resolveMaxSteps > 10000) resolveMaxSteps = 10000;

		// Set software breakpoints on all call/jmp sites
		std::vector<uint32_t> bpIds;
		for (uint32_t i = 0; i < count; i++) {
			uint32_t id = BreakpointManager::Instance().Add(addrs[i]);
			if (id) bpIds.push_back(id);
		}

		// Setup trace state
		auto& tc = VehHandler::Instance().traceCalls_;
		tc.addresses.assign(addrs, addrs + count);
		std::sort(tc.addresses.begin(), tc.addresses.end());
		tc.resolveMode = resolveMode;
		tc.resolveMaxSteps = resolveMaxSteps;
		tc.following.store(false, std::memory_order_relaxed);

		// Build module range table for resolve mode
		if (resolveMode) {
			tc.moduleRanges.clear();
			wchar_t sysDir[MAX_PATH] = {};
			if (sysOnly) {
				GetSystemDirectoryW(sysDir, MAX_PATH);
				for (wchar_t* p = sysDir; *p; p++) *p = towlower(*p);
			}
			HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
			if (snap != INVALID_HANDLE_VALUE) {
				MODULEENTRY32W me; me.dwSize = sizeof(me);
				bool first = true;
				if (Module32FirstW(snap, &me)) {
					do {
						uint64_t base = reinterpret_cast<uint64_t>(me.modBaseAddr);
						uint64_t end = base + me.modBaseSize;
						bool isTarget = !first;  // default: all non-exe
						if (first) first = false;
						if (sysOnly && isTarget) {
							wchar_t path[MAX_PATH]; wcscpy_s(path, me.szExePath);
							for (wchar_t* p = path; *p; p++) *p = towlower(*p);
							isTarget = (wcsstr(path, sysDir) == path);
						}
						tc.moduleRanges.push_back({base, end, isTarget});
					} while (Module32NextW(snap, &me));
				}
				CloseHandle(snap);
			}
		}
		tc.writeIdx.store(0, std::memory_order_relaxed);
		tc.totalHits.store(0, std::memory_order_relaxed);
		tc.active.store(true, std::memory_order_release);

		// Resume all stopped threads
		VehHandler::Instance().ResumeAllStoppedThreads();

		// Wait for duration
		Sleep(durationMs);

		// Deactivate trace + pause
		tc.active.store(false, std::memory_order_release);
		// Note: threads continue running until they hit a BP or are externally paused.
		// Results are already collected in the ring buffer.

		// Remove breakpoints
		for (auto id : bpIds) {
			BreakpointManager::Instance().Remove(id);
		}

		// Aggregate results from ring buffer
		uint32_t totalHits = tc.totalHits.load(std::memory_order_acquire);
		uint32_t rawCount = tc.writeIdx.load(std::memory_order_acquire);
		uint32_t bufCount = (rawCount < tc.kBufferSize) ? rawCount : tc.kBufferSize;

		// Map: (callSite, target) -> hitCount
		struct PairHash {
			size_t operator()(const std::pair<uint64_t,uint64_t>& p) const {
				// 비트폭 독립 결합 (x86에서 size_t=32bit << 32 = UB 회피)
				uint64_t a = std::hash<uint64_t>()(p.first);
				uint64_t b = std::hash<uint64_t>()(p.second);
				uint64_t h = a * 0x9e3779b97f4a7c15ULL + b;
				return static_cast<size_t>(h ^ (h >> 32));
			}
		};
		std::unordered_map<std::pair<uint64_t,uint64_t>, uint32_t, PairHash> aggMap;
		for (uint32_t i = 0; i < bufCount; i++) {
			auto& e = tc.buffer[i];
			aggMap[{e.callSite, e.target}]++;
		}

		// Build response
		uint32_t uniqueCount = static_cast<uint32_t>(aggMap.size());
		std::vector<uint8_t> respBuf(sizeof(TraceCallsResponse) + uniqueCount * sizeof(TraceCallsEntry));
		auto* resp = reinterpret_cast<TraceCallsResponse*>(respBuf.data());
		auto* entries = reinterpret_cast<TraceCallsEntry*>(respBuf.data() + sizeof(TraceCallsResponse));
		resp->status = IpcStatus::Ok;
		resp->uniqueCount = uniqueCount;
		resp->totalHits = totalHits;

		uint32_t idx = 0;
		for (auto& [pair, hits] : aggMap) {
			memset(&entries[idx], 0, sizeof(TraceCallsEntry));
			entries[idx].callSite = pair.first;
			entries[idx].target = pair.second;
			entries[idx].hitCount = hits;
			// SymFromAddr for target
			DWORD64 disp = 0;
			char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
			SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(symBuf);
			sym->SizeOfStruct = sizeof(SYMBOL_INFO); sym->MaxNameLen = MAX_SYM_NAME;
			if (SymFromAddr(GetCurrentProcess(), pair.second, &disp, sym))
				strncpy_s(entries[idx].functionName, sym->Name, sizeof(entries[idx].functionName) - 1);
			IMAGEHLP_MODULE64 modInfo = {}; modInfo.SizeOfStruct = sizeof(modInfo);
			if (SymGetModuleInfo64(GetCurrentProcess(), pair.second, &modInfo))
				strncpy_s(entries[idx].moduleName, modInfo.ModuleName, sizeof(entries[idx].moduleName) - 1);
			idx++;
		}

		SendResponse(command, respBuf.data(), static_cast<uint32_t>(respBuf.size()));
		break;
	}

	case IpcCommand::TraceBasicBlocks: {
		if (payloadSize < kTraceBasicBlocksRequestV3Size) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status)); return;
		}
		TraceBasicBlocksRequest req{};
		memcpy(&req, payload, std::min<size_t>(payloadSize, sizeof(req)));
		const bool explicitV10Wire = req.wireVersion >= kTraceBasicBlocksWireVersion &&
			req.requestSize >= kTraceBasicBlocksRequestV10Size && req.requestSize <= payloadSize;
		const bool explicitV9Wire = req.wireVersion == 9 &&
			req.requestSize >= kTraceBasicBlocksRequestV9Size && req.requestSize <= payloadSize;
		const bool explicitV8Wire = req.wireVersion == 8 &&
			req.requestSize >= kTraceBasicBlocksRequestV8Size && req.requestSize <= payloadSize;
		const bool explicitV7Wire = req.wireVersion == 7 &&
			req.requestSize >= kTraceBasicBlocksRequestV7Size && req.requestSize <= payloadSize;
		const bool explicitV6Wire = req.wireVersion == 6 &&
			req.requestSize >= kTraceBasicBlocksRequestV6Size && req.requestSize <= payloadSize;
		const bool explicitV5Wire = req.wireVersion == kTraceBasicBlocksMinimumExplicitWireVersion &&
			req.requestSize >= kTraceBasicBlocksRequestV4Size && req.requestSize <= payloadSize;
		const bool explicitKnownWire = explicitV10Wire || explicitV9Wire || explicitV8Wire ||
			explicitV7Wire || explicitV6Wire || explicitV5Wire;
		const uint16_t responseHeaderSize = (explicitV10Wire || explicitV9Wire) ? kTraceBasicBlocksResponseV8Size :
			(explicitV8Wire ? kTraceBasicBlocksResponseV7Size :
			(explicitV7Wire ? kTraceBasicBlocksResponseV6Size :
			(explicitKnownWire ? kTraceBasicBlocksResponseV5Size :
			(payloadSize >= kTraceBasicBlocksRequestV4Size ?
				kTraceBasicBlocksResponseV4Size : kTraceBasicBlocksResponseV3Size))));
		CONTEXT stoppedContext{};
		const bool stopped = VehHandler::Instance().IsThreadStopped(req.threadId);
		const bool hasStoppedContext = VehHandler::Instance().GetStoppedContext(req.threadId, stoppedContext);
#ifdef _WIN64
		const uint64_t normalizedIp = hasStoppedContext ? stoppedContext.Rip : 0;
#else
		const uint64_t normalizedIp = hasStoppedContext ? stoppedContext.Eip : 0;
#endif
		auto sendTraceFailure = [&](IpcStatus status, TraceBasicBlocksStartFailure reason,
				bool decodeSucceeded, uint32_t decodedInstructionCount) {
			std::vector<uint8_t> response(responseHeaderSize);
			auto* header = reinterpret_cast<TraceBasicBlocksResponse*>(response.data());
			memset(header, 0, responseHeaderSize);
			header->status = status;
			header->headerSize = responseHeaderSize;
			if (responseHeaderSize >= kTraceBasicBlocksResponseV5Size) {
				header->startFailureReason = static_cast<uint8_t>(reason);
				header->stopped = stopped && hasStoppedContext ? 1 : 0;
				header->ipInRange = hasStoppedContext && normalizedIp >= req.rangeStart &&
					normalizedIp < req.rangeEnd ? 1 : 0;
				header->decodeSucceeded = decodeSucceeded ? 1 : 0;
				header->decodedInstructionCount = decodedInstructionCount;
				header->normalizedIp = normalizedIp;
				header->normalizedRangeStart = req.rangeStart;
				header->normalizedRangeEnd = req.rangeEnd;
			}
			if (responseHeaderSize >= kTraceBasicBlocksResponseV6Size)
				header->occurrenceWindow = req.occurrenceWindow;
			SendResponse(command, response.data(), static_cast<uint32_t>(response.size()));
		};
		if ((req.requestSize != 0 && !explicitKnownWire) ||
			(req.wireVersion != 0 && req.wireVersion < kTraceBasicBlocksMinimumExplicitWireVersion)) {
			sendTraceFailure(IpcStatus::InvalidArgs, TraceBasicBlocksStartFailure::InvalidArguments, false, 0);
			return;
		}
		if (!explicitV6Wire && !explicitV7Wire && !explicitV8Wire && !explicitV9Wire && !explicitV10Wire) {
			req.codeOutputMode = static_cast<uint8_t>(TraceCodeOutputMode::Inline);
			req.codeChunkBytes = 0;
			req.codeStreamOwnerPid = 0;
			req.codeStreamToken = 0;
		}
		if (!explicitV7Wire && !explicitV8Wire && !explicitV9Wire && !explicitV10Wire) req.occurrenceWindow = {};
		if (!explicitV8Wire && !explicitV9Wire && !explicitV10Wire) req.stopOnReturn = 0;
		if (!explicitV9Wire && !explicitV10Wire) req.targetWindow = {};
		if (!explicitV10Wire) {
			req.eventOutputMode = static_cast<uint8_t>(TraceEventOutputMode::Inline);
			req.eventChunkBytes = 0;
			req.eventStreamOwnerPid = 0;
			req.eventStreamToken = 0;
			req.maxEventFileBytes = 0;
		}
		if (req.threadId == 0 || req.rangeStart >= req.rangeEnd ||
			req.rangeEnd - req.rangeStart > 4ULL * 1024 * 1024) {
			sendTraceFailure(IpcStatus::InvalidArgs, TraceBasicBlocksStartFailure::InvalidArguments, false, 0);
			return;
		}
		if (req.maxBlocks == 0) req.maxBlocks = 4096;
		if (req.maxEdges == 0) req.maxEdges = 8192;
		if (req.maxSteps == 0) req.maxSteps = 100000;
		if (req.timeoutMs == 0) req.timeoutMs = 10000;
		if (req.collectMemoryWrites && req.maxMemoryWrites == 0) req.maxMemoryWrites = 4096;
		if (req.collectMemoryReads && req.maxMemoryReads == 0) req.maxMemoryReads = 4096;
		if ((req.collectEvents || req.collectCode || req.collectMemoryEvents || req.collectRegisterEvents) && req.maxEvents == 0)
			req.maxEvents = 8192;
		if (req.collectMemoryEvents && req.maxMemoryEvents == 0) req.maxMemoryEvents = 8192;
		if (req.collectRegisterEvents && req.maxRegisterEvents == 0) req.maxRegisterEvents = 8192;
		if (req.collectCode && req.maxCodeBytes == 0) req.maxCodeBytes = 262144;
		if (req.collectCode && req.maxCodeVersions == 0) req.maxCodeVersions = 4096;
		if (req.collectCode || req.collectMemoryEvents || req.collectRegisterEvents) req.collectEvents = 1;
		const bool fileCodeOutput = req.codeOutputMode == static_cast<uint8_t>(TraceCodeOutputMode::File);
		const bool fileEventOutput = req.eventOutputMode == static_cast<uint8_t>(TraceEventOutputMode::File);
		const uint32_t maxCodeBytes = fileCodeOutput ?
			kTraceBasicBlockMaxFileCodeBytes : kTraceBasicBlockMaxCodeBytes;
		if (req.maxBlocks > 16384 || req.maxEdges > 32768 || req.maxSteps > 5000000 ||
			(req.collectMemoryWrites && req.maxMemoryWrites > 16384) ||
			(req.collectMemoryReads && req.maxMemoryReads > 16384) ||
			(req.collectEvents && !fileEventOutput && req.maxEvents > 32768) ||
			(req.collectMemoryEvents && !fileEventOutput && req.maxMemoryEvents > 65536) ||
			(req.collectRegisterEvents && !fileEventOutput && req.maxRegisterEvents > 65536) ||
			(req.collectCode && (req.maxCodeBytes > maxCodeBytes ||
				req.maxCodeVersions > 16384 || req.maxCodeBytes == 0 || req.maxCodeVersions == 0)) ||
			(req.codeOutputMode > static_cast<uint8_t>(TraceCodeOutputMode::File)) ||
			(fileCodeOutput && (!req.collectCode || !req.codeStreamOwnerPid || !req.codeStreamToken ||
				req.codeChunkBytes < kTraceCodeMinChunkBytes || req.codeChunkBytes > kTraceCodeMaxChunkBytes ||
				req.codeChunkBytes % kTraceCodeChunkAlignment != 0)) ||
			(req.eventOutputMode > static_cast<uint8_t>(TraceEventOutputMode::File)) ||
			(fileEventOutput && (!req.collectEvents || !req.eventStreamOwnerPid || !req.eventStreamToken ||
				req.eventChunkBytes != kTraceEventDefaultChunkBytes ||
				req.maxEventFileBytes < sizeof(TraceEventArtifactHeader) ||
				req.maxEventFileBytes > kTraceEventMaxFileBytes)) ||
			(req.occurrenceWindow.enabled && (!req.occurrenceWindow.address ||
				req.occurrenceWindow.from == 0 ||
				(req.occurrenceWindow.to && req.occurrenceWindow.to < req.occurrenceWindow.from) ||
				req.occurrenceWindow.address < req.rangeStart ||
				req.occurrenceWindow.address >= req.rangeEnd)) ||
			(req.targetWindow.enabled && (!req.targetWindow.address ||
				req.targetWindow.occurrence == 0 || req.targetWindow.afterSteps == 0 ||
				req.targetWindow.beforeSteps > 100000 || req.targetWindow.afterSteps > 100000 ||
				req.targetWindow.address < req.rangeStart || req.targetWindow.address >= req.rangeEnd ||
				req.occurrenceWindow.enabled || req.stopOnReturn || fileCodeOutput || fileEventOutput ||
				req.startCondition.clauseCount || req.stopCondition.clauseCount ||
				req.collectCondition.clauseCount)) ||
			req.dependencySourceCount > kTraceDependencyMaxSources ||
			req.timeoutMs < 100 || req.timeoutMs > 60000 ||
			req.stackBytes > kTraceBasicBlockMaxStackBytes) {
			sendTraceFailure(IpcStatus::InvalidArgs, TraceBasicBlocksStartFailure::InvalidArguments, false, 0);
			return;
		}

		std::vector<VehHandler::TraceBasicBlocksState::Instruction> instructions;
		std::vector<uint64_t> staticBlockStarts;
		instructions.reserve(static_cast<size_t>(req.rangeEnd - req.rangeStart) / 2);
		const bool decodeSucceeded = DecodeBasicTraceRange(
			req.rangeStart, req.rangeEnd, instructions, staticBlockStarts);
		const uint32_t decodedInstructionCount = static_cast<uint32_t>(instructions.size());
		if (!decodeSucceeded) {
			sendTraceFailure(IpcStatus::Error, TraceBasicBlocksStartFailure::DecodeFailed,
				false, decodedInstructionCount);
			break;
		}
		if (req.stopOnReturn) {
#ifdef _WIN64
			const uint64_t entryStackPointer = stoppedContext.Rsp;
			uint64_t returnAddress = 0;
#else
			const uint64_t entryStackPointer = stoppedContext.Esp;
			uint32_t returnAddress = 0;
#endif
			if (!hasStoppedContext || !entryStackPointer ||
				!SafeReadMem(entryStackPointer, &returnAddress, sizeof(returnAddress)) || !returnAddress) {
				sendTraceFailure(IpcStatus::InvalidArgs,
					TraceBasicBlocksStartFailure::ReturnAddressUnavailable, true,
					decodedInstructionCount);
				break;
			}
		}

		HANDLE codeStreamPipe = INVALID_HANDLE_VALUE;
		if (fileCodeOutput) {
			std::wstring codePipeName = GetTraceCodePipeName(req.codeStreamOwnerPid, req.codeStreamToken);
			if (!WaitNamedPipeW(codePipeName.c_str(), 3000)) {
				sendTraceFailure(IpcStatus::Error, TraceBasicBlocksStartFailure::CodeStreamUnavailable,
					true, decodedInstructionCount);
				break;
			}
			codeStreamPipe = CreateFileW(codePipeName.c_str(), GENERIC_WRITE, 0, nullptr,
				OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
			if (codeStreamPipe == INVALID_HANDLE_VALUE) {
				sendTraceFailure(IpcStatus::Error, TraceBasicBlocksStartFailure::CodeStreamUnavailable,
					true, decodedInstructionCount);
				break;
			}
		}
		HANDLE eventStreamPipe = INVALID_HANDLE_VALUE;
		if (fileEventOutput) {
			std::wstring eventPipeName = GetTraceEventPipeName(req.eventStreamOwnerPid, req.eventStreamToken);
			if (!WaitNamedPipeW(eventPipeName.c_str(), 3000)) {
				if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
				sendTraceFailure(IpcStatus::Error, TraceBasicBlocksStartFailure::EventStreamUnavailable,
					true, decodedInstructionCount);
				break;
			}
			eventStreamPipe = CreateFileW(eventPipeName.c_str(), GENERIC_WRITE, 0, nullptr,
				OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
			if (eventStreamPipe == INVALID_HANDLE_VALUE) {
				if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
				sendTraceFailure(IpcStatus::Error, TraceBasicBlocksStartFailure::EventStreamUnavailable,
					true, decodedInstructionCount);
				break;
			}
		}

		auto startTick = GetTickCount64();
		if (!VehHandler::Instance().StartTraceBasicBlocks(req.threadId, req.rangeStart, req.rangeEnd,
				req.maxBlocks, req.maxEdges, req.maxSteps, req.stackBytes,
				req.followExceptions != 0, req.collectMemoryWrites != 0, req.maxMemoryWrites,
				req.collectMemoryReads != 0, req.maxMemoryReads,
				req.collectEvents != 0, req.maxEvents,
				req.collectCode != 0, req.maxCodeBytes, req.maxCodeVersions,
				static_cast<TraceCodeOutputMode>(req.codeOutputMode), req.codeChunkBytes,
				req.codeStreamToken, codeStreamPipe,
				static_cast<TraceEventOutputMode>(req.eventOutputMode), req.eventChunkBytes,
				req.maxEventFileBytes, req.eventStreamToken, eventStreamPipe,
				req.collectMemoryEvents != 0, req.maxMemoryEvents,
				req.collectRegisterEvents != 0, req.maxRegisterEvents,
				req.dependencySources, req.dependencySourceCount,
				req.startCondition, req.stopCondition, req.collectCondition, req.occurrenceWindow,
				req.stopOnReturn != 0, req.targetWindow,
				std::move(instructions), std::move(staticBlockStarts))) {
			TraceBasicBlocksStartFailure reason = TraceBasicBlocksStartFailure::StartRejected;
			if (!stopped || !hasStoppedContext) reason = TraceBasicBlocksStartFailure::ThreadNotStopped;
			else if (normalizedIp < req.rangeStart || normalizedIp >= req.rangeEnd)
				reason = TraceBasicBlocksStartFailure::InstructionPointerOutsideRange;
			sendTraceFailure(IpcStatus::NotFound, reason, true,
				decodedInstructionCount);
			break;
		}

		auto& tb = VehHandler::Instance().traceBasicBlocks_;
		while (!tb.done.load(std::memory_order_acquire) && GetTickCount64() - startTick < req.timeoutMs)
			Sleep(2);
		if (!tb.done.load(std::memory_order_acquire)) {
			VehHandler::Instance().CancelTraceBasicBlocks(TraceBasicBlockStopReason::Timeout);
			uint64_t cancelTick = GetTickCount64();
			while (!tb.done.load(std::memory_order_acquire) && GetTickCount64() - cancelTick < 2000)
				Sleep(2);
		}
		if (!tb.done.load(std::memory_order_acquire)) {
			tb.active.store(false, std::memory_order_release);
			VehHandler::Instance().FinalizeTraceBasicBlocksStreams();
			std::vector<uint8_t> response(responseHeaderSize);
			auto* header = reinterpret_cast<TraceBasicBlocksResponse*>(response.data());
			memset(header, 0, responseHeaderSize);
			header->status = IpcStatus::Error;
			header->stopReason = TraceBasicBlockStopReason::Timeout;
			header->headerSize = responseHeaderSize;
			header->elapsedMs = static_cast<uint32_t>(GetTickCount64() - startTick);
			SendResponse(command, response.data(), static_cast<uint32_t>(response.size())); break;
		}
		// FinishBasicTrace publishes counters before the VEH thread enters its
		// normal stopped-context wait. Give that short hand-off time to complete so
		// register/stack tools are immediately usable when this response returns.
		uint64_t parkTick = GetTickCount64();
		while (!VehHandler::Instance().IsThreadStopped(req.threadId) && GetTickCount64() - parkTick < 2000)
			Sleep(1);
		VehHandler::Instance().FinalizeTraceBasicBlocksStreams();

		struct ResultBlock {
			TraceBasicBlockEntry entry{};
		};
		std::vector<ResultBlock> blocks;
		blocks.reserve(tb.blockCount);
		std::unordered_set<uint64_t> observedStarts;
		std::unordered_map<uint64_t, uint32_t> firstSnapshots;
		for (const auto& slot : tb.blockTable) {
			if (!slot.occupied) continue;
			observedStarts.insert(slot.start);
			firstSnapshots[slot.start] = slot.firstSnapshot;
		}
		std::unordered_set<uint64_t> allBoundaries(tb.staticBlockStarts.begin(), tb.staticBlockStarts.end());
		allBoundaries.insert(observedStarts.begin(), observedStarts.end());
		std::unordered_set<uint64_t> observedTerminators;
		for (const auto& slot : tb.edgeTable) {
			if (slot.occupied) observedTerminators.insert(slot.sourceInstruction);
		}

		for (uint64_t blockStart : observedStarts) {
			TraceBasicBlockEntry entry{};
			entry.start = blockStart;
			entry.end = blockStart;
			entry.firstSnapshot = firstSnapshots[blockStart];
			// Walk contiguous instructions from both the static sweep and the table of
			// instructions decoded on execution (off-sweep, e.g. overlapping code).
			auto& handler = VehHandler::Instance();
			if (auto* first = handler.FindBasicTraceInstruction(blockStart)) {
				entry.hitCount = first->hitCount;
				for (auto* cur = first; cur; cur = handler.FindBasicTraceInstruction(cur->next)) {
					entry.end = cur->next;
					if (cur->terminal || observedTerminators.count(cur->address) || allBoundaries.count(cur->next)) break;
				}
			}
			blocks.push_back({entry});
		}
		std::sort(blocks.begin(), blocks.end(), [](const auto& a, const auto& b) {
			return a.entry.start < b.entry.start;
		});

		std::vector<TraceBasicBlockEdgeEntry> edges;
		edges.reserve(tb.edgeCount);
		for (const auto& slot : tb.edgeTable) {
			if (!slot.occupied) continue;
			TraceBasicBlockEdgeEntry entry{};
			entry.source = slot.sourceBlock;
			entry.sourceInstruction = slot.sourceInstruction;
			entry.target = slot.target;
			entry.hitCount = slot.hitCount;
			entry.snapshot = slot.snapshot;
			entry.exceptionCode = slot.exceptionCode;
			entry.dependencyMask = slot.dependencyMask;
			entry.kind = slot.kind;
			entry.indirect = slot.indirect;
			edges.push_back(entry);
		}
		std::sort(edges.begin(), edges.end(), [](const auto& a, const auto& b) {
			if (a.source != b.source) return a.source < b.source;
			if (a.target != b.target) return a.target < b.target;
			return static_cast<uint8_t>(a.kind) < static_cast<uint8_t>(b.kind);
		});

		std::vector<TraceBasicBlockMemoryWriteEntry> memoryWrites;
		memoryWrites.reserve(tb.memoryWriteCount);
		std::unordered_map<uint64_t, uint64_t> targetLastSteps;
		for (const auto& edge : tb.edgeTable) {
			if (!edge.occupied) continue;
			auto& step = targetLastSteps[edge.target];
			if (edge.firstStep > step) step = edge.firstStep;
		}
		for (const auto& slot : tb.memoryWriteTable) {
			if (!slot.occupied) continue;
			TraceBasicBlockMemoryWriteEntry entry{};
			entry.instruction = slot.instruction;
			entry.address = slot.address;
			entry.hitCount = slot.hitCount;
			entry.firstStep = slot.firstStep;
			entry.dependencyMask = slot.dependencyMask;
			entry.size = slot.size;
			entry.flags = kTraceMemoryValueValid;
			if (IsExecutableAddr(slot.address)) {
				entry.flags |= kTraceMemoryExecutable;
				uint64_t executedAddress = 0;
				auto instruction = std::lower_bound(tb.instructions.begin(), tb.instructions.end(), slot.address,
					[](const auto& item, uint64_t address) { return item.address < address; });
				if (instruction != tb.instructions.end() &&
					instruction->address - slot.address < slot.size &&
					instruction->lastHitStep > slot.firstStep)
					executedAddress = instruction->address;
				if (!executedAddress) {
					for (uint8_t offset = 0; offset < slot.size; ++offset) {
						auto target = targetLastSteps.find(slot.address + offset);
						if (target != targetLastSteps.end() && target->second > slot.firstStep) {
							executedAddress = target->first;
							break;
						}
					}
				}
				if (executedAddress) {
					entry.flags |= kTraceMemoryExecutedAfterWrite;
					entry.executedAddress = executedAddress;
				}
			}
			memcpy(entry.before, slot.before, slot.size);
			memcpy(entry.after, slot.after, slot.size);
			memoryWrites.push_back(entry);
		}
		std::sort(memoryWrites.begin(), memoryWrites.end(), [](const auto& a, const auto& b) {
			if (a.instruction != b.instruction) return a.instruction < b.instruction;
			if (a.address != b.address) return a.address < b.address;
			return memcmp(a.before, b.before, std::min(a.size, b.size)) < 0;
		});
		std::vector<TraceBasicBlockMemoryReadEntry> memoryReads;
		memoryReads.reserve(tb.memoryReadCount);
		for (const auto& slot : tb.memoryReadTable) {
			if (!slot.occupied) continue;
			TraceBasicBlockMemoryReadEntry entry{};
			entry.instruction = slot.instruction; entry.address = slot.address;
			entry.hitCount = slot.hitCount; entry.dependencyMask = slot.dependencyMask;
			entry.size = slot.size; entry.flags = kTraceMemoryValueValid;
			memcpy(entry.value, slot.value, slot.size); memoryReads.push_back(entry);
		}
		std::sort(memoryReads.begin(), memoryReads.end(), [](const auto& a, const auto& b) {
			if (a.instruction != b.instruction) return a.instruction < b.instruction;
			if (a.address != b.address) return a.address < b.address;
			return memcmp(a.value, b.value, std::min(a.size, b.size)) < 0;
		});
		std::vector<TraceBasicBlockExceptionEntry> exceptionEvents;
		exceptionEvents.reserve(tb.exceptionsFollowed);
		for (const auto& slot : tb.edgeTable) {
			if (!slot.occupied || slot.kind != TraceBasicBlockEdgeKind::Exception) continue;
			TraceBasicBlockExceptionEntry entry{};
			entry.code = slot.exceptionCode;
			entry.faultSnapshot = slot.faultSnapshot;
			entry.continuationSnapshot = slot.snapshot;
			entry.faultRip = slot.sourceInstruction;
			entry.faultAddress = slot.faultAddress;
			entry.continuation = slot.target;
			entry.hitCount = slot.hitCount;
			exceptionEvents.push_back(entry);
		}
		std::sort(exceptionEvents.begin(), exceptionEvents.end(), [](const auto& a, const auto& b) {
			if (a.faultRip != b.faultRip) return a.faultRip < b.faultRip;
			return a.continuation < b.continuation;
		});

		const uint32_t responseRegisterEventCount =
			responseHeaderSize >= kTraceBasicBlocksResponseV4Size && !fileEventOutput ?
				tb.registerEventCount : 0;
		const uint32_t responseEventCount = fileEventOutput ? 0 : tb.eventCount;
		const uint32_t responseMemoryEventCount = fileEventOutput ? 0 : tb.memoryEventCount;
		size_t responseSize = responseHeaderSize +
			blocks.size() * sizeof(TraceBasicBlockEntry) +
			edges.size() * sizeof(TraceBasicBlockEdgeEntry) +
			tb.snapshotCount * sizeof(TraceBasicBlockSnapshot) +
			memoryWrites.size() * sizeof(TraceBasicBlockMemoryWriteEntry) +
			memoryReads.size() * sizeof(TraceBasicBlockMemoryReadEntry) +
			exceptionEvents.size() * sizeof(TraceBasicBlockExceptionEntry);
		responseSize += static_cast<size_t>(responseEventCount) * sizeof(TraceBasicBlockEventEntry);
		responseSize += static_cast<size_t>(responseMemoryEventCount) * sizeof(TraceBasicBlockMemoryEventEntry);
		responseSize += static_cast<size_t>(responseRegisterEventCount) * sizeof(TraceBasicBlockRegisterEventEntry);
		const uint32_t inlineCodeVersionCount = fileCodeOutput ? 0 : tb.codeVersionCount;
		const uint32_t inlineCodeByteCount = fileCodeOutput ? 0 : tb.codeByteCount;
		responseSize += static_cast<size_t>(inlineCodeVersionCount) * sizeof(TraceBasicBlockCodeVersionEntry);
		responseSize += inlineCodeByteCount;
		std::vector<uint8_t> response(responseSize);
		auto* header = reinterpret_cast<TraceBasicBlocksResponse*>(response.data());
		memset(header, 0, responseHeaderSize);
		header->status = IpcStatus::Ok;
		header->headerSize = responseHeaderSize;
		header->stopReason = tb.stopReason;
		header->truncated = tb.truncated ? 1 : 0;
		header->blockCount = static_cast<uint32_t>(blocks.size());
		header->edgeCount = static_cast<uint32_t>(edges.size());
		header->snapshotCount = tb.snapshotCount;
		header->memoryWriteCount = static_cast<uint32_t>(memoryWrites.size());
		header->unsupportedMemoryWrites = tb.unsupportedMemoryWrites;
		header->memoryWritesTruncated = tb.memoryWritesTruncated ? 1 : 0;
		header->exceptionEventCount = static_cast<uint32_t>(exceptionEvents.size());
		header->filteredSteps = tb.filteredSteps;
		header->startConditionMet = tb.startConditionMet ? 1 : 0;
		header->memoryReadCount = static_cast<uint32_t>(memoryReads.size());
		header->unsupportedMemoryReads = tb.unsupportedMemoryReads;
		header->memoryReadsTruncated = tb.memoryReadsTruncated ? 1 : 0;
		header->dependencyIncomplete = tb.dependencyIncomplete ? 1 : 0;
		memcpy(header->finalRegisterDependencies, tb.registerDependencies,
			sizeof(header->finalRegisterDependencies));
		header->finalFlagsDependencies = tb.flagsDependencies;
		header->exceptionsFollowed = tb.exceptionsFollowed;
		header->elapsedMs = static_cast<uint32_t>(GetTickCount64() - startTick);
		header->stepsExecuted = tb.stepsExecuted;
		header->finalAddress = tb.finalAddress;
		header->threadId = req.threadId;
		header->eventCount = responseEventCount;
		header->eventCollectionEnabled = req.collectEvents ? 1 : 0;
		header->eventsTruncated = (tb.eventsTruncated || tb.eventStreamTruncated) ? 1 : 0;
		header->eventSchemaVersion = 1;
		header->codeVersionCount = inlineCodeVersionCount;
		header->codeByteCount = inlineCodeByteCount;
		header->codeCollectionEnabled = req.collectCode ? 1 : 0;
		header->codeTruncated = tb.codeTruncated ? 1 : 0;
		header->codeSchemaVersion = 1;
		header->memoryEventCount = responseMemoryEventCount;
		header->memoryEventCollectionEnabled = req.collectMemoryEvents ? 1 : 0;
		header->memoryEventsTruncated = (tb.memoryEventsTruncated ||
			(req.collectMemoryEvents && tb.eventStreamTruncated)) ? 1 : 0;
		header->memoryEventSchemaVersion = req.collectMemoryEvents ? 1 : 0;
		header->memoryEventsDropped = tb.memoryEventsDropped;
		if (responseHeaderSize >= kTraceBasicBlocksResponseV4Size) {
			header->registerEventCount = responseRegisterEventCount;
			header->registerEventCollectionEnabled = req.collectRegisterEvents ? 1 : 0;
			header->registerEventsTruncated = (tb.registerEventsTruncated ||
				(req.collectRegisterEvents && tb.eventStreamTruncated)) ? 1 : 0;
			header->registerEventSchemaVersion = req.collectRegisterEvents ? 1 : 0;
			header->registerEventsDropped = tb.registerEventsDropped;
		}
		if (responseHeaderSize >= kTraceBasicBlocksResponseV5Size) {
			header->stopped = stopped && hasStoppedContext ? 1 : 0;
			header->ipInRange = 1;
			header->decodeSucceeded = 1;
			header->decodedInstructionCount = decodedInstructionCount;
			header->normalizedIp = normalizedIp;
			header->normalizedRangeStart = req.rangeStart;
			header->normalizedRangeEnd = req.rangeEnd;
		}
		if (responseHeaderSize >= kTraceBasicBlocksResponseV6Size) {
			header->occurrenceWindow = req.occurrenceWindow;
			header->occurrenceHits = tb.occurrenceHits;
			header->occurrenceWindowStarted = tb.occurrenceWindowStarted ? 1 : 0;
			header->occurrenceWindowCompleted = tb.occurrenceWindowCompleted ? 1 : 0;
		}
		if (responseHeaderSize >= kTraceBasicBlocksResponseV7Size) {
			header->functionScopeEnabled = tb.stopOnReturn ? 1 : 0;
			header->functionReturned = tb.functionReturned ? 1 : 0;
			header->returnSnapshot = tb.returnSnapshot;
			header->entryStackPointer = tb.entryStackPointer;
			header->returnAddress = tb.returnAddress;
			header->externalSteps = tb.externalSteps;
		}
		if (responseHeaderSize >= kTraceBasicBlocksResponseV8Size) {
			header->targetWindow = tb.targetWindow;
			header->targetOccurrenceHits = tb.targetOccurrenceHits;
			header->targetTriggerSequence = tb.targetTriggerSequence;
			header->targetCaptureStartSequence = tb.targetCaptureStartSequence;
			header->targetCaptureEndSequence = tb.targetCaptureEndSequence;
			header->eventsDropped = tb.eventsDropped;
			header->targetMatched = tb.targetMatched ? 1 : 0;
		}
		if (req.collectCode) header->eventSchemaVersion = 2;

		uint8_t* out = response.data() + responseHeaderSize;
		for (const auto& block : blocks) {
			memcpy(out, &block.entry, sizeof(block.entry)); out += sizeof(block.entry);
		}
		if (!edges.empty()) {
			memcpy(out, edges.data(), edges.size() * sizeof(edges[0]));
			out += edges.size() * sizeof(edges[0]);
		}
		if (tb.snapshotCount) {
			memcpy(out, tb.snapshots.data(), tb.snapshotCount * sizeof(TraceBasicBlockSnapshot));
			out += tb.snapshotCount * sizeof(TraceBasicBlockSnapshot);
		}
		if (!memoryWrites.empty()) {
			memcpy(out, memoryWrites.data(), memoryWrites.size() * sizeof(memoryWrites[0]));
			out += memoryWrites.size() * sizeof(memoryWrites[0]);
		}
		if (!memoryReads.empty()) {
			memcpy(out, memoryReads.data(), memoryReads.size() * sizeof(memoryReads[0]));
			out += memoryReads.size() * sizeof(memoryReads[0]);
		}
		if (!exceptionEvents.empty()) {
			memcpy(out, exceptionEvents.data(), exceptionEvents.size() * sizeof(exceptionEvents[0]));
			out += exceptionEvents.size() * sizeof(exceptionEvents[0]);
		}
		for (uint32_t i = 0; i < responseEventCount; ++i) {
			const auto& event = tb.events[(tb.eventHead + i) % tb.events.size()];
			memcpy(out, &event, sizeof(event)); out += sizeof(event);
		}
		for (uint32_t i = 0; i < responseMemoryEventCount; ++i) {
			const auto& event = tb.memoryEvents[(tb.memoryEventHead + i) % tb.memoryEvents.size()];
			memcpy(out, &event, sizeof(event)); out += sizeof(event);
		}
		for (uint32_t i = 0; i < responseRegisterEventCount; ++i) {
			const auto& event = tb.registerEvents[(tb.registerEventHead + i) % tb.registerEvents.size()];
			memcpy(out, &event, sizeof(event)); out += sizeof(event);
		}
		if (inlineCodeVersionCount) {
			memcpy(out, tb.codeVersions.data(), static_cast<size_t>(inlineCodeVersionCount) * sizeof(tb.codeVersions[0]));
			out += static_cast<size_t>(inlineCodeVersionCount) * sizeof(tb.codeVersions[0]);
		}
		if (inlineCodeByteCount) {
			memcpy(out, tb.codeBytes.data(), inlineCodeByteCount);
		}
		SendResponse(command, response.data(), static_cast<uint32_t>(response.size()));
		break;
	}

	case IpcCommand::Detach: {
		// Detach: 디버깅 상태만 정리하고 파이프 서버는 유지한다.
		// connected_=false로 내부 커맨드 루프만 탈출 → 외부 루프에서 새 클라이언트 대기
		// 이를 통해 어댑터가 다시 attach 할 때 DLL 재주입 없이 즉시 연결 가능
		LOG_INFO("Detach requested");
		ValueScanner::Instance().Reset();
		BreakpointManager::Instance().RemoveAll();
		HwBreakpointManager::Instance().RemoveAll();
		VehHandler::Instance().ResumeAllStoppedThreads(true);  // forDetach=true
		VehHandler::Instance().Uninstall();
		ThreadManager::Instance().ResumeAll();
		ThreadManager::Instance().ThawAll();
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		connected_ = false;
		break;
	}

	case IpcCommand::Terminate: {
		// Terminate: 타겟 프로세스 자체를 내부에서 강제 종료한다.
		// GetCurrentProcess() 의사 핸들은 타겟이 외부 OpenProcess 를 막으려 설정한 DACL 과
		// 무관하게 항상 PROCESS_TERMINATE 권한을 가지므로, 외부 taskkill 이 막히는
		// 자기보호(self-protected) 타겟도 확실히 종료된다.
		uint32_t exitCode = 0;
		if (payloadSize >= sizeof(TerminateRequest)) {
			exitCode = reinterpret_cast<const TerminateRequest*>(payload)->exitCode;
		}
		LOG_INFO("Terminate requested (exitCode=%u) -- killing target from inside", exitCode);
		// 응답은 best-effort (프로세스가 곧 사라지므로 클라이언트는 fire-and-forget).
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		// ExitProcess 는 DLL_PROCESS_DETACH/atexit 를 돌리다 후킹/훼손된 타겟에서 hang 할 수 있으므로
		// 정리 없이 즉시 끝내는 TerminateProcess 를 쓴다.
		TerminateProcess(GetCurrentProcess(), exitCode);
		break;  // 도달하지 않음
	}

	case IpcCommand::Shutdown: {
		// Shutdown: 완전 종료. running_=false로 ServerThread 자체가 종료된다.
		// 프로세스 종료 또는 DLL 언로드 시 사용
		LOG_INFO("Shutdown requested");
		ValueScanner::Instance().Reset();
		BreakpointManager::Instance().RemoveAll();
		HwBreakpointManager::Instance().RemoveAll();
		VehHandler::Instance().Uninstall();
		ThreadManager::Instance().ThawAll();
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		running_ = false;
		break;
	}

	default:
		LOG_WARN("Unknown command: 0x%04X", command);
		IpcStatus status = IpcStatus::InvalidArgs;
		SendResponse(command, &status, sizeof(status));
		break;
	}
}

bool PipeServer::SendEvent(uint32_t eventId, const void* payload, uint32_t payloadSize) {
	if (!connected_ || pipe_ == INVALID_HANDLE_VALUE) return false;
	auto msg = BuildIpcMessage(eventId, payload, payloadSize);
	std::lock_guard<std::mutex> lock(writeMutex_);
	return AsyncWriteExact(msg.data(), static_cast<DWORD>(msg.size()));
}

bool PipeServer::SendResponse(uint32_t command, const void* payload, uint32_t payloadSize) {
	if (!connected_ || pipe_ == INVALID_HANDLE_VALUE) return false;
	auto msg = BuildIpcMessage(command, payload, payloadSize);
	std::lock_guard<std::mutex> lock(writeMutex_);
	const DWORD timeoutMs = payloadSize > 1024 * 1024 ? 15000 : 3000;
	return AsyncWriteExact(msg.data(), static_cast<DWORD>(msg.size()), timeoutMs);
}

void PipeServer::ApplyHwBreakpointsToAllThreads() {
	DWORD currentTid = GetCurrentThreadId();
	auto threads = ThreadManager::Instance().EnumerateThreads();

	for (const auto& t : threads) {
		if (t.id == currentTid) continue; // pipe server 스레드 자신은 skip

		// VEH 핸들러에서 정지된 스레드는 stoppedContexts에 직접 반영
		// (SetThreadContext로는 VEH resume 시 info->ContextRecord에 의해 덮어씌워짐)
		CONTEXT stoppedCtx;
		if (VehHandler::Instance().GetStoppedContext(t.id, stoppedCtx)) {
			HwBreakpointManager::Instance().ClearFromContext(stoppedCtx);
			HwBreakpointManager::Instance().ApplyToContext(stoppedCtx);
			VehHandler::Instance().SetStoppedContext(t.id, stoppedCtx);
			continue;
		}

		// 실행 중인 스레드는 SetThreadContext로 적용
		CONTEXT ctx;
		if (!ThreadManager::Instance().GetContext(t.id, ctx)) continue;

		HwBreakpointManager::Instance().ClearFromContext(ctx);
		HwBreakpointManager::Instance().ApplyToContext(ctx);

		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ThreadManager::Instance().SetContext(t.id, ctx);
	}

	LOG_DEBUG("Applied HW breakpoints to %zu threads", threads.size());
}

} // namespace veh
