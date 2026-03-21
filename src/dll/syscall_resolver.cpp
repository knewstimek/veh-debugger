#include <windows.h>
#include "syscall_resolver.h"
#include "../common/logger.h"
#include <cstring>

namespace veh {

SyscallResolver& SyscallResolver::Instance() {
	static SyscallResolver instance;
	return instance;
}

// ---------------------------------------------------------------------------
// x86/x64 명령어 길이 디코더 (adapter/disassembler.cpp SimpleDisassembler 유래)
// ---------------------------------------------------------------------------
SyscallResolver::InsnInfo SyscallResolver::DecodeInsn(const uint8_t* code, uint32_t maxLen) {
	if (maxLen == 0) return {0, 0, false};

	const uint8_t* p = code;
	int prefixLen = 0;

	// 레거시 프리픽스
	while (prefixLen < 4 && maxLen > (uint32_t)prefixLen) {
		uint8_t c = p[prefixLen];
		if (c == 0x66 || c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 ||
			c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26 || c == 0x64 || c == 0x65) {
			prefixLen++;
		} else {
			break;
		}
	}

	if (prefixLen >= (int)maxLen) return {1, 0, false};

	uint8_t b = p[prefixLen];
	bool rexW = false;

	// REX prefix (0x40~0x4F)
	if (b >= 0x40 && b <= 0x4F) {
		rexW = (b & 0x08) != 0;
		prefixLen++;
		if (prefixLen >= (int)maxLen) return {1, 0, false};
		b = p[prefixLen];
	}

	int opOff = prefixLen;

	auto result = [&](uint8_t len, uint8_t op) -> InsnInfo {
		return {len, op, rexW};
	};

	switch (b) {
	case 0xCC: return result((uint8_t)(opOff + 1), 0xCC);
	case 0x90: return result((uint8_t)(opOff + 1), 0x90);
	case 0xC3: return result((uint8_t)(opOff + 1), 0xC3);
	case 0xCB: return result((uint8_t)(opOff + 1), 0xCB);
	case 0xC2: return result((uint8_t)(opOff + 3), 0xC2);
	case 0xCD: return result((uint8_t)(opOff + 2), 0xCD);
	case 0xEB: return result((uint8_t)(opOff + 2), 0xEB);
	case 0xE9: return result((uint8_t)(opOff + 5), 0xE9);
	case 0xE8: return result((uint8_t)(opOff + 5), 0xE8);

	case 0xFF: {
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			return result((uint8_t)(opOff + extra), 0xFF);
		}
		return result((uint8_t)(opOff + 2), 0xFF);
	}

	case 0x50: case 0x51: case 0x52: case 0x53:
	case 0x54: case 0x55: case 0x56: case 0x57:
		return result((uint8_t)(opOff + 1), b);
	case 0x58: case 0x59: case 0x5A: case 0x5B:
	case 0x5C: case 0x5D: case 0x5E: case 0x5F:
		return result((uint8_t)(opOff + 1), b);

	case 0xB0: case 0xB1: case 0xB2: case 0xB3:
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		return result((uint8_t)(opOff + 2), b);
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		return result((uint8_t)(opOff + (rexW ? 9 : 5)), b);

	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
		return result((uint8_t)(opOff + 2), b);

	case 0x0F: {
		if (opOff + 1 >= (int)maxLen) return result((uint8_t)(opOff + 1), 0x0F);
		uint8_t b2 = p[opOff + 1];
		if (b2 >= 0x80 && b2 <= 0x8F)
			return result((uint8_t)(opOff + 6), 0x0F);
		if (b2 >= 0x90 && b2 <= 0x9F)
			return result((uint8_t)(opOff + 3), 0x0F);
		if (b2 == 0x1F) {
			if (opOff + 2 < (int)maxLen) {
				uint8_t modrm = p[opOff + 2];
				uint8_t mod = modrm >> 6;
				int extra = 3;
				if ((modrm & 7) == 4) extra++;
				if (mod == 1) extra += 1;
				else if (mod == 2) extra += 4;
				return result((uint8_t)(opOff + extra), 0x0F);
			}
		}
		if (b2 == 0x05) return result((uint8_t)(opOff + 2), 0x0F);  // syscall
		if (b2 == 0x34 || b2 == 0x35)  // sysenter / sysexit
			return result((uint8_t)(opOff + 2), 0x0F);
		return result((uint8_t)(opOff + 3), 0x0F);
	}

	default:
		break;
	}

	// ModRM 기반 명령어
	if ((b >= 0x00 && b <= 0x03) || (b >= 0x08 && b <= 0x0B) ||
		(b >= 0x10 && b <= 0x13) || (b >= 0x18 && b <= 0x1B) ||
		(b >= 0x20 && b <= 0x23) || (b >= 0x28 && b <= 0x2B) ||
		(b >= 0x30 && b <= 0x33) || (b >= 0x38 && b <= 0x3B) ||
		(b >= 0x88 && b <= 0x8B) || b == 0x84 || b == 0x85 || b == 0x86 || b == 0x87) {
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			return result((uint8_t)(opOff + extra), b);
		}
	}

	// 즉시값 연산 (80~83)
	if (b >= 0x80 && b <= 0x83) {
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			if (b == 0x80 || b == 0x82 || b == 0x83) extra += 1;
			else extra += 4;
			return result((uint8_t)(opOff + extra), b);
		}
	}

	// F6/F7: test/not/neg/mul/div
	if (b == 0xF6 || b == 0xF7) {
		if (opOff + 1 < (int)maxLen) {
			uint8_t modrm = p[opOff + 1];
			uint8_t mod = modrm >> 6;
			uint8_t reg = (modrm >> 3) & 7;
			int extra = 2;
			if (mod == 0 && (modrm & 7) == 5) extra += 4;
			else if (mod == 1) extra += 1;
			else if (mod == 2) extra += 4;
			if ((modrm & 7) == 4 && mod != 3) extra += 1;
			if (reg == 0) extra += (b == 0xF6) ? 1 : 4;
			return result((uint8_t)(opOff + extra), b);
		}
	}

	return result((uint8_t)(opOff + 1), b);
}

// ---------------------------------------------------------------------------
// ntdll 스텁 파싱: ret까지 디스어셈블 + SSN 추출
// ---------------------------------------------------------------------------
SyscallResolver::StubInfo SyscallResolver::ParseStub(const uint8_t* stub, uint32_t maxLen) {
	StubInfo info = {0, 0xFFFFFFFF};
	uint32_t offset = 0;

	for (int i = 0; i < 30 && offset < maxLen; i++) {
		auto insn = DecodeInsn(stub + offset, maxLen - offset);
		if (insn.length == 0 || offset + insn.length > maxLen) break;

		// mov eax, imm32 (B8, REX.W 없음) -- SSN
		if (insn.opcode == 0xB8 && !insn.hasRexW) {
			uint32_t immOffset = insn.length - 4;
			if (offset + immOffset + 4 <= maxLen) {
				memcpy(&info.ssn, stub + offset + immOffset, 4);
			}
		}

		// ret (C3) 또는 ret imm16 (C2) -- 스텁 끝
		if (insn.opcode == 0xC3 || insn.opcode == 0xC2) {
			info.size = offset + insn.length;
			break;
		}

		offset += insn.length;
	}

	return info;
}

// ---------------------------------------------------------------------------
// 단일 함수 스텁 복사
// ---------------------------------------------------------------------------
size_t SyscallResolver::CopyOneStub(const char* funcName, uint8_t* dest, size_t destRemaining, void** outFunc) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return 0;

	auto* stub = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, funcName));
	if (!stub) {
		LOG_ERROR("SyscallResolver: %s not found in ntdll", funcName);
		return 0;
	}

	StubInfo info = ParseStub(stub, 64);
	if (info.size == 0 || info.size > destRemaining) {
		LOG_ERROR("SyscallResolver: failed to parse %s stub (size=%u)", funcName, info.size);
		return 0;
	}

	memcpy(dest, stub, info.size);
	*outFunc = dest;

	LOG_INFO("SyscallResolver: %s stub=%u bytes, SSN=0x%X -> copied to 0x%p",
		funcName, info.size, info.ssn, dest);

	return info.size;
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
bool SyscallResolver::Initialize() {
	if (initialized_) return true;

	// 실행 가능 메모리 할당 (4KB -- 스텁 6개 충분)
	execPage_ = VirtualAlloc(nullptr, kExecPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!execPage_) {
		LOG_ERROR("SyscallResolver: VirtualAlloc(RWX) failed: %lu", GetLastError());
		return false;
	}

	auto* cursor = static_cast<uint8_t*>(execPage_);
	size_t remaining = kExecPageSize;
	size_t used;

	// 각 함수 스텁 복사
	struct StubEntry {
		const char* name;
		void** funcPtr;
	};

	StubEntry entries[] = {
		{"NtProtectVirtualMemory",  reinterpret_cast<void**>(&pfnProtectVM_)},
		{"NtFlushInstructionCache", reinterpret_cast<void**>(&pfnFlushIC_)},
		{"NtWaitForSingleObject",   reinterpret_cast<void**>(&pfnWaitSingle_)},
		{"NtCreateEvent",           reinterpret_cast<void**>(&pfnCreateEvent_)},
		{"NtClose",                 reinterpret_cast<void**>(&pfnClose_)},
		{"NtSetEvent",              reinterpret_cast<void**>(&pfnSetEvent_)},
	};

	bool allOk = true;
	for (auto& entry : entries) {
		used = CopyOneStub(entry.name, cursor, remaining, entry.funcPtr);
		if (used == 0) {
			LOG_WARN("SyscallResolver: %s copy failed -- will use direct ntdll fallback", entry.name);
			allOk = false;
		} else {
			cursor += used;
			remaining -= used;
			// 16바이트 정렬
			size_t align = (16 - (reinterpret_cast<uintptr_t>(cursor) & 0xF)) & 0xF;
			if (align <= remaining) {
				cursor += align;
				remaining -= align;
			}
		}
	}

	// I-cache 플러시
	::FlushInstructionCache(GetCurrentProcess(), execPage_, kExecPageSize - remaining);

	initialized_ = true;
	LOG_INFO("SyscallResolver: initialized (%s, %zu bytes used)",
		allOk ? "all stubs OK" : "some stubs missing", kExecPageSize - remaining);
	return true;
}

void SyscallResolver::Shutdown() {
	// execPage_는 의도적으로 VirtualFree하지 않음.
	// Uninstall 시 VEH 핸들러에서 깨어난 스레드가 아직 스텁을 실행 중일 수 있으므로
	// 해제하면 해제된 메모리를 코드로 실행 -> 크래시.
	// 프로세스 종료 시 OS가 자동 회수한다.
	pfnProtectVM_ = nullptr;
	pfnFlushIC_ = nullptr;
	pfnWaitSingle_ = nullptr;
	pfnCreateEvent_ = nullptr;
	pfnClose_ = nullptr;
	pfnSetEvent_ = nullptr;
	initialized_ = false;
}

// ---------------------------------------------------------------------------
// 래퍼 함수들
// ---------------------------------------------------------------------------

NTSTATUS SyscallResolver::ProtectVirtualMemory(
	PVOID* baseAddress, PSIZE_T regionSize,
	ULONG newProtect, PULONG oldProtect)
{
	if (pfnProtectVM_) {
		return pfnProtectVM_(GetCurrentProcess(), baseAddress, regionSize, newProtect, oldProtect);
	}
	// 폴백
	using Fn = FnProtectVirtualMemory;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"));
	return direct ? direct(GetCurrentProcess(), baseAddress, regionSize, newProtect, oldProtect)
		: STATUS_UNSUCCESSFUL;
}

NTSTATUS SyscallResolver::FlushInstructionCache(PVOID baseAddress, SIZE_T length) {
	if (pfnFlushIC_) {
		return pfnFlushIC_(GetCurrentProcess(), baseAddress, length);
	}
	// 폴백
	using Fn = FnFlushInstructionCache;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFlushInstructionCache"));
	return direct ? direct(GetCurrentProcess(), baseAddress, length) : STATUS_UNSUCCESSFUL;
}

NTSTATUS SyscallResolver::WaitForSingleObject(HANDLE handle, PLARGE_INTEGER timeout) {
	if (pfnWaitSingle_) {
		return pfnWaitSingle_(handle, FALSE, timeout);
	}
	using Fn = FnWaitForSingleObject;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWaitForSingleObject"));
	return direct ? direct(handle, FALSE, timeout) : STATUS_UNSUCCESSFUL;
}

NTSTATUS SyscallResolver::CreateEvent(PHANDLE eventHandle) {
	if (pfnCreateEvent_) {
		// SynchronizationEvent (auto-reset), non-signaled, no name
		return pfnCreateEvent_(eventHandle, EVENT_ALL_ACCESS, nullptr,
			NtSynchronizationEvent, FALSE);
	}
	using Fn = FnCreateEvent;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateEvent"));
	return direct ? direct(eventHandle, EVENT_ALL_ACCESS, nullptr,
		NtSynchronizationEvent, FALSE) : STATUS_UNSUCCESSFUL;
}

NTSTATUS SyscallResolver::Close(HANDLE handle) {
	if (pfnClose_) {
		return pfnClose_(handle);
	}
	using Fn = FnClose;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose"));
	return direct ? direct(handle) : STATUS_UNSUCCESSFUL;
}

NTSTATUS SyscallResolver::SetEvent(HANDLE handle) {
	if (pfnSetEvent_) {
		return pfnSetEvent_(handle, nullptr);
	}
	using Fn = FnSetEvent;
	static Fn direct = reinterpret_cast<Fn>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetEvent"));
	return direct ? direct(handle, nullptr) : STATUS_UNSUCCESSFUL;
}

} // namespace veh
