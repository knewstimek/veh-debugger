#include <windows.h>
#include "memory.h"
#include "veh_handler.h"
#include <cstring>

namespace veh {

MemoryManager& MemoryManager::Instance() {
	static MemoryManager instance;
	return instance;
}

// SEH를 사용하는 raw memcpy (C++ 객체 없는 함수에서만 사용)
static bool SafeMemcpy(void* dst, const void* src, size_t size) {
	__try {
		memcpy(dst, src, size);
		return true;
	}
	__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH) {
		return false;
	}
}

std::vector<uint8_t> MemoryManager::Read(uint64_t address, uint32_t size) {
	std::vector<uint8_t> buffer(size);
	auto* src = reinterpret_cast<const void*>(address);

	if (!SafeMemcpy(buffer.data(), src, size)) {
		buffer.clear();
	}

	return buffer;
}

bool MemoryManager::Write(uint64_t address, const uint8_t* data, uint32_t size) {
	DWORD oldProtect = 0;

	if (!MakeWritable(address, size, oldProtect)) {
		return false;
	}

	auto* dst = reinterpret_cast<void*>(address);
	bool success = SafeMemcpy(dst, data, size);

	RestoreProtection(address, size, oldProtect);

	if (success) {
		FlushInstructionCache(GetCurrentProcess(), dst, size);
	}

	return success;
}

bool MemoryManager::MakeWritable(uint64_t address, uint32_t size, DWORD& oldProtect) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	return VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &oldProtect) != FALSE;
}

bool MemoryManager::RestoreProtection(uint64_t address, uint32_t size, DWORD oldProtect) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	DWORD dummy = 0;
	return VirtualProtect(ptr, size, oldProtect, &dummy) != FALSE;
}

uint64_t MemoryManager::Allocate(uint32_t size, uint32_t protection) {
	void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
	return reinterpret_cast<uint64_t>(ptr);
}

bool MemoryManager::Free(uint64_t address, uint32_t /*size*/) {
	auto* ptr = reinterpret_cast<LPVOID>(address);
	return VirtualFree(ptr, 0, MEM_RELEASE) != FALSE;
}

// SEH wrapper context -- passed to shellcode thread
struct ShellcodeContext {
	void*    codeAddr;
	bool     crashed;
	uint32_t exceptionCode;
	uint64_t exceptionAddress;
};

// SEH wrapper must be in a separate function (no C++ destructors -- MSVC C2712)
static DWORD SafeCallShellcode(ShellcodeContext* ctx) {
	__try {
		auto fn = reinterpret_cast<DWORD(WINAPI*)(LPVOID)>(ctx->codeAddr);
		return fn(nullptr);
	} __except (
		ctx->crashed = true,
		ctx->exceptionCode = GetExceptionInformation()->ExceptionRecord->ExceptionCode,
		ctx->exceptionAddress = reinterpret_cast<uint64_t>(GetExceptionInformation()->ExceptionRecord->ExceptionAddress),
		EXCEPTION_EXECUTE_HANDLER
	) {
		return 0xDEAD0001;
	}
}

static DWORD WINAPI ShellcodeThreadProc(LPVOID param) {
	DWORD result = SafeCallShellcode(reinterpret_cast<ShellcodeContext*>(param));
	// Always unregister (covers fire-and-forget + normal paths; erase is idempotent)
	VehHandler::Instance().UnregisterShellcodeThread(GetCurrentThreadId());
	return result;
}

bool MemoryManager::ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs,
                                     uint64_t& allocAddr, uint32_t& exitCode,
                                     bool& crashed, uint32_t& exceptionCode, uint64_t& exceptionAddress) {
	crashed = false;
	exceptionCode = 0;
	exceptionAddress = 0;
	// 1. Allocate RWX page
	void* mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem) return false;
	allocAddr = reinterpret_cast<uint64_t>(mem);

	// 2. Copy shellcode
	memcpy(mem, code, size);
	FlushInstructionCache(GetCurrentProcess(), mem, size);

	// 3. Prepare context for SEH wrapper
	ShellcodeContext ctx = {};
	ctx.codeAddr = mem;

	// 4. Create thread suspended, register with VEH, then resume
	DWORD tid = 0;
	HANDLE hThread = CreateThread(nullptr, 0, ShellcodeThreadProc, &ctx, CREATE_SUSPENDED, &tid);
	if (!hThread) {
		VirtualFree(mem, 0, MEM_RELEASE);
		allocAddr = 0;
		return false;
	}
	VehHandler::Instance().RegisterShellcodeThread(tid);
	ResumeThread(hThread);

	if (timeoutMs == 0) {
		// Fire-and-forget: don't wait, don't free (caller manages)
		// Note: VEH registration stays until thread exits naturally
		CloseHandle(hThread);
		exitCode = 0;
		return true;
	}

	// 5. Wait for completion
	DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
	if (waitResult == WAIT_OBJECT_0) {
		DWORD code32 = 0;
		GetExitCodeThread(hThread, &code32);
		exitCode = code32;
	} else {
		// Timeout - terminate thread, then wait for actual termination
		TerminateThread(hThread, 0xDEAD);
		WaitForSingleObject(hThread, 5000);
		exitCode = 0xDEAD;
	}
	CloseHandle(hThread);
	VehHandler::Instance().UnregisterShellcodeThread(tid);

	// 6. Copy crash info from context
	if (ctx.crashed) {
		crashed = true;
		exceptionCode = ctx.exceptionCode;
		exceptionAddress = ctx.exceptionAddress;
	}

	// 7. Free RWX page (safe: thread is guaranteed dead at this point)
	VirtualFree(mem, 0, MEM_RELEASE);
	allocAddr = 0;

	return (waitResult == WAIT_OBJECT_0);
}

// Accessors for crash info from last ExecuteShellcode
// (pipe_server reads ShellcodeContext via response struct)

} // namespace veh
