#include <windows.h>
#include "memory.h"
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

bool MemoryManager::ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs,
                                     uint64_t& allocAddr, uint32_t& exitCode) {
	// 1. Allocate RWX page
	void* mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem) return false;
	allocAddr = reinterpret_cast<uint64_t>(mem);

	// 2. Copy shellcode
	memcpy(mem, code, size);
	FlushInstructionCache(GetCurrentProcess(), mem, size);

	// 3. Execute via CreateThread
	HANDLE hThread = CreateThread(nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0, nullptr);
	if (!hThread) {
		VirtualFree(mem, 0, MEM_RELEASE);
		allocAddr = 0;
		return false;
	}

	if (timeoutMs == 0) {
		// Fire-and-forget: don't wait, don't free (caller manages)
		CloseHandle(hThread);
		exitCode = 0;
		return true;
	}

	// 4. Wait for completion
	DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
	if (waitResult == WAIT_OBJECT_0) {
		DWORD code32 = 0;
		GetExitCodeThread(hThread, &code32);
		exitCode = code32;
	} else {
		// Timeout - terminate thread, then wait for actual termination
		TerminateThread(hThread, 0xDEAD);
		WaitForSingleObject(hThread, 5000);  // wait for thread to actually die
		exitCode = 0xDEAD;
	}
	CloseHandle(hThread);

	// 5. Free RWX page (safe: thread is guaranteed dead at this point)
	VirtualFree(mem, 0, MEM_RELEASE);
	allocAddr = 0;

	return (waitResult == WAIT_OBJECT_0);
}

} // namespace veh
