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

} // namespace veh
