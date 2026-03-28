#pragma once
#include <cstdint>
#include <vector>
#include <windows.h>

namespace veh {

class MemoryManager {
public:
	static MemoryManager& Instance();

	std::vector<uint8_t> Read(uint64_t address, uint32_t size);
	bool Write(uint64_t address, const uint8_t* data, uint32_t size);

	// Change memory protection temporarily for patching
	bool MakeWritable(uint64_t address, uint32_t size, DWORD& oldProtect);
	bool RestoreProtection(uint64_t address, uint32_t size, DWORD oldProtect);

	// Allocate/free memory pages
	uint64_t Allocate(uint32_t size, uint32_t protection);
	bool Free(uint64_t address, uint32_t size);

	// Execute shellcode: alloc RWX -> copy -> CreateThread -> wait -> free
	// Returns thread exit code. Sets allocAddr to the RWX page address.
	bool ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs,
	                      uint64_t& allocAddr, uint32_t& exitCode);
};

} // namespace veh
