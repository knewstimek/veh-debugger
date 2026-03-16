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
};

} // namespace veh
