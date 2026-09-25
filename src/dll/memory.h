#pragma once
#include <cstdint>
#include <vector>
#include <windows.h>
#include "../common/ipc_protocol.h"

namespace veh {

// SEH-protected bulk copy used by target-side memory operations.
bool SafeCopyMemory(void* dst, const void* src, size_t size);

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
	bool Protect(uint64_t address, uint64_t size, uint32_t protection,
		ProtectMemoryMethod requestedMethod, uint32_t& oldProtection,
		ProtectMemoryMethod& appliedMethod, uint32_t& errorCode);

	// Region list from VirtualQuery. Returns the resume address when maxRegions was hit, else 0.
	uint64_t QueryMap(uint64_t start, uint64_t end, uint32_t maxRegions, bool includeFree,
	                  std::vector<MemoryRegionEntry>& out);

	struct SearchResult {
		std::vector<uint64_t> hits;
		uint64_t nextAddress = 0;   // non-zero when maxResults was hit
		uint64_t scannedBytes = 0;
		uint32_t regionsScanned = 0;
	};
	// Masked byte-pattern scan over readable committed memory. BP bytes are
	// masked back to the original code, and [excludeStart, excludeEnd) (the
	// request buffer holding the pattern itself) never matches.
	bool Search(const SearchMemoryRequest& req, const uint8_t* pattern, const uint8_t* mask,
	            uint64_t excludeStart, uint64_t excludeEnd, SearchResult& result);

	// Execute shellcode: alloc RWX -> copy -> CreateThread (SEH-wrapped) -> wait -> free
	// Returns thread exit code. Sets allocAddr to the RWX page address.
	// Crash info: if shellcode crashes, crashed=true with exception details.
	bool ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs,
	                      uint64_t& allocAddr, uint32_t& exitCode,
	                      bool& crashed, uint32_t& exceptionCode, uint64_t& exceptionAddress);
};

} // namespace veh
