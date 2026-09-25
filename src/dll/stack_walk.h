#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <windows.h>
#include "../common/ipc_protocol.h"

namespace veh {

struct StackFrame {
	uint64_t    address;
	uint64_t    returnAddress;
	uint64_t    frameBase;
	uint64_t    moduleBase;
	std::string moduleName;
	std::string functionName;
	std::string sourceFile;
	uint32_t    line;
};

struct AddressSymbol {
	uint64_t    moduleBase = 0;
	uint64_t    displacement = 0;   // from functionName's start
	std::string moduleName;
	std::string functionName;       // PDB symbol, else nearest export
	std::string sourceFile;
	uint32_t    line = 0;
};

class StackWalker {
public:
	static StackWalker& Instance();

	void Initialize();
	std::vector<StackFrame> Walk(uint32_t threadId, uint32_t startFrame = 0, uint32_t maxFrames = 50);

	// Module/function/line for arbitrary addresses (same resolution as stack frames)
	std::vector<AddressSymbol> Symbolize(const std::vector<uint64_t>& addresses);

	// Enumerate local variables for a given frame using PDB symbols
	std::vector<LocalVariableInfo> EnumLocals(uint32_t threadId, uint64_t instructionAddress, uint64_t frameBase);

private:
	bool initialized_ = false;
	std::mutex dbghelpMutex_;
};

} // namespace veh
