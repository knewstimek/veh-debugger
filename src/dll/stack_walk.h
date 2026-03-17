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

class StackWalker {
public:
	static StackWalker& Instance();

	void Initialize();
	std::vector<StackFrame> Walk(uint32_t threadId, uint32_t startFrame = 0, uint32_t maxFrames = 50);

	// Enumerate local variables for a given frame using PDB symbols
	std::vector<LocalVariableInfo> EnumLocals(uint32_t threadId, uint64_t instructionAddress, uint64_t frameBase);

private:
	bool initialized_ = false;
	std::mutex dbghelpMutex_;
};

} // namespace veh
