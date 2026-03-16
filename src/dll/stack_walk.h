#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <windows.h>

namespace veh {

struct StackFrame {
	uint64_t    address;
	uint64_t    returnAddress;
	uint64_t    frameBase;
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

private:
	bool initialized_ = false;
	std::mutex dbghelpMutex_;
};

} // namespace veh
