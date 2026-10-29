#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
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
    // Loader callbacks only publish an epoch; never enter DbgHelp or its mutex.
    void NotifyModulesChanged(uint64_t base) noexcept;
    bool RefreshModules();
	std::vector<StackFrame> Walk(uint32_t threadId, uint32_t startFrame = 0, uint32_t maxFrames = 50);

	// Module/function/line for arbitrary addresses (same resolution as stack frames)
	std::vector<AddressSymbol> Symbolize(const std::vector<uint64_t>& addresses);
    IpcStatus FindSymbols(const std::string& name, uint32_t maximum,
        std::vector<FindSymbolEntry>& entries, uint32_t& flags, uint64_t moduleBase = 0);

	// PDB type layout (and values when req.address != 0). false when the type is not found.
	bool DisplayType(const DisplayTypeRequest& req, DisplayTypeResponse& resp,
	                 std::vector<DisplayTypeMember>& members);

	// Enumerate local variables for a given frame using PDB symbols
	std::vector<LocalVariableInfo> EnumLocals(uint32_t threadId, uint64_t instructionAddress, uint64_t frameBase);

private:
	bool initialized_ = false;
	std::mutex dbghelpMutex_;
    std::atomic<uint64_t> moduleEpoch_{0}, refreshedEpoch_{0};
    std::atomic<uint64_t> invalidatedModules_[256]{};
    std::atomic<bool> invalidateAllModules_{false};
    bool RefreshModulesLocked(bool force = false);
};

} // namespace veh
