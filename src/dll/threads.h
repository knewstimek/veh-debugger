#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>

namespace veh {

struct ThreadEntry {
	uint32_t    id;
	HANDLE      handle;
	std::string name;
};

class ThreadManager {
public:
	static ThreadManager& Instance();

	std::vector<ThreadEntry> EnumerateThreads();
	bool SuspendThread(uint32_t threadId);
	bool ResumeThread(uint32_t threadId);
	void SuspendAllExcept(uint32_t excludeThreadId);
	void ResumeAll();

	bool GetContext(uint32_t threadId, CONTEXT& ctx);
	bool SetContext(uint32_t threadId, const CONTEXT& ctx);

	// Set trap flag for single-stepping
	bool SetSingleStep(uint32_t threadId);

private:
	HANDLE OpenThread(uint32_t threadId);
};

} // namespace veh
