#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <set>
#include <mutex>
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
	std::vector<uint32_t> GetSuspendedThreadIds();

	// User freeze: an extra OS suspend count tracked apart from Pause, so
	// ResumeAll (Continue) does not release it. Thaw on detach/cleanup.
	bool FreezeThread(uint32_t threadId);
	bool ThawThread(uint32_t threadId);
	void ThawAll();
	std::vector<uint32_t> GetFrozenThreadIds();

	bool GetContext(uint32_t threadId, CONTEXT& ctx);
	bool SetContext(uint32_t threadId, const CONTEXT& ctx);

	// Set trap flag for single-stepping
	bool SetSingleStep(uint32_t threadId);

	// DLL internal thread management (pipe server, heartbeat, etc.)
	// These threads are excluded from EnumerateThreads results and
	// protected from SuspendThread/GetContext to prevent deadlocks.
	void RegisterInternalThread(uint32_t threadId);
	void UnregisterInternalThread(uint32_t threadId);
	bool IsInternalThread(uint32_t threadId);

private:
	HANDLE OpenThread(uint32_t threadId);
	std::set<uint32_t> internalThreads_;
	std::mutex internalMutex_;
	std::set<uint32_t> suspendedThreads_;
	std::mutex suspendedMutex_;
	std::set<uint32_t> frozenThreads_;
	std::mutex frozenMutex_;
};

} // namespace veh
