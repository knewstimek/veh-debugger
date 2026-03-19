#include <windows.h>
#include "threads.h"
#include "../common/logger.h"
#include <tlhelp32.h>

// GetThreadDescription은 Windows 10 1607+에서 사용 가능
typedef HRESULT(WINAPI* GetThreadDescription_t)(HANDLE, PWSTR*);

namespace veh {

ThreadManager& ThreadManager::Instance() {
	static ThreadManager instance;
	return instance;
}

// 현재 프로세스의 모든 스레드 열거
std::vector<ThreadEntry> ThreadManager::EnumerateThreads() {
	std::vector<ThreadEntry> result;
	const DWORD pid = GetCurrentProcessId();
	const DWORD currentTid = GetCurrentThreadId();

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: %lu", GetLastError());
		return result;
	}

	// GetThreadDescription 동적 로드
	static auto pGetThreadDescription = reinterpret_cast<GetThreadDescription_t>(
		GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription"));

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;

			ThreadEntry entry;
			entry.id = te.th32ThreadID;
			entry.handle = nullptr; // 핸들은 필요 시 OpenThread로 획득

			// 스레드 이름 얻기 (가능한 경우)
			if (pGetThreadDescription) {
				HANDLE hThread = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
				if (hThread) {
					PWSTR desc = nullptr;
					if (SUCCEEDED(pGetThreadDescription(hThread, &desc)) && desc) {
						// 와이드 → 멀티바이트 변환
						int len = WideCharToMultiByte(CP_UTF8, 0, desc, -1, nullptr, 0, nullptr, nullptr);
						if (len > 0) {
							entry.name.resize(len - 1);
							WideCharToMultiByte(CP_UTF8, 0, desc, -1, entry.name.data(), len, nullptr, nullptr);
						}
						LocalFree(desc);
					}
					CloseHandle(hThread);
				}
			}

			// Skip DLL internal threads (pipe server, heartbeat, etc.)
			if (IsInternalThread(te.th32ThreadID)) continue;

			result.push_back(std::move(entry));
		} while (Thread32Next(snap, &te));
	}

	CloseHandle(snap);
	size_t internalCount;
	{
		std::lock_guard<std::mutex> lock(internalMutex_);
		internalCount = internalThreads_.size();
	}
	LOG_DEBUG("Enumerated %zu threads in PID %lu (excluding %zu internal)",
		result.size(), pid, internalCount);
	return result;
}

HANDLE ThreadManager::OpenThread(uint32_t threadId) {
	HANDLE h = ::OpenThread(
		THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
		FALSE, threadId);
	if (!h) {
		LOG_ERROR("OpenThread(%u) failed: %lu", threadId, GetLastError());
	}
	return h;
}

bool ThreadManager::SuspendThread(uint32_t threadId) {
	if (IsInternalThread(threadId)) {
		LOG_WARN("SuspendThread(%u) rejected: internal DLL thread (deadlock prevention)", threadId);
		return false;
	}
	HANDLE h = OpenThread(threadId);
	if (!h) return false;

	DWORD prev = ::SuspendThread(h);
	CloseHandle(h);

	if (prev == static_cast<DWORD>(-1)) {
		LOG_ERROR("SuspendThread(%u) failed: %lu", threadId, GetLastError());
		return false;
	}

	LOG_DEBUG("Suspended thread %u (prev count=%lu)", threadId, prev);
	return true;
}

bool ThreadManager::ResumeThread(uint32_t threadId) {
	HANDLE h = OpenThread(threadId);
	if (!h) return false;

	DWORD prev = ::ResumeThread(h);
	CloseHandle(h);

	if (prev == static_cast<DWORD>(-1)) {
		LOG_ERROR("ResumeThread(%u) failed: %lu", threadId, GetLastError());
		return false;
	}

	LOG_DEBUG("Resumed thread %u (prev count=%lu)", threadId, prev);
	return true;
}

void ThreadManager::SuspendAllExcept(uint32_t excludeThreadId) {
	auto threads = EnumerateThreads(); // already excludes internal threads
	for (const auto& t : threads) {
		if (t.id != excludeThreadId) {
			SuspendThread(t.id);
		}
	}
	LOG_DEBUG("Suspended all threads except %u", excludeThreadId);
}

void ThreadManager::ResumeAll() {
	auto threads = EnumerateThreads();
	for (const auto& t : threads) {
		ResumeThread(t.id);
	}
	LOG_DEBUG("Resumed all threads");
}

bool ThreadManager::GetContext(uint32_t threadId, CONTEXT& ctx) {
	// Prevent deadlock: never suspend DLL internal threads (pipe server, etc.)
	if (IsInternalThread(threadId)) {
		LOG_WARN("GetContext(%u) rejected: internal DLL thread (deadlock prevention)", threadId);
		return false;
	}

	HANDLE h = OpenThread(threadId);
	if (!h) return false;

	DWORD prev = ::SuspendThread(h);
	if (prev == static_cast<DWORD>(-1)) {
		LOG_ERROR("SuspendThread for GetContext(%u) failed: %lu", threadId, GetLastError());
		CloseHandle(h);
		return false;
	}

	ctx.ContextFlags = CONTEXT_ALL;
	BOOL ok = ::GetThreadContext(h, &ctx);

	::ResumeThread(h);
	CloseHandle(h);

	if (!ok) {
		LOG_ERROR("GetThreadContext(%u) failed: %lu", threadId, GetLastError());
		return false;
	}

	return true;
}

bool ThreadManager::SetContext(uint32_t threadId, const CONTEXT& ctx) {
	if (IsInternalThread(threadId)) {
		LOG_WARN("SetContext(%u) rejected: internal DLL thread (deadlock prevention)", threadId);
		return false;
	}
	HANDLE h = OpenThread(threadId);
	if (!h) return false;

	DWORD prev = ::SuspendThread(h);
	if (prev == static_cast<DWORD>(-1)) {
		LOG_ERROR("SuspendThread for SetContext(%u) failed: %lu", threadId, GetLastError());
		CloseHandle(h);
		return false;
	}

	BOOL ok = ::SetThreadContext(h, &ctx);

	::ResumeThread(h);
	CloseHandle(h);

	if (!ok) {
		LOG_ERROR("SetThreadContext(%u) failed: %lu", threadId, GetLastError());
		return false;
	}

	return true;
}

bool ThreadManager::SetSingleStep(uint32_t threadId) {
	CONTEXT ctx;
	if (!GetContext(threadId, ctx)) return false;

	// EFLAGS의 TF(Trap Flag) 비트 설정
	ctx.EFlags |= 0x100;

	if (!SetContext(threadId, ctx)) return false;

	LOG_DEBUG("Set single-step (TF) for thread %u", threadId);
	return true;
}

void ThreadManager::RegisterInternalThread(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(internalMutex_);
	internalThreads_.insert(threadId);
	LOG_DEBUG("Registered internal thread %u", threadId);
}

void ThreadManager::UnregisterInternalThread(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(internalMutex_);
	internalThreads_.erase(threadId);
	LOG_DEBUG("Unregistered internal thread %u", threadId);
}

bool ThreadManager::IsInternalThread(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(internalMutex_);
	return internalThreads_.count(threadId) > 0;
}

} // namespace veh
