#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace veh {

// Debug event types
enum class DebugEventType {
	BreakpointHit,
	SingleStepComplete,
	AccessViolation,
	Exception,
};

struct DebugEvent {
	DebugEventType type;
	uint32_t       threadId;
	uint64_t       address;
	uint32_t       breakpointId;  // for breakpoint events
	uint32_t       exceptionCode; // for exception events
};

// Callback to notify the pipe server of debug events
using DebugEventCallback = std::function<void(const DebugEvent&)>;

class VehHandler {
public:
	static VehHandler& Instance();

	bool Install();
	void Uninstall();

	void SetEventCallback(DebugEventCallback cb);

	bool IsInstalled() const { return handler_ != nullptr; }

	// 스레드 재개 시그널 (continue/step 명령에서 호출)
	void ResumeStoppedThread(uint32_t threadId);
	void ResumeAllStoppedThreads();

	// 정지된 스레드의 예외 시점 컨텍스트 가져오기
	bool GetStoppedContext(uint32_t threadId, CONTEXT& ctx);

private:
	static LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS info);
	LONG HandleException(PEXCEPTION_POINTERS info);

	// 스레드가 stopped 상태에서 대기할 이벤트 가져오기/생성
	HANDLE GetOrCreateThreadEvent(uint32_t threadId);

	PVOID handler_ = nullptr;
	DebugEventCallback callback_;
	std::atomic<bool> installed_{false};

	// 스레드별 대기 이벤트 (auto-reset)
	std::mutex eventMapMutex_;
	std::unordered_map<uint32_t, HANDLE> threadEvents_;

	// 정지된 스레드의 예외 컨텍스트 저장
	std::mutex contextMapMutex_;
	std::unordered_map<uint32_t, CONTEXT> stoppedContexts_;

	// Track which address needs re-arming after single-step
	struct PendingRearm {
		uint64_t address;
		uint32_t threadId;
		bool     active;
	};
	static thread_local PendingRearm pendingRearm_;
};

} // namespace veh
