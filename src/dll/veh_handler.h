#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>

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
	const CONTEXT* context;       // VEH 정지 시점의 컨텍스트 (BP 히트 시 전달)
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
	void ResumeStoppedThread(uint32_t threadId, bool step = false);
	void ResumeAllStoppedThreads(bool forDetach = false);

	// 스레드가 VEH 핸들러에서 정지(대기) 중인지 확인
	bool IsThreadStopped(uint32_t threadId);

	// 정지된 스레드의 예외 시점 컨텍스트 가져오기/설정하기
	bool GetStoppedContext(uint32_t threadId, CONTEXT& ctx);
	bool SetStoppedContext(uint32_t threadId, const CONTEXT& ctx);

	// TraceCallers
	void StartTrace(uint64_t address);
	void StopTrace();
	std::unordered_map<uint64_t, uint32_t> GetTraceResults(uint32_t& totalHits);

	// 내부 스레드 등록 (pipe server 등) -- trace_callers에서 스킵하기 위해
	void SetInternalThread(uint32_t tid) { internalTid_.store(tid, std::memory_order_relaxed); }

private:
	static LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS info);
	LONG HandleException(PEXCEPTION_POINTERS info);

	// 스레드가 stopped 상태에서 대기할 이벤트 가져오기/생성
	HANDLE GetOrCreateThreadEvent(uint32_t threadId);

	PVOID handler_ = nullptr;
	DebugEventCallback callback_;
	std::atomic<bool> installed_{false};

	// VEH 재진입 방지 TLS 슬롯 (thread_local 금지 -> TlsAlloc 사용)
	DWORD reentryTlsSlot_ = TLS_OUT_OF_INDEXES;

	// 스레드별 대기 이벤트 (auto-reset)
	std::mutex eventMapMutex_;
	std::unordered_map<uint32_t, HANDLE> threadEvents_;

	// 정지된 스레드의 예외 컨텍스트 저장
	std::mutex contextMapMutex_;
	std::unordered_map<uint32_t, CONTEXT> stoppedContexts_;

	// Step 요청 플래그 (파이프 스레드 → VEH 스레드 전달)
	std::mutex stepFlagMutex_;
	std::unordered_map<uint32_t, bool> stepFlags_;

	// TraceCallers 모드 (lock-free ring buffer - VEH 핸들러에서 안전하게 사용)
	std::atomic<uint64_t> traceAddress_{0};   // 0 = trace 비활성
	static constexpr uint32_t kTraceBufferSize = 65536;
	std::atomic<uint32_t> traceWriteIdx_{0};
	uint64_t traceBuffer_[kTraceBufferSize];   // lock-free ring buffer
	std::atomic<uint32_t> traceTotalHits_{0};
	std::atomic<uint32_t> internalTid_{0};  // pipe server tid (trace skip)

	// Track which address needs re-arming after single-step
	struct PendingRearm {
		uint64_t address;
		uint32_t threadId;
		bool     active;
		bool     stepRequested;  // true면 rearm 후 다시 TF 설정하여 StepCompleted 발생
	};
	static thread_local PendingRearm pendingRearm_;
};

} // namespace veh
