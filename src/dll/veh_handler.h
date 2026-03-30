#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
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
	void ResumeStoppedThread(uint32_t threadId, bool step = false, bool passException = false);
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

	// TraceCalls: monitor where call/jmp instructions go at runtime
	// Zero IPC per hit: VEH records target in lock-free ring buffer, auto-continues
	struct TraceCallsState {
		std::atomic<bool> active{false};
		std::vector<uint64_t> addresses;  // sorted, for binary search in VEH
		bool IsTraced(uint64_t addr) const;
		// Lock-free ring buffer
		static constexpr uint32_t kBufferSize = 65536;
		struct Entry { uint64_t callSite; uint64_t target; };
		std::atomic<uint32_t> writeIdx{0};
		Entry buffer[kBufferSize];
		std::atomic<uint32_t> totalHits{0};
	};
	TraceCallsState traceCalls_;

	// TraceRegister: single-step loop inside VEH, no IPC per step
	struct TraceRegState {
		std::atomic<bool> active{false};
		uint32_t threadId = 0;
		uint32_t regIndex = 0;
		uint32_t maxSteps = 0;
		uint8_t mode = 0;          // 0=changed, 1=equals, 2=not_equals
		uint64_t compareValue = 0;
		uint64_t initialValue = 0;
		// Results (written by VEH thread, read by pipe thread)
		std::atomic<bool> done{false};
		bool found = false;
		uint32_t stepsExecuted = 0;
		uint64_t resultAddress = 0;
		uint64_t oldValue = 0;
		uint64_t newValue = 0;
	};
	TraceRegState traceReg_;
	void StartTraceRegister(uint32_t threadId, uint32_t regIndex, uint32_t maxSteps,
	                         uint8_t mode, uint64_t compareValue);

	// TraceMemory: VEH signals when HW BP hits (same pattern as traceReg_)
	struct TraceMemState {
		std::atomic<bool> active{false};
		uint32_t hwBpId = 0;        // temp HW BP to watch for
		uint64_t watchAddress = 0;
		uint32_t watchSize = 0;
		// Results
		std::atomic<bool> done{false};
		bool found = false;
		uint32_t threadId = 0;
		uint64_t instructionAddress = 0;
		uint64_t oldValue = 0;
		uint64_t newValue = 0;
	};
	TraceMemState traceMem_;

	// ResolveImport: step from thunk until RIP enters a loaded DLL
	struct ImportResolveState {
		std::atomic<bool> active{false};
		uint32_t threadId = 0;
		uint32_t maxSteps = 0;
		bool followExceptions = false;    // pass non-SINGLE_STEP to SEH, keep TF
		uint32_t maxExceptionPasses = 50; // safety limit per thunk
		// Module ranges for "is RIP in a DLL?" check
		struct ModRange {
			uint64_t base; uint64_t end;
			bool isTarget;  // true = valid resolve target (filtered by target_modules/system_only)
		};
		std::vector<ModRange> moduleRanges;
		uint64_t exeBase = 0;
		uint64_t exeEnd = 0;
		// INT3-based stepping (anti-TF): pipe_server places INT3, VEH catches it
		std::atomic<uint64_t> pendingInt3Addr{0};  // address where INT3 was placed
		std::atomic<uint8_t>  pendingInt3Byte{0};  // original byte at that address
		// UEF safety net: park stub for unhandled exception recovery
		void* parkStub = nullptr;         // NOP sled (executable page) for UEF redirect
		// Diagnostic trace log (ring buffer, last N addresses + exception codes)
		static constexpr uint32_t kTraceLogSize = 32;
		struct TraceLogEntry {
			uint64_t address;
			uint32_t exceptionCode;  // 0 for normal single-step
		};
		TraceLogEntry traceLog[kTraceLogSize] = {};
		uint32_t traceLogIdx = 0;
		// Results
		std::atomic<bool> done{false};
		bool found = false;
		uint32_t stepsExecuted = 0;
		uint32_t exceptionsPassed = 0;    // exceptions forwarded to SEH
		uint64_t targetAddress = 0;
	};
	ImportResolveState importResolve_;

	// 내부 스레드 등록 (pipe server 등) -- BP 투명 스킵 + trace_callers 스킵
	void SetInternalThread(uint32_t tid) { internalTid_.store(tid, std::memory_order_relaxed); }

	// 셸코드 스레드 등록/해제 -- VEH 핸들러가 예외를 무시 (CONTINUE_SEARCH)
	void RegisterShellcodeThread(uint32_t tid);
	void UnregisterShellcodeThread(uint32_t tid);
	bool IsShellcodeThread(uint32_t tid);

	// NotifyAndWait 결과
	enum class WaitResult { Resumed, Detached, NoCallback };

private:
	static LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS info);
	LONG HandleException(PEXCEPTION_POINTERS info);

	// 공통 패턴: 컨텍스트 저장 -> 이벤트 생성 -> 콜백 -> 대기 -> 컨텍스트 복원
	// 4개 예외 경로(BP, HW BP, step complete, exception)에서 공유
	WaitResult NotifyAndWait(PEXCEPTION_POINTERS info, uint32_t tid,
		DebugEventType type, uint64_t addr, uint32_t bpId, DWORD code);

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

	// Step 요청 플래그 (파이프 스레드 -> VEH 스레드 전달)
	std::mutex stepFlagMutex_;
	std::unordered_map<uint32_t, bool> stepFlags_;

	// Pass exception 플래그 (continue 시 EXCEPTION_CONTINUE_SEARCH 반환)
	std::unordered_map<uint32_t, bool> passExceptionFlags_;

	// 셸코드 스레드 셋 (VEH가 예외 무시)
	std::mutex shellcodeThreadMutex_;
	std::unordered_set<uint32_t> shellcodeThreads_;

	// TraceCallers 모드 (lock-free ring buffer - VEH 핸들러에서 안전하게 사용)
	std::atomic<uint64_t> traceAddress_{0};   // 0 = trace 비활성
	static constexpr uint32_t kTraceBufferSize = 65536;
	std::atomic<uint32_t> traceWriteIdx_{0};
	uint64_t traceBuffer_[kTraceBufferSize];   // lock-free ring buffer
	std::atomic<uint32_t> traceTotalHits_{0};
	std::atomic<uint32_t> internalTid_{0};  // pipe server tid (trace skip)

	// Track which address needs re-arming after single-step (per-thread)
	struct PendingRearm {
		uint64_t address;
		uint32_t threadId;
		bool     active;
		bool     stepRequested;  // true면 rearm 후 다시 TF 설정하여 StepCompleted 발생
	};
	DWORD pendingRearmTlsSlot_ = TLS_OUT_OF_INDEXES;
	PendingRearm& GetPendingRearm();
};

} // namespace veh
