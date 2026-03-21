#include <windows.h>
#include "veh_handler.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "threads.h"
#include "../common/logger.h"

// __try/__except requires separate function (no C++ destructors allowed)
static uint64_t ReadCallerFromStack(const CONTEXT* ctx) {
	__try {
#ifdef _WIN64
		// RtlVirtualUnwind -- PE unwind 테이블로 정확한 caller 획득 (함수 중간 BP에서도 동작)
		DWORD64 imageBase = 0;
		PRUNTIME_FUNCTION rtFunc = RtlLookupFunctionEntry(ctx->Rip, &imageBase, nullptr);
		if (rtFunc) {
			CONTEXT tmpCtx = *ctx;
			PVOID handlerData = nullptr;
			DWORD64 establisherFrame = 0;
			RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx->Rip,
				rtFunc, &tmpCtx, &handlerData, &establisherFrame, nullptr);
			return tmpCtx.Rip;
		}
		// Leaf function (unwind info 없음) -- [RSP] 폴백
		return *reinterpret_cast<uint64_t*>(ctx->Rsp);
#else
		return static_cast<uint64_t>(*reinterpret_cast<uint32_t*>(ctx->Esp));
#endif
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

namespace veh {

VehHandler::PendingRearm& VehHandler::GetPendingRearm() {
	auto* p = static_cast<PendingRearm*>(TlsGetValue(pendingRearmTlsSlot_));
	if (!p) {
		p = static_cast<PendingRearm*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PendingRearm)));
		TlsSetValue(pendingRearmTlsSlot_, p);
	}
	return *p;
}

VehHandler& VehHandler::Instance() {
	static VehHandler instance;
	return instance;
}

bool VehHandler::Install() {
	if (installed_) {
		LOG_WARN("VEH handler already installed");
		return true;
	}

	// TLS 슬롯 할당 (thread_local 사용 금지 -> TlsAlloc, ManualMap 호환)
	reentryTlsSlot_ = TlsAlloc();
	pendingRearmTlsSlot_ = TlsAlloc();
	if (reentryTlsSlot_ == TLS_OUT_OF_INDEXES || pendingRearmTlsSlot_ == TLS_OUT_OF_INDEXES) {
		LOG_ERROR("TlsAlloc failed: %lu", GetLastError());
		if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES) { TlsFree(reentryTlsSlot_); reentryTlsSlot_ = TLS_OUT_OF_INDEXES; }
		if (pendingRearmTlsSlot_ != TLS_OUT_OF_INDEXES) { TlsFree(pendingRearmTlsSlot_); pendingRearmTlsSlot_ = TLS_OUT_OF_INDEXES; }
		return false;
	}

	// 첫 번째 핸들러로 등록 (1 = first handler)
	handler_ = AddVectoredExceptionHandler(1, ExceptionHandler);
	if (!handler_) {
		LOG_ERROR("AddVectoredExceptionHandler failed: %lu", GetLastError());
		TlsFree(reentryTlsSlot_);
		reentryTlsSlot_ = TLS_OUT_OF_INDEXES;
		return false;
	}

	installed_ = true;
	LOG_INFO("VEH handler installed");
	return true;
}

void VehHandler::Uninstall() {
	if (!installed_) return;
	installed_ = false;  // 먼저 설정하여 새 예외 진입 차단

	// 대기 중인 모든 스레드 깨우기 (detach이므로 TF/rearm 취소 유도)
	ResumeAllStoppedThreads(true);

	if (handler_) {
		RemoveVectoredExceptionHandler(handler_);
		handler_ = nullptr;
	}

	// TLS 슬롯 해제 (per-thread HeapAlloc 메모리는 프로세스 종료 시 OS 회수)
	if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES) {
		TlsFree(reentryTlsSlot_);
		reentryTlsSlot_ = TLS_OUT_OF_INDEXES;
	}
	if (pendingRearmTlsSlot_ != TLS_OUT_OF_INDEXES) {
		TlsFree(pendingRearmTlsSlot_);
		pendingRearmTlsSlot_ = TLS_OUT_OF_INDEXES;
	}

	// 이벤트 핸들 정리
	{
		std::lock_guard<std::mutex> lock(eventMapMutex_);
		for (auto& [tid, evt] : threadEvents_) {
			CloseHandle(evt);
		}
		threadEvents_.clear();
	}

	LOG_INFO("VEH handler uninstalled");
}

void VehHandler::SetEventCallback(DebugEventCallback cb) {
	callback_ = std::move(cb);
}

HANDLE VehHandler::GetOrCreateThreadEvent(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	auto it = threadEvents_.find(threadId);
	if (it != threadEvents_.end()) return it->second;
	HANDLE evt = CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset
	if (!evt) {
		LOG_ERROR("CreateEventW failed for thread %u: %lu", threadId, GetLastError());
		return nullptr;
	}
	threadEvents_[threadId] = evt;
	return evt;
}

void VehHandler::ResumeStoppedThread(uint32_t threadId, bool step) {
	LOG_DEBUG("ResumeStoppedThread(%u, step=%d)", threadId, step);

	// step 플래그 설정 (VEH 핸들러 스레드에서 읽음)
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		if (step) {
			stepFlags_[threadId] = true;
		} else {
			stepFlags_.erase(threadId);
		}
	}

	// NOTE: stoppedContexts_는 여기서 erase하지 않음!
	// VEH 핸들러가 WaitForSingleObject에서 깨어난 뒤 context를 복원해야 하므로,
	// erase는 VEH 핸들러 쪽에서 복원 완료 후 수행한다.
	// (여기서 erase하면 VEH가 detach로 오판하여 TF/rearm을 취소하는 버그 발생)

	std::lock_guard<std::mutex> lock(eventMapMutex_);
	auto it = threadEvents_.find(threadId);
	if (it != threadEvents_.end()) {
		SetEvent(it->second);
		// NOTE: CloseHandle은 VEH 핸들러(WaitForSingleObject 호출자)가 담당
		threadEvents_.erase(it);
	}
}

void VehHandler::ResumeAllStoppedThreads(bool forDetach) {
	LOG_DEBUG("ResumeAllStoppedThreads(forDetach=%d)", forDetach);
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		stepFlags_.clear();
	}
	if (forDetach) {
		// Detach: stoppedContexts_를 먼저 비워서 VEH 핸들러가 detach를 감지하게 함
		// -> TF 클리어 + pendingRearm 취소 (VEH 해제 후 SINGLE_STEP 크래시 방지)
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		stoppedContexts_.clear();
	}
	// Normal continue: stoppedContexts_를 유지 -- VEH 핸들러가 context 복원 후 자체 정리
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	for (auto& [tid, evt] : threadEvents_) {
		SetEvent(evt);
		// NOTE: CloseHandle은 VEH 핸들러(WaitForSingleObject 호출자)가 담당
	}
	threadEvents_.clear();
}

bool VehHandler::IsThreadStopped(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	return threadEvents_.find(threadId) != threadEvents_.end();
}

bool VehHandler::GetStoppedContext(uint32_t threadId, CONTEXT& ctx) {
	std::lock_guard<std::mutex> lock(contextMapMutex_);
	auto it = stoppedContexts_.find(threadId);
	if (it == stoppedContexts_.end()) return false;
	ctx = it->second;
	return true;
}

bool VehHandler::SetStoppedContext(uint32_t threadId, const CONTEXT& ctx) {
	std::lock_guard<std::mutex> lock(contextMapMutex_);
	auto it = stoppedContexts_.find(threadId);
	if (it == stoppedContexts_.end()) return false;
	it->second = ctx;
	return true;
}

// 정적 콜백 → 싱글톤 인스턴스의 HandleException 호출
LONG CALLBACK VehHandler::ExceptionHandler(PEXCEPTION_POINTERS info) {
	return Instance().HandleException(info);
}

// RAII guard for TLS reentry flag (all return paths auto-clear)
struct TlsReentryGuard {
	DWORD slot;
	TlsReentryGuard(DWORD s) : slot(s) { TlsSetValue(slot, reinterpret_cast<LPVOID>(1)); }
	~TlsReentryGuard() { TlsSetValue(slot, nullptr); }
};

VehHandler::WaitResult VehHandler::NotifyAndWait(
		PEXCEPTION_POINTERS info, uint32_t tid,
		DebugEventType type, uint64_t addr, uint32_t bpId, DWORD code) {
	if (!callback_) return WaitResult::NoCallback;

	// 1) 예외 컨텍스트 저장 (stackTrace/레지스터 검사용)
	{
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		stoppedContexts_[tid] = *info->ContextRecord;
	}

	// 2) 이벤트 핸들을 callback 전에 생성 (IsThreadStopped race 방지)
	HANDLE waitEvent = GetOrCreateThreadEvent(tid);
	if (!waitEvent) {
		// CreateEventW 실패 -- stoppedContexts_ 롤백, callback 호출하지 않음
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		stoppedContexts_.erase(tid);
		return WaitResult::NoCallback;
	}

	// 3) 콜백으로 어댑터에 알림
	DebugEvent evt;
	evt.type = type;
	evt.threadId = tid;
	evt.address = addr;
	evt.breakpointId = bpId;
	evt.exceptionCode = code;
	evt.context = info->ContextRecord;
	callback_(evt);

	LOG_DEBUG("Thread %u waiting for continue signal (type=%d)", tid, (int)type);
	WaitForSingleObject(waitEvent, INFINITE);
	CloseHandle(waitEvent);
	LOG_DEBUG("Thread %u resumed", tid);

	// 5) 정지 중 수정된 컨텍스트 복원 / detach 판별
	{
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		auto ctxIt = stoppedContexts_.find(tid);
		if (ctxIt != stoppedContexts_.end()) {
			*info->ContextRecord = ctxIt->second;
			stoppedContexts_.erase(ctxIt);
			return WaitResult::Resumed;
		}
	}
	return WaitResult::Detached;
}

LONG VehHandler::HandleException(PEXCEPTION_POINTERS info) {
	if (!installed_) return EXCEPTION_CONTINUE_SEARCH;

	// 재진입 방지: VEH 핸들러 안에서 호출한 API에 BP가 걸려도 재귀하지 않음
	if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES && TlsGetValue(reentryTlsSlot_)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	TlsReentryGuard reentryGuard(reentryTlsSlot_);

	const DWORD code = info->ExceptionRecord->ExceptionCode;
	const uint64_t addr = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
	const uint32_t tid = GetCurrentThreadId();

	switch (code) {
	case EXCEPTION_BREAKPOINT: { // 0x80000003 — INT3 히트
		auto bp = BreakpointManager::Instance().FindByAddress(addr);
		if (!bp) {
			LOG_DEBUG("FindByAddress(0x%llX) returned nullopt — not our BP", addr);
			return EXCEPTION_CONTINUE_SEARCH;
		}

		LOG_INFO("Breakpoint #%u hit at 0x%llX (tid=%u)", bp->id, addr, tid);

		// 원본 바이트 복원 (INT3 -> 원래 명령어)
		BreakpointManager::Instance().Disable(bp->id);

		// Trap Flag 설정 -> 한 명령어 실행 후 SINGLE_STEP 예외 발생
		info->ContextRecord->EFlags |= 0x100;

		// 싱글스텝 후 브레이크포인트 재활성화를 위해 기록
		auto& rearm = GetPendingRearm();
		rearm = {addr, tid, true, false};

		// TraceCallers 모드: caller 수집 후 자동 continue (멈추지 않음)
		if (traceAddress_.load(std::memory_order_relaxed) == addr) {
			// 내부 스레드(pipe server)는 스킵 -- IPC 처리 지연/데드락 방지
			if (tid != internalTid_.load(std::memory_order_relaxed)) {
				uint64_t caller = ReadCallerFromStack(info->ContextRecord);
				// Lock-free ring buffer write (no mutex, no heap alloc in VEH)
				uint32_t idx = traceWriteIdx_.fetch_add(1, std::memory_order_relaxed);
				traceBuffer_[idx % kTraceBufferSize] = caller;
				traceTotalHits_.fetch_add(1, std::memory_order_relaxed);
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// 내부 스레드(pipe server) BP 투명 스킵 -- 데드락 방지
		// 원본 바이트 복원 + TF는 이미 위에서 완료. rearm으로 single-step 후 BP 자동 재설치.
		// callback/wait 없이 바로 실행 재개하여 IPC 파이프가 블록되지 않도록 함.
		if (tid == internalTid_.load(std::memory_order_relaxed)) {
			LOG_DEBUG("Internal thread %u hit BP #%u at 0x%llX -- transparent skip", tid, bp->id, addr);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		{
			auto result = NotifyAndWait(info, tid, DebugEventType::BreakpointHit, addr, bp->id, code);
			if (result == WaitResult::Detached) {
				// Detach: TF 제거 + rearm 취소 (VEH 해제 후 SINGLE_STEP 크래시 방지)
				info->ContextRecord->EFlags &= ~0x100;
				rearm = {0, 0, false, false};
				LOG_DEBUG("Thread %u: forced resume (detach), TF cleared", tid);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (result == WaitResult::Resumed) {
				// step 플래그 확인 (rearm 후 다시 TF 설정)
				std::lock_guard<std::mutex> lock(stepFlagMutex_);
				auto it = stepFlags_.find(tid);
				if (it != stepFlags_.end() && it->second) {
					rearm.stepRequested = true;
					stepFlags_.erase(it);
					LOG_DEBUG("Thread %u: step requested, will re-TF after rearm", tid);
				}
			}
		}

		// HW BP를 context에 반영 (정지 중 설정/제거된 HW BP가 DR 레지스터에 적용됨)
		HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
		HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	case EXCEPTION_SINGLE_STEP: { // 0x80000004 — TF 또는 HW BP
		// 1) 소프트 브레이크포인트 재활성화 대기 중인 경우
		auto& rearm = GetPendingRearm();
		if (rearm.active) {
			BreakpointManager::Instance().RearmBreakpoint(rearm.address);
			LOG_DEBUG("Rearmed breakpoint at 0x%llX", rearm.address);
			bool wantStep = rearm.stepRequested;
			rearm.active = false;
			rearm.stepRequested = false;

			if (wantStep) {
				// StepOver/StepIn 요청: rearm 후 다시 TF 설정 → 다음 SINGLE_STEP에서 StepCompleted
				info->ContextRecord->EFlags |= 0x100;
				LOG_DEBUG("Step requested after rearm — TF set again at 0x%llX", addr);
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// 2) 하드웨어 브레이크포인트 확인 (DR6 상태)
		DWORD64 dr6 = info->ContextRecord->Dr6;
		for (uint8_t slot = 0; slot < 4; ++slot) {
			if (dr6 & (1ULL << slot)) {
				auto hwbp = HwBreakpointManager::Instance().FindBySlot(slot);
				if (hwbp) {
					LOG_INFO("HW breakpoint #%u (slot %u) hit at 0x%llX (tid=%u)",
						hwbp->id, slot, addr, tid);

					// DR6 해당 비트 클리어
					info->ContextRecord->Dr6 &= ~(1ULL << slot);

					{
						auto result = NotifyAndWait(info, tid, DebugEventType::BreakpointHit, addr, hwbp->id, code);
						if (result == WaitResult::Detached) {
							LOG_DEBUG("Thread %u (HW BP): forced resume (detach)", tid);
							return EXCEPTION_CONTINUE_EXECUTION;
						}
					}

					// HW BP를 context에 반영
					HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
					HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);

					return EXCEPTION_CONTINUE_EXECUTION;
				}
			}
		}

		// 3) 일반 싱글스텝 완료 (StepInto/StepOver 요청에 의한)
		LOG_DEBUG("Single step completed at 0x%llX (tid=%u)", addr, tid);

		{
			auto result = NotifyAndWait(info, tid, DebugEventType::SingleStepComplete, addr, 0, code);
			if (result == WaitResult::Detached) {
				LOG_DEBUG("Thread %u (step): forced resume (detach)", tid);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			if (result == WaitResult::Resumed) {
				// step 플래그 확인 -- 연속 스텝 요청이면 TF 재설정
				std::lock_guard<std::mutex> lock(stepFlagMutex_);
				auto it = stepFlags_.find(tid);
				if (it != stepFlags_.end() && it->second) {
					info->ContextRecord->EFlags |= 0x100;
					stepFlags_.erase(it);
					LOG_DEBUG("Thread %u: consecutive step -- TF set at 0x%llX", tid, addr);
				}
			}
		}

		// HW BP를 context에 반영
		HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
		HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	default: {
		// Crash-like 예외만 캡처 (C++ throw, OutputDebugString 등은 무시)
		bool shouldStop = false;
		switch (code) {
		case EXCEPTION_ACCESS_VIOLATION:       // 0xC0000005
		case EXCEPTION_INT_DIVIDE_BY_ZERO:     // 0xC0000094
		case EXCEPTION_PRIV_INSTRUCTION:       // 0xC0000096
		case EXCEPTION_ILLEGAL_INSTRUCTION:    // 0xC000001D
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:  // 0xC000008C
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:     // 0xC000008E
		case EXCEPTION_DATATYPE_MISALIGNMENT:  // 0x80000002
			shouldStop = true;
			break;
		}

		if (!shouldStop || !callback_) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		LOG_INFO("Exception 0x%08X at 0x%llX (tid=%u)", code, addr, tid);
		NotifyAndWait(info, tid, DebugEventType::Exception, addr, 0, code);

		// OS SEH 체인에 전달 (프로세스 crash/SEH 핸들러가 처리)
		return EXCEPTION_CONTINUE_SEARCH;
	}
	}
}

void VehHandler::StartTrace(uint64_t address) {
	traceWriteIdx_.store(0, std::memory_order_relaxed);
	traceTotalHits_.store(0, std::memory_order_relaxed);
	traceAddress_.store(address, std::memory_order_release);
	LOG_INFO("TraceCallers started at 0x%llX", address);
}

void VehHandler::StopTrace() {
	traceAddress_.store(0, std::memory_order_release);
	LOG_INFO("TraceCallers stopped");
}

std::unordered_map<uint64_t, uint32_t> VehHandler::GetTraceResults(uint32_t& totalHits) {
	totalHits = traceTotalHits_.load(std::memory_order_acquire);
	uint32_t writeIdx = traceWriteIdx_.load(std::memory_order_acquire);
	uint32_t count = (writeIdx < kTraceBufferSize) ? writeIdx : kTraceBufferSize;

	// Aggregate ring buffer into map
	std::unordered_map<uint64_t, uint32_t> result;
	for (uint32_t i = 0; i < count; i++) {
		uint64_t caller = traceBuffer_[i];
		if (caller != 0) {
			result[caller]++;
		}
	}
	return result;
}

} // namespace veh
