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

// thread_local: 각 스레드마다 재활성화 대기 정보 보관
thread_local VehHandler::PendingRearm VehHandler::pendingRearm_ = {0, 0, false, false};

VehHandler& VehHandler::Instance() {
	static VehHandler instance;
	return instance;
}

bool VehHandler::Install() {
	if (installed_) {
		LOG_WARN("VEH handler already installed");
		return true;
	}

	// 첫 번째 핸들러로 등록 (1 = first handler)
	handler_ = AddVectoredExceptionHandler(1, ExceptionHandler);
	if (!handler_) {
		LOG_ERROR("AddVectoredExceptionHandler failed: %lu", GetLastError());
		return false;
	}

	installed_ = true;
	LOG_INFO("VEH handler installed");
	return true;
}

void VehHandler::Uninstall() {
	if (!installed_) return;
	installed_ = false;  // 먼저 설정하여 새 예외 진입 차단

	// 대기 중인 모든 스레드 깨우기
	ResumeAllStoppedThreads();

	if (handler_) {
		RemoveVectoredExceptionHandler(handler_);
		handler_ = nullptr;
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

	{
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		stoppedContexts_.erase(threadId);
	}
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	auto it = threadEvents_.find(threadId);
	if (it != threadEvents_.end()) {
		SetEvent(it->second);
		CloseHandle(it->second);
		threadEvents_.erase(it);
	}
}

void VehHandler::ResumeAllStoppedThreads() {
	LOG_DEBUG("ResumeAllStoppedThreads");
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		stepFlags_.clear();
	}
	{
		std::lock_guard<std::mutex> lock(contextMapMutex_);
		stoppedContexts_.clear();
	}
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	for (auto& [tid, evt] : threadEvents_) {
		SetEvent(evt);
		CloseHandle(evt);
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

LONG VehHandler::HandleException(PEXCEPTION_POINTERS info) {
	if (!installed_) return EXCEPTION_CONTINUE_SEARCH;

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
		pendingRearm_ = {addr, tid, true, false};

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

		// 이벤트 콜백으로 어댑터에 알림
		if (callback_) {
			// 예외 컨텍스트 저장 (stackTrace 등에서 사용)
			{
				std::lock_guard<std::mutex> lock(contextMapMutex_);
				stoppedContexts_[tid] = *info->ContextRecord;
			}

			DebugEvent evt;
			evt.type = DebugEventType::BreakpointHit;
			evt.threadId = tid;
			evt.address = addr;
			evt.breakpointId = bp->id;
			evt.exceptionCode = code;
			evt.context = info->ContextRecord;
			callback_(evt);

			// continue/step 시그널이 올 때까지 대기
			HANDLE waitEvent = GetOrCreateThreadEvent(tid);
			if (waitEvent) {
				LOG_DEBUG("Thread %u waiting for continue signal", tid);
				WaitForSingleObject(waitEvent, INFINITE);
				LOG_DEBUG("Thread %u resumed", tid);

				// 정지 중에 SetStoppedContext로 수정된 컨텍스트를 반영
				{
					std::lock_guard<std::mutex> lock(contextMapMutex_);
					auto ctxIt = stoppedContexts_.find(tid);
					if (ctxIt != stoppedContexts_.end()) {
						*info->ContextRecord = ctxIt->second;
					} else {
						// Forced resume (detach) -- TF 제거하여 VEH 해제 후 SINGLE_STEP 크래시 방지
						info->ContextRecord->EFlags &= ~0x100;
						pendingRearm_ = {0, 0, false, false};
						LOG_DEBUG("Thread %u: forced resume (detach), TF cleared", tid);
						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}

				// 파이프 스레드에서 설정한 step 플래그 확인
				{
					std::lock_guard<std::mutex> lock(stepFlagMutex_);
					auto it = stepFlags_.find(tid);
					if (it != stepFlags_.end() && it->second) {
						pendingRearm_.stepRequested = true;
						stepFlags_.erase(it);
						LOG_DEBUG("Thread %u: step requested, will re-TF after rearm", tid);
					}
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
		if (pendingRearm_.active) {
			BreakpointManager::Instance().RearmBreakpoint(pendingRearm_.address);
			LOG_DEBUG("Rearmed breakpoint at 0x%llX", pendingRearm_.address);
			bool wantStep = pendingRearm_.stepRequested;
			pendingRearm_.active = false;
			pendingRearm_.stepRequested = false;

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

					if (callback_) {
						{
							std::lock_guard<std::mutex> lock(contextMapMutex_);
							stoppedContexts_[tid] = *info->ContextRecord;
						}

						DebugEvent evt;
						evt.type = DebugEventType::BreakpointHit;
						evt.threadId = tid;
						evt.address = addr;
						evt.breakpointId = hwbp->id;
						evt.exceptionCode = code;
						callback_(evt);

						HANDLE waitEvent = GetOrCreateThreadEvent(tid);
						if (waitEvent) {
							LOG_DEBUG("Thread %u (HW BP) waiting for continue signal", tid);
							WaitForSingleObject(waitEvent, INFINITE);
							LOG_DEBUG("Thread %u (HW BP) resumed", tid);
							// Reflect any context modifications made during stop
							{
								std::lock_guard<std::mutex> lock(contextMapMutex_);
								auto ctxIt = stoppedContexts_.find(tid);
								if (ctxIt != stoppedContexts_.end()) {
									*info->ContextRecord = ctxIt->second;
								} else {
									// Forced resume (detach) -- 안전하게 계속 실행
									LOG_DEBUG("Thread %u (HW BP): forced resume (detach)", tid);
									return EXCEPTION_CONTINUE_EXECUTION;
								}
							}
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

		if (callback_) {
			{
				std::lock_guard<std::mutex> lock(contextMapMutex_);
				stoppedContexts_[tid] = *info->ContextRecord;
			}

			DebugEvent evt;
			evt.type = DebugEventType::SingleStepComplete;
			evt.threadId = tid;
			evt.address = addr;
			evt.breakpointId = 0;
			evt.exceptionCode = code;
			callback_(evt);

			HANDLE waitEvent = GetOrCreateThreadEvent(tid);
			if (waitEvent) {
				LOG_DEBUG("Thread %u (step) waiting for continue signal", tid);
				WaitForSingleObject(waitEvent, INFINITE);
				LOG_DEBUG("Thread %u (step) resumed", tid);

				// Reflect any context modifications made during stop
				{
					std::lock_guard<std::mutex> lock(contextMapMutex_);
					auto ctxIt = stoppedContexts_.find(tid);
					if (ctxIt != stoppedContexts_.end()) {
						*info->ContextRecord = ctxIt->second;
					} else {
						// Forced resume (detach)
						LOG_DEBUG("Thread %u (step): forced resume (detach)", tid);
						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}

				// step 플래그 확인 -- 연속 스텝 요청이면 TF 재설정
				{
					std::lock_guard<std::mutex> lock(stepFlagMutex_);
					auto it = stepFlags_.find(tid);
					if (it != stepFlags_.end() && it->second) {
						info->ContextRecord->EFlags |= 0x100;
						stepFlags_.erase(it);
						LOG_DEBUG("Thread %u: consecutive step — TF set at 0x%llX", tid, addr);
					}
				}
			}
		}

		// HW BP를 context에 반영
		HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
		HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	default:
		// 우리가 처리하지 않는 예외 → 다음 핸들러로 전달
		return EXCEPTION_CONTINUE_SEARCH;
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
