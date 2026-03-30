#include <windows.h>
#include "veh_handler.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "memory.h"
#include "threads.h"
#include "syscall_resolver.h"
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
	auto* p = static_cast<PendingRearm*>(SafeTlsGetValue(pendingRearmTlsSlot_));
	if (!p) {
		// HeapAlloc은 VEH 경로 첫 호출 시 1회만, 이후 캐시됨
		p = static_cast<PendingRearm*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PendingRearm)));
		if (!p) {
			// HeapAlloc 실패 시 정적 폴백 (메모리 극한 상황, 프로세스당 1개면 충분)
			static PendingRearm fallback = {0, 0, false, false};
			return fallback;
		}
		SafeTlsSetValue(pendingRearmTlsSlot_, p);
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

	// SyscallResolver 초기화 (VEH 등록 전에 수행)
	// ntdll 스텁 복사본 생성 -- PatchByte에서 VirtualProtect 대신 사용
	if (!SyscallResolver::Instance().Initialize()) {
		LOG_WARN("SyscallResolver init failed -- PatchByte will use ntdll direct call fallback");
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

	// SyscallResolver 정리 (실행 가능 페이지 해제)
	SyscallResolver::Instance().Shutdown();

	// TLS 슬롯 해제 (per-thread HeapAlloc 메모리는 프로세스 종료 시 OS 회수)
	if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES) {
		TlsFree(reentryTlsSlot_);
		reentryTlsSlot_ = TLS_OUT_OF_INDEXES;
	}
	if (pendingRearmTlsSlot_ != TLS_OUT_OF_INDEXES) {
		TlsFree(pendingRearmTlsSlot_);
		pendingRearmTlsSlot_ = TLS_OUT_OF_INDEXES;
	}

	// NOTE: threadEvents_는 ResumeAllStoppedThreads(true)에서 이미 clear 완료.
	// 깨어난 스레드가 NotifyAndWait에서 NtClose를 호출하므로 여기서 추가 정리 불요.

	LOG_INFO("VEH handler uninstalled");
}

void VehHandler::SetEventCallback(DebugEventCallback cb) {
	callback_ = std::move(cb);
}

HANDLE VehHandler::GetOrCreateThreadEvent(uint32_t threadId) {
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	auto it = threadEvents_.find(threadId);
	if (it != threadEvents_.end()) return it->second;
	HANDLE evt = nullptr;
	auto& resolver = SyscallResolver::Instance();
	NTSTATUS status = resolver.CreateEvent(&evt);
	if (!NT_SUCCESS(status) || !evt) {
		LOG_ERROR("NtCreateEvent failed for thread %u: 0x%08X", threadId, status);
		return nullptr;
	}
	threadEvents_[threadId] = evt;
	return evt;
}

void VehHandler::ResumeStoppedThread(uint32_t threadId, bool step, bool passException) {
	LOG_DEBUG("ResumeStoppedThread(%u, step=%d, passEx=%d)", threadId, step, passException);

	// step + passException 플래그 설정 (VEH 핸들러 스레드에서 읽음)
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		if (step) {
			stepFlags_[threadId] = true;
		} else {
			stepFlags_.erase(threadId);
		}
		if (passException) {
			passExceptionFlags_[threadId] = true;
		} else {
			passExceptionFlags_.erase(threadId);
		}
	}

	// NOTE: stoppedContexts_는 여기서 erase하지 않음!
	// VEH 핸들러가 WaitForSingleObject에서 깨어난 뒤 context를 복원해야 하므로,
	// erase는 VEH 핸들러 쪽에서 복원 완료 후 수행한다.
	// (여기서 erase하면 VEH가 detach로 오판하여 TF/rearm을 취소하는 버그 발생)

	std::lock_guard<std::mutex> lock(eventMapMutex_);
	auto it = threadEvents_.find(threadId);
	if (it != threadEvents_.end()) {
		SyscallResolver::Instance().SetEvent(it->second);
		// NOTE: NtClose는 VEH 핸들러(NtWaitForSingleObject 호출자)가 담당
		threadEvents_.erase(it);
	}
}

void VehHandler::ResumeAllStoppedThreads(bool forDetach) {
	LOG_DEBUG("ResumeAllStoppedThreads(forDetach=%d)", forDetach);
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		stepFlags_.clear();
		passExceptionFlags_.clear();
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
		SyscallResolver::Instance().SetEvent(evt);
		// NOTE: NtClose는 VEH 핸들러(NtWaitForSingleObject 호출자)가 담당
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
// SafeTlsSetValue 사용 -- TEB 직접 접근으로 BP 재진입 방지
struct TlsReentryGuard {
	DWORD slot;
	TlsReentryGuard(DWORD s) : slot(s) { SafeTlsSetValue(slot, reinterpret_cast<LPVOID>(1)); }
	~TlsReentryGuard() { SafeTlsSetValue(slot, nullptr); }
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
	auto& resolver = SyscallResolver::Instance();
	resolver.WaitForSingleObject(waitEvent, nullptr);  // nullptr = INFINITE
	resolver.Close(waitEvent);
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
	if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES && SafeTlsGetValue(reentryTlsSlot_)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	TlsReentryGuard reentryGuard(reentryTlsSlot_);

	const DWORD code = info->ExceptionRecord->ExceptionCode;
	const uint64_t addr = reinterpret_cast<uint64_t>(info->ExceptionRecord->ExceptionAddress);
	// TEB direct read -- GetCurrentThreadId() 대신 사용
	// (사용자가 GetCurrentThreadId에 BP 걸면 VEH 재진입 crash 방지)
#ifdef _WIN64
	const uint32_t tid = __readgsdword(0x48);  // GS:[0x48] = TEB.ClientId.UniqueThread
#else
	const uint32_t tid = __readfsdword(0x24);  // FS:[0x24] = TEB.ClientId.UniqueThread
#endif

	// 셸코드 스레드: 모든 예외를 VEH에서 무시 (SEH/__except가 처리)
	if (IsShellcodeThread(tid)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	switch (code) {
	case EXCEPTION_BREAKPOINT: { // 0x80000003 — INT3 히트
		auto bp = BreakpointManager::Instance().FindByAddress(addr);
		if (!bp) {
			LOG_DEBUG("FindByAddress(0x%llX) returned nullopt — not our BP", addr);
			// ImportResolve: exception-based thunk -- set TF and let SEH handle
			if (importResolve_.active.load(std::memory_order_acquire) &&
				tid == importResolve_.threadId && importResolve_.followExceptions) {
				if (importResolve_.exceptionsPassed < importResolve_.maxExceptionPasses) {
					importResolve_.exceptionsPassed++;
					importResolve_.stepsExecuted++;
					info->ContextRecord->EFlags |= 0x100;  // TF survives through SEH
					LOG_DEBUG("ImportResolve: passing INT3 at 0x%llX to SEH, TF set (pass #%u)",
						addr, importResolve_.exceptionsPassed);
					return EXCEPTION_CONTINUE_SEARCH;
				}
				// Max passes exceeded - abort resolve
				importResolve_.found = false;
				importResolve_.targetAddress = addr;
				importResolve_.active.store(false, std::memory_order_relaxed);
				importResolve_.done.store(true, std::memory_order_release);
				LOG_WARN("ImportResolve: max exception passes exceeded at 0x%llX", addr);
			}
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

		// pass_exception: 예외를 SEH로 전달 (CFF/난독화 INT3 등)
		{
			std::lock_guard<std::mutex> lock(stepFlagMutex_);
			auto pit = passExceptionFlags_.find(tid);
			if (pit != passExceptionFlags_.end() && pit->second) {
				passExceptionFlags_.erase(pit);
				// BP를 다시 활성화 (Disable로 원본 복원했으므로)
				BreakpointManager::Instance().Enable(bp->id);
				// TF 제거, rearm 취소
				info->ContextRecord->EFlags &= ~0x100;
				rearm = {0, 0, false, false};
				LOG_DEBUG("Thread %u: pass_exception, forwarding to SEH", tid);
				return EXCEPTION_CONTINUE_SEARCH;
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

					// TraceMemory: if this is our temp HW BP, record result and skip NotifyAndWait
					if (traceMem_.active.load(std::memory_order_acquire) && hwbp->id == traceMem_.hwBpId) {
						// Read new value at watched address
						uint64_t newVal = 0;
						auto newData = MemoryManager::Instance().Read(traceMem_.watchAddress, traceMem_.watchSize);
						if (!newData.empty()) memcpy(&newVal, newData.data(), (traceMem_.watchSize > 8) ? 8 : traceMem_.watchSize);

						traceMem_.found = true;
						traceMem_.threadId = tid;
						traceMem_.instructionAddress = addr;
						traceMem_.newValue = newVal;
						traceMem_.active.store(false, std::memory_order_relaxed);
						traceMem_.done.store(true, std::memory_order_release);
						LOG_INFO("TraceMemory: write detected at 0x%llX by tid=%u (0x%llX -> 0x%llX)",
							traceMem_.watchAddress, tid, traceMem_.oldValue, newVal);

						// Remove temp HW BP and continue execution
						HwBreakpointManager::Instance().Remove(hwbp->id);
						HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
						HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);
						return EXCEPTION_CONTINUE_EXECUTION;
					}

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

		// 3) ResolveImport: step until RIP enters a loaded DLL range
		if (importResolve_.active.load(std::memory_order_acquire) && tid == importResolve_.threadId) {
			importResolve_.stepsExecuted++;
			bool inDll = false;
			// Check if RIP is in any module range (but not the main exe)
			for (auto& mr : importResolve_.moduleRanges) {
				if (addr >= mr.base && addr < mr.end) {
					// Skip if it's the main exe itself
					if (mr.base != importResolve_.exeBase) {
						inDll = true;
						break;
					}
				}
			}

			if (inDll || importResolve_.stepsExecuted >= importResolve_.maxSteps) {
				importResolve_.found = inDll;
				importResolve_.targetAddress = addr;
				importResolve_.active.store(false, std::memory_order_relaxed);
				importResolve_.done.store(true, std::memory_order_release);
				// Fall through to NotifyAndWait (thread stays stopped)
			} else {
				info->ContextRecord->EFlags |= 0x100;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		// 4) TraceRegister: check register condition, loop internally if not met
		if (traceReg_.active.load(std::memory_order_relaxed) && tid == traceReg_.threadId) {
			traceReg_.stepsExecuted++;
			uint64_t curVal = 0;
#ifdef _WIN64
			switch (traceReg_.regIndex) {
				case 0: curVal = info->ContextRecord->Rax; break;
				case 1: curVal = info->ContextRecord->Rbx; break;
				case 2: curVal = info->ContextRecord->Rcx; break;
				case 3: curVal = info->ContextRecord->Rdx; break;
				case 4: curVal = info->ContextRecord->Rsi; break;
				case 5: curVal = info->ContextRecord->Rdi; break;
				case 6: curVal = info->ContextRecord->Rbp; break;
				case 7: curVal = info->ContextRecord->Rsp; break;
				case 8: curVal = info->ContextRecord->R8; break;
				case 9: curVal = info->ContextRecord->R9; break;
				case 10: curVal = info->ContextRecord->R10; break;
				case 11: curVal = info->ContextRecord->R11; break;
				case 12: curVal = info->ContextRecord->R12; break;
				case 13: curVal = info->ContextRecord->R13; break;
				case 14: curVal = info->ContextRecord->R14; break;
				case 15: curVal = info->ContextRecord->R15; break;
				case 16: curVal = info->ContextRecord->Rip; break;
				case 17: curVal = info->ContextRecord->EFlags; break;
				default: curVal = 0; break;
			}
#else
			switch (traceReg_.regIndex) {
				case 0: curVal = info->ContextRecord->Eax; break;
				case 1: curVal = info->ContextRecord->Ebx; break;
				case 2: curVal = info->ContextRecord->Ecx; break;
				case 3: curVal = info->ContextRecord->Edx; break;
				case 4: curVal = info->ContextRecord->Esi; break;
				case 5: curVal = info->ContextRecord->Edi; break;
				case 6: curVal = info->ContextRecord->Ebp; break;
				case 7: curVal = info->ContextRecord->Esp; break;
				case 16: curVal = info->ContextRecord->Eip; break;
				case 17: curVal = info->ContextRecord->EFlags; break;
				default: curVal = 0; break;
			}
#endif

			bool conditionMet = false;
			switch (traceReg_.mode) {
				case 0: conditionMet = (curVal != traceReg_.initialValue); break; // changed
				case 1: conditionMet = (curVal == traceReg_.compareValue); break; // equals
				case 2: conditionMet = (curVal != traceReg_.compareValue); break; // not_equals
			}

			if (conditionMet || traceReg_.stepsExecuted >= traceReg_.maxSteps) {
				// Done: store results and signal
				traceReg_.found = conditionMet;
				traceReg_.resultAddress = addr;
				traceReg_.oldValue = traceReg_.initialValue;
				traceReg_.newValue = curVal;
				traceReg_.active.store(false, std::memory_order_relaxed);
				traceReg_.done.store(true, std::memory_order_release);
				LOG_INFO("TraceRegister: %s after %u steps at 0x%llX (0x%llX -> 0x%llX)",
					conditionMet ? "found" : "max_steps", traceReg_.stepsExecuted, addr,
					traceReg_.initialValue, curVal);
				// Fall through to NotifyAndWait -- thread pauses, pipe_server reads done flag
				// This is intentional: thread must be stopped for subsequent inspection
			} else {
				// Continue stepping: set TF again
				info->ContextRecord->EFlags |= 0x100;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		// 4) 일반 싱글스텝 완료 (StepInto/StepOver 요청에 의한)
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
		// ImportResolve: exception-based thunk (AV, PRIV_INSTRUCTION, etc.)
		// Set TF and let SEH handle -- after SEH redirects, TF fires SINGLE_STEP to resume trace
		if (importResolve_.active.load(std::memory_order_acquire) &&
			tid == importResolve_.threadId && importResolve_.followExceptions) {
			if (importResolve_.exceptionsPassed < importResolve_.maxExceptionPasses) {
				importResolve_.exceptionsPassed++;
				importResolve_.stepsExecuted++;
				info->ContextRecord->EFlags |= 0x100;
				LOG_DEBUG("ImportResolve: passing exception 0x%08X at 0x%llX to SEH, TF set (pass #%u)",
					code, addr, importResolve_.exceptionsPassed);
				return EXCEPTION_CONTINUE_SEARCH;
			}
			// Max passes exceeded - abort resolve
			importResolve_.found = false;
			importResolve_.targetAddress = addr;
			importResolve_.active.store(false, std::memory_order_relaxed);
			importResolve_.done.store(true, std::memory_order_release);
			LOG_WARN("ImportResolve: max exception passes exceeded (0x%08X at 0x%llX)", code, addr);
		}

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

void VehHandler::RegisterShellcodeThread(uint32_t tid) {
	std::lock_guard<std::mutex> lock(shellcodeThreadMutex_);
	shellcodeThreads_.insert(tid);
}

void VehHandler::UnregisterShellcodeThread(uint32_t tid) {
	std::lock_guard<std::mutex> lock(shellcodeThreadMutex_);
	shellcodeThreads_.erase(tid);
}

bool VehHandler::IsShellcodeThread(uint32_t tid) {
	std::lock_guard<std::mutex> lock(shellcodeThreadMutex_);
	return shellcodeThreads_.count(tid) > 0;
}

void VehHandler::StartTraceRegister(uint32_t threadId, uint32_t regIndex, uint32_t maxSteps,
                                     uint8_t mode, uint64_t compareValue) {
	traceReg_.threadId = threadId;
	traceReg_.regIndex = regIndex;
	traceReg_.maxSteps = maxSteps;
	traceReg_.mode = mode;
	traceReg_.compareValue = compareValue;
	traceReg_.stepsExecuted = 0;
	traceReg_.found = false;
	traceReg_.resultAddress = 0;
	traceReg_.oldValue = 0;
	traceReg_.newValue = 0;
	traceReg_.done.store(false, std::memory_order_relaxed);

	// Read initial register value BEFORE activating trace (race fix)
	CONTEXT ctx;
	if (GetStoppedContext(threadId, ctx)) {
		uint64_t val = 0;
#ifdef _WIN64
		switch (regIndex) {
			case 0: val = ctx.Rax; break; case 1: val = ctx.Rbx; break;
			case 2: val = ctx.Rcx; break; case 3: val = ctx.Rdx; break;
			case 4: val = ctx.Rsi; break; case 5: val = ctx.Rdi; break;
			case 6: val = ctx.Rbp; break; case 7: val = ctx.Rsp; break;
			case 8: val = ctx.R8; break;  case 9: val = ctx.R9; break;
			case 10: val = ctx.R10; break; case 11: val = ctx.R11; break;
			case 12: val = ctx.R12; break; case 13: val = ctx.R13; break;
			case 14: val = ctx.R14; break; case 15: val = ctx.R15; break;
			case 16: val = ctx.Rip; break; case 17: val = ctx.EFlags; break;
		}
#else
		switch (regIndex) {
			case 0: val = ctx.Eax; break; case 1: val = ctx.Ebx; break;
			case 2: val = ctx.Ecx; break; case 3: val = ctx.Edx; break;
			case 4: val = ctx.Esi; break; case 5: val = ctx.Edi; break;
			case 6: val = ctx.Ebp; break; case 7: val = ctx.Esp; break;
			case 16: val = ctx.Eip; break; case 17: val = ctx.EFlags; break;
		}
#endif
		traceReg_.initialValue = val;
	}

	// Activate trace AFTER initialValue is set, BEFORE resume
	traceReg_.active.store(true, std::memory_order_release);

	// Resume thread with step (TF set)
	ResumeStoppedThread(threadId, true);
}

} // namespace veh
