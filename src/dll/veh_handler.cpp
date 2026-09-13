#include <windows.h>
#include <algorithm>
#include <cctype>
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
	// InitThread와 ServerThread가 동시에 Install()에 들어오는 race를 막는다.
	// lock 안에서 installed_를 재확인하여 AddVectoredExceptionHandler 중복 호출 방지.
	std::lock_guard<std::mutex> lock(installMutex_);
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

	continueHandler_ = AddVectoredContinueHandler(1, ContinueHandler);
	if (!continueHandler_) {
		LOG_WARN("AddVectoredContinueHandler failed: %lu (exception edges may be unavailable)", GetLastError());
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
	if (continueHandler_) {
		RemoveVectoredContinueHandler(continueHandler_);
		continueHandler_ = nullptr;
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

static uint16_t SafeCopyTraceStack(uint64_t stackPointer, uint8_t* dst, uint16_t size) {
	if (!stackPointer || !dst || !size) return 0;
	__try {
		memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(stackPointer)), size);
		return size;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

static bool SafeCopyTraceValue(uint64_t address, uint8_t* dst, uint8_t size) {
	if (!address || !dst || !size) return false;
	__try {
		memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), size);
		return true;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

static bool SafeCopyTraceCode(uint64_t address, uint8_t* dst, size_t size) {
	if (!address || !dst || !size) return false;
	__try {
		memcpy(dst, reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), size);
		return true;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

std::vector<uint32_t> VehHandler::GetStoppedThreadIds() {
	std::lock_guard<std::mutex> lock(eventMapMutex_);
	std::vector<uint32_t> result;
	result.reserve(threadEvents_.size());
	for (const auto& [threadId, event] : threadEvents_) {
		(void)event;
		result.push_back(threadId);
	}
	std::sort(result.begin(), result.end());
	return result;
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

LONG CALLBACK VehHandler::ContinueHandler(PEXCEPTION_POINTERS info) {
	return Instance().HandleContinue(info);
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

// --- Module-load breakpoints ---

static std::string ToLowerCopy(const char* s) {
	std::string r = s ? s : "";
	for (auto& c : r) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
	return r;
}

void VehHandler::AddModuleLoadPattern(const char* name) {
	if (!name || !*name) return;
	std::lock_guard<std::mutex> lock(moduleLoadMutex_);
	std::string n = name;
	for (auto& p : moduleLoadPatterns_) if (p == n) return;  // dedup
	moduleLoadPatterns_.push_back(n);
}

void VehHandler::RemoveModuleLoadPattern(const char* name) {
	if (!name) return;
	std::lock_guard<std::mutex> lock(moduleLoadMutex_);
	std::string n = name;
	for (auto it = moduleLoadPatterns_.begin(); it != moduleLoadPatterns_.end(); ++it) {
		if (*it == n) { moduleLoadPatterns_.erase(it); return; }
	}
}

void VehHandler::ClearModuleLoadPatterns() {
	std::lock_guard<std::mutex> lock(moduleLoadMutex_);
	moduleLoadPatterns_.clear();
}

bool VehHandler::MatchModuleLoad(const char* baseName) {
	if (!baseName) return false;
	std::string b = ToLowerCopy(baseName);
	std::lock_guard<std::mutex> lock(moduleLoadMutex_);
	if (moduleLoadPatterns_.empty()) return false;
	for (auto& p : moduleLoadPatterns_) {
		if (b.find(ToLowerCopy(p.c_str())) != std::string::npos) return true;
	}
	return false;
}

void VehHandler::NotifyModuleLoadStop(uint64_t base, uint32_t size, const char* name, uint32_t tid) {
	if (!callback_) return;
	// Stash module info for the event callback (same thread, read synchronously below).
	pendingModuleSize_ = size;
	strncpy_s(pendingModuleName_, sizeof(pendingModuleName_), name ? name : "", _TRUNCATE);
	// Capture the loader thread's context so inspection tools can read it while stopped.
	// No INT3: we synthesize EXCEPTION_POINTERS and reuse the normal stop/wait path,
	// so the target's SEH is never involved.
	CONTEXT ctx;
	RtlCaptureContext(&ctx);
	EXCEPTION_RECORD rec{};
	rec.ExceptionAddress = reinterpret_cast<PVOID>(static_cast<uintptr_t>(base));
	EXCEPTION_POINTERS ptrs{ &rec, &ctx };
	NotifyAndWait(&ptrs, tid, DebugEventType::ModuleLoad, base, 0, 0);

	// This synthetic stop does not honor step/passException (the loader thread just
	// resumes the load). Clear any flags a step/pass_exception resume may have set so
	// they don't leak into the next real breakpoint on this thread.
	{
		std::lock_guard<std::mutex> lock(stepFlagMutex_);
		stepFlags_.erase(tid);
		passExceptionFlags_.erase(tid);
	}
}

static uint64_t BasicTraceHash(uint64_t value) {
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	return value ^ (value >> 31);
}

VehHandler::TraceBasicBlocksState::Instruction* VehHandler::FindBasicTraceInstruction(uint64_t address) {
	auto& insns = traceBasicBlocks_.instructions;
	size_t lo = 0, hi = insns.size();
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (insns[mid].address < address) lo = mid + 1;
		else hi = mid;
	}
	return (lo < insns.size() && insns[lo].address == address) ? &insns[lo] : nullptr;
}

uint64_t VehHandler::NormalizeBasicTraceBlockStart(uint64_t address, bool dynamicTarget) const {
	if (dynamicTarget) return address;
	const auto& insns = traceBasicBlocks_.instructions;
	size_t lo = 0, hi = insns.size();
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (insns[mid].address < address) lo = mid + 1;
		else hi = mid;
	}
	if (lo < insns.size() && insns[lo].address == address)
		return insns[lo].staticBlockStart;
	return address;
}

static void FillBasicTraceRegisterValues(const CONTEXT* ctx, uint64_t* regs, uint8_t& is32bit) {
	memset(regs, 0, sizeof(uint64_t) * kTraceBasicBlockRegisterCount);
	if (!ctx) return;
#ifdef _WIN64
	is32bit = 0;
	uint64_t values[kTraceBasicBlockRegisterCount] = {
		ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx, ctx->Rsi, ctx->Rdi, ctx->Rbp, ctx->Rsp,
		ctx->R8, ctx->R9, ctx->R10, ctx->R11, ctx->R12, ctx->R13, ctx->R14, ctx->R15,
		ctx->Rip, ctx->EFlags & ~0x100ULL
	};
#else
	is32bit = 1;
	uint64_t values[kTraceBasicBlockRegisterCount] = {
		ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx, ctx->Esi, ctx->Edi, ctx->Ebp, ctx->Esp,
		0, 0, 0, 0, 0, 0, 0, 0, ctx->Eip, ctx->EFlags & ~0x100UL
	};
#endif
	memcpy(regs, values, sizeof(values));
}

void VehHandler::FillBasicTraceSnapshot(const CONTEXT* ctx, TraceBasicBlockSnapshot& s) {
	memset(&s, 0, sizeof(s));
	if (!ctx) return;
#ifdef _WIN64
	s.instructionPointer = ctx->Rip;
	s.stackPointer = ctx->Rsp;
#else
	s.instructionPointer = ctx->Eip;
	s.stackPointer = ctx->Esp;
#endif
	FillBasicTraceRegisterValues(ctx, s.registers, s.is32bit);
	s.stackSize = SafeCopyTraceStack(s.stackPointer, s.stack, traceBasicBlocks_.stackBytes);
	return;
}

uint32_t VehHandler::CaptureBasicTraceSnapshot(const CONTEXT* ctx) {
	auto& tb = traceBasicBlocks_;
	if (!ctx || tb.snapshotCount >= tb.snapshots.size()) return UINT32_MAX;
	uint32_t index = tb.snapshotCount++;
	FillBasicTraceSnapshot(ctx, tb.snapshots[index]);
	return index;
}

static uint64_t BasicTraceContextRegister(const CONTEXT* ctx, uint8_t index) {
	if (!ctx) return 0;
#ifdef _WIN64
	const uint64_t values[16] = {ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx,
		ctx->Rsi, ctx->Rdi, ctx->Rbp, ctx->Rsp, ctx->R8, ctx->R9, ctx->R10,
		ctx->R11, ctx->R12, ctx->R13, ctx->R14, ctx->R15};
#else
	const uint64_t values[8] = {ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx,
		ctx->Esi, ctx->Edi, ctx->Ebp, ctx->Esp};
#endif
	return index < sizeof(values) / sizeof(values[0]) ? values[index] : 0;
}

bool VehHandler::EvaluateBasicTraceCondition(const TraceCondition& condition, const CONTEXT* ctx) const {
	if (!condition.clauseCount) return true;
	auto operandValue = [&](const TraceConditionOperand& operand, uint64_t& value) -> bool {
		switch (operand.kind) {
		case TraceConditionOperandKind::Immediate:
			value = operand.immediate; return true;
		case TraceConditionOperandKind::Register:
			if (operand.registerIndex < 16) value = BasicTraceContextRegister(ctx, operand.registerIndex);
			else if (operand.registerIndex == 16) {
#ifdef _WIN64
				value = ctx->Rip;
#else
				value = ctx->Eip;
#endif
			} else if (operand.registerIndex == 17) value = ctx->EFlags;
			else return false;
			return true;
		case TraceConditionOperandKind::MemoryAtRegister: {
			if (operand.registerIndex >= 16 || operand.size == 0 || operand.size > 8) return false;
			uint64_t address = BasicTraceContextRegister(ctx, operand.registerIndex) +
				static_cast<uint64_t>(operand.offset);
#ifndef _WIN64
			address = static_cast<uint32_t>(address);
#endif
			value = 0;
			return SafeCopyTraceValue(address, reinterpret_cast<uint8_t*>(&value), operand.size);
		}
		default: return false;
		}
	};
	bool aggregate = condition.matchAny == 0;
	for (uint8_t i = 0; i < condition.clauseCount && i < kTraceConditionMaxClauses; ++i) {
		uint64_t lhs = 0, rhs = 0;
		bool valid = operandValue(condition.clauses[i].lhs, lhs) &&
			operandValue(condition.clauses[i].rhs, rhs);
		bool matched = false;
		if (valid) {
			switch (condition.clauses[i].comparison) {
			case TraceConditionComparison::Equal: matched = lhs == rhs; break;
			case TraceConditionComparison::NotEqual: matched = lhs != rhs; break;
			case TraceConditionComparison::Less: matched = lhs < rhs; break;
			case TraceConditionComparison::LessEqual: matched = lhs <= rhs; break;
			case TraceConditionComparison::Greater: matched = lhs > rhs; break;
			case TraceConditionComparison::GreaterEqual: matched = lhs >= rhs; break;
			}
		}
		if (condition.matchAny && matched) return true;
		if (!condition.matchAny && !matched) return false;
		aggregate = matched;
	}
	return aggregate;
}

bool VehHandler::AdvanceBasicTraceOccurrence(uint64_t address) {
	auto& tb = traceBasicBlocks_;
	if (!tb.occurrenceWindow.enabled || address != tb.occurrenceWindow.address) return true;
	++tb.occurrenceHits;
	if (tb.occurrenceHits == tb.occurrenceWindow.from) {
		tb.occurrenceWindowActive = true;
		tb.occurrenceWindowStarted = true;
	}
	if (tb.occurrenceWindow.to && tb.occurrenceHits > tb.occurrenceWindow.to) {
		tb.occurrenceWindowActive = false;
		tb.occurrenceWindowCompleted = true;
		return false;
	}
	return true;
}

void VehHandler::EvictBasicTraceTargetEvents(uint64_t sequence) {
	auto& tb = traceBasicBlocks_;
	if (!tb.targetWindow.enabled || tb.targetMatched) return;
	const uint64_t cutoff = sequence > tb.targetWindow.beforeSteps ?
		sequence - tb.targetWindow.beforeSteps : 0;
	auto evict = [cutoff](auto& values, uint32_t& head, uint32_t& count) {
		while (count && values[head].sequence < cutoff) {
			head = (head + 1) % static_cast<uint32_t>(values.size());
			--count;
		}
	};
	if (!tb.events.empty()) evict(tb.events, tb.eventHead, tb.eventCount);
	if (!tb.memoryEvents.empty()) evict(tb.memoryEvents, tb.memoryEventHead, tb.memoryEventCount);
	if (!tb.registerEvents.empty()) evict(tb.registerEvents, tb.registerEventHead, tb.registerEventCount);
}

void VehHandler::AdvanceBasicTraceTarget(uint64_t address, uint64_t sequence) {
	auto& tb = traceBasicBlocks_;
	if (!tb.targetWindow.enabled || tb.targetMatched || address != tb.targetWindow.address) return;
	++tb.targetOccurrenceHits;
	if (tb.targetOccurrenceHits != tb.targetWindow.occurrence) return;
	EvictBasicTraceTargetEvents(sequence);
	tb.targetMatched = true;
	tb.targetTriggerSequence = sequence;
	tb.targetCaptureStartSequence = sequence > tb.targetWindow.beforeSteps ?
		sequence - tb.targetWindow.beforeSteps : 0;
	tb.targetCaptureEndSequence = sequence;
	CompactBasicTraceTargetCode();
	// Aggregate tables are not rings and would otherwise serialize the entire
	// trigger-search prefix. Keep the ordered pre-window above, then scope all
	// aggregate metadata to the trigger and post-trigger portion.
	std::fill(tb.blockTable.begin(), tb.blockTable.end(), TraceBasicBlocksState::BlockSlot{});
	std::fill(tb.edgeTable.begin(), tb.edgeTable.end(), TraceBasicBlocksState::EdgeSlot{});
	std::fill(tb.memoryWriteTable.begin(), tb.memoryWriteTable.end(), TraceBasicBlocksState::MemoryWriteSlot{});
	std::fill(tb.memoryReadTable.begin(), tb.memoryReadTable.end(), TraceBasicBlocksState::MemoryReadSlot{});
	tb.blockCount = tb.edgeCount = tb.snapshotCount = tb.exceptionsFollowed = 0;
	tb.memoryWriteCount = tb.memoryReadCount = 0;
	tb.unsupportedMemoryWrites = tb.unsupportedMemoryReads = 0;
	tb.memoryWritesTruncated = tb.memoryReadsTruncated = false;
	tb.dependencyIncomplete = false;
}

bool VehHandler::BasicTraceCollectionGate(const CONTEXT* ctx) const {
	const auto& tb = traceBasicBlocks_;
	if (tb.targetWindow.enabled) return tb.startConditionMet;
	return tb.startConditionMet && tb.occurrenceWindowActive &&
		(tb.collectCondition.clauseCount == 0 ||
		 EvaluateBasicTraceCondition(tb.collectCondition, ctx));
}

void VehHandler::PrepareBasicTraceMemoryWrites(
		const TraceBasicBlocksState::Instruction* instruction, const CONTEXT* ctx) {
	auto& tb = traceBasicBlocks_;
	tb.pendingWriteCount = 0;
	tb.pendingReadCount = 0;
	tb.pendingRegisterWriteMask = 0;
	tb.pendingDependencyMask = 0;
	tb.pendingWritesFlags = 0;
	if (!instruction || !ctx) return;
	if (tb.collectMemoryWrites || tb.collectMemoryEvents)
		tb.unsupportedMemoryWrites += instruction->unsupportedWrites;
	if (tb.collectMemoryReads || tb.collectMemoryEvents)
		tb.unsupportedMemoryReads += instruction->unsupportedReads;
	uint32_t dependency = instruction->readsFlags ? tb.flagsDependencies : 0;
	for (uint8_t reg = 0; reg < 16; ++reg)
		if (instruction->readRegisterMask & (1u << reg)) dependency |= tb.registerDependencies[reg];
	auto effectiveAddress = [&](const TraceBasicBlocksState::WriteOperand& operand) {
		uint64_t address = 0;
		if (operand.ripRelative) address = instruction->next + static_cast<uint64_t>(operand.displacement);
		else {
			uint64_t base = operand.base == 0xFF ? 0 : BasicTraceContextRegister(ctx, operand.base);
			uint64_t index = operand.index == 0xFF ? 0 : BasicTraceContextRegister(ctx, operand.index);
			address = base + index * operand.scale + static_cast<uint64_t>(operand.displacement);
			if (operand.preDecrementStack) address -= operand.size;
#ifndef _WIN64
			address = static_cast<uint32_t>(address);
#endif
		}
		return address;
	};
	for (uint8_t i = 0; i < instruction->readOperandCount; ++i) {
		const auto& operand = instruction->readOperands[i];
		uint64_t address = effectiveAddress(operand);
		uint32_t readDependency = 0;
		uint64_t readEnd = address + operand.size;
		for (uint8_t source = 0; source < tb.dependencySourceCount; ++source) {
			const auto& configured = tb.dependencySources[source];
			if (configured.kind != TraceDependencySourceKind::Memory) continue;
			uint64_t sourceEnd = configured.address + configured.size;
			if (address < sourceEnd && configured.address < readEnd) readDependency |= 1u << source;
		}
		if (!tb.memoryTaintTable.empty()) {
			size_t mask = tb.memoryTaintTable.size() - 1;
			size_t index = static_cast<size_t>(BasicTraceHash(address) ^ operand.size) & mask;
			for (size_t probe = 0; probe < tb.memoryTaintTable.size(); ++probe) {
				const auto& slot = tb.memoryTaintTable[index];
				if (!slot.occupied) break;
				if (slot.address == address && slot.size == operand.size) { readDependency |= slot.dependencyMask; break; }
				index = (index + 1) & mask;
			}
		}
		dependency |= readDependency;
		if (tb.collectMemoryReads || tb.collectMemoryEvents) {
			auto& pending = tb.pendingReads[tb.pendingReadCount];
			pending = {};
			pending.instruction = instruction->address;
			pending.address = address;
			pending.size = operand.size;
			pending.dependencyMask = readDependency;
			pending.accessIndex = i;
			if (!SafeCopyTraceValue(address, pending.value, operand.size)) tb.unsupportedMemoryReads++;
			else tb.pendingReadCount++;
		}
	}
	if (instruction->clearsDependencies) dependency = 0;
	tb.pendingDependencyMask = dependency;
	tb.pendingRegisterWriteMask = instruction->writeRegisterMask;
	tb.pendingWritesFlags = instruction->writesFlags;
	const_cast<TraceBasicBlocksState::Instruction*>(instruction)->lastDependencyMask = dependency;
	if (!tb.collectMemoryWrites && !tb.collectMemoryEvents && !tb.dependencySourceCount) return;
	for (uint8_t i = 0; i < instruction->writeOperandCount; ++i) {
		const auto& operand = instruction->writeOperands[i];
		uint64_t address = effectiveAddress(operand);
		auto& pending = tb.pendingWrites[tb.pendingWriteCount];
		pending = {};
		pending.instruction = instruction->address;
		pending.address = address;
		pending.size = operand.size;
		pending.dependencyMask = dependency;
		pending.accessIndex = static_cast<uint8_t>(instruction->readOperandCount + i);
		if (!SafeCopyTraceValue(address, pending.before, operand.size)) {
			tb.unsupportedMemoryWrites++;
			continue;
		}
		tb.pendingWriteCount++;
	}
}

bool VehHandler::RecordBasicTraceMemoryWrite(
		const TraceBasicBlocksState::PendingWrite& pending, const uint8_t* after) {
	auto& tb = traceBasicBlocks_;
	if (tb.memoryWriteTable.empty()) return false;
	uint64_t key = BasicTraceHash(pending.instruction) ^ BasicTraceHash(pending.address);
	for (uint8_t i = 0; i < pending.size; ++i)
		key = BasicTraceHash(key ^ (static_cast<uint64_t>(pending.before[i]) << ((i & 7) * 8)) ^
			(static_cast<uint64_t>(after[i]) << (((i + 3) & 7) * 8)));
	size_t mask = tb.memoryWriteTable.size() - 1;
	size_t index = static_cast<size_t>(key) & mask;
	for (size_t probe = 0; probe < tb.memoryWriteTable.size(); ++probe) {
		auto& slot = tb.memoryWriteTable[index];
		if (!slot.occupied) {
			if (tb.memoryWriteCount >= tb.maxMemoryWrites) return false;
			slot.occupied = 1;
			slot.instruction = pending.instruction;
			slot.address = pending.address;
			slot.size = pending.size;
			slot.hitCount = 1;
			slot.firstStep = tb.stepsExecuted + 1;
			slot.dependencyMask = pending.dependencyMask;
			memcpy(slot.before, pending.before, pending.size);
			memcpy(slot.after, after, pending.size);
			tb.memoryWriteCount++;
			return true;
		}
		if (slot.instruction == pending.instruction && slot.address == pending.address &&
			slot.size == pending.size && memcmp(slot.before, pending.before, pending.size) == 0 &&
			memcmp(slot.after, after, pending.size) == 0) {
			slot.hitCount++;
			slot.dependencyMask |= pending.dependencyMask;
			return true;
		}
		index = (index + 1) & mask;
	}
	return false;
}

bool VehHandler::RecordBasicTraceMemoryRead(const TraceBasicBlocksState::PendingRead& pending) {
	auto& tb = traceBasicBlocks_;
	if (tb.memoryReadTable.empty()) return false;
	uint64_t key = BasicTraceHash(pending.instruction) ^ BasicTraceHash(pending.address) ^ pending.size;
	for (uint8_t i = 0; i < pending.size; ++i)
		key = BasicTraceHash(key ^ (static_cast<uint64_t>(pending.value[i]) << ((i & 7) * 8)));
	size_t mask = tb.memoryReadTable.size() - 1;
	size_t index = static_cast<size_t>(key) & mask;
	for (size_t probe = 0; probe < tb.memoryReadTable.size(); ++probe) {
		auto& slot = tb.memoryReadTable[index];
		if (!slot.occupied) {
			if (tb.memoryReadCount >= tb.maxMemoryReads) return false;
			slot.occupied = 1; slot.instruction = pending.instruction; slot.address = pending.address;
			slot.size = pending.size; slot.hitCount = 1; slot.dependencyMask = pending.dependencyMask;
			memcpy(slot.value, pending.value, pending.size); tb.memoryReadCount++; return true;
		}
		if (slot.instruction == pending.instruction && slot.address == pending.address &&
			slot.size == pending.size && memcmp(slot.value, pending.value, pending.size) == 0) {
			slot.hitCount++; slot.dependencyMask |= pending.dependencyMask; return true;
		}
		index = (index + 1) & mask;
	}
	return false;
}

void VehHandler::RecordBasicTraceMemoryEvent(
		const TraceBasicBlocksState::PendingRead& pending, uint64_t sequence) {
	auto& tb = traceBasicBlocks_;
	if (!tb.collectMemoryEvents) return;
	EvictBasicTraceTargetEvents(sequence);
	if (tb.memoryEventCount >= tb.memoryEvents.size()) {
		tb.memoryEventsTruncated = true;
		tb.memoryEventsDropped++;
		return;
	}
	uint32_t index = (tb.memoryEventHead + tb.memoryEventCount) %
		static_cast<uint32_t>(tb.memoryEvents.size());
	++tb.memoryEventCount;
	auto& event = tb.memoryEvents[index];
	event = {};
	event.sequence = sequence;
	event.instruction = pending.instruction;
	event.address = pending.address;
	event.threadId = tb.threadId;
	event.dependencyMask = pending.dependencyMask;
	event.size = pending.size;
	event.kind = TraceMemoryAccessKind::Read;
	event.accessIndex = pending.accessIndex;
	event.flags = kTraceMemoryValueValid;
	memcpy(event.value, pending.value, pending.size);
}

void VehHandler::RecordBasicTraceMemoryEvent(
		const TraceBasicBlocksState::PendingWrite& pending, const uint8_t* after, uint64_t sequence) {
	auto& tb = traceBasicBlocks_;
	if (!tb.collectMemoryEvents) return;
	EvictBasicTraceTargetEvents(sequence);
	if (tb.memoryEventCount >= tb.memoryEvents.size()) {
		tb.memoryEventsTruncated = true;
		tb.memoryEventsDropped++;
		return;
	}
	uint32_t index = (tb.memoryEventHead + tb.memoryEventCount) %
		static_cast<uint32_t>(tb.memoryEvents.size());
	++tb.memoryEventCount;
	auto& event = tb.memoryEvents[index];
	event = {};
	event.sequence = sequence;
	event.instruction = pending.instruction;
	event.address = pending.address;
	event.threadId = tb.threadId;
	event.dependencyMask = pending.dependencyMask;
	event.size = pending.size;
	event.kind = TraceMemoryAccessKind::Write;
	event.accessIndex = pending.accessIndex;
	event.flags = kTraceMemoryValueValid;
	memcpy(event.before, pending.before, pending.size);
	memcpy(event.after, after, pending.size);
}

void VehHandler::RecordBasicTraceEvent(TraceBasicBlockEventType type, uint64_t sequence,
		uint64_t source, uint64_t sourceInstruction, uint64_t target,
		TraceBasicBlockEdgeKind edgeKind, uint32_t exceptionCode, bool indirect, uint32_t codeVersion) {
	auto& tb = traceBasicBlocks_;
	if (!tb.collectEvents) return;
	EvictBasicTraceTargetEvents(sequence);
	if (tb.eventCount >= tb.events.size()) {
		tb.eventsTruncated = true;
		++tb.eventsDropped;
		return;
	}
	uint32_t index = (tb.eventHead + tb.eventCount) % static_cast<uint32_t>(tb.events.size());
	++tb.eventCount;
	auto& event = tb.events[index];
	event.sequence = sequence;
	event.source = source;
	event.sourceInstruction = sourceInstruction;
	event.target = target;
	event.threadId = tb.threadId;
	event.exceptionCode = exceptionCode;
	event.codeVersion = codeVersion;
	event.type = type;
	event.edgeKind = edgeKind;
	event.indirect = indirect ? 1 : 0;
}

bool VehHandler::CompactBasicTraceTargetCode() {
	auto& tb = traceBasicBlocks_;
	if (!tb.targetWindow.enabled || tb.codeFileOutput || !tb.collectCode) return false;
	if (tb.targetCodeVersionRemap.size() < tb.codeVersionCount ||
		tb.targetCodeVersionsScratch.size() < tb.maxCodeVersions ||
		tb.targetCodeBytesScratch.size() < tb.maxCodeBytes) return false;
	std::fill(tb.targetCodeVersionRemap.begin(), tb.targetCodeVersionRemap.end(), UINT32_MAX);
	for (uint32_t i = 0; i < tb.eventCount; ++i) {
		const auto& event = tb.events[(tb.eventHead + i) % tb.events.size()];
		if (event.codeVersion < tb.codeVersionCount)
			tb.targetCodeVersionRemap[event.codeVersion] = UINT32_MAX - 1;
	}
	uint32_t newCount = 0;
	uint32_t newBytes = 0;
	for (uint32_t oldId = 0; oldId < tb.codeVersionCount; ++oldId) {
		if (tb.targetCodeVersionRemap[oldId] != UINT32_MAX - 1) continue;
		const auto& oldEntry = tb.codeVersions[oldId];
		if (newCount >= tb.maxCodeVersions || oldEntry.dataOffset + oldEntry.size > tb.codeByteCount ||
			newBytes + oldEntry.size > tb.maxCodeBytes) return false;
		auto entry = oldEntry;
		entry.id = newCount;
		entry.dataOffset = newBytes;
		memcpy(tb.targetCodeBytesScratch.data() + newBytes,
			tb.codeBytes.data() + oldEntry.dataOffset, oldEntry.size);
		tb.targetCodeVersionsScratch[newCount] = entry;
		tb.targetCodeVersionRemap[oldId] = newCount++;
		newBytes += oldEntry.size;
	}
	for (uint32_t i = 0; i < tb.eventCount; ++i) {
		auto& event = tb.events[(tb.eventHead + i) % tb.events.size()];
		if (event.codeVersion < tb.targetCodeVersionRemap.size())
			event.codeVersion = tb.targetCodeVersionRemap[event.codeVersion];
	}
	tb.codeBytes.swap(tb.targetCodeBytesScratch);
	tb.codeVersions.swap(tb.targetCodeVersionsScratch);
	tb.codeVersionCount = newCount;
	tb.codeByteCount = newBytes;
	std::fill(tb.codeVersionTable.begin(), tb.codeVersionTable.end(), TraceBasicBlocksState::CodeVersionSlot{});
	for (uint32_t id = 0; id < newCount; ++id) {
		const auto& entry = tb.codeVersions[id];
		uint64_t secondaryHash = 1099511628211ULL;
		const uint8_t* bytes = tb.codeBytes.data() + entry.dataOffset;
		for (uint32_t i = 0; i < entry.size; ++i) {
			secondaryHash ^= static_cast<uint64_t>(bytes[i]) + i;
			secondaryHash *= 14029467366897019727ULL;
		}
		size_t mask = tb.codeVersionTable.size() - 1;
		size_t index = static_cast<size_t>(BasicTraceHash(entry.blockStart) ^
			BasicTraceHash(entry.hash) ^ entry.size) & mask;
		while (tb.codeVersionTable[index].occupied) index = (index + 1) & mask;
		auto& slot = tb.codeVersionTable[index];
		slot.occupied = 1;
		slot.entry = entry;
		slot.secondaryHash = secondaryHash;
	}
	return true;
}

uint32_t VehHandler::CaptureBasicTraceCodeVersion(uint64_t blockStart, uint64_t sequence) {
	auto& tb = traceBasicBlocks_;
	if (!tb.collectCode) return UINT32_MAX;
	auto* first = FindBasicTraceInstruction(blockStart);
	if (!first) { tb.codeTruncated = true; return UINT32_MAX; }
	uint64_t blockEnd = first->next;
	for (auto* current = first; !current->terminal;) {
		auto* next = FindBasicTraceInstruction(current->next);
		if (!next || next->address != blockEnd || next->staticBlockStart != first->staticBlockStart) break;
		blockEnd = next->next;
		current = next;
	}
	uint64_t wideSize = blockEnd - blockStart;
	if (!wideSize || wideSize > tb.codeScratch.size() || wideSize > UINT32_MAX) {
		tb.codeTruncated = true; return UINT32_MAX;
	}
	uint32_t size = static_cast<uint32_t>(wideSize);
	if (!SafeCopyTraceCode(blockStart, tb.codeScratch.data(), size)) {
		tb.codeTruncated = true; return UINT32_MAX;
	}
	uint64_t hash = 1469598103934665603ULL;
	uint64_t secondaryHash = 1099511628211ULL;
	for (uint32_t i = 0; i < size; ++i) {
		hash ^= tb.codeScratch[i]; hash *= 1099511628211ULL;
		secondaryHash ^= static_cast<uint64_t>(tb.codeScratch[i]) + i;
		secondaryHash *= 14029467366897019727ULL;
	}
	size_t mask = tb.codeVersionTable.size() - 1;
	size_t index = static_cast<size_t>(BasicTraceHash(blockStart) ^ BasicTraceHash(hash) ^ size) & mask;
	for (size_t probe = 0; probe < tb.codeVersionTable.size(); ++probe) {
		auto& slot = tb.codeVersionTable[index];
		if (!slot.occupied) {
			if (tb.codeVersionCount >= tb.maxCodeVersions ||
				tb.codeByteCount + size > tb.maxCodeBytes) {
				const uint32_t oldCount = tb.codeVersionCount;
				const uint32_t oldBytes = tb.codeByteCount;
				if (tb.targetWindow.enabled && !tb.targetMatched &&
					CompactBasicTraceTargetCode() &&
					(tb.codeVersionCount < oldCount || tb.codeByteCount < oldBytes))
					return CaptureBasicTraceCodeVersion(blockStart, sequence);
				tb.codeTruncated = true; return UINT32_MAX;
			}
			TraceBasicBlockCodeVersionEntry entry{};
			entry.blockStart = blockStart; entry.blockEnd = blockEnd;
			entry.hash = hash; entry.firstSequence = sequence;
			entry.id = tb.codeVersionCount; entry.dataOffset = tb.codeByteCount;
			entry.size = size;
			if (tb.codeFileOutput) {
				if (!tb.codeStreamAccepting) { tb.codeTruncated = true; return UINT32_MAX; }
				TraceCodeArtifactRecord record{};
				record.blockStart = blockStart; record.blockEnd = blockEnd;
				record.hash = hash; record.firstSequence = sequence;
				record.dataOffset = tb.codeByteCount; record.id = entry.id; record.size = size;
				if (!AppendBasicTraceCodeStream(&record, sizeof(record)) ||
					!AppendBasicTraceCodeStream(tb.codeScratch.data(), size)) {
					tb.codeStreamAccepting = false; tb.codeTruncated = true; return UINT32_MAX;
				}
				tb.codeStreamCommittedBytes = tb.codeStreamProducedBytes;
			} else {
				memcpy(tb.codeBytes.data() + tb.codeByteCount, tb.codeScratch.data(), size);
			}
			slot.occupied = 1;
			slot.entry = entry;
			slot.secondaryHash = secondaryHash;
			tb.codeByteCount += size;
			tb.codeVersions[tb.codeVersionCount] = entry;
			return tb.codeVersionCount++;
		}
		const auto& entry = slot.entry;
		if (entry.blockStart == blockStart && entry.size == size && entry.hash == hash &&
			slot.secondaryHash == secondaryHash &&
			(tb.codeFileOutput ||
			 memcmp(tb.codeBytes.data() + entry.dataOffset, tb.codeScratch.data(), size) == 0))
			return entry.id;
		index = (index + 1) & mask;
	}
	tb.codeTruncated = true;
	return UINT32_MAX;
}

bool VehHandler::PublishBasicTraceCodeStreamBuffer() {
	auto& tb = traceBasicBlocks_;
	if (!tb.codeFileOutput || !tb.codeStreamBufferCount) return false;
	auto& buffer = tb.codeStreamBuffers[tb.codeStreamProducerIndex];
	if (buffer.state.load(std::memory_order_acquire) != 1 || buffer.size == 0) return true;
	buffer.index = tb.codeStreamNextChunk++;
	buffer.state.store(2, std::memory_order_release);
	SyscallResolver::Instance().SetEvent(tb.codeStreamReadyEvent);
	return true;
}

bool VehHandler::AppendBasicTraceCodeStream(const void* data, size_t size) {
	auto& tb = traceBasicBlocks_;
	if (!tb.codeFileOutput || !tb.codeStreamAccepting || !data) return false;
	const auto* input = static_cast<const uint8_t*>(data);
	while (size) {
		auto& buffer = tb.codeStreamBuffers[tb.codeStreamProducerIndex];
		if (buffer.state.load(std::memory_order_acquire) != 1) return false;
		size_t available = tb.codeChunkBytes - buffer.size;
		size_t copied = std::min(size, available);
		memcpy(buffer.bytes.data() + buffer.size, input, copied);
		buffer.size += static_cast<uint32_t>(copied);
		tb.codeStreamProducedBytes += copied;
		input += copied;
		size -= copied;
		if (buffer.size == tb.codeChunkBytes) {
			PublishBasicTraceCodeStreamBuffer();
			uint32_t next = (tb.codeStreamProducerIndex + 1) % tb.codeStreamBufferCount;
			auto& nextBuffer = tb.codeStreamBuffers[next];
			uint8_t expected = 0;
			if (!nextBuffer.state.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
				tb.codeStreamAccepting = false;
				return size == 0;
			}
			nextBuffer.size = 0;
			tb.codeStreamProducerIndex = next;
		}
	}
	return true;
}

static bool WriteTraceCodeStreamExact(HANDLE pipe, const void* data, DWORD size) {
	const auto* cursor = static_cast<const uint8_t*>(data);
	DWORD total = 0;
	while (total < size) {
		OVERLAPPED ov{};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;
		DWORD written = 0;
		BOOL ok = WriteFile(pipe, cursor + total, size - total, &written, &ov);
		if (!ok && GetLastError() == ERROR_IO_PENDING) {
			DWORD wait = WaitForSingleObject(ov.hEvent, 10000);
			if (wait == WAIT_OBJECT_0) ok = GetOverlappedResult(pipe, &ov, &written, FALSE);
			else { CancelIoEx(pipe, &ov); ok = FALSE; }
		}
		CloseHandle(ov.hEvent);
		if (!ok || !written) return false;
		total += written;
	}
	return true;
}

void VehHandler::RunBasicTraceCodeStreamWriter() {
	auto& tb = traceBasicBlocks_;
	uint32_t consumer = 0;
	uint32_t chunksWritten = 0;
	while (true) {
		bool handled = false;
		if (tb.codeStreamBufferCount) {
			auto& buffer = tb.codeStreamBuffers[consumer];
			uint8_t expected = 2;
			if (buffer.state.compare_exchange_strong(expected, 3, std::memory_order_acq_rel)) {
				handled = true;
				if (!tb.codeStreamTransferFailed.load(std::memory_order_acquire)) {
					TraceCodeStreamFrameHeader frame{};
					frame.magic = kTraceCodeStreamMagic;
					frame.schemaVersion = kTraceCodeArtifactSchemaVersion;
					frame.type = static_cast<uint16_t>(TraceCodeStreamFrameType::Data);
					frame.token = tb.codeStreamToken;
					frame.chunkIndex = buffer.index;
					frame.streamOffset = static_cast<uint64_t>(buffer.index) * tb.codeChunkBytes;
					frame.payloadSize = buffer.size;
					frame.payloadHash = TraceCodePayloadHash(buffer.bytes.data(), buffer.size);
					if (!WriteTraceCodeStreamExact(tb.codeStreamPipe, &frame, sizeof(frame)) ||
						!WriteTraceCodeStreamExact(tb.codeStreamPipe, buffer.bytes.data(), buffer.size))
						tb.codeStreamTransferFailed.store(true, std::memory_order_release);
					else
						++chunksWritten;
				}
				buffer.size = 0;
				buffer.state.store(0, std::memory_order_release);
				consumer = (consumer + 1) % tb.codeStreamBufferCount;
			}
		}
		if (tb.codeStreamProducerDone.load(std::memory_order_acquire)) {
			bool ready = false;
			for (uint32_t i = 0; i < tb.codeStreamBufferCount; ++i)
				if (tb.codeStreamBuffers[i].state.load(std::memory_order_acquire) == 2) { ready = true; break; }
			if (!ready) break;
		}
		if (!handled) WaitForSingleObject(tb.codeStreamReadyEvent, 100);
	}
	if (!tb.codeStreamTransferFailed.load(std::memory_order_acquire)) {
		TraceCodeStreamComplete complete{};
		complete.committedRecordBytes = tb.codeStreamCommittedBytes;
		complete.codeByteCount = tb.codeByteCount;
		complete.versionCount = tb.codeVersionCount;
		complete.chunkCount = chunksWritten;
		complete.truncated = tb.codeTruncated ? 1 : 0;
		TraceCodeStreamFrameHeader frame{};
		frame.magic = kTraceCodeStreamMagic;
		frame.schemaVersion = kTraceCodeArtifactSchemaVersion;
		frame.type = static_cast<uint16_t>(TraceCodeStreamFrameType::Complete);
		frame.token = tb.codeStreamToken;
		frame.chunkIndex = chunksWritten;
		frame.streamOffset = tb.codeStreamCommittedBytes;
		frame.payloadSize = sizeof(complete);
		frame.payloadHash = TraceCodePayloadHash(&complete, sizeof(complete));
		if (!WriteTraceCodeStreamExact(tb.codeStreamPipe, &frame, sizeof(frame)) ||
			!WriteTraceCodeStreamExact(tb.codeStreamPipe, &complete, sizeof(complete)))
			tb.codeStreamTransferFailed.store(true, std::memory_order_release);
	}
}

void VehHandler::StopBasicTraceCodeStream(bool abort) {
	auto& tb = traceBasicBlocks_;
	if (!tb.codeFileOutput) return;
	if (abort) tb.codeTruncated = true;
	PublishBasicTraceCodeStreamBuffer();
	tb.codeStreamProducerDone.store(true, std::memory_order_release);
	SyscallResolver::Instance().SetEvent(tb.codeStreamReadyEvent);
	if (tb.codeStreamThread.joinable()) tb.codeStreamThread.join();
	if (tb.codeStreamTransferFailed.load(std::memory_order_acquire)) tb.codeTruncated = true;
	if (tb.codeStreamPipe != INVALID_HANDLE_VALUE) {
		CloseHandle(tb.codeStreamPipe);
		tb.codeStreamPipe = INVALID_HANDLE_VALUE;
	}
	if (tb.codeStreamReadyEvent) {
		SyscallResolver::Instance().Close(tb.codeStreamReadyEvent);
		tb.codeStreamReadyEvent = nullptr;
	}
}

void VehHandler::FinalizeTraceBasicBlocksCodeStream() {
	StopBasicTraceCodeStream(false);
}

void VehHandler::CompleteBasicTraceMemoryWrites() {
	auto& tb = traceBasicBlocks_;
	const uint64_t sequence = tb.stepsExecuted + 1;
	for (uint8_t i = 0; i < tb.pendingReadCount; ++i) {
		RecordBasicTraceMemoryEvent(tb.pendingReads[i], sequence);
		if (tb.collectMemoryReads && !RecordBasicTraceMemoryRead(tb.pendingReads[i]))
			tb.memoryReadsTruncated = true;
	}
	tb.pendingReadCount = 0;
	for (uint8_t i = 0; i < tb.pendingWriteCount; ++i) {
		uint8_t after[kTraceMemoryMaxValueBytes]{};
		const auto& pending = tb.pendingWrites[i];
		if (!SafeCopyTraceValue(pending.address, after, pending.size)) {
			tb.unsupportedMemoryWrites++;
			continue;
		}
		RecordBasicTraceMemoryEvent(pending, after, sequence);
		if (tb.collectMemoryWrites && !RecordBasicTraceMemoryWrite(pending, after)) tb.memoryWritesTruncated = true;
		if (!tb.memoryTaintTable.empty()) {
			size_t mask = tb.memoryTaintTable.size() - 1;
			size_t index = static_cast<size_t>(BasicTraceHash(pending.address) ^ pending.size) & mask;
			for (size_t probe = 0; probe < tb.memoryTaintTable.size(); ++probe) {
				auto& slot = tb.memoryTaintTable[index];
				if (!slot.occupied || (slot.address == pending.address && slot.size == pending.size)) {
					slot.occupied = 1; slot.address = pending.address; slot.size = pending.size;
					slot.dependencyMask = pending.dependencyMask; break;
				}
				index = (index + 1) & mask;
			}
		}
	}
	tb.pendingWriteCount = 0;
	for (uint8_t reg = 0; reg < 16; ++reg)
		if (tb.pendingRegisterWriteMask & (1u << reg)) tb.registerDependencies[reg] = tb.pendingDependencyMask;
	if (tb.pendingWritesFlags) tb.flagsDependencies = tb.pendingDependencyMask;
	tb.pendingRegisterWriteMask = 0; tb.pendingDependencyMask = 0; tb.pendingWritesFlags = 0;
}

void VehHandler::PrepareBasicTraceRegisterEvent(uint64_t instruction, const CONTEXT* ctx) {
	auto& tb = traceBasicBlocks_;
	tb.pendingRegisterEventValid = false;
	if (!tb.collectRegisterEvents || !ctx) return;
	auto& event = tb.pendingRegisterEvent;
	event = {};
	event.instruction = instruction;
	event.threadId = tb.threadId;
	FillBasicTraceRegisterValues(ctx, event.before, event.is32bit);
	tb.pendingRegisterEventValid = true;
}

void VehHandler::CompleteBasicTraceRegisterEvent(const CONTEXT* ctx) {
	auto& tb = traceBasicBlocks_;
	if (!tb.pendingRegisterEventValid || !ctx) return;
	auto event = tb.pendingRegisterEvent;
	tb.pendingRegisterEventValid = false;
	event.sequence = tb.stepsExecuted + 1;
	EvictBasicTraceTargetEvents(event.sequence);
	uint8_t afterIs32bit = event.is32bit;
	FillBasicTraceRegisterValues(ctx, event.after, afterIs32bit);
	const uint32_t registerCount = event.is32bit ? 8 : 16;
	for (uint32_t i = 0; i < registerCount; ++i)
		if (event.before[i] != event.after[i]) event.changedMask |= 1u << i;
	if (event.before[17] != event.after[17]) event.changedMask |= 1u << 17;
	if (tb.registerEventCount >= tb.registerEvents.size()) {
		tb.registerEventsTruncated = true;
		tb.registerEventsDropped++;
		return;
	}
	uint32_t index = (tb.registerEventHead + tb.registerEventCount) %
		static_cast<uint32_t>(tb.registerEvents.size());
	++tb.registerEventCount;
	tb.registerEvents[index] = event;
}

bool VehHandler::RecordBasicTraceBlock(uint64_t start, const CONTEXT* ctx, uint32_t snapshot) {
	auto& tb = traceBasicBlocks_;
	if (tb.blockTable.empty()) return false;
	size_t mask = tb.blockTable.size() - 1;
	size_t index = static_cast<size_t>(BasicTraceHash(start)) & mask;
	for (size_t probe = 0; probe < tb.blockTable.size(); ++probe) {
		auto& slot = tb.blockTable[index];
		if (!slot.occupied) {
			if (tb.blockCount >= tb.maxBlocks) return false;
			slot.occupied = 1;
			slot.start = start;
			slot.firstSnapshot = snapshot != UINT32_MAX ? snapshot : CaptureBasicTraceSnapshot(ctx);
			tb.blockCount++;
			return true;
		}
		if (slot.start == start) return true;
		index = (index + 1) & mask;
	}
	return false;
}

bool VehHandler::RecordBasicTraceEdge(uint64_t sourceBlock, uint64_t sourceInstruction,
		uint64_t target, TraceBasicBlockEdgeKind kind, uint32_t exceptionCode,
		bool indirect, const CONTEXT* ctx, uint32_t* snapshotOut,
		uint64_t faultAddress, const TraceBasicBlockSnapshot* faultSnapshot) {
	auto& tb = traceBasicBlocks_;
	if (tb.edgeTable.empty()) return false;
	uint64_t key = BasicTraceHash(sourceBlock) ^ BasicTraceHash(sourceInstruction + 0x517cc1b727220a95ULL) ^
		BasicTraceHash(target + 0x9e3779b97f4a7c15ULL);
	key ^= (static_cast<uint64_t>(kind) << 56) ^ exceptionCode;
	size_t mask = tb.edgeTable.size() - 1;
	size_t index = static_cast<size_t>(BasicTraceHash(key)) & mask;
	for (size_t probe = 0; probe < tb.edgeTable.size(); ++probe) {
		auto& slot = tb.edgeTable[index];
		if (!slot.occupied) {
			if (tb.edgeCount >= tb.maxEdges) return false;
			slot.occupied = 1;
			slot.sourceBlock = sourceBlock;
			slot.sourceInstruction = sourceInstruction;
			slot.target = target;
			slot.kind = kind;
			slot.exceptionCode = exceptionCode;
			slot.indirect = indirect ? 1 : 0;
			auto* source = FindBasicTraceInstruction(sourceInstruction);
			slot.dependencyMask = source ? source->lastDependencyMask : 0;
			slot.hitCount = 1;
			slot.firstStep = tb.stepsExecuted;
			slot.snapshot = CaptureBasicTraceSnapshot(ctx);
			slot.faultAddress = faultAddress;
			if (faultSnapshot && tb.snapshotCount < tb.snapshots.size()) {
				slot.faultSnapshot = tb.snapshotCount++;
				tb.snapshots[slot.faultSnapshot] = *faultSnapshot;
			}
			if (snapshotOut) *snapshotOut = slot.snapshot;
			tb.edgeCount++;
			return true;
		}
		if (slot.sourceBlock == sourceBlock && slot.sourceInstruction == sourceInstruction &&
			slot.target == target && slot.kind == kind &&
			slot.exceptionCode == exceptionCode) {
			slot.hitCount++;
			auto* source = FindBasicTraceInstruction(sourceInstruction);
			if (source) slot.dependencyMask |= source->lastDependencyMask;
			if (snapshotOut) *snapshotOut = slot.snapshot;
			return true;
		}
		index = (index + 1) & mask;
	}
	return false;
}

void VehHandler::FinishBasicTrace(TraceBasicBlockStopReason reason, uint64_t finalAddress, bool truncated) {
	auto& tb = traceBasicBlocks_;
	tb.stopReason = reason;
	tb.finalAddress = finalAddress;
	tb.truncated = tb.truncated || truncated;
	tb.stopPending = false;
	tb.pendingException = false;
	tb.pendingWriteCount = 0;
	tb.pendingReadCount = 0;
	tb.pendingRegisterEventValid = false;
	tb.active.store(false, std::memory_order_release);
	tb.done.store(true, std::memory_order_release);
}

bool VehHandler::StartTraceBasicBlocks(uint32_t threadId, uint64_t rangeStart, uint64_t rangeEnd,
		uint32_t maxBlocks, uint32_t maxEdges, uint32_t maxSteps, uint16_t stackBytes,
		bool followExceptions, bool collectMemoryWrites, uint32_t maxMemoryWrites,
		bool collectMemoryReads, uint32_t maxMemoryReads,
		bool collectEvents, uint32_t maxEvents,
		bool collectCode, uint32_t maxCodeBytes, uint32_t maxCodeVersions,
		TraceCodeOutputMode codeOutputMode, uint32_t codeChunkBytes,
		uint64_t codeStreamToken, HANDLE codeStreamPipe,
		bool collectMemoryEvents, uint32_t maxMemoryEvents,
		bool collectRegisterEvents, uint32_t maxRegisterEvents,
		const TraceDependencySource* dependencySources, uint8_t dependencySourceCount,
		const TraceCondition& startCondition, const TraceCondition& stopCondition,
		const TraceCondition& collectCondition, const TraceOccurrenceWindow& occurrenceWindow,
		bool stopOnReturn, const TraceTargetWindow& targetWindow,
		std::vector<TraceBasicBlocksState::Instruction>&& instructions,
		std::vector<uint64_t>&& staticBlockStarts) {
	if (traceReg_.active.load(std::memory_order_acquire) ||
		importResolve_.active.load(std::memory_order_acquire) ||
		traceCalls_.active.load(std::memory_order_acquire) ||
		traceBasicBlocks_.active.load(std::memory_order_acquire)) {
		if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
		return false;
	}

	CONTEXT ctx{};
	if (!GetStoppedContext(threadId, ctx)) {
		if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
		return false;
	}
#ifdef _WIN64
	uint64_t ip = ctx.Rip;
	uint64_t entryStackPointer = ctx.Rsp;
#else
	uint64_t ip = ctx.Eip;
	uint64_t entryStackPointer = ctx.Esp;
#endif
	if (ip < rangeStart || ip >= rangeEnd || instructions.empty()) {
		if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
		return false;
	}
	uint64_t returnAddress = 0;
	if (stopOnReturn) {
#ifdef _WIN64
		if (!SafeCopyTraceValue(entryStackPointer, reinterpret_cast<uint8_t*>(&returnAddress),
				static_cast<uint8_t>(sizeof(returnAddress))) || !returnAddress) {
#else
		uint32_t returnAddress32 = 0;
		if (!SafeCopyTraceValue(entryStackPointer, reinterpret_cast<uint8_t*>(&returnAddress32),
				static_cast<uint8_t>(sizeof(returnAddress32))) || !returnAddress32) {
#endif
			if (codeStreamPipe != INVALID_HANDLE_VALUE) CloseHandle(codeStreamPipe);
			return false;
		}
#ifndef _WIN64
		returnAddress = returnAddress32;
#endif
	}

	auto nextPowerOfTwo = [](size_t value) {
		size_t result = 1;
		while (result < value) result <<= 1;
		return result;
	};

	auto& tb = traceBasicBlocks_;
	tb.active.store(false, std::memory_order_relaxed);
	tb.done.store(false, std::memory_order_relaxed);
	tb.cancelRequested.store(false, std::memory_order_relaxed);
	tb.threadId = threadId;
	tb.rangeStart = rangeStart;
	tb.rangeEnd = rangeEnd;
	tb.maxBlocks = maxBlocks;
	tb.maxEdges = maxEdges;
	tb.maxSteps = maxSteps;
	tb.stackBytes = stackBytes;
	tb.followExceptions = followExceptions;
	tb.collectMemoryWrites = collectMemoryWrites;
	tb.maxMemoryWrites = maxMemoryWrites;
	tb.collectMemoryReads = collectMemoryReads;
	tb.maxMemoryReads = maxMemoryReads;
	tb.collectEvents = collectEvents;
	tb.maxEvents = maxEvents;
	tb.collectCode = collectCode;
	tb.maxCodeBytes = maxCodeBytes;
	tb.maxCodeVersions = maxCodeVersions;
	tb.codeFileOutput = collectCode && codeOutputMode == TraceCodeOutputMode::File;
	tb.codeChunkBytes = tb.codeFileOutput ? codeChunkBytes : 0;
	tb.codeStreamToken = tb.codeFileOutput ? codeStreamToken : 0;
	tb.codeStreamPipe = tb.codeFileOutput ? codeStreamPipe : INVALID_HANDLE_VALUE;
	tb.collectMemoryEvents = collectMemoryEvents;
	tb.maxMemoryEvents = maxMemoryEvents;
	tb.collectRegisterEvents = collectRegisterEvents;
	tb.maxRegisterEvents = maxRegisterEvents;
	tb.dependencySourceCount = dependencySourceCount;
	memset(tb.dependencySources, 0, sizeof(tb.dependencySources));
	if (dependencySourceCount) memcpy(tb.dependencySources, dependencySources,
		static_cast<size_t>(dependencySourceCount) * sizeof(dependencySources[0]));
	tb.startCondition = startCondition;
	tb.stopCondition = stopCondition;
	tb.collectCondition = collectCondition;
	tb.occurrenceWindow = occurrenceWindow;
	tb.targetWindow = targetWindow;
	tb.instructions = std::move(instructions);
	tb.staticBlockStarts = std::move(staticBlockStarts);
	tb.blockTable.assign(nextPowerOfTwo(static_cast<size_t>(maxBlocks) * 2), {});
	tb.edgeTable.assign(nextPowerOfTwo(static_cast<size_t>(maxEdges) * 2), {});
	if (collectMemoryWrites)
		tb.memoryWriteTable.assign(nextPowerOfTwo(static_cast<size_t>(maxMemoryWrites) * 2), {});
	else
		tb.memoryWriteTable.clear();
	if (collectMemoryReads)
		tb.memoryReadTable.assign(nextPowerOfTwo(static_cast<size_t>(maxMemoryReads) * 2), {});
	else
		tb.memoryReadTable.clear();
	if (dependencySourceCount)
		tb.memoryTaintTable.assign(nextPowerOfTwo(static_cast<size_t>(maxMemoryWrites + maxMemoryReads + 64) * 2), {});
	else
		tb.memoryTaintTable.clear();
	tb.snapshots.assign(static_cast<size_t>(maxEdges) * 2 + 1, {});
	if (collectEvents) tb.events.assign(maxEvents, {});
	else tb.events.clear();
	if (collectMemoryEvents) tb.memoryEvents.assign(maxMemoryEvents, {});
	else tb.memoryEvents.clear();
	if (collectRegisterEvents) tb.registerEvents.assign(maxRegisterEvents, {});
	else tb.registerEvents.clear();
	if (collectCode) {
		tb.codeVersionTable.assign(nextPowerOfTwo(static_cast<size_t>(maxCodeVersions) * 2), {});
		tb.codeVersions.assign(maxCodeVersions, {});
		// A single captured block cannot exceed the decoded trace range.  Keep the
		// larger cumulative version budget from needlessly doubling allocation.
		const size_t maxBlockBytes = static_cast<size_t>(std::min<uint64_t>(
			maxCodeBytes, rangeEnd - rangeStart));
		tb.codeScratch.assign(maxBlockBytes, 0);
		if (tb.codeFileOutput) {
			tb.codeBytes.clear();
			tb.codeStreamBufferCount = static_cast<uint32_t>(std::max<size_t>(3,
				(maxBlockBytes + sizeof(TraceCodeArtifactRecord) + codeChunkBytes - 1) /
				codeChunkBytes + 2));
			tb.codeStreamBufferCount = std::min(tb.codeStreamBufferCount,
				TraceBasicBlocksState::kMaxCodeStreamBuffers);
			for (uint32_t i = 0; i < TraceBasicBlocksState::kMaxCodeStreamBuffers; ++i) {
				auto& buffer = tb.codeStreamBuffers[i];
				buffer.bytes.clear(); buffer.size = 0; buffer.index = 0;
				buffer.state.store(0, std::memory_order_relaxed);
				if (i < tb.codeStreamBufferCount) buffer.bytes.assign(codeChunkBytes, 0);
			}
			tb.codeStreamProducerIndex = 0;
			tb.codeStreamNextChunk = 0;
			tb.codeStreamProducedBytes = 0;
			tb.codeStreamCommittedBytes = 0;
			tb.codeStreamAccepting = true;
			tb.codeStreamProducerDone.store(false, std::memory_order_relaxed);
			tb.codeStreamTransferFailed.store(false, std::memory_order_relaxed);
			if (!NT_SUCCESS(SyscallResolver::Instance().CreateEvent(&tb.codeStreamReadyEvent))) {
				CloseHandle(tb.codeStreamPipe); tb.codeStreamPipe = INVALID_HANDLE_VALUE;
				return false;
			}
			tb.codeStreamBuffers[0].state.store(1, std::memory_order_relaxed);
			try { tb.codeStreamThread = std::thread(&VehHandler::RunBasicTraceCodeStreamWriter, this); }
			catch (...) {
				SyscallResolver::Instance().Close(tb.codeStreamReadyEvent); tb.codeStreamReadyEvent = nullptr;
				CloseHandle(tb.codeStreamPipe); tb.codeStreamPipe = INVALID_HANDLE_VALUE;
				return false;
			}
		} else {
			tb.codeBytes.assign(maxCodeBytes, 0);
			if (targetWindow.enabled) {
				tb.targetCodeBytesScratch.assign(maxCodeBytes, 0);
				tb.targetCodeVersionsScratch.assign(maxCodeVersions, {});
				tb.targetCodeVersionRemap.assign(maxCodeVersions, UINT32_MAX);
			} else {
				tb.targetCodeBytesScratch.clear();
				tb.targetCodeVersionsScratch.clear();
				tb.targetCodeVersionRemap.clear();
			}
		}
	} else {
		tb.codeVersionTable.clear(); tb.codeVersions.clear(); tb.codeBytes.clear(); tb.codeScratch.clear();
		tb.targetCodeBytesScratch.clear(); tb.targetCodeVersionsScratch.clear();
		tb.targetCodeVersionRemap.clear();
		tb.codeFileOutput = false;
	}
	tb.blockCount = tb.edgeCount = tb.snapshotCount = tb.exceptionsFollowed = 0;
	tb.memoryWriteCount = tb.unsupportedMemoryWrites = 0;
	tb.memoryWritesTruncated = false;
	tb.memoryReadCount = tb.unsupportedMemoryReads = 0;
	tb.memoryReadsTruncated = false;
	tb.dependencyIncomplete = false;
	tb.eventsTruncated = false;
	tb.eventsDropped = 0;
	tb.eventCount = 0;
	tb.eventHead = 0;
	tb.memoryEventCount = 0;
	tb.memoryEventHead = 0;
	tb.memoryEventsDropped = 0;
	tb.memoryEventsTruncated = false;
	tb.registerEventCount = 0;
	tb.registerEventHead = 0;
	tb.registerEventsDropped = 0;
	tb.registerEventsTruncated = false;
	tb.pendingRegisterEventValid = false;
	tb.codeVersionCount = tb.codeByteCount = 0;
	tb.codeTruncated = false;
	memset(tb.registerDependencies, 0, sizeof(tb.registerDependencies));
	tb.flagsDependencies = 0;
	for (uint8_t source = 0; source < dependencySourceCount; ++source)
		if (dependencySources[source].kind == TraceDependencySourceKind::Register &&
			dependencySources[source].registerIndex < 16)
			tb.registerDependencies[dependencySources[source].registerIndex] |= 1u << source;
	tb.pendingWriteCount = 0;
	tb.pendingReadCount = 0;
	tb.filteredSteps = 0;
	tb.stopOnReturn = stopOnReturn;
	tb.functionReturned = false;
	tb.externalCallActive = false;
	tb.entryStackPointer = entryStackPointer;
	tb.returnAddress = returnAddress;
	tb.externalReturnAddress = 0;
	tb.externalSteps = 0;
	tb.returnSnapshot = UINT32_MAX;
	tb.stepsExecuted = 0;
	tb.initialAddress = tb.currentBlock = tb.previousInstruction = tb.finalAddress = ip;
	tb.stopReason = TraceBasicBlockStopReason::Completed;
	tb.truncated = false;
	tb.stopPending = false;
	tb.pendingException = false;
	tb.pendingExceptionFaultAddress = 0;

	tb.occurrenceHits = 0;
	tb.occurrenceWindowActive = !occurrenceWindow.enabled;
	tb.occurrenceWindowStarted = !occurrenceWindow.enabled;
	tb.occurrenceWindowCompleted = false;
	tb.targetOccurrenceHits = 0;
	tb.targetTriggerSequence = 0;
	tb.targetCaptureStartSequence = 0;
	tb.targetCaptureEndSequence = 0;
	tb.targetMatched = false;
	AdvanceBasicTraceOccurrence(ip);
	AdvanceBasicTraceTarget(ip, 0);
	tb.startConditionMet = startCondition.clauseCount == 0 || EvaluateBasicTraceCondition(startCondition, &ctx);
	tb.collectWindowActive = BasicTraceCollectionGate(&ctx);
	if (tb.collectWindowActive) {
		uint32_t initialSnapshot = CaptureBasicTraceSnapshot(&ctx);
		if (!RecordBasicTraceBlock(ip, &ctx, initialSnapshot)) {
			StopBasicTraceCodeStream(true); return false;
		}
		uint32_t version = CaptureBasicTraceCodeVersion(ip, 0);
		RecordBasicTraceEvent(TraceBasicBlockEventType::BlockEntry, 0, 0, 0, ip,
			TraceBasicBlockEdgeKind::Fallthrough, 0, false, version);
	}

	// Avoid leaving a generic step flag behind: write TF into the stopped context
	// directly, then resume it as a normal continue.
	ctx.EFlags |= 0x100;
	if (!SetStoppedContext(threadId, ctx)) {
		StopBasicTraceCodeStream(true); return false;
	}
	if (tb.collectWindowActive) {
		PrepareBasicTraceMemoryWrites(FindBasicTraceInstruction(ip), &ctx);
		PrepareBasicTraceRegisterEvent(ip, &ctx);
	}
	tb.active.store(true, std::memory_order_release);
	ResumeStoppedThread(threadId, false);
	return true;
}

void VehHandler::CancelTraceBasicBlocks(TraceBasicBlockStopReason reason) {
	auto& tb = traceBasicBlocks_;
	if (!tb.active.load(std::memory_order_acquire)) return;
	tb.pendingStopReason = reason;
	tb.cancelRequested.store(true, std::memory_order_release);
}

VehHandler::BasicTraceStepResult VehHandler::HandleBasicTraceSingleStep(
		PEXCEPTION_POINTERS info, uint32_t tid, uint64_t addr) {
	auto& tb = traceBasicBlocks_;
	if (!tb.active.load(std::memory_order_acquire) || tid != tb.threadId)
		return BasicTraceStepResult::NotActive;
	CompleteBasicTraceMemoryWrites();
	CompleteBasicTraceRegisterEvent(info->ContextRecord);

	if (tb.cancelRequested.load(std::memory_order_acquire) || tb.stopPending) {
		TraceBasicBlockStopReason reason = tb.pendingStopReason;
		FinishBasicTrace(reason, addr, reason != TraceBasicBlockStopReason::Completed);
		return BasicTraceStepResult::Stop;
	}
	bool inRange = addr >= tb.rangeStart && addr < tb.rangeEnd;
	auto* current = inRange ? FindBasicTraceInstruction(addr) : nullptr;
	if (inRange) AdvanceBasicTraceTarget(addr, tb.stepsExecuted + 1);
	auto* previousInstruction = FindBasicTraceInstruction(tb.previousInstruction);
	if (tb.stopOnReturn && previousInstruction &&
		previousInstruction->kind == TraceBasicBlockEdgeKind::Return &&
		addr == tb.returnAddress) {
#ifdef _WIN64
		const uint64_t stackPointer = info->ContextRecord->Rsp;
		const uint64_t returnStackPointer = tb.entryStackPointer + sizeof(uint64_t);
#else
		const uint64_t stackPointer = info->ContextRecord->Esp;
		const uint64_t returnStackPointer = tb.entryStackPointer + sizeof(uint32_t);
#endif
		if (stackPointer >= returnStackPointer) {
			++tb.stepsExecuted;
			++previousInstruction->hitCount;
			previousInstruction->lastHitStep = tb.stepsExecuted;
			uint32_t snapshot = UINT32_MAX;
			if (!RecordBasicTraceEdge(tb.currentBlock, tb.previousInstruction, addr,
					TraceBasicBlockEdgeKind::Return, 0, previousInstruction->indirect != 0,
					info->ContextRecord, &snapshot)) {
				FinishBasicTrace(TraceBasicBlockStopReason::MaxEdges, addr, true);
				return BasicTraceStepResult::Stop;
			}
			RecordBasicTraceEvent(TraceBasicBlockEventType::Edge, tb.stepsExecuted,
				tb.currentBlock, tb.previousInstruction, addr, TraceBasicBlockEdgeKind::Return,
				0, previousInstruction->indirect != 0, UINT32_MAX);
			tb.functionReturned = true;
			tb.returnSnapshot = snapshot;
			FinishBasicTrace(TraceBasicBlockStopReason::FunctionReturn, addr);
			return BasicTraceStepResult::Stop;
		}
	}

	if (tb.externalCallActive) {
		++tb.stepsExecuted;
		++tb.filteredSteps;
		++tb.externalSteps;
		tb.finalAddress = addr;
		if (inRange && addr == tb.externalReturnAddress) {
			tb.externalCallActive = false;
			tb.externalReturnAddress = 0;
			tb.currentBlock = tb.previousInstruction = addr;
			if (tb.collectWindowActive) {
				uint32_t snapshot = CaptureBasicTraceSnapshot(info->ContextRecord);
				if (!RecordBasicTraceBlock(addr, info->ContextRecord, snapshot)) {
					FinishBasicTrace(TraceBasicBlockStopReason::MaxBlocks, addr, true);
					return BasicTraceStepResult::Stop;
				}
				uint32_t version = CaptureBasicTraceCodeVersion(addr, tb.stepsExecuted);
				RecordBasicTraceEvent(TraceBasicBlockEventType::BlockEntry, tb.stepsExecuted,
					0, 0, addr, TraceBasicBlockEdgeKind::Fallthrough, 0, false, version);
				PrepareBasicTraceMemoryWrites(current, info->ContextRecord);
				PrepareBasicTraceRegisterEvent(addr, info->ContextRecord);
			}
		}
		if (tb.stepsExecuted >= tb.maxSteps) {
			FinishBasicTrace(TraceBasicBlockStopReason::MaxSteps, addr, true);
			return BasicTraceStepResult::Stop;
		}
		info->ContextRecord->EFlags |= 0x100;
		info->ContextRecord->Dr6 = 0;
		return BasicTraceStepResult::Continue;
	}
	const bool wasCollecting = tb.collectWindowActive;
	if (inRange && !AdvanceBasicTraceOccurrence(addr)) {
		auto* previous = wasCollecting ? previousInstruction : nullptr;
		++tb.stepsExecuted;
		if (previous) {
			++previous->hitCount;
			previous->lastHitStep = tb.stepsExecuted;
		} else if (!wasCollecting) {
			++tb.filteredSteps;
		}
		tb.finalAddress = addr;
		FinishBasicTrace(TraceBasicBlockStopReason::OccurrenceWindow, addr);
		return BasicTraceStepResult::Stop;
	}

	if (!tb.startConditionMet) {
		tb.stepsExecuted++;
		tb.filteredSteps++;
		tb.finalAddress = addr;
		if (!inRange) {
			FinishBasicTrace(TraceBasicBlockStopReason::LeftRange, addr);
			return BasicTraceStepResult::Stop;
		}
		if (EvaluateBasicTraceCondition(tb.startCondition, info->ContextRecord)) {
			tb.startConditionMet = true;
			tb.collectWindowActive = BasicTraceCollectionGate(info->ContextRecord);
			tb.currentBlock = tb.previousInstruction = addr;
			if (tb.collectWindowActive) {
				if (!RecordBasicTraceBlock(addr, info->ContextRecord)) {
					FinishBasicTrace(TraceBasicBlockStopReason::MaxBlocks, addr, true);
					return BasicTraceStepResult::Stop;
				}
				uint32_t version = CaptureBasicTraceCodeVersion(addr, tb.stepsExecuted);
				RecordBasicTraceEvent(TraceBasicBlockEventType::BlockEntry,
					tb.stepsExecuted, 0, 0, addr, TraceBasicBlockEdgeKind::Fallthrough, 0, false, version);
				PrepareBasicTraceMemoryWrites(current, info->ContextRecord);
				PrepareBasicTraceRegisterEvent(addr, info->ContextRecord);
			}
		}
		if (tb.stepsExecuted >= tb.maxSteps) {
			FinishBasicTrace(TraceBasicBlockStopReason::MaxSteps, addr, true);
			return BasicTraceStepResult::Stop;
		}
		info->ContextRecord->EFlags |= 0x100;
		info->ContextRecord->Dr6 = 0;
		return BasicTraceStepResult::Continue;
	}

	if (!tb.collectWindowActive) {
		tb.stepsExecuted++;
		tb.filteredSteps++;
		tb.finalAddress = addr;
		if (!inRange) {
			FinishBasicTrace(TraceBasicBlockStopReason::LeftRange, addr);
			return BasicTraceStepResult::Stop;
		}
		if (tb.stopCondition.clauseCount && EvaluateBasicTraceCondition(tb.stopCondition, info->ContextRecord)) {
			FinishBasicTrace(TraceBasicBlockStopReason::Condition, addr);
			return BasicTraceStepResult::Stop;
		}
		if (BasicTraceCollectionGate(info->ContextRecord)) {
			tb.collectWindowActive = true;
			tb.currentBlock = tb.previousInstruction = addr;
			if (!RecordBasicTraceBlock(addr, info->ContextRecord)) {
				FinishBasicTrace(TraceBasicBlockStopReason::MaxBlocks, addr, true);
				return BasicTraceStepResult::Stop;
			}
			uint32_t version = CaptureBasicTraceCodeVersion(addr, tb.stepsExecuted);
			RecordBasicTraceEvent(TraceBasicBlockEventType::BlockEntry,
				tb.stepsExecuted, 0, 0, addr, TraceBasicBlockEdgeKind::Fallthrough, 0, false, version);
			PrepareBasicTraceMemoryWrites(current, info->ContextRecord);
			PrepareBasicTraceRegisterEvent(addr, info->ContextRecord);
		}
		if (tb.stepsExecuted >= tb.maxSteps) {
			FinishBasicTrace(TraceBasicBlockStopReason::MaxSteps, addr, true);
			return BasicTraceStepResult::Stop;
		}
		info->ContextRecord->EFlags |= 0x100;
		info->ContextRecord->Dr6 = 0;
		return BasicTraceStepResult::Continue;
	}

	auto* previous = previousInstruction;
	if (previous) previous->hitCount++;
	tb.stepsExecuted++;
	if (previous) previous->lastHitStep = tb.stepsExecuted;

	bool nonSequential = !previous || addr != previous->next;
	bool staticBoundary = current && current->staticBlockStart == addr && tb.currentBlock != addr;
	bool boundary = !inRange || nonSequential || staticBoundary || (previous && previous->terminal);
	if (boundary) {
		TraceBasicBlockEdgeKind kind = TraceBasicBlockEdgeKind::Branch;
		if (!inRange) {
			kind = tb.stopOnReturn && previous &&
				previous->kind == TraceBasicBlockEdgeKind::Call ?
				TraceBasicBlockEdgeKind::Call : TraceBasicBlockEdgeKind::RangeExit;
		} else if (previous && previous->terminal) kind = previous->kind;
		else if (!nonSequential) kind = TraceBasicBlockEdgeKind::Fallthrough;

		bool dynamicTarget = nonSequential && !(previous && previous->terminal);
		uint64_t targetBlock = inRange ? NormalizeBasicTraceBlockStart(addr, dynamicTarget) : addr;
		uint32_t snapshot = UINT32_MAX;
		if (!RecordBasicTraceEdge(tb.currentBlock, tb.previousInstruction, targetBlock,
				kind, 0, previous && previous->indirect != 0, info->ContextRecord, &snapshot)) {
			FinishBasicTrace(TraceBasicBlockStopReason::MaxEdges, addr, true);
			return BasicTraceStepResult::Stop;
		}
		// The aggregate CFG target may be normalized to a static block start that
		// was never executed (for example after self-modifying a direct branch).
		// Capture from the concrete destination so completeness describes executed
		// instruction bytes and the ordered edge points at their containing version.
		uint32_t version = inRange ? CaptureBasicTraceCodeVersion(addr, tb.stepsExecuted) : UINT32_MAX;
		RecordBasicTraceEvent(TraceBasicBlockEventType::Edge, tb.stepsExecuted,
			tb.currentBlock, tb.previousInstruction, targetBlock, kind, 0,
			previous && previous->indirect != 0, version);
		if (!inRange) {
			if (tb.stopOnReturn && previous && previous->kind == TraceBasicBlockEdgeKind::Call) {
				tb.externalCallActive = true;
				tb.externalReturnAddress = previous->next;
				tb.pendingWriteCount = 0;
				tb.pendingReadCount = 0;
				tb.pendingRegisterEventValid = false;
				tb.finalAddress = addr;
				info->ContextRecord->EFlags |= 0x100;
				info->ContextRecord->Dr6 = 0;
				return BasicTraceStepResult::Continue;
			}
			FinishBasicTrace(TraceBasicBlockStopReason::LeftRange, addr);
			return BasicTraceStepResult::Stop;
		}
		if (!RecordBasicTraceBlock(targetBlock, info->ContextRecord, snapshot)) {
			FinishBasicTrace(TraceBasicBlockStopReason::MaxBlocks, addr, true);
			return BasicTraceStepResult::Stop;
		}
		tb.currentBlock = targetBlock;
	}

	tb.previousInstruction = addr;
	tb.finalAddress = addr;
	if (tb.targetMatched) {
		tb.targetCaptureEndSequence = tb.stepsExecuted;
		if (tb.stepsExecuted >= tb.targetTriggerSequence + tb.targetWindow.afterSteps) {
			FinishBasicTrace(TraceBasicBlockStopReason::TargetWindow, addr);
			return BasicTraceStepResult::Stop;
		}
	}
	if (tb.stopCondition.clauseCount && EvaluateBasicTraceCondition(tb.stopCondition, info->ContextRecord)) {
		FinishBasicTrace(TraceBasicBlockStopReason::Condition, addr);
		return BasicTraceStepResult::Stop;
	}
	if (tb.stepsExecuted >= tb.maxSteps) {
		FinishBasicTrace(TraceBasicBlockStopReason::MaxSteps, addr, true);
		return BasicTraceStepResult::Stop;
	}
	if (!BasicTraceCollectionGate(info->ContextRecord)) {
		tb.collectWindowActive = false;
		tb.pendingWriteCount = 0;
		tb.pendingReadCount = 0;
		if (tb.dependencySourceCount) tb.dependencyIncomplete = true;
		info->ContextRecord->EFlags |= 0x100;
		info->ContextRecord->Dr6 = 0;
		return BasicTraceStepResult::Continue;
	}
	PrepareBasicTraceMemoryWrites(current, info->ContextRecord);
	PrepareBasicTraceRegisterEvent(addr, info->ContextRecord);
	info->ContextRecord->EFlags |= 0x100;
	info->ContextRecord->Dr6 = 0;
	return BasicTraceStepResult::Continue;
}

bool VehHandler::HandleBasicTraceException(PEXCEPTION_POINTERS info, uint32_t tid,
		uint64_t addr, DWORD code) {
	auto& tb = traceBasicBlocks_;
	if (!tb.active.load(std::memory_order_acquire) || tid != tb.threadId)
		return false;
	if (tb.externalCallActive && (addr < tb.rangeStart || addr >= tb.rangeEnd)) {
		++tb.stepsExecuted;
		++tb.filteredSteps;
		++tb.externalSteps;
		tb.finalAddress = addr;
		if (tb.stepsExecuted >= tb.maxSteps) {
			tb.stopPending = true;
			tb.pendingStopReason = TraceBasicBlockStopReason::MaxSteps;
			tb.truncated = true;
		}
		info->ContextRecord->EFlags |= 0x100;
		return true;
	}
	if (addr < tb.rangeStart || addr >= tb.rangeEnd) return false;
	if (!tb.followExceptions) {
		FinishBasicTrace(TraceBasicBlockStopReason::Exception, addr);
		return false;
	}

	tb.stepsExecuted++;
	tb.exceptionsFollowed++;
	tb.pendingWriteCount = 0;
	tb.pendingReadCount = 0;
	tb.pendingRegisterEventValid = false;
	tb.pendingRegisterWriteMask = 0;
	tb.pendingException = true;
	tb.pendingExceptionCollect = tb.startConditionMet && tb.collectWindowActive;
	tb.pendingExceptionSourceBlock = tb.currentBlock;
	tb.pendingExceptionInstruction = addr;
	tb.pendingExceptionCode = code;
	tb.pendingExceptionFaultAddress = 0;
	if (info->ExceptionRecord && info->ExceptionRecord->NumberParameters >= 2)
		tb.pendingExceptionFaultAddress = info->ExceptionRecord->ExceptionInformation[1];
	if (tb.pendingExceptionCollect)
		FillBasicTraceSnapshot(info->ContextRecord, tb.pendingExceptionSnapshot);
	else
		tb.filteredSteps++;
	if (tb.stepsExecuted >= tb.maxSteps) {
		tb.stopPending = true;
		tb.pendingStopReason = TraceBasicBlockStopReason::MaxSteps;
		tb.truncated = true;
	}
	info->ContextRecord->EFlags |= 0x100;
	return true;
}

LONG VehHandler::HandleContinue(PEXCEPTION_POINTERS info) {
	if (!installed_.load(std::memory_order_acquire) || !info || !info->ContextRecord)
		return EXCEPTION_CONTINUE_SEARCH;
	ScopedThreadLogSilence logSilence;
	if (reentryTlsSlot_ != TLS_OUT_OF_INDEXES && SafeTlsGetValue(reentryTlsSlot_))
		return EXCEPTION_CONTINUE_SEARCH;
	TlsReentryGuard reentryGuard(reentryTlsSlot_);
#ifdef _WIN64
	const uint32_t tid = __readgsdword(0x48);
	const uint64_t destination = info->ContextRecord->Rip;
#else
	const uint32_t tid = __readfsdword(0x24);
	const uint64_t destination = info->ContextRecord->Eip;
#endif
	auto& tb = traceBasicBlocks_;
	if (!tb.active.load(std::memory_order_acquire) || tid != tb.threadId || !tb.pendingException)
		return EXCEPTION_CONTINUE_SEARCH;
	const bool destinationInRange = destination >= tb.rangeStart && destination < tb.rangeEnd;
	if (destinationInRange && !AdvanceBasicTraceOccurrence(destination)) {
		tb.stopPending = true;
		tb.pendingStopReason = TraceBasicBlockStopReason::OccurrenceWindow;
	}

	if (!tb.pendingExceptionCollect) {
		tb.pendingException = false;
		tb.finalAddress = destination;
		if (!destinationInRange) {
			tb.stopPending = true;
			tb.pendingStopReason = TraceBasicBlockStopReason::LeftRange;
		} else {
			if (!tb.startConditionMet && EvaluateBasicTraceCondition(tb.startCondition, info->ContextRecord))
				tb.startConditionMet = true;
			bool collect = !tb.stopPending && BasicTraceCollectionGate(info->ContextRecord);
			tb.collectWindowActive = collect;
			tb.currentBlock = tb.previousInstruction = destination;
			if (collect) {
				if (!RecordBasicTraceBlock(destination, info->ContextRecord)) {
					tb.stopPending = true;
					tb.pendingStopReason = TraceBasicBlockStopReason::MaxBlocks;
					tb.truncated = true;
				} else {
					PrepareBasicTraceMemoryWrites(FindBasicTraceInstruction(destination), info->ContextRecord);
					PrepareBasicTraceRegisterEvent(destination, info->ContextRecord);
				}
			}
			if (tb.stopCondition.clauseCount && EvaluateBasicTraceCondition(tb.stopCondition, info->ContextRecord)) {
				tb.stopPending = true;
				tb.pendingStopReason = TraceBasicBlockStopReason::Condition;
			}
		}
		info->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_SEARCH;
	}

	uint32_t snapshot = UINT32_MAX;
	if (!RecordBasicTraceEdge(tb.pendingExceptionSourceBlock, tb.pendingExceptionInstruction,
			destination, TraceBasicBlockEdgeKind::Exception, tb.pendingExceptionCode,
			false, info->ContextRecord, &snapshot, tb.pendingExceptionFaultAddress,
			&tb.pendingExceptionSnapshot)) {
		tb.stopPending = true;
		tb.pendingStopReason = TraceBasicBlockStopReason::MaxEdges;
		tb.truncated = true;
	} else {
		uint32_t version = destination >= tb.rangeStart && destination < tb.rangeEnd ?
			CaptureBasicTraceCodeVersion(destination, tb.stepsExecuted) : UINT32_MAX;
		RecordBasicTraceEvent(TraceBasicBlockEventType::Edge, tb.stepsExecuted,
			tb.pendingExceptionSourceBlock, tb.pendingExceptionInstruction, destination,
			TraceBasicBlockEdgeKind::Exception, tb.pendingExceptionCode, false, version);
	}
	tb.pendingException = false;

	if (!destinationInRange) {
		tb.stopPending = true;
		tb.pendingStopReason = TraceBasicBlockStopReason::LeftRange;
	} else if (!tb.stopPending) {
		uint64_t targetBlock = NormalizeBasicTraceBlockStart(destination, true);
		if (!RecordBasicTraceBlock(targetBlock, info->ContextRecord, snapshot)) {
			tb.stopPending = true;
			tb.pendingStopReason = TraceBasicBlockStopReason::MaxBlocks;
			tb.truncated = true;
		} else {
			tb.currentBlock = targetBlock;
			tb.previousInstruction = destination;
		}
	}
	tb.finalAddress = destination;
	if (!tb.stopPending) {
		PrepareBasicTraceMemoryWrites(FindBasicTraceInstruction(destination), info->ContextRecord);
		PrepareBasicTraceRegisterEvent(destination, info->ContextRecord);
	}
	// Even when a limit was reached, one final TF event is needed to park the
	// target through the normal stopped-context path.
	info->ContextRecord->EFlags |= 0x100;
	return EXCEPTION_CONTINUE_SEARCH;
}

LONG VehHandler::HandleException(PEXCEPTION_POINTERS info) {
	if (!installed_) return EXCEPTION_CONTINUE_SEARCH;
	// Never enter stdio/WriteFile or the logger mutex from a VEH callback. The
	// interrupted code may itself be the logger, and users may breakpoint any API
	// that logging depends on.
	ScopedThreadLogSilence logSilence;

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
			// A target-owned INT3 can be an exception-based control-flow edge.
			if (HandleBasicTraceException(info, tid, addr, code)) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
			// TraceCalls follow-through: INT3 in thunk -- pass to SEH, keep TF
			if (traceCalls_.following.load(std::memory_order_acquire) && tid == traceCalls_.followThreadId) {
				traceCalls_.followSteps++;
				if (traceCalls_.followSteps < traceCalls_.resolveMaxSteps) {
					info->ContextRecord->EFlags |= 0x100;
					LOG_DEBUG("TraceCalls follow: passing INT3 to SEH at 0x%llX", addr);
					return EXCEPTION_CONTINUE_SEARCH;
				}
			}
			// ImportResolve: INT3-based stepping -- our placed INT3
			if (importResolve_.active.load(std::memory_order_acquire) &&
				tid == importResolve_.threadId &&
				importResolve_.pendingInt3Addr.load(std::memory_order_acquire) != 0 &&
				addr == importResolve_.pendingInt3Addr.load(std::memory_order_relaxed)) {
				// Restore original byte
				uint8_t origByte = importResolve_.pendingInt3Byte.load(std::memory_order_relaxed);
				MemoryManager::Instance().Write(addr, &origByte, 1);
				importResolve_.pendingInt3Addr.store(0, std::memory_order_release);
				// Adjust RIP back to original instruction (INT3 advanced past it)
#ifdef _WIN64
				info->ContextRecord->Rip = addr;
#else
				info->ContextRecord->Eip = static_cast<DWORD>(addr);
#endif
				// Record trace
				auto& tl = importResolve_.traceLog[importResolve_.traceLogIdx % ImportResolveState::kTraceLogSize];
				tl.address = addr;
				tl.exceptionCode = 0;
				importResolve_.traceLogIdx++;
				importResolve_.stepsExecuted++;
				// Signal step done -- pipe_server controls the flow
				importResolve_.done.store(true, std::memory_order_release);
				LOG_DEBUG("ImportResolve: INT3 step at 0x%llX, signaling pipe_server", addr);
				{
					auto result = NotifyAndWait(info, tid, DebugEventType::SingleStepComplete, addr, 0, code);
					if (result == WaitResult::Detached) {
						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			// ImportResolve: exception-based thunk -- set TF and let SEH handle
			if (importResolve_.active.load(std::memory_order_acquire) &&
				tid == importResolve_.threadId && importResolve_.followExceptions) {
				if (importResolve_.exceptionsPassed < importResolve_.maxExceptionPasses) {
					importResolve_.exceptionsPassed++;
					importResolve_.stepsExecuted++;
					// Record trace log with exception code
					auto& tl = importResolve_.traceLog[importResolve_.traceLogIdx % ImportResolveState::kTraceLogSize];
					tl.address = addr;
					tl.exceptionCode = code;
					importResolve_.traceLogIdx++;
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

			// A foreign INT3 can be reached after the user redirects RIP (or from a
			// program's own DebugBreak). Surface it as a debugger exception instead
			// of letting an unhandled 0x80000003 terminate the target. Normal continue
			// consumes the already-executed INT3; pass_exception forwards it to SEH.
			if (!callback_) return EXCEPTION_CONTINUE_SEARCH;
			auto result = NotifyAndWait(info, tid, DebugEventType::Exception, addr, 0, code);
			if (result == WaitResult::Detached) return EXCEPTION_CONTINUE_SEARCH;
			{
				std::lock_guard<std::mutex> lock(stepFlagMutex_);
				auto pass = passExceptionFlags_.find(tid);
				if (pass != passExceptionFlags_.end() && pass->second) {
					passExceptionFlags_.erase(pass);
					stepFlags_.erase(tid);
					return EXCEPTION_CONTINUE_SEARCH;
				}
				auto step = stepFlags_.find(tid);
				if (step != stepFlags_.end() && step->second) {
					info->ContextRecord->EFlags |= 0x100;
					stepFlags_.erase(step);
				}
			}
			// VEH receives RIP/EIP at the INT3 byte. If the user did not redirect it
			// while stopped, normal continue skips the one-byte DebugBreak instruction;
			// otherwise honor the explicitly edited instruction pointer.
#ifdef _WIN64
			if (info->ContextRecord->Rip == addr) info->ContextRecord->Rip = addr + 1;
#else
			if (info->ContextRecord->Eip == static_cast<DWORD>(addr)) {
				info->ContextRecord->Eip = static_cast<DWORD>(addr + 1);
			}
#endif
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (traceBasicBlocks_.active.load(std::memory_order_acquire) &&
			tid == traceBasicBlocks_.threadId) {
			// User breakpoints are not part of the target CFG. End the trace and
			// surface the breakpoint through the ordinary debugger path.
			FinishBasicTrace(TraceBasicBlockStopReason::Exception, addr);
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

		// TraceCalls: auto-continue, target will be recorded in SINGLE_STEP rearm
		if (traceCalls_.active.load(std::memory_order_acquire) && traceCalls_.IsTraced(addr)) {
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
		// Basic-block tracing owns TF for one thread and must run before the
		// generic rearm/HW/step paths consume this event.
		if (traceBasicBlocks_.active.load(std::memory_order_acquire) &&
			tid == traceBasicBlocks_.threadId) {
			auto& traceRearm = GetPendingRearm();
			if (traceRearm.active && traceRearm.threadId == tid) {
				BreakpointManager::Instance().RearmBreakpoint(traceRearm.address);
				traceRearm = {0, 0, false, false};
			}
			auto traceResult = HandleBasicTraceSingleStep(info, tid, addr);
			if (traceResult == BasicTraceStepResult::Continue)
				return EXCEPTION_CONTINUE_EXECUTION;
			if (traceResult == BasicTraceStepResult::Stop) {
				NotifyAndWait(info, tid, DebugEventType::SingleStepComplete, addr, 0, code);
				HwBreakpointManager::Instance().ClearFromContext(*info->ContextRecord);
				HwBreakpointManager::Instance().ApplyToContext(*info->ContextRecord);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		// 1) 소프트 브레이크포인트 재활성화 대기 중인 경우
		auto& rearm = GetPendingRearm();
		if (rearm.active) {
			uint64_t rearmAddr = rearm.address;
			BreakpointManager::Instance().RearmBreakpoint(rearmAddr);
			LOG_DEBUG("Rearmed breakpoint at 0x%llX", rearmAddr);
			bool wantStep = rearm.stepRequested;
			rearm.active = false;
			rearm.stepRequested = false;

			// TraceCalls: record (callSite -> target) and auto-continue
			if (traceCalls_.active.load(std::memory_order_acquire) && traceCalls_.IsTraced(rearmAddr)) {
				if (traceCalls_.resolveMode && !traceCalls_.following.load(std::memory_order_relaxed)) {
					// Resolve mode: start follow-through with natural context
					traceCalls_.following.store(true, std::memory_order_release);
					traceCalls_.followThreadId = tid;
					traceCalls_.followCallSite = rearmAddr;
					traceCalls_.followSteps = 0;
					info->ContextRecord->EFlags |= 0x100;  // TF to step through thunk
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				// Simple mode or already following: record immediate target
				uint32_t idx = traceCalls_.writeIdx.fetch_add(1, std::memory_order_relaxed);
				traceCalls_.buffer[idx % TraceCallsState::kBufferSize] = {rearmAddr, addr};
				traceCalls_.totalHits.fetch_add(1, std::memory_order_relaxed);
				return EXCEPTION_CONTINUE_EXECUTION;
			}

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
						if (result == WaitResult::Resumed) {
							// A step requested while stopped at a HW execute/data breakpoint must
							// arm TF here. Unlike the software-BP path there is no rearm
							// SINGLE_STEP that can consume stepFlags_ for us.
							std::lock_guard<std::mutex> lock(stepFlagMutex_);
							auto it = stepFlags_.find(tid);
							if (it != stepFlags_.end() && it->second) {
								info->ContextRecord->EFlags |= 0x100;
								stepFlags_.erase(it);
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

		// 3) TraceCalls follow-through: stepping through thunk to target module
		if (traceCalls_.following.load(std::memory_order_acquire) && tid == traceCalls_.followThreadId) {
			traceCalls_.followSteps++;

			// Check if RIP is in a target module
			bool inTarget = false;
			for (auto& mr : traceCalls_.moduleRanges) {
				if (addr >= mr.base && addr < mr.end && mr.isTarget) {
					inTarget = true;
					break;
				}
			}

			if (inTarget || traceCalls_.followSteps >= traceCalls_.resolveMaxSteps) {
				// Done: record final target
				uint32_t idx = traceCalls_.writeIdx.fetch_add(1, std::memory_order_relaxed);
				traceCalls_.buffer[idx % TraceCallsState::kBufferSize] = {traceCalls_.followCallSite, addr};
				traceCalls_.totalHits.fetch_add(1, std::memory_order_relaxed);
				traceCalls_.following.store(false, std::memory_order_release);
				LOG_DEBUG("TraceCalls resolve: 0x%llX -> 0x%llX (%u steps)",
					traceCalls_.followCallSite, addr, traceCalls_.followSteps);
				return EXCEPTION_CONTINUE_EXECUTION;
			}

			// Continue stepping through thunk
			info->ContextRecord->EFlags |= 0x100;
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		// 4) ResolveImport: TF fallback step -- signal pipe_server, let it decide next action
		if (importResolve_.active.load(std::memory_order_acquire) && tid == importResolve_.threadId) {
			importResolve_.stepsExecuted++;
			// Record trace log entry (ring buffer)
			auto& tl = importResolve_.traceLog[importResolve_.traceLogIdx % ImportResolveState::kTraceLogSize];
			tl.address = addr;
			tl.exceptionCode = 0;  // TF single-step
			importResolve_.traceLogIdx++;
			// Signal step done -- pipe_server controls all flow decisions
			importResolve_.done.store(true, std::memory_order_release);
			// Fall through to NotifyAndWait (thread stops, pipe_server reads context)
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
		if (HandleBasicTraceException(info, tid, addr, code)) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// The IPC server deliberately uses local SEH probes while decoding target
		// memory. Never surface those recoverable exceptions as debugger stops: the
		// server thread is also the only thread that could service a continue, so
		// parking it in NotifyAndWait would deadlock the control pipe.
		if (tid == internalTid_.load(std::memory_order_relaxed)) {
			return EXCEPTION_CONTINUE_SEARCH;
		}

		// TraceCalls follow-through: pass exceptions to SEH, keep TF
		if (traceCalls_.following.load(std::memory_order_acquire) && tid == traceCalls_.followThreadId) {
			traceCalls_.followSteps++;
			if (traceCalls_.followSteps < traceCalls_.resolveMaxSteps) {
				info->ContextRecord->EFlags |= 0x100;  // TF survives through SEH
				LOG_DEBUG("TraceCalls follow: passing exception 0x%08X to SEH at 0x%llX", code, addr);
				return EXCEPTION_CONTINUE_SEARCH;
			}
			// Max steps: abort follow, record current position
			uint32_t idx = traceCalls_.writeIdx.fetch_add(1, std::memory_order_relaxed);
			traceCalls_.buffer[idx % TraceCallsState::kBufferSize] = {traceCalls_.followCallSite, addr};
			traceCalls_.totalHits.fetch_add(1, std::memory_order_relaxed);
			traceCalls_.following.store(false, std::memory_order_release);
		}

		// ImportResolve: exception-based thunk (AV, PRIV_INSTRUCTION, etc.)
		// Set TF and let SEH handle -- after SEH redirects, TF fires SINGLE_STEP to resume trace
		if (importResolve_.active.load(std::memory_order_acquire) &&
			tid == importResolve_.threadId && importResolve_.followExceptions) {
			if (importResolve_.exceptionsPassed < importResolve_.maxExceptionPasses) {
				importResolve_.exceptionsPassed++;
				importResolve_.stepsExecuted++;
				// Record trace log with exception code
				{
					auto& tl = importResolve_.traceLog[importResolve_.traceLogIdx % ImportResolveState::kTraceLogSize];
					tl.address = addr;
					tl.exceptionCode = code;
					importResolve_.traceLogIdx++;
				}
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

bool VehHandler::TraceCallsState::IsTraced(uint64_t addr) const {
	// Binary search on sorted vector
	auto it = std::lower_bound(addresses.begin(), addresses.end(), addr);
	return it != addresses.end() && *it == addr;
}

} // namespace veh
