#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>
#include <array>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "../common/ipc_protocol.h"

namespace veh {

// Debug event types
enum class DebugEventType {
	BreakpointHit,
	SingleStepComplete,
	AccessViolation,
	Exception,
	ModuleLoad,   // stopped in the loader after a matching module was mapped
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

	// installed_(atomic)를 읽는다. Install이 handler_ 설정 후 installed_=true로 두므로
	// installed_==true면 handler_ 설정이 완료된 상태. ServerThread의 무락 읽기 data race 회피.
	bool IsInstalled() const { return installed_.load(); }

	// 스레드 재개 시그널 (continue/step 명령에서 호출)
	void ResumeStoppedThread(uint32_t threadId, bool step = false, bool passException = false);
	void ResumeAllStoppedThreads(bool forDetach = false);

	// 스레드가 VEH 핸들러에서 정지(대기) 중인지 확인
	bool IsThreadStopped(uint32_t threadId);
	std::vector<uint32_t> GetStoppedThreadIds();

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
		// Resolve mode: follow through thunks to final target
		bool resolveMode = false;
		uint32_t resolveMaxSteps = 2000;
		// Module ranges for resolve target detection
		struct ModRange { uint64_t base; uint64_t end; bool isTarget; };
		std::vector<ModRange> moduleRanges;
		// Follow-through state (one thread at a time)
		std::atomic<bool> following{false};
		uint32_t followThreadId = 0;
		uint64_t followCallSite = 0;
		uint32_t followSteps = 0;
	};
	TraceCallsState traceCalls_;

	// TraceBasicBlocks: one stopped thread is single-stepped entirely inside the
	// injected DLL. All storage is allocated before the thread resumes; the VEH
	// callback only performs bounded lookups and writes into fixed-size tables.
	struct TraceBasicBlocksState {
		static constexpr uint8_t kMaxWriteOperands = 2;
		static constexpr uint8_t kMaxReadOperands = 4;
		struct WriteOperand {
			int64_t displacement = 0;
			uint8_t base = 0xFF;
			uint8_t index = 0xFF;
			uint8_t scale = 0;
			uint8_t size = 0;
			uint8_t ripRelative = 0;
			uint8_t preDecrementStack = 0;
		};
		struct Instruction {
			uint64_t address = 0;
			uint64_t next = 0;
			uint64_t staticBlockStart = 0;
			uint64_t hitCount = 0;
			uint64_t lastHitStep = 0;
			uint8_t terminal = 0;
			uint8_t indirect = 0;
			uint8_t writeOperandCount = 0;
			uint8_t unsupportedWrites = 0;
			WriteOperand writeOperands[kMaxWriteOperands]{};
			uint8_t readOperandCount = 0;
			uint8_t unsupportedReads = 0;
			WriteOperand readOperands[kMaxReadOperands]{};
			uint32_t readRegisterMask = 0;
			uint32_t writeRegisterMask = 0;
			uint8_t readsFlags = 0;
			uint8_t writesFlags = 0;
			uint8_t clearsDependencies = 0;
			uint32_t lastDependencyMask = 0;
			TraceBasicBlockEdgeKind kind = TraceBasicBlockEdgeKind::Fallthrough;
		};
		struct BlockSlot {
			uint64_t start = 0;
			uint32_t firstSnapshot = UINT32_MAX;
			uint8_t occupied = 0;
		};
		struct MemoryWriteSlot {
			uint64_t instruction = 0;
			uint64_t address = 0;
			uint64_t hitCount = 0;
			uint64_t firstStep = 0;
			uint8_t size = 0;
			uint8_t before[kTraceMemoryMaxValueBytes]{};
			uint8_t after[kTraceMemoryMaxValueBytes]{};
			uint32_t dependencyMask = 0;
			uint8_t occupied = 0;
		};
		struct PendingWrite {
			uint64_t instruction = 0;
			uint64_t address = 0;
			uint8_t size = 0;
			uint8_t before[kTraceMemoryMaxValueBytes]{};
			uint32_t dependencyMask = 0;
			uint8_t accessIndex = 0;
		};
		struct MemoryReadSlot {
			uint64_t instruction = 0;
			uint64_t address = 0;
			uint64_t hitCount = 0;
			uint32_t dependencyMask = 0;
			uint8_t size = 0;
			uint8_t value[kTraceMemoryMaxValueBytes]{};
			uint8_t occupied = 0;
		};
		struct PendingRead {
			uint64_t instruction = 0;
			uint64_t address = 0;
			uint32_t dependencyMask = 0;
			uint8_t size = 0;
			uint8_t value[kTraceMemoryMaxValueBytes]{};
			uint8_t accessIndex = 0;
		};
		struct MemoryTaintSlot {
			uint64_t address = 0;
			uint32_t dependencyMask = 0;
			uint8_t size = 0;
			uint8_t occupied = 0;
		};
		struct EdgeSlot {
			uint64_t sourceBlock = 0;
			uint64_t sourceInstruction = 0;
			uint64_t target = 0;
			uint64_t hitCount = 0;
			uint64_t firstStep = 0;
			uint32_t snapshot = UINT32_MAX;
			uint32_t exceptionCode = 0;
			uint64_t faultAddress = 0;
			uint32_t faultSnapshot = UINT32_MAX;
			TraceBasicBlockEdgeKind kind = TraceBasicBlockEdgeKind::Fallthrough;
			uint8_t indirect = 0;
			uint32_t dependencyMask = 0;
			uint8_t occupied = 0;
		};
		struct CodeVersionSlot {
			TraceBasicBlockCodeVersionEntry entry{};
			uint64_t secondaryHash = 0;
			uint8_t occupied = 0;
		};
		// A 4 MiB decoded range needs 17 minimum-sized chunks when a record
		// header crosses the boundary, plus two slots so the writer can advance.
		static constexpr uint32_t kMaxCodeStreamBuffers = 19;
		struct CodeStreamBuffer {
			std::vector<uint8_t> bytes;
			std::atomic<uint8_t> state{0}; // 0 free, 1 filling, 2 ready, 3 writing
			uint32_t size = 0;
			uint64_t index = 0;
		};

		std::atomic<bool> active{false};
		std::atomic<bool> done{false};
		std::atomic<bool> cancelRequested{false};
		uint32_t threadId = 0;
		uint64_t rangeStart = 0;
		uint64_t rangeEnd = 0;
		uint32_t maxBlocks = 0;
		uint32_t maxEdges = 0;
		uint32_t maxSteps = 0;
		uint16_t stackBytes = 0;
		bool followExceptions = false;
		bool collectMemoryWrites = false;
		uint32_t maxMemoryWrites = 0;
		bool collectMemoryReads = false;
		uint32_t maxMemoryReads = 0;
		bool collectEvents = false;
		uint32_t maxEvents = 0;
		bool collectCode = false;
		uint32_t maxCodeBytes = 0;
		uint32_t maxCodeVersions = 0;
		bool collectMemoryEvents = false;
		uint32_t maxMemoryEvents = 0;
		bool collectRegisterEvents = false;
		uint32_t maxRegisterEvents = 0;
		uint8_t dependencySourceCount = 0;
		TraceDependencySource dependencySources[kTraceDependencyMaxSources]{};
		TraceCondition startCondition{};
		TraceCondition stopCondition{};
		TraceCondition collectCondition{};
		bool startConditionMet = true;
		bool collectWindowActive = true;
		TraceOccurrenceWindow occurrenceWindow{};
		uint64_t occurrenceHits = 0;
		bool occurrenceWindowActive = true;
		bool occurrenceWindowStarted = false;
		bool occurrenceWindowCompleted = false;
		uint32_t filteredSteps = 0;
		bool stopOnReturn = false;
		bool functionReturned = false;
		bool externalCallActive = false;
		uint64_t entryStackPointer = 0;
		uint64_t returnAddress = 0;
		uint64_t externalReturnAddress = 0;
		uint64_t externalSteps = 0;
		uint32_t returnSnapshot = UINT32_MAX;
		std::vector<Instruction> instructions;
		std::vector<uint64_t> staticBlockStarts;
		std::vector<BlockSlot> blockTable;
		std::vector<EdgeSlot> edgeTable;
		std::vector<MemoryWriteSlot> memoryWriteTable;
		std::vector<MemoryReadSlot> memoryReadTable;
		std::vector<MemoryTaintSlot> memoryTaintTable;
		std::vector<TraceBasicBlockSnapshot> snapshots;
		std::vector<TraceBasicBlockEventEntry> events;
		std::vector<TraceBasicBlockMemoryEventEntry> memoryEvents;
		std::vector<TraceBasicBlockRegisterEventEntry> registerEvents;
		std::vector<CodeVersionSlot> codeVersionTable;
		std::vector<TraceBasicBlockCodeVersionEntry> codeVersions;
		std::vector<uint8_t> codeBytes;
		std::vector<uint8_t> codeScratch;
		bool codeFileOutput = false;
		uint32_t codeChunkBytes = 0;
		uint64_t codeStreamToken = 0;
		HANDLE codeStreamPipe = INVALID_HANDLE_VALUE;
		HANDLE codeStreamReadyEvent = nullptr;
		std::thread codeStreamThread;
		std::array<CodeStreamBuffer, kMaxCodeStreamBuffers> codeStreamBuffers;
		uint32_t codeStreamBufferCount = 0;
		uint32_t codeStreamProducerIndex = 0;
		uint64_t codeStreamNextChunk = 0;
		uint64_t codeStreamProducedBytes = 0;
		uint64_t codeStreamCommittedBytes = 0;
		bool codeStreamAccepting = false;
		std::atomic<bool> codeStreamProducerDone{false};
		std::atomic<bool> codeStreamTransferFailed{false};
		uint32_t blockCount = 0;
		uint32_t edgeCount = 0;
		uint32_t snapshotCount = 0;
		uint32_t exceptionsFollowed = 0;
		uint32_t memoryWriteCount = 0;
		uint32_t unsupportedMemoryWrites = 0;
		bool memoryWritesTruncated = false;
		uint32_t memoryReadCount = 0;
		uint32_t unsupportedMemoryReads = 0;
		bool memoryReadsTruncated = false;
		bool dependencyIncomplete = false;
		bool eventsTruncated = false;
		uint32_t eventCount = 0;
		uint32_t memoryEventCount = 0;
		uint64_t memoryEventsDropped = 0;
		bool memoryEventsTruncated = false;
		uint32_t registerEventCount = 0;
		uint64_t registerEventsDropped = 0;
		bool registerEventsTruncated = false;
		TraceBasicBlockRegisterEventEntry pendingRegisterEvent{};
		bool pendingRegisterEventValid = false;
		uint32_t codeVersionCount = 0;
		uint32_t codeByteCount = 0;
		bool codeTruncated = false;
		uint32_t registerDependencies[16]{};
		uint32_t flagsDependencies = 0;
		uint32_t pendingRegisterWriteMask = 0;
		uint32_t pendingDependencyMask = 0;
		uint8_t pendingWritesFlags = 0;
		uint8_t pendingReadCount = 0;
		PendingRead pendingReads[kMaxReadOperands]{};
		uint8_t pendingWriteCount = 0;
		PendingWrite pendingWrites[kMaxWriteOperands]{};
		uint64_t stepsExecuted = 0;
		uint64_t initialAddress = 0;
		uint64_t currentBlock = 0;
		uint64_t previousInstruction = 0;
		uint64_t finalAddress = 0;
		TraceBasicBlockStopReason stopReason = TraceBasicBlockStopReason::Completed;
		bool truncated = false;
		bool stopPending = false;
		TraceBasicBlockStopReason pendingStopReason = TraceBasicBlockStopReason::Completed;
		bool pendingException = false;
		bool pendingExceptionCollect = true;
		uint64_t pendingExceptionSourceBlock = 0;
		uint64_t pendingExceptionInstruction = 0;
		uint32_t pendingExceptionCode = 0;
		uint64_t pendingExceptionFaultAddress = 0;
		TraceBasicBlockSnapshot pendingExceptionSnapshot{};
	};
	TraceBasicBlocksState traceBasicBlocks_;
	bool StartTraceBasicBlocks(uint32_t threadId, uint64_t rangeStart, uint64_t rangeEnd,
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
		bool stopOnReturn,
		std::vector<TraceBasicBlocksState::Instruction>&& instructions,
		std::vector<uint64_t>&& staticBlockStarts);
	void CancelTraceBasicBlocks(TraceBasicBlockStopReason reason);
	void FinalizeTraceBasicBlocksCodeStream();

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
	uint32_t GetInternalThread() const { return internalTid_.load(std::memory_order_relaxed); }

	// Module-load breakpoints: freeze the loading thread when a matching module loads.
	// Matching runs in the loader-notification callback (dllmain); the stop reuses
	// NotifyAndWait so no INT3/patching is involved (SEH is never consulted).
	void AddModuleLoadPattern(const char* name);
	void RemoveModuleLoadPattern(const char* name);
	void ClearModuleLoadPatterns();
	bool MatchModuleLoad(const char* baseName);
	void NotifyModuleLoadStop(uint64_t base, uint32_t size, const char* name, uint32_t tid);
	// Read back the module info stashed for the last NotifyModuleLoadStop (same thread,
	// consumed synchronously inside the event callback).
	uint32_t GetPendingModuleSize() const { return pendingModuleSize_; }
	const char* GetPendingModuleName() const { return pendingModuleName_; }

	// 셸코드 스레드 등록/해제 -- VEH 핸들러가 예외를 무시 (CONTINUE_SEARCH)
	void RegisterShellcodeThread(uint32_t tid);
	void UnregisterShellcodeThread(uint32_t tid);
	bool IsShellcodeThread(uint32_t tid);

	// NotifyAndWait 결과
	enum class WaitResult { Resumed, Detached, NoCallback };

private:
	static LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS info);
	static LONG CALLBACK ContinueHandler(PEXCEPTION_POINTERS info);
	LONG HandleException(PEXCEPTION_POINTERS info);
	LONG HandleContinue(PEXCEPTION_POINTERS info);
	enum class BasicTraceStepResult { NotActive, Continue, Stop };
	BasicTraceStepResult HandleBasicTraceSingleStep(PEXCEPTION_POINTERS info, uint32_t tid, uint64_t addr);
	bool HandleBasicTraceException(PEXCEPTION_POINTERS info, uint32_t tid, uint64_t addr, DWORD code);
	void FinishBasicTrace(TraceBasicBlockStopReason reason, uint64_t finalAddress, bool truncated = false);
	void FillBasicTraceSnapshot(const CONTEXT* ctx, TraceBasicBlockSnapshot& snapshot);
	uint32_t CaptureBasicTraceSnapshot(const CONTEXT* ctx);
	bool RecordBasicTraceBlock(uint64_t start, const CONTEXT* ctx, uint32_t snapshot = UINT32_MAX);
	bool RecordBasicTraceEdge(uint64_t sourceBlock, uint64_t sourceInstruction, uint64_t target,
		TraceBasicBlockEdgeKind kind, uint32_t exceptionCode, bool indirect, const CONTEXT* ctx,
		uint32_t* snapshotOut = nullptr, uint64_t faultAddress = 0,
		const TraceBasicBlockSnapshot* faultSnapshot = nullptr);
	TraceBasicBlocksState::Instruction* FindBasicTraceInstruction(uint64_t address);
	uint64_t NormalizeBasicTraceBlockStart(uint64_t address, bool dynamicTarget) const;
	void PrepareBasicTraceMemoryWrites(const TraceBasicBlocksState::Instruction* instruction,
		const CONTEXT* ctx);
	void CompleteBasicTraceMemoryWrites();
	void PrepareBasicTraceRegisterEvent(uint64_t instruction, const CONTEXT* ctx);
	void CompleteBasicTraceRegisterEvent(const CONTEXT* ctx);
	bool RecordBasicTraceMemoryWrite(const TraceBasicBlocksState::PendingWrite& pending,
		const uint8_t* after);
	bool RecordBasicTraceMemoryRead(const TraceBasicBlocksState::PendingRead& pending);
	void RecordBasicTraceMemoryEvent(const TraceBasicBlocksState::PendingRead& pending, uint64_t sequence);
	void RecordBasicTraceMemoryEvent(const TraceBasicBlocksState::PendingWrite& pending,
		const uint8_t* after, uint64_t sequence);
	void RecordBasicTraceEvent(TraceBasicBlockEventType type, uint64_t sequence,
		uint64_t source, uint64_t sourceInstruction, uint64_t target,
		TraceBasicBlockEdgeKind edgeKind = TraceBasicBlockEdgeKind::Fallthrough,
		uint32_t exceptionCode = 0, bool indirect = false, uint32_t codeVersion = UINT32_MAX);
	uint32_t CaptureBasicTraceCodeVersion(uint64_t blockStart, uint64_t sequence);
	bool AppendBasicTraceCodeStream(const void* data, size_t size);
	bool PublishBasicTraceCodeStreamBuffer();
	void RunBasicTraceCodeStreamWriter();
	void StopBasicTraceCodeStream(bool abort);
	bool AdvanceBasicTraceOccurrence(uint64_t address);
	bool BasicTraceCollectionGate(const CONTEXT* ctx) const;
	bool EvaluateBasicTraceCondition(const TraceCondition& condition, const CONTEXT* ctx) const;

	// 공통 패턴: 컨텍스트 저장 -> 이벤트 생성 -> 콜백 -> 대기 -> 컨텍스트 복원
	// 4개 예외 경로(BP, HW BP, step complete, exception)에서 공유
	WaitResult NotifyAndWait(PEXCEPTION_POINTERS info, uint32_t tid,
		DebugEventType type, uint64_t addr, uint32_t bpId, DWORD code);

	// 스레드가 stopped 상태에서 대기할 이벤트 가져오기/생성
	HANDLE GetOrCreateThreadEvent(uint32_t threadId);

	PVOID handler_ = nullptr;
	PVOID continueHandler_ = nullptr;
	DebugEventCallback callback_;
	std::atomic<bool> installed_{false};
	// Install() 직렬화 - InitThread와 ServerThread가 동시에 들어와도
	// AddVectoredExceptionHandler가 중복 호출되지 않게 한다(attach race 방지).
	std::mutex installMutex_;

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

	// Module-load breakpoint patterns (matched case-insensitively as substrings)
	std::mutex moduleLoadMutex_;
	std::vector<std::string> moduleLoadPatterns_;
	uint32_t pendingModuleSize_ = 0;
	char     pendingModuleName_[256] = {};

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
