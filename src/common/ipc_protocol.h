#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace veh {

// Named pipe — 디버거 티 안 나는 이름 사용
// dotnet diagnostic 파이프처럼 위장
inline std::wstring GetPipeName(uint32_t pid) {
	return L"\\\\.\\pipe\\dotnet-diagnostic-" + std::to_wstring(pid);
}

// 커스텀 파이프 이름 지원
inline std::wstring GetPipeName(uint32_t pid, const std::wstring& prefix) {
	if (prefix.empty()) return GetPipeName(pid);
	return L"\\\\.\\pipe\\" + prefix + L"-" + std::to_wstring(pid);
}

inline std::wstring GetTraceCodePipeName(uint32_t ownerPid, uint64_t token) {
	wchar_t suffix[40]{};
	swprintf_s(suffix, L"%u-%016llx", ownerPid, token);
	return L"\\\\.\\pipe\\veh-trace-code-" + std::wstring(suffix);
}

inline std::wstring GetTraceEventPipeName(uint32_t ownerPid, uint64_t token) {
	wchar_t suffix[40]{};
	swprintf_s(suffix, L"%u-%016llx", ownerPid, token);
	return L"\\\\.\\pipe\\veh-trace-event-" + std::wstring(suffix);
}

// IPC message header
#pragma pack(push, 1)
struct IpcHeader {
	uint32_t command;
	uint32_t payloadSize;
};
#pragma pack(pop)

// IPC Commands (Adapter -> DLL)
enum class IpcCommand : uint32_t {
	// Breakpoints
	SetBreakpoint          = 0x0001,
	RemoveBreakpoint       = 0x0002,
	RemoveBreakpointByAddr = 0x0005,
	SetHwBreakpoint        = 0x0003,
	RemoveHwBreakpoint     = 0x0004,
	SetModuleLoadStop      = 0x0006,  // stop when a matching module is loaded

	// Execution control
	Continue               = 0x0010,
	StepOver               = 0x0011,
	StepInto               = 0x0012,
	StepOut                = 0x0013,
	Pause                  = 0x0014,
	TerminateThread        = 0x0015,
	SetInstructionPointer  = 0x0016,

	// State queries
	GetThreads             = 0x0020,
	GetStackTrace          = 0x0021,
	GetRegisters           = 0x0022,
	GetModules             = 0x0023,
	SetRegister            = 0x0024,
	SetRegisters           = 0x0025,
	IsThreadStopped        = 0x0026,
	FreezeThread           = 0x0027,  // user freeze/thaw that survives continue

	// Memory
	ReadMemory             = 0x0030,
	WriteMemory            = 0x0031,

	// Symbol resolution (PDB)
	ResolveSourceLine      = 0x0040,
	ResolveFunction        = 0x0041,
	EnumLocals             = 0x0042,
	Symbolize              = 0x0043,  // addresses -> module!function+offset, source line

	// Tracing
	TraceCallers           = 0x0050,

	// Memory management
	AllocateMemory         = 0x0060,
	FreeMemory             = 0x0061,
	ExecuteShellcode       = 0x0062,
	QueryMemoryMap         = 0x0063,
	SearchMemory           = 0x0064,
	ValueScan              = 0x0066,

	// Dynamic tracing
	TraceRegister          = 0x0070,
	TraceMemory            = 0x0071,
	ResolveImport          = 0x0072,
	TraceCalls             = 0x0073,
	TraceBasicBlocks       = 0x0074,

	// Lifecycle
	Heartbeat              = 0x00FE,
	Detach                 = 0x00F0,
	Terminate              = 0x00F1,  // terminate the target from inside (bypasses external OpenProcess locks)
	Shutdown               = 0x00FF,
};

// IPC Events (DLL -> Adapter)
enum class IpcEvent : uint32_t {
	BreakpointHit          = 0x1001,
	StepCompleted          = 0x1002,
	ExceptionOccurred      = 0x1003,
	ThreadCreated          = 0x1004,
	ThreadExited           = 0x1005,
	ModuleLoaded           = 0x1006,
	ModuleUnloaded         = 0x1007,
	ProcessExited          = 0x1008,
	Paused                 = 0x1009,
	ModuleLoadStopped      = 0x100A,  // stopped at a matching module load
	HeartbeatAck           = 0x10FE,
	Error                  = 0x10FF,
	Ready                  = 0x1000,
};

// IPC Response codes
enum class IpcStatus : uint32_t {
	Ok                     = 0,
	Error                  = 1,
	NotFound               = 2,
	InvalidArgs            = 3,
};

// --- Payload structures ---
#pragma pack(push, 1)

struct SetBreakpointRequest {
	uint64_t address;
};

struct SetBreakpointResponse {
	IpcStatus status;
	uint32_t id;
};

struct RemoveBreakpointRequest {
	uint32_t id;
};

struct RemoveBreakpointByAddrRequest {
	uint64_t address;
};

struct SetHwBreakpointRequest {
	uint64_t address;
	uint8_t  type;     // DR7 R/W field: 0=exec, 1=write, 3=readwrite
	uint8_t  size;     // 1, 2, 4, 8
};

struct SetHwBreakpointResponse {
	IpcStatus status;
	uint32_t id;
	uint8_t  slot;     // DR0~DR3
};

// Module-load breakpoint: freeze the loading thread when a matching module loads.
struct SetModuleLoadStopRequest {
	uint8_t action;      // 0 = add pattern, 1 = remove pattern, 2 = clear all
	char    name[256];   // module-name substring, case-insensitive (e.g. "D2Common")
};

struct SetModuleLoadStopResponse {
	IpcStatus status;
};

struct ModuleLoadStopEvent {
	uint64_t baseAddress;
	uint32_t size;
	uint32_t threadId;
	char     name[256];
};

struct RemoveHwBreakpointRequest {
	uint32_t id;
};

struct ContinueRequest {
	uint32_t threadId;
	uint8_t  passException;  // 1 = pass exception to SEH (EXCEPTION_CONTINUE_SEARCH)
	uint8_t  wantDetails;    // 1 = return ContinueResponse; 0 = fire-and-forget
};

// Followed by resumedCount uint32_t values, then stillStoppedCount uint32_t values.
// The lists describe debugger-managed stops (VEH waits and veh_pause suspensions).
struct ContinueResponse {
	IpcStatus status;
	uint32_t  resumedCount;
	uint32_t  stillStoppedCount;
};

struct StepRequest {
	uint32_t threadId;
};

struct PauseRequest {
	uint32_t threadId;   // 0 = all threads
};

// A frozen thread holds its own OS suspend count, separate from Pause, so
// Continue (which resumes paused threads) leaves it frozen until thawed.
enum class FreezeOp : uint8_t { List = 0, Freeze = 1, Thaw = 2 };

struct FreezeThreadRequest {
	uint32_t threadId;   // Thaw: 0 = all frozen threads
	FreezeOp op;
	uint8_t  reserved[3];
};

struct FreezeThreadResponse {
	IpcStatus status;
	uint32_t  count;     // followed by uint32_t frozenThreadIds[count]
};

struct TerminateThreadRequest {
	uint32_t threadId;
};

// Terminate the whole target process from inside the DLL.
// The target's own-process pseudo-handle always holds PROCESS_TERMINATE regardless of any
// DACL the target set to block *external* OpenProcess -- so this works on self-protected targets.
struct TerminateRequest {
	uint32_t exitCode;
};

struct SetInstructionPointerRequest {
	uint32_t threadId;
	uint64_t address;
};

struct ReadMemoryRequest {
	uint64_t address;
	uint32_t size;
};

struct WriteMemoryRequest {
	uint64_t address;
	uint32_t size;
	// followed by `size` bytes of data
};

// Thread info
struct ThreadInfo {
	uint32_t id;
	char     name[64];
};

struct GetThreadsResponse {
	IpcStatus status;
	uint32_t  count;
	// followed by `count` ThreadInfo structs
};

// Stack frame
struct StackFrameInfo {
	uint64_t address;
	uint64_t returnAddress;
	uint64_t frameBase;
	uint64_t moduleBase;     // 모듈 베이스 주소 (ntdll.dll+0xOFFSET 표시용)
	char     moduleName[128];
	char     functionName[128];
	char     sourceFile[256];
	uint32_t line;
};

struct GetStackTraceRequest {
	uint32_t threadId;
	uint32_t startFrame;
	uint32_t maxFrames;
};

struct GetStackTraceResponse {
	IpcStatus status;
	uint32_t  totalFrames;
	uint32_t  count;
	// followed by `count` StackFrameInfo structs
};

// Registers (x64)
struct RegisterSet {
	uint64_t rax, rbx, rcx, rdx;
	uint64_t rsi, rdi, rbp, rsp;
	uint64_t r8, r9, r10, r11;
	uint64_t r12, r13, r14, r15;
	uint64_t rip;
	uint64_t rflags;
	uint64_t cs, ss, ds, es, fs, gs;
	// Debug registers (DR0~DR3: HW BP address, DR6: status, DR7: control)
	uint64_t dr0, dr1, dr2, dr3;
	uint64_t dr6, dr7;
	// XMM registers
	uint8_t  xmm[16][16]; // XMM0~XMM15
	uint8_t  is32bit;      // 1이면 32비트 프로세스 (eax~eip만 유효)
};

struct GetRegistersRequest {
	uint32_t threadId;
};

struct GetRegistersResponse {
	IpcStatus   status;
	RegisterSet regs;
};

struct SetRegisterRequest {
	uint32_t threadId;
	uint32_t regIndex;   // RegisterSet 내 오프셋 (0=rax, 1=rbx, ..., 16=rip, 17=rflags)
	uint64_t value;
};

struct SetRegisterResponse {
	IpcStatus status;
};

struct SetRegistersRequest {
	uint32_t threadId;
	RegisterSet regs;
};

struct SetRegistersResponse {
	IpcStatus status;
};

struct IsThreadStoppedRequest { uint32_t threadId; };
struct IsThreadStoppedResponse { IpcStatus status; uint8_t stopped; };

// Module info
struct ModuleInfo {
	uint64_t baseAddress;
	uint32_t size;
	char     name[256];
	char     path[512];
};

struct GetModulesResponse {
	IpcStatus status;
	uint32_t  count;
	// followed by `count` ModuleInfo structs
};

// Events
struct BreakpointHitEvent {
	uint32_t threadId;
	uint32_t breakpointId;
	uint64_t address;
	RegisterSet regs;  // VEH 정지 시점의 레지스터 (조건부 BP 평가에 사용, SendAndReceive 데드락 방지)
};

struct StepCompletedEvent {
	uint32_t threadId;
	uint64_t address;
};

struct ExceptionEvent {
	uint32_t threadId;
	uint32_t exceptionCode;
	uint64_t address;
	char     description[256];
};

struct ThreadEvent {
	uint32_t threadId;
};

struct ModuleEvent {
	ModuleInfo module;
};

struct ProcessExitEvent {
	uint32_t exitCode;
};

// Symbol resolution
struct ResolveSourceLineRequest {
	char     fileName[512];
	uint32_t line;
};

struct ResolveSourceLineResponse {
	IpcStatus status;
	uint64_t  address;
};

struct ResolveFunctionRequest {
	char functionName[256];
};

struct ResolveFunctionResponse {
	IpcStatus status;
	uint64_t  address;
};

static constexpr uint32_t kSymbolizeMaxAddresses = 256;

struct SymbolizeRequest {
	uint32_t count;              // followed by uint64_t addresses[count]
};

struct SymbolizeEntry {
	uint64_t address;
	uint64_t moduleBase;         // 0 when the address is in no module
	uint64_t displacement;       // from functionName's start
	uint32_t line;               // 0 when no source line
	char     moduleName[64];
	char     functionName[256];  // PDB symbol, else nearest export, else empty
	char     sourceFile[260];
};

struct SymbolizeResponse {
	IpcStatus status;
	uint32_t  count;             // followed by SymbolizeEntry[count]
};

// Local variable enumeration (via PDB symbols)
struct EnumLocalsRequest {
	uint32_t threadId;
	uint64_t instructionAddress;  // RIP of the frame (for SymSetContext)
	uint64_t frameBase;           // RBP/frame base (for computing variable addresses)
};

struct LocalVariableInfo {
	char     name[64];
	char     typeName[64];
	uint64_t address;     // computed absolute address (frameBase + offset)
	uint32_t size;        // size in bytes
	uint32_t flags;       // SYMFLAG_PARAMETER, SYMFLAG_LOCAL, etc.
	uint8_t  value[32];   // first 32 bytes of value (inline preview)
	uint32_t valueSize;   // actual bytes read into value[]
};

static constexpr uint32_t kMaxLocals = 64;

struct EnumLocalsResponse {
	IpcStatus status;
	uint32_t  count;
	// followed by `count` LocalVariableInfo structs
};

// --- Dynamic tracing ---
struct TraceRegisterRequest {
	uint32_t threadId;
	uint32_t regIndex;     // RegisterSet offset (0=rax, 1=rbx, ..., 16=rip)
	uint32_t maxSteps;     // max single-steps before giving up
	uint8_t  mode;         // 0=changed, 1=equals compareValue, 2=not_equals compareValue
	uint64_t compareValue; // for mode 1/2
};

struct TraceRegisterResponse {
	IpcStatus status;
	uint8_t  found;         // 1 if condition met, 0 if max steps reached
	uint32_t stepsExecuted;
	uint64_t address;       // instruction address that triggered the condition
	uint64_t oldValue;
	uint64_t newValue;
};

struct TraceMemoryRequest {
	uint64_t address;       // memory address to watch
	uint32_t size;          // 1, 2, 4, or 8 bytes
	uint32_t timeoutMs;     // max wait time
};

struct TraceMemoryResponse {
	IpcStatus status;
	uint8_t  found;
	uint32_t threadId;      // thread that wrote to the address
	uint64_t instructionAddress;  // instruction that triggered the write
	uint64_t oldValue;
	uint64_t newValue;
};

// --- Import resolution ---
struct ResolveImportRequest {
	uint32_t threadId;     // stopped thread to hijack for stepping
	uint32_t count;        // number of thunk addresses (follows this struct)
	uint32_t maxStepsPerThunk;  // max steps per import (default 1000)
	uint8_t  followExceptions;  // 1 = pass non-SINGLE_STEP exceptions to SEH, keep TF for trace
	uint8_t  systemOnly;        // 1 = only resolve to system DLLs (Windows dir)
	uint8_t  targetModuleCount; // number of target module names (0 = all non-exe)
	uint8_t  reserved;
	// followed by: uint64_t thunkAddresses[count]
	// followed by: char targetModules[targetModuleCount][64]  (null-terminated names)
};

struct ResolveImportEntry {
	uint64_t thunkAddress;
	uint64_t targetAddress;
	char     moduleName[128];
	char     functionName[128];
	uint8_t  resolved;          // 1=success, 0=failed (max steps or error)
	uint8_t  traceCount;        // number of valid trace entries (max 16)
	uint8_t  exceptionsPassed;  // total exceptions forwarded to SEH
	uint8_t  reserved;
	uint32_t stepsExecuted;
	// Diagnostic: last 16 addresses visited + exception codes (ring buffer tail)
	uint64_t traceAddresses[16];
	uint32_t traceExcCodes[16]; // 0=single-step, nonzero=exception code at that addr
};

struct ResolveImportResponse {
	IpcStatus status;
	uint32_t  count;
	// followed by: ResolveImportEntry[count]
};

// --- TraceCalls: monitor call/jmp targets at runtime ---
struct TraceCallsRequest {
	uint32_t durationMs;    // monitoring duration (0 = use default 5000)
	uint32_t count;         // number of call/jmp site addresses
	uint8_t  resolve;       // 1 = follow through thunks to final target (system DLL)
	uint8_t  systemOnly;    // 1 = only system DLLs as resolve target
	uint16_t resolveMaxSteps; // max steps per thunk follow (0 = default 2000)
	// followed by: uint64_t addresses[count]
};

struct TraceCallsEntry {
	uint64_t callSite;
	uint64_t target;
	uint32_t hitCount;
	char     moduleName[64];
	char     functionName[64];
};

struct TraceCallsResponse {
	IpcStatus status;
	uint32_t  uniqueCount;   // number of unique (callSite, target) pairs
	uint32_t  totalHits;
	// followed by: TraceCallsEntry[uniqueCount]
};

// --- TraceBasicBlocks: discover executed basic blocks and control-flow edges ---
enum class TraceBasicBlockStopReason : uint8_t {
	Completed       = 0,
	LeftRange       = 1,
	MaxSteps        = 2,
	MaxBlocks       = 3,
	MaxEdges        = 4,
	Timeout         = 5,
	Exception       = 6,
	Cancelled       = 7,
	Condition       = 8,
	OccurrenceWindow = 9,
	FunctionReturn   = 10,
	TargetWindow     = 11,
};

enum class TraceBasicBlockEdgeKind : uint8_t {
	Fallthrough = 0,
	Branch      = 1,
	Call        = 2,
	Return      = 3,
	Exception   = 4,
	RangeExit   = 5,
};

enum class TraceConditionOperandKind : uint8_t {
	None = 0,
	Register = 1,
	MemoryAtRegister = 2,
	Immediate = 3,
};

enum class TraceConditionComparison : uint8_t {
	Equal = 0,
	NotEqual = 1,
	Less = 2,
	LessEqual = 3,
	Greater = 4,
	GreaterEqual = 5,
};

struct TraceConditionOperand {
	uint64_t immediate;
	int64_t offset;
	TraceConditionOperandKind kind;
	uint8_t registerIndex;
	uint8_t size;
	uint8_t reserved;
};

struct TraceConditionClause {
	TraceConditionOperand lhs;
	TraceConditionOperand rhs;
	TraceConditionComparison comparison;
	uint8_t reserved[7];
};

static constexpr uint8_t kTraceConditionMaxClauses = 4;
struct TraceCondition {
	TraceConditionClause clauses[kTraceConditionMaxClauses];
	uint8_t clauseCount;
	uint8_t matchAny;
	uint8_t reserved[6];
};

enum class TraceDependencySourceKind : uint8_t { Register = 0, Memory = 1 };
struct TraceDependencySource {
	uint64_t address;
	uint64_t size;
	TraceDependencySourceKind kind;
	uint8_t registerIndex;
	uint8_t reserved[6];
};
static constexpr uint8_t kTraceDependencyMaxSources = 32;
static constexpr uint32_t kTraceBasicBlockMaxCodeBytes = 16U * 1024 * 1024;
static constexpr uint32_t kTraceBasicBlockMaxFileCodeBytes = 400U * 1024 * 1024;
static constexpr uint32_t kTraceCodeDefaultChunkBytes = 4U * 1024 * 1024;
static constexpr uint32_t kTraceCodeMinChunkBytes = 256U * 1024;
static constexpr uint32_t kTraceCodeMaxChunkBytes = 8U * 1024 * 1024;
static constexpr uint32_t kTraceCodeChunkAlignment = 64U * 1024;
static constexpr uint32_t kTraceEventDefaultChunkBytes = 256U * 1024;
static constexpr uint64_t kTraceEventMaxFileBytes = 4ULL * 1024 * 1024 * 1024;

enum class TraceCodeOutputMode : uint8_t {
	Inline = 0,
	File = 1,
};

enum class TraceEventOutputMode : uint8_t {
	Inline = 0,
	File = 1,
};

// Entry-to-entry dispatcher window. Collection begins before executing the
// `from`th visit and ends immediately before the (to + 1)th visit. A zero `to`
// leaves the upper bound open.
struct TraceOccurrenceWindow {
	uint64_t address;
	uint32_t from;
	uint32_t to;
	uint8_t enabled;
	uint8_t reserved[7];
};

// Instruction window centered on one concrete occurrence. Before the trigger,
// ordered event arrays operate as bounded rings; after the trigger they retain
// events linearly until `afterSteps` completed instructions have been observed.
struct TraceTargetWindow {
	uint64_t address;
	uint32_t occurrence;
	uint32_t beforeSteps;
	uint32_t afterSteps;
	uint8_t enabled;
	uint8_t reserved[7];
};

struct TraceBasicBlocksRequest {
	uint32_t threadId;       // thread currently stopped in VEH
	uint64_t rangeStart;     // inclusive
	uint64_t rangeEnd;       // exclusive
	uint32_t maxBlocks;      // unique executed block entries
	uint32_t maxEdges;       // unique observed edges
	uint32_t maxSteps;       // instruction/exception events
	uint32_t timeoutMs;
	uint16_t stackBytes;     // bytes copied from SP per snapshot (max 256)
	uint8_t  followExceptions;
	uint8_t  collectMemoryWrites;
	uint32_t maxMemoryWrites; // unique before/after transitions
	TraceCondition startCondition;
	TraceCondition stopCondition;
	TraceCondition collectCondition;
	uint8_t collectMemoryReads;
	uint8_t dependencySourceCount;
	uint16_t wireVersion;      // 0 for legacy clients; current protocol version otherwise
	uint32_t maxMemoryReads;
	TraceDependencySource dependencySources[kTraceDependencyMaxSources];
	uint8_t collectEvents;     // ordered basic-block entry/transition stream
	uint8_t collectCode;       // runtime block bytes and version mapping
	uint16_t requestSize;      // 0 for legacy clients; bytes understood by the sender
	uint32_t maxEvents;
	uint32_t maxCodeBytes;
	uint32_t maxCodeVersions;
	uint8_t collectMemoryEvents; // ordered per-occurrence memory access stream
	uint8_t reserved4[3];
	uint32_t maxMemoryEvents;
	uint8_t collectRegisterEvents; // ordered per-occurrence register delta stream
	uint8_t reserved5[3];
	uint32_t maxRegisterEvents;
	uint8_t codeOutputMode;       // TraceCodeOutputMode; inline for legacy requests
	uint8_t reserved6[3];
	uint32_t codeChunkBytes;      // file mode transport chunk size
	uint32_t codeStreamOwnerPid;  // process hosting the one-shot inbound data pipe
	uint32_t reserved7;
	uint64_t codeStreamToken;     // unguessable per-capture pipe suffix
	TraceOccurrenceWindow occurrenceWindow;
	uint8_t stopOnReturn;
	uint8_t reserved8[7];
	TraceTargetWindow targetWindow;
	uint8_t eventOutputMode;      // TraceEventOutputMode; inline for legacy requests
	uint8_t reserved9[3];
	uint32_t eventChunkBytes;     // private stream transport chunk size
	uint32_t eventStreamOwnerPid;
	uint32_t reserved10;
	uint64_t eventStreamToken;
	uint64_t maxEventFileBytes;   // includes the artifact header
};

static constexpr uint16_t kTraceBasicBlocksWireVersion = 10;
static constexpr uint16_t kTraceBasicBlocksMinimumExplicitWireVersion = 5;
static constexpr uint16_t kTraceBasicBlocksRequestV3Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, collectRegisterEvents));
static constexpr uint16_t kTraceBasicBlocksRequestV4Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, codeOutputMode));
static constexpr uint16_t kTraceBasicBlocksRequestV6Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, occurrenceWindow));
static constexpr uint16_t kTraceBasicBlocksRequestV7Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, stopOnReturn));
static constexpr uint16_t kTraceBasicBlocksRequestV8Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, targetWindow));
static constexpr uint16_t kTraceBasicBlocksRequestV9Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksRequest, eventOutputMode));
static constexpr uint16_t kTraceBasicBlocksRequestV10Size =
	static_cast<uint16_t>(sizeof(TraceBasicBlocksRequest));
static_assert(kTraceBasicBlocksRequestV3Size < kTraceBasicBlocksRequestV4Size);
static_assert(kTraceBasicBlocksRequestV4Size < kTraceBasicBlocksRequestV6Size);
static_assert(kTraceBasicBlocksRequestV6Size < kTraceBasicBlocksRequestV7Size);
static_assert(kTraceBasicBlocksRequestV7Size < kTraceBasicBlocksRequestV8Size);
static_assert(kTraceBasicBlocksRequestV8Size < kTraceBasicBlocksRequestV9Size);
static_assert(kTraceBasicBlocksRequestV9Size < kTraceBasicBlocksRequestV10Size);

// Runtime-code file artifact and the private one-shot stream carrying its
// record bytes.  These packed little-endian structures are intentionally
// independent of pointer width so analyzers can read x86/x64 captures on any OS.
static constexpr uint64_t kTraceCodeArtifactMagic = 0x0045444F43484556ULL; // "VEHCODE\0"
static constexpr uint32_t kTraceCodeArtifactSchemaVersion = 1;
static constexpr uint32_t kTraceCodeArtifactFlagComplete = 1u << 0;
static constexpr uint32_t kTraceCodeArtifactFlagTruncated = 1u << 1;
static constexpr uint32_t kTraceCodeStreamMagic = 0x43535456; // "VTSC"

enum class TraceCodeStreamFrameType : uint16_t {
	Data = 1,
	Complete = 2,
	Error = 3,
};

#pragma pack(push, 1)
struct TraceCodeArtifactHeader {
	uint64_t magic;
	uint32_t schemaVersion;
	uint32_t headerSize;
	uint32_t flags;
	uint32_t chunkBytes;
	uint64_t rangeStart;
	uint64_t rangeEnd;
	uint64_t codeByteCount;
	uint64_t recordByteCount;
	uint32_t versionCount;
	uint32_t chunkCount;
};

struct TraceCodeArtifactRecord {
	uint64_t blockStart;
	uint64_t blockEnd;
	uint64_t hash;
	uint64_t firstSequence;
	uint64_t dataOffset;
	uint32_t id;
	uint32_t size;
};

struct TraceCodeStreamFrameHeader {
	uint32_t magic;
	uint16_t schemaVersion;
	uint16_t type;
	uint64_t token;
	uint64_t chunkIndex;
	uint64_t streamOffset;
	uint32_t payloadSize;
	uint32_t reserved;
	uint64_t payloadHash;
};

struct TraceCodeStreamComplete {
	uint64_t committedRecordBytes;
	uint64_t codeByteCount;
	uint32_t versionCount;
	uint32_t chunkCount;
	uint8_t truncated;
	uint8_t reserved[7];
};
#pragma pack(pop)
static_assert(sizeof(TraceCodeArtifactHeader) == 64);
static_assert(sizeof(TraceCodeArtifactRecord) == 48);
static_assert(sizeof(TraceCodeStreamFrameHeader) == 48);
static_assert(sizeof(TraceCodeStreamComplete) == 32);

inline uint64_t TraceCodePayloadHash(const void* data, size_t size) {
	const auto* bytes = static_cast<const uint8_t*>(data);
	uint64_t hash = 1469598103934665603ULL;
	for (size_t i = 0; i < size; ++i) { hash ^= bytes[i]; hash *= 1099511628211ULL; }
	return hash;
}

struct TraceBasicBlockEntry {
	uint64_t start;
	uint64_t end;            // exclusive, based on the bytes decoded at trace start
	uint64_t hitCount;
	uint32_t firstSnapshot;  // UINT32_MAX when unavailable
};

struct TraceBasicBlockEdgeEntry {
	uint64_t source;         // source block start
	uint64_t sourceInstruction; // instruction that transferred control
	uint64_t target;         // target block start or out-of-range address
	uint64_t hitCount;
	uint32_t snapshot;       // destination context on first observation
	uint32_t exceptionCode;  // non-zero for exception edges
	uint32_t dependencyMask; // sources influencing the control-transfer instruction
	TraceBasicBlockEdgeKind kind;
	uint8_t  indirect;       // call/jump target came from a register or memory operand
};

static constexpr uint32_t kTraceBasicBlockRegisterCount = 18;
static constexpr uint32_t kTraceBasicBlockMaxStackBytes = 256;

struct TraceBasicBlockSnapshot {
	uint64_t instructionPointer;
	uint64_t stackPointer;
	// x64: rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8-r15,rip,eflags
	// x86: eax,ebx,ecx,edx,esi,edi,ebp,esp,0..0,eip,eflags
	uint64_t registers[kTraceBasicBlockRegisterCount];
	uint8_t  is32bit;
	uint16_t stackSize;
	uint8_t  stack[kTraceBasicBlockMaxStackBytes];
};

static constexpr uint8_t kTraceMemoryValueValid = 0x01;
static constexpr uint8_t kTraceMemoryExecutable = 0x02;
static constexpr uint8_t kTraceMemoryExecutedAfterWrite = 0x04;
static constexpr uint32_t kTraceMemoryMaxValueBytes = 16;

struct TraceBasicBlockMemoryWriteEntry {
	uint64_t instruction;
	uint64_t address;
	uint64_t hitCount;
	uint64_t firstStep;
	uint64_t executedAddress;
	uint32_t dependencyMask;
	uint8_t  size;
	uint8_t  flags;
	uint8_t  before[kTraceMemoryMaxValueBytes];
	uint8_t  after[kTraceMemoryMaxValueBytes];
};

struct TraceBasicBlockMemoryReadEntry {
	uint64_t instruction;
	uint64_t address;
	uint64_t hitCount;
	uint32_t dependencyMask;
	uint8_t size;
	uint8_t flags;
	uint8_t value[kTraceMemoryMaxValueBytes];
};

struct TraceBasicBlockExceptionEntry {
	uint32_t code;
	uint32_t faultSnapshot;
	uint32_t continuationSnapshot;
	uint32_t reserved;
	uint64_t faultRip;
	uint64_t faultAddress;
	uint64_t continuation;
	uint64_t hitCount;
};

enum class TraceBasicBlockEventType : uint8_t {
	BlockEntry = 0,
	Edge = 1,
};

// Version 1 ordered-event record. Sequence is the trace step number and every
// record is scoped to threadId. BlockEntry uses target for the entered block;
// Edge supplies source/sourceInstruction/target and edgeKind.
struct TraceBasicBlockEventEntry {
	uint64_t sequence;
	uint64_t source;
	uint64_t sourceInstruction;
	uint64_t target;
	uint32_t threadId;
	uint32_t exceptionCode;
	uint32_t codeVersion;      // version id for the entered target, UINT32_MAX when unavailable
	TraceBasicBlockEventType type;
	TraceBasicBlockEdgeKind edgeKind;
	uint8_t indirect;
	uint8_t reserved[1];
};

enum class TraceMemoryAccessKind : uint8_t {
	Read = 0,
	Write = 1,
};

// Ordered memory access record. Sequence shares the trace-step space used by
// TraceBasicBlockEventEntry. accessIndex distinguishes multiple logical memory
// accesses performed by one instruction occurrence.
struct TraceBasicBlockMemoryEventEntry {
	uint64_t sequence;
	uint64_t instruction;
	uint64_t address;
	uint32_t threadId;
	uint32_t dependencyMask;
	uint8_t size;
	TraceMemoryAccessKind kind;
	uint8_t accessIndex;
	uint8_t flags;
	uint8_t value[kTraceMemoryMaxValueBytes];  // read value
	uint8_t before[kTraceMemoryMaxValueBytes]; // write value before execution
	uint8_t after[kTraceMemoryMaxValueBytes];  // write value after execution
};

// Ordered register delta record. One record is retained for every completed
// instruction occurrence in the collection window, including an empty delta.
// IP is identified by instruction/sequence and is excluded from changedMask.
struct TraceBasicBlockRegisterEventEntry {
	uint64_t sequence;
	uint64_t instruction;
	uint32_t threadId;
	uint32_t changedMask; // bits 0-15: GPRs, bit 17: EFLAGS
	uint64_t before[kTraceBasicBlockRegisterCount];
	uint64_t after[kTraceBasicBlockRegisterCount];
	uint8_t is32bit;
	uint8_t reserved[7];
};

// Portable ordered-event artifact. The header and records are packed,
// little-endian, and pointer-width independent. Each record begins with a type
// and payload size so readers can reject incomplete or unknown records without
// scanning into a partial tail.
static constexpr uint64_t kTraceEventArtifactMagic = 0x00544E5645484556ULL; // "VEHEVNT\0"
static constexpr uint32_t kTraceEventArtifactSchemaVersion = 1;
static constexpr uint32_t kTraceEventArtifactFlagComplete = 1u << 0;
static constexpr uint32_t kTraceEventArtifactFlagTruncated = 1u << 1;
static constexpr uint32_t kTraceEventStreamMagic = 0x45535456; // "VTSE"

enum class TraceEventRecordType : uint16_t {
	BasicBlock = 1,
	Memory = 2,
	Register = 3,
};

enum class TraceEventTruncationReason : uint32_t {
	None = 0,
	SizeLimit = 1,
	TransferFailure = 2,
};

enum class TraceEventStreamFrameType : uint16_t {
	Data = 1,
	Complete = 2,
	Error = 3,
};

#pragma pack(push, 1)
struct TraceEventArtifactHeader {
	uint64_t magic;
	uint32_t schemaVersion;
	uint32_t headerSize;
	uint32_t flags;
	uint32_t recordHeaderSize;
	uint32_t basicBlockEntrySize;
	uint32_t memoryEntrySize;
	uint32_t registerEntrySize;
	uint64_t recordByteCount;
	uint64_t basicBlockEventCount;
	uint64_t memoryEventCount;
	uint64_t registerEventCount;
	uint64_t waitTimeNs;
	uint32_t truncationReason;
	uint32_t chunkCount;
	uint32_t reserved;
};

struct TraceEventArtifactRecordHeader {
	uint16_t type;
	uint16_t reserved;
	uint32_t payloadSize;
};

struct TraceEventStreamFrameHeader {
	uint32_t magic;
	uint16_t schemaVersion;
	uint16_t type;
	uint64_t token;
	uint64_t chunkIndex;
	uint64_t streamOffset;
	uint32_t payloadSize;
	uint32_t reserved;
	uint64_t payloadHash;
};

struct TraceEventStreamComplete {
	uint64_t committedRecordBytes;
	uint64_t basicBlockEventCount;
	uint64_t memoryEventCount;
	uint64_t registerEventCount;
	uint64_t waitTimeNs;
	uint32_t chunkCount;
	uint32_t truncationReason;
	uint8_t truncated;
	uint8_t reserved[7];
};
#pragma pack(pop)
static_assert(sizeof(TraceBasicBlockEventEntry) == 48);
static_assert(sizeof(TraceBasicBlockMemoryEventEntry) == 84);
static_assert(sizeof(TraceBasicBlockRegisterEventEntry) == 320);
static_assert(sizeof(TraceEventArtifactHeader) == 88);
static_assert(sizeof(TraceEventArtifactRecordHeader) == 8);
static_assert(sizeof(TraceEventStreamFrameHeader) == 48);
static_assert(sizeof(TraceEventStreamComplete) == 56);

inline uint64_t TraceEventPayloadHash(const void* data, size_t size) {
	return TraceCodePayloadHash(data, size);
}

struct TraceBasicBlockCodeVersionEntry {
	uint64_t blockStart;
	uint64_t blockEnd;
	uint64_t hash;
	uint64_t firstSequence;
	uint32_t id;
	uint32_t dataOffset;
	uint32_t size;
};

struct TraceBasicBlocksResponse {
	IpcStatus status;
	TraceBasicBlockStopReason stopReason;
	uint8_t   truncated;
	uint16_t  headerSize;      // 0 for legacy responses; array payload begins here otherwise
	uint32_t  blockCount;
	uint32_t  edgeCount;
	uint32_t  snapshotCount;
	uint32_t  memoryWriteCount;
	uint32_t  unsupportedMemoryWrites;
	uint32_t  memoryWritesTruncated;
	uint32_t  exceptionEventCount;
	uint32_t  filteredSteps;
	uint8_t   startConditionMet;
	uint32_t  memoryReadCount;
	uint32_t  unsupportedMemoryReads;
	uint32_t  memoryReadsTruncated;
	uint32_t  dependencyIncomplete;
	uint32_t  finalRegisterDependencies[16];
	uint32_t  finalFlagsDependencies;
	uint32_t  exceptionsFollowed;
	uint32_t  elapsedMs;
	uint64_t  stepsExecuted;
	uint64_t  finalAddress;
	uint32_t  threadId;
	uint32_t  eventCount;
	uint8_t   eventCollectionEnabled;
	uint8_t   eventsTruncated;
	uint16_t  eventSchemaVersion;
	uint32_t  codeVersionCount;
	uint32_t  codeByteCount;
	uint8_t   codeCollectionEnabled;
	uint8_t   codeTruncated;
	uint16_t  codeSchemaVersion;
	uint32_t  memoryEventCount;
	uint8_t   memoryEventCollectionEnabled;
	uint8_t   memoryEventsTruncated;
	uint16_t  memoryEventSchemaVersion;
	uint64_t  memoryEventsDropped;
	uint32_t  registerEventCount;
	uint8_t   registerEventCollectionEnabled;
	uint8_t   registerEventsTruncated;
	uint16_t  registerEventSchemaVersion;
	uint64_t  registerEventsDropped;
	uint8_t   startFailureReason;
	uint8_t   stopped;
	uint8_t   ipInRange;
	uint8_t   decodeSucceeded;
	uint32_t  decodedInstructionCount;
	uint64_t  normalizedIp;
	uint64_t  normalizedRangeStart;
	uint64_t  normalizedRangeEnd;
	TraceOccurrenceWindow occurrenceWindow;
	uint64_t  occurrenceHits;
	uint8_t   occurrenceWindowStarted;
	uint8_t   occurrenceWindowCompleted;
	uint8_t   reservedOccurrence[6];
	uint8_t   functionScopeEnabled;
	uint8_t   functionReturned;
	uint16_t  reservedFunctionScope;
	uint32_t  returnSnapshot;
	uint64_t  entryStackPointer;
	uint64_t  returnAddress;
	uint64_t  externalSteps;
	TraceTargetWindow targetWindow;
	uint64_t  targetOccurrenceHits;
	uint64_t  targetTriggerSequence;
	uint64_t  targetCaptureStartSequence;
	uint64_t  targetCaptureEndSequence;
	uint64_t  eventsDropped;
	uint8_t   targetMatched;
	uint8_t   reservedTarget[7];
	// followed by TraceBasicBlockEntry[blockCount],
	// TraceBasicBlockEdgeEntry[edgeCount], TraceBasicBlockSnapshot[snapshotCount],
	// TraceBasicBlockMemoryWriteEntry[memoryWriteCount],
	// TraceBasicBlockMemoryReadEntry[memoryReadCount],
	// TraceBasicBlockExceptionEntry[exceptionEventCount],
	// TraceBasicBlockEventEntry[eventCount],
	// TraceBasicBlockMemoryEventEntry[memoryEventCount],
	// TraceBasicBlockRegisterEventEntry[registerEventCount],
	// TraceBasicBlockCodeVersionEntry[codeVersionCount], uint8_t codeBytes[codeByteCount]
};

enum class TraceBasicBlocksStartFailure : uint8_t {
	None = 0,
	InvalidArguments = 1,
	DecodeFailed = 2,
	ThreadNotStopped = 3,
	InstructionPointerOutsideRange = 4,
	CollectorBusy = 5,
	StartRejected = 6,
	CodeStreamUnavailable = 7,
	ReturnAddressUnavailable = 8,
	EventStreamUnavailable = 9,
};

static constexpr uint16_t kTraceBasicBlocksResponseV3Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksResponse, registerEventCount));
static constexpr uint16_t kTraceBasicBlocksResponseV4Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksResponse, startFailureReason));
static constexpr uint16_t kTraceBasicBlocksResponseV5Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksResponse, occurrenceWindow));
static constexpr uint16_t kTraceBasicBlocksResponseV6Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksResponse, functionScopeEnabled));
static constexpr uint16_t kTraceBasicBlocksResponseV7Size =
	static_cast<uint16_t>(offsetof(TraceBasicBlocksResponse, targetWindow));
static constexpr uint16_t kTraceBasicBlocksResponseV8Size =
	static_cast<uint16_t>(sizeof(TraceBasicBlocksResponse));
static_assert(kTraceBasicBlocksResponseV3Size < kTraceBasicBlocksResponseV4Size);
static_assert(kTraceBasicBlocksResponseV4Size < kTraceBasicBlocksResponseV5Size);
static_assert(kTraceBasicBlocksResponseV5Size < kTraceBasicBlocksResponseV6Size);
static_assert(kTraceBasicBlocksResponseV6Size < kTraceBasicBlocksResponseV7Size);
static_assert(kTraceBasicBlocksResponseV7Size < kTraceBasicBlocksResponseV8Size);

// --- Memory management ---
struct AllocateMemoryRequest {
	uint32_t size;
	uint32_t protection;  // PAGE_EXECUTE_READWRITE etc.
};

struct AllocateMemoryResponse {
	IpcStatus status;
	uint64_t  address;
};

struct FreeMemoryRequest {
	uint64_t address;
	uint32_t size;
};

// --- Memory map / search ---
struct QueryMemoryMapRequest {
	uint64_t startAddress;
	uint64_t endAddress;     // exclusive, 0 = end of user space
	uint32_t maxRegions;
	uint8_t  includeFree;
	uint8_t  reserved[3];
};

struct MemoryRegionEntry {
	uint64_t baseAddress;
	uint64_t allocationBase;
	uint64_t regionSize;
	uint32_t state;              // MEM_COMMIT / MEM_RESERVE / MEM_FREE
	uint32_t protect;
	uint32_t allocationProtect;
	uint32_t type;               // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
};

struct QueryMemoryMapResponse {
	IpcStatus status;
	uint32_t  count;
	uint8_t   truncated;
	uint64_t  nextAddress;       // resume point when truncated
	// followed by MemoryRegionEntry[count]
};

enum class RegionFilter : uint8_t { Any = 0, Require = 1, Exclude = 2 };

constexpr uint8_t kRegionTypeImage = 1, kRegionTypePrivate = 2, kRegionTypeMapped = 4;

struct SearchMemoryRequest {
	uint64_t     startAddress;
	uint64_t     endAddress;     // exclusive, 0 = end of user space
	uint32_t     patternSize;
	uint32_t     maxResults;
	uint32_t     alignment;      // match addresses must be multiples of this (1 = any)
	RegionFilter writable;
	RegionFilter executable;
	uint8_t      typeMask;       // kRegionType* bits, 0 = all
	uint8_t      reserved;
	// followed by pattern[patternSize], mask[patternSize] (mask bit 1 = compare)
};

struct SearchMemoryResponse {
	IpcStatus status;
	uint32_t  count;
	uint8_t   truncated;
	uint32_t  regionsScanned;
	uint64_t  scannedBytes;
	uint64_t  nextAddress;       // resume point when truncated
	// followed by uint64_t addresses[count]
};

enum class ValueScanOperation : uint8_t { First = 0, Next = 1, Results = 2, Reset = 3 };
enum class ValueScanType : uint8_t {
	None = 0, I8 = 1, U8 = 2, I16 = 3, U16 = 4, I32 = 5, U32 = 6,
	I64 = 7, U64 = 8, F32 = 9, F64 = 10
};
enum class ValueScanCompare : uint8_t {
	Exact = 0, Between = 1, Greater = 2, Less = 3, Unknown = 4,
	Changed = 5, Unchanged = 6, Increased = 7, Decreased = 8,
	IncreasedBy = 9, DecreasedBy = 10
};
enum class ValueScanMode : uint8_t { None = 0, List = 1, Snapshot = 2 };
enum class ValueScanFailure : uint8_t {
	None = 0,
	NoSession = 1,
	InvalidRequest = 2,
	TypeMismatch = 3,
	TooManyResults = 4,
	SnapshotTooLarge = 5,
	AllocationFailed = 6
};

struct ValueScanRequest {
	uint64_t           startAddress;
	uint64_t           endAddress;       // exclusive, 0 = end of user space
	uint64_t           value;            // raw little-endian value bits
	uint64_t           value2;           // upper bound for between
	uint64_t           offset;           // candidate offset for results
	uint32_t           alignment;
	uint32_t           maxResults;       // response page size, max 1000
	ValueScanOperation operation;
	ValueScanType      valueType;
	ValueScanCompare   compare;
	RegionFilter       writable;
	RegionFilter       executable;
	uint8_t            typeMask;         // kRegionType* bits, 0 = all
	uint8_t            reserved[2];
};

struct ValueScanEntry {
	uint64_t address;
	uint64_t value;                    // raw bits interpreted using valueType
};

struct ValueScanResponse {
	IpcStatus       status;
	ValueScanFailure failure;
	ValueScanMode    mode;
	ValueScanType    valueType;
	uint8_t          reserved;
	uint64_t         candidates;
	uint64_t         scannedBytes;
	uint32_t         count;
	// followed by ValueScanEntry[count]
};

struct ExecuteShellcodeRequest {
	uint32_t size;        // shellcode byte count (follows this struct)
	uint32_t timeoutMs;   // max wait time (0 = fire-and-forget)
};

struct ExecuteShellcodeResponse {
	IpcStatus status;
	uint64_t  allocatedAddress;  // RWX page address (freed if not fire-and-forget)
	uint32_t  exitCode;          // thread exit code
	uint8_t   crashed;           // 1 if shellcode thread crashed
	uint32_t  exceptionCode;     // exception code if crashed
	uint64_t  exceptionAddress;  // crash address if crashed
};

// --- TraceCallers ---
struct TraceCallersRequest {
	uint64_t address;          // BP address to trace
	uint32_t durationMs;       // how long to trace (ms)
};

struct TraceCallerEntry {
	uint64_t callerAddress;    // return address ([RSP] at BP hit)
	uint32_t hitCount;
};

struct TraceCallersResponse {
	IpcStatus status;
	uint32_t totalHits;        // total BP hits
	uint32_t uniqueCallers;    // number of TraceCallerEntry following
	// followed by: TraceCallerEntry[uniqueCallers]
};

#pragma pack(pop)

// Helper: Build IPC message
inline std::vector<uint8_t> BuildIpcMessage(uint32_t command, const void* payload = nullptr, uint32_t payloadSize = 0) {
	std::vector<uint8_t> msg(sizeof(IpcHeader) + payloadSize);
	auto* hdr = reinterpret_cast<IpcHeader*>(msg.data());
	hdr->command = command;
	hdr->payloadSize = payloadSize;
	if (payload && payloadSize > 0) {
		memcpy(msg.data() + sizeof(IpcHeader), payload, payloadSize);
	}
	return msg;
}

} // namespace veh
