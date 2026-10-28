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
	GetProcesses           = 0x0028,  // VM-scoped guest OS process snapshot

	// Memory
	ReadMemory             = 0x0030,
	WriteMemory            = 0x0031,
	PatchCode              = 0x0032,  // bounded replacement of whole original instructions

	// Symbol resolution (PDB)
	ResolveSourceLine      = 0x0040,
	ResolveFunction        = 0x0041,
	EnumLocals             = 0x0042,
	Symbolize              = 0x0043,  // addresses -> module!function+offset, source line
	DisplayType            = 0x0044,  // PDB struct layout (+ values) at an address

	// Tracing
	TraceCallers           = 0x0050,

	// Memory management
	AllocateMemory         = 0x0060,
	FreeMemory             = 0x0061,
	ExecuteShellcode       = 0x0062,
	QueryMemoryMap         = 0x0063,
	SearchMemory           = 0x0064,
	ProtectMemory          = 0x0065,
	ValueScan              = 0x0066,

	// Dynamic tracing
	TraceRegister          = 0x0070,
	TraceMemory            = 0x0071,
	ResolveImport          = 0x0072,
	TraceCalls             = 0x0073,
	TraceBasicBlocks       = 0x0074,
	TraceMemoryCollect     = 0x0075,  // every instruction touching an address for a while, without stopping

	// System inspection: machine-wide state outside the target process. Only
	// backends running below the OS serve these; others answer Unsupported.
	ReadPhysical           = 0x0080,
	WritePhysical          = 0x0081,
	TranslateAddress       = 0x0082,  // virtual -> physical with every paging entry
	PhysicalToVirtual      = 0x0083,  // physical -> kernel virtual
	ReadSystemMemory       = 0x0084,  // kernel virtual memory
	WriteSystemMemory      = 0x0085,  // kernel virtual memory (through physical: ignores page protection)
	AccessMsr              = 0x0086,
	ExecuteCpuid           = 0x0087,
	AccessPort             = 0x0088,  // I/O port IN/OUT
	QueryIdt               = 0x0089,
	QueryApic              = 0x008A,
	QueryIoApic            = 0x008B,
	AccessPciConfig        = 0x008C,
	GetSystemModules       = 0x008D,  // kernel modules
	ResolveAddressSpace    = 0x008E,  // the target's page-table root (CR3) by several methods
	ConfigureTransparency  = 0x008F,  // hide the debugger's time from the target's clock

	// System events: machine-wide occurrences (CPUID, MSR access, exceptions, port
	// I/O, system calls, memory accesses...) matched by filters and recorded, or
	// halting the machine for a kernel debugger. Backends below the OS only.
	AddSystemEvent         = 0x0090,
	RemoveSystemEvent      = 0x0091,
	ListSystemEvents       = 0x0092,
	DrainSystemEvents      = 0x0093,
	AddHiddenHook          = 0x0094,  // execution hook that edits registers / returns at once; code untouched

	// Explicit VM-wide execution; separate from process/thread Pause/Continue.
	ControlVirtualMachine  = 0x0095,
	TraceVirtualCpu        = 0x0096,

	// Branch tracing: last branches of a stopped thread (LBR) or the full path
	// of the target (Intel PT). Query says what the machine offers, and why not.
	QueryBranchTrace       = 0x0098,
	StartBranchTrace       = 0x0099,
	StopBranchTrace        = 0x009A,
	ReadBranchTrace        = 0x009B,

	// Lifecycle
	GetCapabilities        = 0x00FC,  // backend identity and per-command support (older peers answer InvalidArgs)
	GetTargetInfo          = 0x00FD,  // guest PID namespace and address width; empty request
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
	// Non-terminal backend diagnostic: not detach, target exit, or a stop event.
	// MCP/DAP currently log receipt only; no standardized payload/loss-count format.
	Error                  = 0x10FF,
	Ready                  = 0x1000,
};

// IPC Response codes
enum class IpcStatus : uint32_t {
	Ok                     = 0,
	Error                  = 1,
	NotFound               = 2,
	InvalidArgs            = 3,
	Unsupported            = 4,  // the backend does not implement this command
	LimitReached           = 5,  // a backend table is full (breakpoint/watch slots); free one first
	InvalidState           = 6,  // supported operation refused before starting in the current target state
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
	char    name[256];   // case-insensitive base-name substring (e.g. "version.dll"), not a path
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

// PatchCode v1: target-side read/decode/validate/write; no relocation.
// Default span covers whole original instructions until codeSize fits.
// Caller supplies an instruction start.
// Backends advertise only after implementing this complete contract.
// Not atomic with respect to running threads or external/self-modifying writers.
inline constexpr uint32_t kPatchCodeMaxBytes = 4096;
inline constexpr uint32_t kPatchCodeNopFill = 1; // unset: preserve original tail bytes
enum class PatchCodeDetail : uint32_t {
    None = 0, TooLarge = 1, SplitInstruction = 2, // value 3 reserved
    Unreadable = 4, InvalidInstruction = 5, BreakpointOverlap = 6,
    WriteFailed = 7, ArchitectureMismatch = 8, OriginalChanged = 9
};
struct PatchCodeRequest {
    uint32_t version;       // 1
    uint32_t flags;         // kPatchCodeNopFill only
    uint64_t address;
    uint32_t codeSize;      // 1..kPatchCodeMaxBytes; followed by codeSize bytes
    uint32_t overwriteSize; // 0: minimum whole-instruction span covering codeSize; else exact span
    uint32_t addressBits;   // 32 or 64, must match the target
};
struct PatchCodeResponse {
    IpcStatus status;
    PatchCodeDetail detail;
    uint32_t overwriteSize;
    uint32_t instructionCount;
    // On Ok: overwriteSize original bytes, then overwriteSize patched bytes.
    // Non-Ok may be status-only or this header without trailing bytes.
};
static_assert(sizeof(PatchCodeRequest) == 28 && sizeof(PatchCodeResponse) == 16,
    "PatchCode wire layout");

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

// One complete guest OS process snapshot; names are bounded raw image-name bytes.
struct GuestProcessInfo {
	uint32_t pid;
	uint32_t addressBits;
	char     name[64];
};
static_assert(sizeof(GuestProcessInfo) == 72);

struct GetProcessesResponse {
	IpcStatus status;
	uint32_t  count;
	// followed by exactly `count` GuestProcessInfo structs on success
};
static_assert(sizeof(GetProcessesResponse) == 8);

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

static constexpr uint32_t kDisplayTypeMaxMembers = 1024;

struct DisplayTypeRequest {
	uint64_t address;            // 0 = layout only, no values
	uint32_t maxMembers;
	uint8_t  maxDepth;           // nested struct/base-class expansion levels (0 = top level only)
	uint8_t  reserved[3];
	char     typeName[256];      // "Type" or "module!Type"
};

enum class TypeMemberKind : uint8_t {
	Other, Int, UInt, Float, Bool, Char, Pointer, Struct, Array, Enum, BaseClass,
};

struct DisplayTypeMember {
	uint32_t       offset;       // from the start of the displayed type
	uint32_t       size;         // bytes (storage size for bitfields)
	uint32_t       bitPosition;
	uint32_t       bitLength;    // 0 when not a bitfield
	uint8_t        depth;        // nesting level, 0 = direct member
	TypeMemberKind kind;
	uint8_t        valueSize;    // bytes in value, 0 = not read
	uint8_t        reserved;
	uint8_t        value[8];     // little-endian; bitfields already shifted and masked
	char           name[128];    // dotted path for nested members
	char           typeName[128];
};

struct DisplayTypeResponse {
	IpcStatus status;
	uint32_t  count;             // followed by DisplayTypeMember[count]
	uint32_t  typeSize;
	uint8_t   truncated;         // maxMembers reached
	uint8_t   reserved[3];
	char      moduleName[64];    // module whose PDB defined the type
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

// Collect mode (veh_trace_memory duration_ms): the watch stays for durationMs
// and every hit is counted per instruction; nothing stops.
static constexpr uint8_t kTraceAccessWrite = 1;
static constexpr uint8_t kTraceAccessRead = 2;
static constexpr uint8_t kTraceEntryAfterInstruction = 0x01; // instructionAddress follows the access (a DR trap)
struct TraceMemoryCollectRequest {
	uint64_t address;
	uint32_t size;        // bytes watched (a DR backend: 1, 2, 4 or 8)
	uint32_t durationMs;
	uint8_t  access;      // kTraceAccessWrite, or kTraceAccessWrite | kTraceAccessRead
	uint8_t  reserved[3];
	uint32_t maxEntries;  // distinct instructions kept (0: backend default)
};
struct TraceMemoryCollectEntry {
	uint64_t instructionAddress;
	uint64_t hits;
	uint32_t firstThreadId;
	uint8_t  access;      // kTraceAccess* bits seen
	uint8_t  flags;       // kTraceEntry*
	uint8_t  reserved[2];
	uint64_t regs[16];    // rax..r15 (RegisterSet order) at the first hit
	uint64_t rflags;
};
struct TraceMemoryCollectResponse { // followed by TraceMemoryCollectEntry[entryCount]
	IpcStatus status;
	uint32_t entryCount;
	uint64_t totalHits;
	uint64_t droppedHits; // hits of instructions past maxEntries (counted, not listed)
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

enum class ProtectMemoryMethod : uint8_t { Api = 0, Nt = 1, Syscall = 2 };

struct ProtectMemoryRequest {
	uint64_t            address;
	uint64_t            size;
	uint32_t            protection;
	ProtectMemoryMethod method;
	uint8_t             reserved[3];
};

struct ProtectMemoryResponse {
	IpcStatus           status;
	uint32_t            oldProtection;
	uint32_t            errorCode;
	ProtectMemoryMethod method;
	uint8_t             reserved[3];
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

// --- System inspection ---
// cpu = logical processor index; ~0u = any (the backend picks one).
struct PhysicalMemoryRequest {   // ReadPhysical / ReadSystemMemory; Write* append `size` bytes
	uint64_t address;
	uint32_t size;              // at most kSystemMemoryMax
	uint32_t reserved;
};
static constexpr uint32_t kSystemMemoryMax = 0x10000;
// Response: IpcStatus, then the bytes read (reads) or nothing (writes).

struct TranslateAddressRequest {
	uint64_t address;
	uint32_t flags;             // kTranslateTargetSpace: the target's address space (else the kernel's)
	uint32_t reserved;
};
static constexpr uint32_t kTranslateTargetSpace = 1;
struct TranslateAddressResponse {
	IpcStatus status;
	uint32_t  levels;           // 4 or 5
	uint64_t  cr3;
	uint64_t  entries[5];       // PML5E (5-level only), PML4E, PDPTE, PDE, PTE; walk order
	uint32_t  entryCount;       // entries filled (a large page or a non-present entry ends the walk)
	uint32_t  present;          // the address translates
	uint64_t  physical;
	uint64_t  pageSize;
};

struct PhysicalToVirtualRequest {
	uint64_t physical;
};
struct PhysicalToVirtualResponse {
	IpcStatus status;
	uint32_t  reserved;
	uint64_t  address;          // 0 when no kernel mapping exists
};

struct AccessMsrRequest {
	uint32_t cpu;
	uint32_t index;
	uint32_t write;
	uint32_t reserved;
	uint64_t value;
};
struct AccessMsrResponse {
	IpcStatus status;           // Error: the MSR faulted (#GP)
	uint32_t  cpu;
	uint64_t  value;
};

struct ExecuteCpuidRequest {
	uint32_t cpu;
	uint32_t leaf;
	uint32_t subleaf;
	uint32_t reserved;
};
struct ExecuteCpuidResponse {
	IpcStatus status;
	uint32_t  cpu;
	uint32_t  eax, ebx, ecx, edx;
};

struct AccessPortRequest {
	uint16_t port;
	uint8_t  size;              // 1, 2 or 4
	uint8_t  write;
	uint32_t value;
};
struct AccessPortResponse {
	IpcStatus status;
	uint32_t  value;
};

struct QueryIdtRequest {
	uint32_t cpu;
};
struct IdtEntry {
	uint64_t handler;
	uint16_t selector;
	uint8_t  ist;
	uint8_t  type;              // gate type (14 interrupt, 15 trap)
	uint8_t  dpl;
	uint8_t  present;
	uint8_t  reserved[2];
};
struct QueryIdtResponse {
	IpcStatus status;
	uint32_t  cpu;
	uint64_t  base;
	uint32_t  limit;
	uint32_t  count;            // IdtEntry[count] follow
};

struct QueryApicRequest {
	uint32_t cpu;
};
struct ApicRegister {
	uint32_t offset;            // xAPIC MMIO offset (x2APIC MSR = 0x800 + offset / 16)
	uint32_t value;
};
struct QueryApicResponse {
	IpcStatus status;
	uint32_t  cpu;
	uint64_t  baseMsr;          // IA32_APIC_BASE
	uint32_t  x2apic;
	uint32_t  count;            // ApicRegister[count] follow
};

struct IoApicRedirection {
	uint64_t entry;
};
struct QueryIoApicResponse {
	IpcStatus status;
	uint32_t  id;
	uint64_t  address;          // MMIO base (ACPI MADT)
	uint32_t  gsiBase;
	uint32_t  version;          // bits 0-7 version, 16-23 max redirection entry
	uint32_t  count;            // IoApicRedirection[count] follow
	uint32_t  reserved;
};

struct AccessPciConfigRequest {
	uint8_t  bus;
	uint8_t  device;
	uint8_t  function;
	uint8_t  write;
	uint16_t offset;            // within the 256-byte configuration space
	uint16_t size;              // bytes; writes append them
};
// Response: IpcStatus, then the bytes read. NotFound: no device there.

struct SystemModuleEntry {
	uint64_t base;
	uint32_t size;
	uint32_t reserved;
	char     path[256];
};
struct GetSystemModulesResponse {
	IpcStatus status;
	uint32_t  count;            // SystemModuleEntry[count] follow
};

// Every candidate is checked by reading the target's PEB through it. With
// apply, the chosen root replaces the one the OS reports for later accesses.
enum class AddressSpaceMethod : uint32_t {
	Auto = 0,          // first valid of the methods below, in order
	KernelRecord = 1,  // the process object's page-table root
	UserShadow = 2,    // the user-only root of kernel page-table isolation
	Observed = 3,      // the root in use when the backend last saw one of its threads
	Probe = 4,         // every root the processors load during a short window
	Scan = 5,          // physical pages that translate the PEB correctly
	All = 6,
};
struct ResolveAddressSpaceRequest {
	AddressSpaceMethod method;
	uint32_t apply;             // 1 = use the chosen root from now on, 2 = back to the OS record
	uint32_t probeMs;           // Probe window (default 100, max 2000)
	uint32_t reserved;
};
struct AddressSpaceCandidate {
	uint64_t root;
	AddressSpaceMethod method;
	uint32_t valid;
};
// Timing transparency: the target's RDTSC/RDTSCP (and the time sources built
// on them) exclude the time the debugger holds it.
struct ConfigureTransparencyRequest {
	uint32_t timing;            // 0 off, 1 on, 2 unchanged
	uint32_t measure;           // 1: time CPUID as a process sees it, without and with the compensation
};
struct ConfigureTransparencyResponse {
	IpcStatus status;
	uint32_t  timing;           // now on for the target
	uint64_t  exitCost;         // estimated cycles one hypervisor round trip adds
	uint64_t  cpuidCycles;      // measure: CPUID as seen without compensation
	uint64_t  cpuidCyclesHidden; // measure: ... with it
};

enum class SystemEventType : uint32_t {
	Cpuid = 1,        // value: leaf
	MsrRead = 2,      // value: MSR index
	MsrWrite = 3,     // value: MSR index, detail: value written
	Exception = 4,    // value: vector, detail: error code
	PortIn = 5,       // value: port, detail: size
	PortOut = 6,      // value: port, detail: size
	Syscall = 7,      // value: system call number, detail: first argument
	Hypercall = 8,    // value: rax
	Xsetbv = 9,       // value: XCR index, detail: value
	Rdtsc = 10,
	MemoryRead = 11,  // value: address, detail: physical address
	MemoryWrite = 12,
	MemoryExecute = 13,
	DebugRegister = 14, // value: debug register number, detail: 1 write, 0 read
	SyscallReturn = 15, // value: the status returned (rax), detail: the system call number
	Interrupt = 16,     // value: vector (delivered to the target as usual afterwards)
};
struct AddSystemEventRequest {
	uint32_t type;      // SystemEventType
	uint32_t action;    // 0 record, 1 stop (halt the machine for a connected kernel debugger)
	uint32_t pid;       // 0 = any process
	uint32_t tid;       // 0 = any thread
	uint32_t cpu;       // ~0u = any processor
	uint32_t privilege; // bit 0 kernel mode, bit 1 user mode; 0 = both
	uint64_t low;       // value range, inclusive (memory events: addresses, in pid's space or the kernel's)
	uint64_t high;
};
struct AddSystemEventResponse {
	IpcStatus status;
	uint32_t  id;
};
struct RemoveSystemEventRequest {
	uint32_t id;        // ~0u = every event
};
struct SystemEventInfo {
	uint32_t id;
	uint32_t type;
	uint32_t action;
	uint32_t pid;
	uint32_t tid;
	uint32_t cpu;
	uint32_t privilege;
	uint32_t hits;
	uint64_t low;
	uint64_t high;
};
struct ListSystemEventsResponse {
	IpcStatus status;
	uint32_t  count;    // SystemEventInfo[count] follow
};
struct DrainSystemEventsRequest {
	uint32_t max;       // records wanted (0 = as many as fit)
};
struct SystemEventRecord {
	uint32_t id;
	uint32_t type;
	uint32_t cpu;
	uint32_t pid;
	uint32_t tid;
	uint32_t privilege; // 0 kernel, 3 user
	uint64_t value;
	uint64_t detail;
	uint64_t rip, rsp, pageTable;
	uint64_t rax, rbx, rcx, rdx, r8, r9, r10, r11;
	uint64_t timestamp; // TSC
};
struct DrainSystemEventsResponse {
	IpcStatus status;
	uint32_t  count;    // SystemEventRecord[count] follow
	uint32_t  dropped;  // records lost to a full buffer since the last drain
};

// A hidden execution hook: when address executes (in process pid, 0 = kernel)
// the registers in regMask take values[], and with returnNow the function
// returns at once to its caller with returnValue (popping returnPop extra stack
// bytes, for stdcall). The code is never modified. Listed and removed as system
// events (type MemoryExecute, action 2).
struct AddHiddenHookRequest {
	uint64_t address;
	uint32_t pid;
	uint32_t returnNow;
	uint32_t returnPop;
	uint32_t regMask;     // bit n: register n of rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip rflags
	uint64_t returnValue;
	uint64_t values[18];
};
struct AddHiddenHookResponse {
	IpcStatus status;
	uint32_t  id;
};

enum class BranchTraceKind : uint32_t {
	LastBranches = 1,   // recorded continuously; a stopping thread keeps the ones that led to its stop
	FullPath = 2,       // every branch of the target process while running
};
struct QueryBranchTraceResponse {
	IpcStatus status;
	uint32_t  lastBranches;     // usable
	uint32_t  lastBranchDepth;
	uint32_t  fullPath;         // usable
	uint32_t  active;           // BranchTraceKind running, 0 none
	char      provider[32];     // e.g. "Intel PT", "Intel LBR", "AMD LBRv2", "none"
	char      lastBranchesReason[128]; // empty when usable
	char      fullPathReason[128];
};
struct StartBranchTraceRequest {
	uint32_t kind;              // BranchTraceKind
	uint32_t bufferKb;          // FullPath: per processor (power of two; 0 = 4096)
};
struct ReadBranchTraceRequest {
	uint32_t kind;              // BranchTraceKind
	uint32_t threadId;          // LastBranches: a stopped thread
	uint32_t maxBranches;       // 0 = as many as fit
};
struct BranchRecord {
	uint64_t from;
	uint64_t to;
};
struct ReadBranchTraceResponse {
	IpcStatus status;
	uint32_t  kind;
	uint32_t  count;            // BranchRecord[count] follow (newest first for LastBranches)
	uint32_t  lost;             // FullPath: places where data was lost or the walk lost sync
};

struct ResolveAddressSpaceResponse {
	IpcStatus status;
	uint32_t  count;            // AddressSpaceCandidate[count] follow
	uint32_t  chosen;           // index, UINT32_MAX = none valid
	uint32_t  probed;           // distinct roots the probe saw (all processes)
	uint64_t  inUse;            // root used for the target now
};

// --- Explicit virtual-machine execution (wire version1) ---
// These operations affect the VM, independently of the attached guest PID.
// Trace executes just the selected vCPU while every other vCPU stays paused.
// They do not implement selective OS-thread stops or hardware trace throughput.
enum class VirtualMachineAction : uint32_t { Query = 0, Pause = 1, Resume = 2 };
enum class VirtualMachineState : uint32_t { Other = 0, Running = 1, Paused = 2, PoweredOff = 3 };
struct ControlVirtualMachineRequest { VirtualMachineAction action; uint32_t reserved; };
struct ControlVirtualMachineResponse { IpcStatus status; VirtualMachineState state; };
struct TraceVirtualCpuRequest {
    uint32_t cpu, cplMask;
    uint64_t cr3Roots[2];
    uint64_t ripBegin, ripEnd; // exclusive; equal disables the RIP boundary
    uint32_t maxInstructions, durationMs, cr3Count, reserved;
};
// CR3/CPL/RIP filters stop BEFORE executing out of scope. Deadline is checked
// between instructions and cannot interrupt one instruction/device handler.
// engine1=interpreter; stopReason1=budget,2=deadline,3=filter,4=failure.
// At most64 records; success: completed=count+lost. Failure can have side effects
// and can retire an instruction whose post-state could not be captured.
struct TraceVirtualCpuResponse {
    IpcStatus status;
    uint32_t wireVersion;
    uint64_t completed, lost, elapsedNs;
    uint32_t count, stopReason, engine;
    int32_t executionStatus;
};
struct VirtualCpuInstructionRecord {
    uint64_t sequence, timestampNs, cr3, ip;
    uint64_t nextIp, rax, rbx, rcx, rdx, rsp, rflags; // post-instruction values
    uint32_t cpu, cpl;
};
static_assert(sizeof(ControlVirtualMachineRequest)==8);
static_assert(sizeof(ControlVirtualMachineResponse)==8);
static_assert(sizeof(TraceVirtualCpuRequest)==56);
static_assert(sizeof(TraceVirtualCpuResponse)==48);
static_assert(sizeof(VirtualCpuInstructionRecord)==96);

// --- Backend capabilities ---
// The same protocol is served by the in-process VEH DLL and by out-of-process
// backends. Clients ask once after Ready; a peer that
// predates the command answers a bare InvalidArgs status, which means "VEH DLL,
// everything it knows".
enum class IpcBackend : uint32_t { VehDll = 0, Hypervisor = 1 };

constexpr uint32_t kCapStopsThreads        = 1u << 0;  // breakpoints/steps can hold a thread stopped
constexpr uint32_t kCapHiddenBreakpoints   = 1u << 1;  // breakpoints do not modify target code bytes
constexpr uint32_t kCapNoTargetFootprint   = 1u << 2;  // nothing is injected into the target process
constexpr uint32_t kCapExecWriteTracking   = 1u << 3;  // writes to executed code are observed completely

// Guest targets require explicit frontend scope selection and this metadata.
// A guest PID must never be passed to host process/thread APIs. Backends validate
// the bound process identity on every query; failure publishes no metadata.
constexpr uint32_t kCapGuestTarget = 1u << 4;
// A VM session has no OS PID and no single address width. Both metadata fields
// must be zero; clients must explicitly opt into vm scope before connecting.
constexpr uint32_t kCapVirtualMachineTarget = 1u << 5;
enum class IpcTargetScope : uint32_t { Host = 0, Guest = 1, VirtualMachine = 2 };
struct GetTargetInfoResponse {
    IpcStatus status;
    IpcTargetScope scope;
    uint32_t pid;
    uint32_t addressBits; // Guest:32/64; VirtualMachine:0 with pid0
};
static_assert(sizeof(GetTargetInfoResponse) == 16);

struct GetCapabilitiesResponse {
	IpcStatus  status;
	IpcBackend backend;
	uint32_t   flags;          // kCap* bits
	uint8_t    commands[32];   // bit n set = IpcCommand value n is implemented
	char       name[32];       // human-readable backend name
};

inline void SetCommandSupported(uint8_t (&bits)[32], IpcCommand cmd) {
	const uint32_t n = static_cast<uint32_t>(cmd);
	if (n < 256) bits[n / 8] |= static_cast<uint8_t>(1u << (n % 8));
}

inline bool IsCommandSupported(const uint8_t (&bits)[32], IpcCommand cmd) {
	const uint32_t n = static_cast<uint32_t>(cmd);
	return n < 256 && (bits[n / 8] & (1u << (n % 8))) != 0;
}

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
