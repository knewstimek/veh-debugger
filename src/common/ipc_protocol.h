#pragma once
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

	// Memory
	ReadMemory             = 0x0030,
	WriteMemory            = 0x0031,

	// Symbol resolution (PDB)
	ResolveSourceLine      = 0x0040,
	ResolveFunction        = 0x0041,
	EnumLocals             = 0x0042,

	// Tracing
	TraceCallers           = 0x0050,

	// Lifecycle
	Heartbeat              = 0x00FE,
	Detach                 = 0x00F0,
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

struct RemoveHwBreakpointRequest {
	uint32_t id;
};

struct ContinueRequest {
	uint32_t threadId;
};

struct StepRequest {
	uint32_t threadId;
};

struct PauseRequest {
	uint32_t threadId;   // 0 = all threads
};

struct TerminateThreadRequest {
	uint32_t threadId;
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
