#pragma once
#include <string>
#include <vector>
#include <optional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <thread>
#include "adapter/pipe_client.h"
#include "adapter/injector.h"
#include "adapter/disassembler.h"
#include "common/ipc_protocol.h"

namespace veh {

// --- Result types (pure C++, no JSON dependency) ---

struct BpResult {
	bool ok = false;
	uint32_t id = 0;
};

struct HwBpResult {
	bool ok = false;
	uint32_t id = 0;
	uint8_t slot = 0;
};

struct StopEvent {
	bool stopped = false;
	bool timeout = false;
	std::string reason;   // "breakpoint", "exception", "pause", "step", "exit"
	std::string bpType;   // "software", "hardware", ""
	uint64_t address = 0;
	uint32_t threadId = 0;
	uint32_t breakpointId = 0;
};

struct ThreadEntry {
	uint32_t id;
	std::string name;
};

struct StackFrame {
	uint64_t address;
	uint64_t returnAddress;
	uint64_t frameBase;
	uint64_t moduleBase;
	std::string moduleName;
	std::string functionName;
	std::string sourceFile;
	uint32_t line;
};

struct ModuleEntry {
	std::string name;
	std::string path;
	uint64_t baseAddress;
	uint32_t size;
};

struct DisasmInsn {
	uint64_t address;
	std::string bytes;
	std::string mnemonic;
};

struct ShellcodeResult {
	bool ok = false;
	uint32_t exitCode = 0;
	uint64_t allocatedAddress = 0;
	bool crashed = false;
	uint32_t exceptionCode = 0;
	uint64_t exceptionAddress = 0;
};

struct LocalVarEntry {
	std::string name;
	std::string typeName;
	uint64_t address;
	uint32_t size;
	uint32_t flags;
	std::vector<uint8_t> value;
};

struct TraceResult {
	uint32_t totalHits = 0;
	uint32_t uniqueCallers = 0;
	struct Caller { uint64_t address; uint32_t hitCount; };
	std::vector<Caller> callers;
};

struct EvalResult {
	bool ok = false;
	std::string value;
	std::string type;
	uint64_t address = 0;       // computed address (for pointer deref)
	std::string tebAddress;     // for segment expressions
	std::string error;
};

// --- Breakpoint tracking (shared by MCP & future batch) ---

struct SwBpInfo {
	uint32_t id;
	uint64_t address;
	std::string condition;
	std::string hitCondition;
	std::string logMessage;
	uint32_t hitCount = 0;
	std::string source;
	uint32_t line = 0;
	std::string functionName;
};

struct HwBpInfo {
	uint32_t id;
	uint64_t address;
	uint8_t type;
	uint8_t size;
};

// --- DebugSession: IPC wrapper with session state ---

class DebugSession {
public:
	DebugSession();
	~DebugSession();

	// --- Lifecycle ---
	bool Attach(uint32_t pid);
	struct LaunchOptions {
		std::string program;
		std::vector<std::string> args;
		bool stopOnEntry = true;
		bool runAsInvoker = false;
		std::string injectionMethod = "auto";
	};
	struct LaunchResult {
		bool ok = false;
		uint32_t pid = 0;
		std::string error;
	};
	LaunchResult Launch(const LaunchOptions& opts);
	bool Detach();
	bool IsAttached() const { return attached_; }
	uint32_t GetTargetPid() const { return targetPid_; }
	bool IsTargetAlive();

	// --- Breakpoints ---
	BpResult SetBreakpoint(uint64_t address);
	bool RemoveBreakpoint(uint32_t id);
	bool RemoveBreakpointByAddress(uint64_t address);
	HwBpResult SetHwBreakpoint(uint64_t address, uint8_t type, uint8_t size);
	bool RemoveHwBreakpoint(uint32_t id);

	// BP tracking (conditions are MCP/DAP-level, not IPC)
	std::vector<SwBpInfo>& GetSwBreakpoints() { return swBreakpoints_; }
	std::vector<HwBpInfo>& GetHwBreakpoints() { return hwBreakpoints_; }
	std::mutex& GetBpMutex() { return bpMutex_; }

	// --- Execution control ---
	bool Continue(uint32_t threadId = 0, bool passException = false);
	bool StepIn(uint32_t threadId);
	bool StepOver(uint32_t threadId);
	bool StepOut(uint32_t threadId);
	bool Pause(uint32_t threadId = 0);
	void ResumeMainThread();

	// Wait for stop event (blocks)
	StopEvent WaitForStop(int timeoutSec = 10);
	// Consume cached stop event without sending Continue
	std::optional<StopEvent> ConsumeCachedStop();

	// --- State queries ---
	std::vector<ThreadEntry> GetThreads();
	std::vector<StackFrame> GetStackTrace(uint32_t threadId, uint32_t maxFrames = 20);
	std::optional<RegisterSet> GetRegisters(uint32_t threadId);
	bool SetRegister(uint32_t threadId, uint32_t regIndex, uint64_t value);
	std::vector<ModuleEntry> GetModules();
	std::vector<LocalVarEntry> EnumLocals(uint32_t threadId, uint64_t instrAddr, uint64_t frameBase);

	// --- Memory ---
	std::vector<uint8_t> ReadMemory(uint64_t address, uint32_t size);
	bool WriteMemory(uint64_t address, const uint8_t* data, uint32_t size);
	uint64_t AllocateMemory(uint32_t size, uint32_t protection);
	bool FreeMemory(uint64_t address);
	ShellcodeResult ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs);

	// --- Analysis ---
	std::vector<DisasmInsn> Disassemble(uint64_t address, uint32_t count);
	EvalResult Evaluate(const std::string& expression, uint32_t threadId);
	TraceResult TraceCallers(uint64_t address, uint32_t durationSec);

	// --- Resolve (PDB) ---
	uint64_t ResolveSourceLine(const std::string& file, uint32_t line);
	uint64_t ResolveFunction(const std::string& name);

	// --- IPC event handling ---
	using EventCallback = std::function<void(uint32_t eventId, const uint8_t* payload, uint32_t size)>;
	void SetEventCallback(EventCallback cb);

	// Stop event signaling (called from event callback)
	void SignalStop(const std::string& reason, uint64_t addr, uint32_t threadId,
	                uint32_t bpId, const std::string& bpType = "");

	// Process monitor
	void StartProcessMonitor();
	void StopProcessMonitor();

	// Direct access (for advanced use / backward compat)
	PipeClient& GetPipeClient() { return pipeClient_; }
	HANDLE GetTargetProcess() const { return targetProcess_; }
	IDisassembler* GetDisassembler() { return disassembler_.get(); }

	// Helper
	static bool TryParseRegisterName(const std::string& name);
	static uint64_t ResolveRegisterByName(const std::string& name, const RegisterSet& regs);
	static uint32_t GetRegisterIndex(const std::string& name);

private:
	std::string GetExeDir();
	std::string ResolveDll(const std::string& dir, bool use32);
	std::string GetDllPath(uint32_t pid);
	std::string GetDllPathForExe(const std::string& exePath);

	PipeClient pipeClient_;
	std::unique_ptr<IDisassembler> disassembler_ = CreateDisassembler();

	// Session state
	uint32_t targetPid_ = 0;
	HANDLE targetProcess_ = nullptr;
	std::atomic<bool> attached_{false};
	std::atomic<bool> launchedByUs_{false};
	uint32_t launchedMainThreadId_ = 0;
	bool mainThreadResumed_ = false;

	// Breakpoint tracking
	std::vector<SwBpInfo> swBreakpoints_;
	std::vector<HwBpInfo> hwBreakpoints_;
	std::mutex bpMutex_;

	// Stop event synchronization
	std::mutex stopMutex_;
	std::condition_variable stopCv_;
	bool stopOccurred_ = false;
	StopEvent lastStop_;

	// Process monitor
	std::thread processMonitorThread_;
	HANDLE monitorStopEvent_ = nullptr;
};

} // namespace veh
