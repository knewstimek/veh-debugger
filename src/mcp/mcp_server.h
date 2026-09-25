#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <unordered_map>
#include "adapter/transport.h"
#include "debug_session.h"
#include "common/ipc_protocol.h"
#include <nlohmann/json.hpp>

namespace veh {

using json = nlohmann::json;

class BatchExecutor;

class McpServer {
public:
	explicit McpServer(std::string toolProfile = "lite");
	~McpServer();

	void SetTransport(dap::Transport* transport);
	void Run();
	void Stop();

private:
	// JSON-RPC message handling
	void OnMessage(const std::string& jsonStr);
	void SendResult(const json& id, const json& result);
	void SendError(const json& id, int code, const std::string& message);
	void SendNotification(const std::string& method, const json& params);

		// MCP protocol handlers
		void OnInitialize(const json& id, const json& params);
		void OnToolsList(const json& id, const json& params);
		void OnToolsCall(const json& id, const json& params);
		void OnResourcesList(const json& id, const json& params);
		void OnResourceTemplatesList(const json& id, const json& params);

	// Tool implementations
	json ToolAttach(const json& args);
	json ToolLaunch(const json& args);
	json ToolDetach(const json& args);
	json ToolTerminate(const json& args);
	json ToolSetBreakpoint(const json& args);
	json ToolSetModuleBreakpoint(const json& args);
	json ToolRemoveBreakpoint(const json& args);
	json ToolSetSourceBreakpoint(const json& args);
	json ToolSetFunctionBreakpoint(const json& args);
	json ToolListBreakpoints(const json& args);
	json ToolSetDataBreakpoint(const json& args);
	json ToolRemoveDataBreakpoint(const json& args);
	json ToolContinue(const json& args);
	json ToolStepIn(const json& args);
	json ToolStepOver(const json& args);
	json ToolStepOut(const json& args);
	json ToolPause(const json& args);
	json ToolThreads(const json& args);
	json ToolStackTrace(const json& args);
	json ToolRegisters(const json& args);
	json ToolReadMemory(const json& args);
	json ToolReadPointerChain(const json& args);
	json ToolWriteMemory(const json& args);
	json ToolModules(const json& args);
	json ToolDisassemble(const json& args);
	json ToolEnumLocals(const json& args);
	json ToolSymbolize(const json& args);
	json ToolEvaluate(const json& args);
	json ToolSetRegister(const json& args);
	json ToolExceptionInfo(const json& args);
	json ToolTraceCallers(const json& args);
	json ToolDumpMemory(const json& args);
	json ToolAllocateMemory(const json& args);
	json ToolFreeMemory(const json& args);
	json ToolMemoryMap(const json& args);
	json ToolSearchMemory(const json& args);
	bool ParseRangeArgs(const json& args, uint64_t& start, uint64_t& end, std::string& error);
	static std::string ModuleLocation(uint64_t address, const std::vector<ModuleEntry>& modules);
	json ToolExecuteShellcode(const json& args);
	json ToolBatch(const json& args);
	json ToolTraceRegister(const json& args);
	json ToolTraceMemory(const json& args);
	json ToolResolveImports(const json& args);
	json ToolTraceCalls(const json& args);
	json ToolTraceBasicBlocks(const json& args);
	json ToolTargetedCapture(const json& args);
	json ToolCheckpointCreate(const json& args);
	json ToolCheckpointRestore(const json& args);
	json ToolCheckpointDiff(const json& args);
	json ToolCheckpointDelete(const json& args);
	json ToolToolbox(const json& args);

	// Tool list definition
	// One entry per MCP tool: handler, discovery metadata, and the MCP definition
	struct ToolDef {
		std::string name;
		json (McpServer::*handler)(const json&);
		const char* category;
		unsigned profiles;  // eager-profile bits; the full profile exposes every tool
		bool nested;        // callable from batch steps, capture setup, breakpoint actions
		json definition;    // {name, description, inputSchema}
		bool InProfile(unsigned mask) const { return mask == ~0u || (profiles & mask) != 0; }
	};
	static ToolDef Tool(json (McpServer::*handler)(const json&), const char* category,
		unsigned profiles, bool nested, json definition);
	static std::vector<ToolDef> BuildAllToolsList();
	const ToolDef* FindTool(const std::string& name) const;
	json GetToolsList() const;
	json DispatchTool(const std::string& name, const json& args, bool* known = nullptr);
	// Tool runner for batch steps, targeted-capture setup, and breakpoint actions
	json RunNestedTool(const std::string& name, const json& args);
	BatchExecutor NewBatchExecutor();

	// IPC event handler (breakpoint hit, etc.)
	void OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size);

	// StepOver CALL skip helpers
	bool IsCallInstruction(uint32_t threadId, uint64_t& nextInsnAddr);
	bool IsNextInstructionCall(uint32_t threadId, uint64_t& addrAfterCall);
	bool SetTempBpAndContinue(uint64_t address);
	void CleanupTempStepOverBp();

	// Condition/evaluate helpers (MCP-level logic)
	bool EvaluateCondition(const std::string& condition, uint32_t threadId, const RegisterSet* cachedRegs);
	std::string ExpandLogMessage(const std::string& msg, uint32_t threadId, const RegisterSet* cachedRegs);

	// Helper
	bool ParseAddress(const std::string& addrStr, uint64_t& out);
	std::string NotAttachedMessage();
	std::string IpcErrorMessage();
	void ResetSessionEventState();
	bool IsCurrentStopEvent(const StopEvent& event);

	dap::Transport* transport_ = nullptr;
	DebugSession session_;
	std::string toolProfile_;
	const std::vector<ToolDef> tools_ = BuildAllToolsList();
	std::atomic<bool> running_{false};

	// Last exception info (cached from ExceptionOccurred event)
	struct {
		uint32_t threadId = 0;
		uint32_t code = 0;
		uint64_t address = 0;
		std::string description;
	} lastException_;
	std::mutex exceptionMutex_;

	std::mutex sendMutex_;

	struct CheckpointRegion {
		uint64_t address = 0;
		uint64_t allocationBase = 0;
		uint64_t regionBase = 0;
		uint64_t regionSize = 0;
		uint32_t type = 0;
		uint32_t protection = 0;
		size_t restoreOffset = 0;
		bool restorable = true;
		std::string kind = "memory";
		std::vector<uint8_t> bytes;
	};
	struct CheckpointThreadEnvironment {
		uint64_t teb = 0;
		uint64_t nativeTeb = 0;
		uint64_t fsBase = 0;
		uint64_t gsBase = 0;
		bool wow64 = false;
	};
	struct Checkpoint {
		uint64_t id = 0;
		uint64_t sessionGeneration = 0;
		uint32_t threadId = 0;
		RegisterSet registers{};
		CheckpointThreadEnvironment environment{};
		std::vector<CheckpointRegion> regions;
		size_t byteSize = 0;
	};
	std::mutex checkpointMutex_;
	std::unordered_map<uint64_t, Checkpoint> checkpoints_;
	uint64_t nextCheckpointId_ = 1;
	size_t checkpointBytes_ = 0;

	// Temp breakpoint for StepOver CALL skip (guarded by eventMutex_)
	uint32_t tempStepOverBpId_ = 0;

	// Step completion synchronization
	std::mutex stepMutex_;
	std::condition_variable stepCv_;
	bool stepCompleted_ = false;
	uint64_t stepCompletedAddr_ = 0;
	uint32_t stepCompletedThread_ = 0;

	// Event queue for thread-safe notification delivery
	std::queue<std::pair<std::string, json>> pendingEvents_;
	std::queue<uint32_t> pendingAutoContinue_; // threadIds to auto-continue (from condition/logpoint)
	struct PendingBreakpointAction { uint32_t threadId; json steps; };
	std::queue<PendingBreakpointAction> pendingBreakpointActions_;
	std::mutex eventMutex_;
	void FlushEvents();
	void StoreBreakpointAction(uint32_t breakpointId, const json& action);

	// Exception filter: codes to auto-pass to SEH (set by veh_continue ignore_exceptions)
	std::vector<uint32_t> ignoreExceptionCodes_;
	std::mutex filterMutex_;

	// BP actions: breakpoint ID -> action steps (executed on hit, then auto-continue)
	std::unordered_map<uint32_t, json> bpActions_;  // guarded by session_.GetBpMutex()

	// Deferred BP retry: single persistent worker + condvar.
	// ModuleLoaded (reader thread) only signals via NotifyRetry() -- it never touches
	// the BP mutex or the std::thread object, so reader/tool/main races on the thread
	// object are eliminated. The worker lives for the McpServer lifetime (each tool call
	// runs on its own thread, so ad-hoc spawn/join was unsafe). Created/joined exactly once.
	std::thread retryThread_;
	std::mutex retryMutex_;
	std::condition_variable retryCv_;
	bool retryWake_ = false;   // guarded by retryMutex_
	bool retryStop_ = false;   // guarded by retryMutex_
	void StartRetryThread();
	void StopRetryThread();
	void RetryThreadLoop();
	void NotifyRetry();
	void RetryPendingBreakpointsOnce();
};

} // namespace veh
