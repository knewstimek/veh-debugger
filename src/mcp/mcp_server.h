#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include "adapter/transport.h"
#include "debug_session.h"
#include "common/ipc_protocol.h"
#include <nlohmann/json.hpp>

namespace veh {

using json = nlohmann::json;

class McpServer {
public:
	McpServer();
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

	// Tool implementations (31 tools + veh_batch)
	json ToolAttach(const json& args);
	json ToolLaunch(const json& args);
	json ToolDetach(const json& args);
	json ToolSetBreakpoint(const json& args);
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
	json ToolWriteMemory(const json& args);
	json ToolModules(const json& args);
	json ToolDisassemble(const json& args);
	json ToolEnumLocals(const json& args);
	json ToolEvaluate(const json& args);
	json ToolSetRegister(const json& args);
	json ToolExceptionInfo(const json& args);
	json ToolTraceCallers(const json& args);
	json ToolDumpMemory(const json& args);
	json ToolAllocateMemory(const json& args);
	json ToolFreeMemory(const json& args);
	json ToolExecuteShellcode(const json& args);
	json ToolBatch(const json& args);
	json ToolTraceRegister(const json& args);
	json ToolTraceMemory(const json& args);
	json ToolResolveImports(const json& args);
	json ToolTraceCalls(const json& args);

	// Tool list definition
	json GetToolsList();

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

	dap::Transport* transport_ = nullptr;
	DebugSession session_;
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
	std::mutex eventMutex_;
	void FlushEvents();

	// Exception filter: codes to auto-pass to SEH (set by veh_continue ignore_exceptions)
	std::vector<uint32_t> ignoreExceptionCodes_;
	std::mutex filterMutex_;

	// BP actions: breakpoint ID -> action steps (executed on hit, then auto-continue)
	std::unordered_map<uint32_t, json> bpActions_;  // guarded by session_.GetBpMutex()
};

} // namespace veh
