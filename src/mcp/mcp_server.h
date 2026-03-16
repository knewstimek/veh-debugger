#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <vector>
#include <mutex>
#include <queue>
#include "adapter/transport.h"
#include "adapter/pipe_client.h"
#include "adapter/injector.h"
#include "adapter/disassembler.h"
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

	// Tool implementations (19 tools)
	json ToolAttach(const json& args);
	json ToolLaunch(const json& args);
	json ToolDetach(const json& args);
	json ToolSetBreakpoint(const json& args);
	json ToolRemoveBreakpoint(const json& args);
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

	// Tool list definition
	json GetToolsList();

	// IPC event handler (breakpoint hit, etc.)
	void OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size);

	// Helper
	std::string GetExeDir();
	std::string ResolveDll(const std::string& dir, bool use32);
	std::string GetDllPath(uint32_t pid);
	std::string GetDllPathForExe(const std::string& exePath);
	bool ParseAddress(const std::string& addrStr, uint64_t& out);

	dap::Transport* transport_ = nullptr;
	PipeClient pipeClient_;
	std::unique_ptr<IDisassembler> disassembler_ = CreateDisassembler();
	std::atomic<bool> running_{false};

	// Session state
	uint32_t targetPid_ = 0;
	HANDLE targetProcess_ = nullptr;
	std::atomic<bool> attached_{false};
	std::atomic<bool> launchedByUs_{false};

	// Breakpoint tracking
	struct BpMapping { uint32_t id; uint64_t address; };
	std::vector<BpMapping> swBreakpoints_;
	struct HwBpMapping { uint32_t id; uint64_t address; uint8_t type; uint8_t size; };
	std::vector<HwBpMapping> hwBreakpoints_;

	std::mutex sendMutex_;

	// Event queue for thread-safe notification delivery
	std::queue<std::pair<std::string, json>> pendingEvents_;
	std::mutex eventMutex_;
	void FlushEvents();
};

} // namespace veh
