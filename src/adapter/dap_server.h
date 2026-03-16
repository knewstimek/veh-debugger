#pragma once
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "dap_types.h"
#include "transport.h"
#include "pipe_client.h"
#include "injector.h"
#include "disassembler.h"

namespace veh::dap {

class DapServer {
public:
	DapServer();

	void SetTransport(Transport* transport);
	void Run();
	void Stop();

private:
	// DAP message handling
	void OnMessage(const std::string& jsonStr);
	void HandleRequest(const Request& req);
	void SendResponse(const Response& resp);
	void SendEvent(const std::string& event, const json& body = json::object());

	// DAP command handlers
	void OnInitialize(const Request& req);
	void OnLaunch(const Request& req);
	void OnAttach(const Request& req);
	void OnDisconnect(const Request& req);
	void OnTerminate(const Request& req);
	void OnConfigurationDone(const Request& req);

	void OnSetBreakpoints(const Request& req);
	void OnSetFunctionBreakpoints(const Request& req);
	void OnSetExceptionBreakpoints(const Request& req);
	void OnSetInstructionBreakpoints(const Request& req);
	void OnSetDataBreakpoints(const Request& req);
	void OnDataBreakpointInfo(const Request& req);

	void OnContinue(const Request& req);
	void OnNext(const Request& req);
	void OnStepIn(const Request& req);
	void OnStepOut(const Request& req);
	void OnPause(const Request& req);

	void OnThreads(const Request& req);
	void OnStackTrace(const Request& req);
	void OnScopes(const Request& req);
	void OnVariables(const Request& req);
	void OnEvaluate(const Request& req);

	void OnModules(const Request& req);
	void OnLoadedSources(const Request& req);
	void OnExceptionInfo(const Request& req);

	void OnReadMemory(const Request& req);
	void OnWriteMemory(const Request& req);
	void OnDisassemble(const Request& req);

	// 추가 DAP 명령
	void OnRestart(const Request& req);
	void OnCancel(const Request& req);
	void OnTerminateThreads(const Request& req);
	void OnGoto(const Request& req);
	void OnGotoTargets(const Request& req);
	void OnSource(const Request& req);
	void OnCompletions(const Request& req);

	// IPC event handling (from VEH DLL)
	void OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size);

	// Helpers
	std::string GetDllPath();
	void Cleanup();

	Transport* transport_ = nullptr;
	PipeClient pipeClient_;
	std::unique_ptr<veh::IDisassembler> disassembler_ = veh::CreateDisassembler();
	std::atomic<bool> running_{false};
	std::atomic<bool> initialized_{false};
	std::atomic<bool> configured_{false};
	std::atomic<int> seq_{1};

	// Session state
	uint32_t targetPid_ = 0;
	HANDLE targetProcess_ = nullptr;
	bool launchedByUs_ = false;
	bool stopOnEntry_ = false;
	std::string programPath_;
	InjectionMethod injectionMethod_ = InjectionMethod::Auto;

	// Variable references
	// Format: high 16 bits = scope type, low 16 bits = thread/frame id
	// Scope types: 1=registers, 2=locals(memory), 3=modules
	static constexpr int SCOPE_REGISTERS = 0x10000000;
	static constexpr int SCOPE_MEMORY    = 0x20000000;
	static constexpr int SCOPE_MASK      = 0xF0000000;

	// Track last exception for exceptionInfo
	struct LastException {
		uint32_t threadId = 0;
		uint32_t code = 0;
		std::string description;
	} lastException_;

	// Breakpoint ID mapping (DAP source breakpoints → VEH breakpoint IDs)
	struct BreakpointMapping {
		int dapId;
		uint32_t vehId;
		uint64_t address;
		std::string source;
	};
	std::vector<BreakpointMapping> breakpointMappings_;
	int nextDapBpId_ = 1;

	// Data breakpoint (hardware watchpoint) mapping
	struct DataBreakpointMapping {
		int dapId;
		uint32_t vehId;
		uint64_t address;
		uint8_t type;  // 0=exec, 1=write, 2=readwrite
		uint8_t size;
	};
	std::vector<DataBreakpointMapping> dataBreakpointMappings_;
};

} // namespace veh::dap
