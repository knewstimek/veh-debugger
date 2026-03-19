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
#include "symbol_engine.h"

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
	void OnSetVariable(const Request& req);

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
	void ResumeMainThread();
	void Cleanup(bool detachOnly = false);

	Transport* transport_ = nullptr;
	PipeClient pipeClient_;
	std::unique_ptr<veh::IDisassembler> disassembler_ = veh::CreateDisassembler();
	veh::SymbolEngine symbolEngine_;
	bool symbolEngineReady_ = false;
	std::atomic<bool> running_{false};
	std::atomic<bool> initialized_{false};
	std::atomic<bool> configured_{false};
	std::atomic<int> seq_{1};

	// Session state
	uint32_t targetPid_ = 0;
	HANDLE targetProcess_ = nullptr;
	bool launchedByUs_ = false;
	bool stopOnEntry_ = false;
	uint32_t launchedMainThreadId_ = 0;  // OS 스레드 ID (CREATE_SUSPENDED 상태)
	bool mainThreadResumed_ = false;     // configurationDone 또는 continue에서 resume 완료
	std::string programPath_;
	std::string launchArgStr_;   // restart 시 인자 보존용
	std::string launchCwd_;      // restart 시 작업 디렉토리 보존용
	InjectionMethod injectionMethod_ = InjectionMethod::Auto;

	// Variable references
	// Format: SCOPE_MASK 비트 = scope type, 나머지 비트 = frameId (frameMap_의 key)
	// Scope types: 1=registers, 2=locals, 3=reserved
	static constexpr int SCOPE_REGISTERS = 0x10000000;
	static constexpr int SCOPE_LOCALS    = 0x20000000;
	static constexpr int SCOPE_MASK      = 0xF0000000;

	// Track last exception for exceptionInfo
	struct LastException {
		uint32_t threadId = 0;
		uint32_t code = 0;
		std::string description;
	} lastException_;

	// Breakpoint ID mapping (DAP → VEH breakpoint IDs)
	// BpType으로 구분하여 setBreakpoints/setFunctionBreakpoints/setInstructionBreakpoints가
	// 서로의 BP를 잘못 제거하지 않도록 함 (DAP 스펙: 각 요청은 해당 타입만 full-replace)
	enum class BpType { Source, Function, Instruction };
	struct BreakpointMapping {
		int dapId;
		uint32_t vehId;
		uint64_t address;
		std::string source;
		std::string condition;
		std::string hitCondition;
		uint32_t hitCount = 0;
		std::string logMessage;
		BpType type = BpType::Source;
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

	// Mutex for breakpointMappings_ and dataBreakpointMappings_ (accessed from both DAP and IPC event threads)
	std::mutex breakpointMutex_;

	// Mutex for frameMap_/nextFrameId_ (accessed from DAP and IPC event threads)
	std::mutex frameMutex_;

	// Mutex for transport send ordering (seq_ increment + send must be atomic)
	std::mutex sendMutex_;

	// Mutex for lastException_ (written by IPC thread, read by DAP thread)
	std::mutex exceptionMutex_;

	// Frame ID → (threadId, frameIndex) 매핑
	// Windows 스레드 ID는 16비트를 초과할 수 있어(예: 169644) 비트 패킹 불가.
	// 순차 ID를 발급하고 맵으로 원래 threadId/frameIndex를 복원한다.
	struct FrameInfo {
		uint32_t threadId;
		int frameIndex;
		uint64_t instructionAddress;  // RIP of the frame (for EnumLocals)
		uint64_t frameBase;           // RBP/frame base (for EnumLocals)
	};
	std::unordered_map<int, FrameInfo> frameMap_;
	int nextFrameId_ = 1;

	// Last stopped thread for evaluate context
	std::atomic<uint32_t> lastStoppedThreadId_{0};

	// Source-line stepping state (instruction-level → source-line 변환)
	// DAP 스레드(쓰기)와 Reader 스레드(읽기/쓰기) 모두 접근
	// steppingMutex_로 보호 — DAP thread가 OnNext/OnStepIn 등에서 설정, Reader thread가 StepCompleted/BreakpointHit에서 읽기
	std::mutex steppingMutex_;
	enum class SteppingMode { None, Over, In, Out };
	SteppingMode steppingMode_ = SteppingMode::None;
	uint32_t steppingThreadId_ = 0;
	bool steppingInstruction_ = false; // granularity=="instruction" → 인스트럭션 단위 스텝
	uint64_t steppingStartAddr_ = 0;     // 현재 라인의 시작 주소
	uint64_t steppingNextLineAddr_ = 0;  // 다음 라인의 시작 주소
	uint32_t steppingSourceLine_ = 0;    // 스텝 시작 소스 라인
	std::string steppingSourceFile_;     // 스텝 시작 소스 파일

	// StepOver용 임시 브레이크포인트 (call 건너뛰기)
	uint32_t stepOverTempBpId_ = 0;      // VEH BP ID (0이면 없음)
	uint64_t stepOverTempBpAddr_ = 0;    // 주소 기반 추적 (auto-step에서 fire-and-forget)



	// DAP 스레드에서 호출: 현재 top frame의 소스 라인 범위를 미리 resolve
	void ResolveStepRange(uint32_t threadId);
	// 현재 스레드의 top frame 소스 라인 조회
	bool GetTopFrameSourceLine(uint32_t threadId, std::string& file, uint32_t& line);
	// 현재 RIP의 명령어가 CALL인지 판별 + 리턴주소 계산
	bool IsCallInstruction(uint32_t threadId, uint64_t& nextInsnAddr);
	// BP rearm 시 다음 명령어가 CALL인지 판별 (2-instruction 실행 문제 대응)
	bool IsNextInstructionCall(uint32_t threadId, uint64_t& addrAfterCall);
	// 이전 스텝의 좀비 temp BP 정리 (ID 또는 주소 기반)
	void CleanupStaleTempBp();

	// Condition evaluation helpers
	bool EvaluateCondition(const std::string& condition, uint32_t threadId, const RegisterSet* cachedRegs = nullptr);
	uint64_t ResolveRegisterByName(const std::string& name, const RegisterSet& regs);
	bool TryParseRegisterName(const std::string& name);
	std::string ExpandLogMessage(const std::string& msg, uint32_t threadId, const RegisterSet* cachedRegs = nullptr);

	// Process exit monitor
	void StartProcessMonitor();
	void StopProcessMonitor();
	std::thread processMonitorThread_;
};

} // namespace veh::dap
