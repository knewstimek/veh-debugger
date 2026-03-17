#include "dap_server.h"
#include "logger.h"
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <set>

// VEH_DAP_TRACE: 파일 기반 DAP 디버그 로그 (cmake -DVEH_DAP_TRACE=ON)
#ifdef VEH_DAP_TRACE
namespace {
void DumpToFile(const char* tag, const std::string& msg) {
	std::ofstream f("C:\\tmp\\veh_dap_trace.log", std::ios::app);
	if (f.is_open()) f << "[" << tag << "] " << msg << "\n";
}
}
#define DAP_TRACE(tag, msg) DumpToFile(tag, msg)
#else
#define DAP_TRACE(tag, msg) ((void)0)
#endif

// base64 인코딩 (readMemory 응답용)
namespace {
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string Base64Encode(const uint8_t* data, size_t len) {
	std::string result;
	result.reserve((len + 2) / 3 * 4);
	for (size_t i = 0; i < len; i += 3) {
		uint32_t n = (uint32_t)data[i] << 16;
		if (i + 1 < len) n |= (uint32_t)data[i + 1] << 8;
		if (i + 2 < len) n |= data[i + 2];
		result += b64chars[(n >> 18) & 0x3F];
		result += b64chars[(n >> 12) & 0x3F];
		result += (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
		result += (i + 2 < len) ? b64chars[n & 0x3F] : '=';
	}
	return result;
}
std::vector<uint8_t> Base64Decode(const std::string& s) {
	std::vector<uint8_t> result;
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++) T[b64chars[i]] = i;
	int val = 0, valb = -8;
	for (uint8_t c : s) {
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			result.push_back((val >> valb) & 0xFF);
			valb -= 8;
		}
	}
	return result;
}
} // anonymous namespace

namespace veh::dap {

DapServer::DapServer() = default;

void DapServer::SetTransport(Transport* transport) {
	transport_ = transport;
	transport_->SetMessageCallback([this](const std::string& json) {
		OnMessage(json);
	});
}

void DapServer::Run() {
	running_ = true;
	transport_->Start();

	// 메인 루프 — transport가 종료될 때까지 대기
	while (running_) {
		Sleep(100);
	}

	Cleanup();
}

void DapServer::Stop() {
	running_ = false;
}

void DapServer::OnMessage(const std::string& jsonStr) {
	try {
		json j = json::parse(jsonStr);
		if (j.value("type", "") == "request") {
			Request req;
			req.seq = j.value("seq", 0);
			req.command = j.value("command", "");
			req.arguments = j.value("arguments", json::object());
			HandleRequest(req);
		}
	} catch (const std::exception& e) {
		LOG_ERROR("JSON parse error: %s", e.what());
	}
}

void DapServer::HandleRequest(const Request& req) {
	LOG_DEBUG("Request: %s (seq=%d)", req.command.c_str(), req.seq);
	DAP_TRACE("REQUEST", req.command + " | " + req.arguments.dump());

	// 명령어 디스패치
	#define HANDLE_CMD(name, fn) if (req.command == name) { fn(req); return; }
	HANDLE_CMD("initialize",              OnInitialize)
	HANDLE_CMD("launch",                  OnLaunch)
	HANDLE_CMD("attach",                  OnAttach)
	HANDLE_CMD("disconnect",              OnDisconnect)
	HANDLE_CMD("terminate",               OnTerminate)
	HANDLE_CMD("configurationDone",       OnConfigurationDone)
	HANDLE_CMD("setBreakpoints",          OnSetBreakpoints)
	HANDLE_CMD("setFunctionBreakpoints",  OnSetFunctionBreakpoints)
	HANDLE_CMD("setExceptionBreakpoints", OnSetExceptionBreakpoints)
	HANDLE_CMD("setInstructionBreakpoints", OnSetInstructionBreakpoints)
	HANDLE_CMD("setDataBreakpoints",      OnSetDataBreakpoints)
	HANDLE_CMD("dataBreakpointInfo",      OnDataBreakpointInfo)
	HANDLE_CMD("continue",                OnContinue)
	HANDLE_CMD("next",                    OnNext)
	HANDLE_CMD("stepIn",                  OnStepIn)
	HANDLE_CMD("stepOut",                 OnStepOut)
	HANDLE_CMD("pause",                   OnPause)
	HANDLE_CMD("threads",                 OnThreads)
	HANDLE_CMD("stackTrace",              OnStackTrace)
	HANDLE_CMD("scopes",                  OnScopes)
	HANDLE_CMD("variables",               OnVariables)
	HANDLE_CMD("evaluate",                OnEvaluate)
	HANDLE_CMD("setVariable",             OnSetVariable)
	HANDLE_CMD("modules",                 OnModules)
	HANDLE_CMD("loadedSources",           OnLoadedSources)
	HANDLE_CMD("exceptionInfo",           OnExceptionInfo)
	HANDLE_CMD("readMemory",              OnReadMemory)
	HANDLE_CMD("writeMemory",             OnWriteMemory)
	HANDLE_CMD("disassemble",             OnDisassemble)
	HANDLE_CMD("restart",                 OnRestart)
	HANDLE_CMD("cancel",                  OnCancel)
	HANDLE_CMD("terminateThreads",        OnTerminateThreads)
	HANDLE_CMD("goto",                    OnGoto)
	HANDLE_CMD("gotoTargets",             OnGotoTargets)
	HANDLE_CMD("source",                  OnSource)
	HANDLE_CMD("completions",             OnCompletions)
	#undef HANDLE_CMD

	// Unknown command
	{
		Response resp;
		resp.request_seq = req.seq;
		resp.command = req.command;
		resp.success = false;
		resp.message = "Unsupported command: " + req.command;
		SendResponse(resp);
	}
}

void DapServer::SendResponse(const Response& resp) {
	json j = {
		{"seq", 0},  // placeholder
		{"type", "response"},
		{"request_seq", resp.request_seq},
		{"success", resp.success},
		{"command", resp.command},
		{"body", resp.body},
	};
	if (!resp.success && !resp.message.empty()) {
		j["message"] = resp.message;
	}
	{
		std::lock_guard<std::mutex> lock(sendMutex_);
		j["seq"] = seq_++;
		transport_->Send(j.dump());
	}
}

void DapServer::SendEvent(const std::string& event, const json& body) {
	json j = {
		{"seq", 0},  // placeholder
		{"type", "event"},
		{"event", event},
		{"body", body},
	};
	{
		std::lock_guard<std::mutex> lock(sendMutex_);
		j["seq"] = seq_++;
		transport_->Send(j.dump());
	}
}

// --- Lifecycle ---

void DapServer::OnInitialize(const Request& req) {
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "initialize";
	resp.body = MakeCapabilities();
	SendResponse(resp);

	initialized_ = true;
	SendEvent("initialized");
}

void DapServer::OnLaunch(const Request& req) {
	programPath_ = req.arguments.value("program", "");
	std::string cwd = req.arguments.value("cwd", "");
	stopOnEntry_ = req.arguments.value("stopOnEntry", false);
	injectionMethod_ = ParseInjectionMethod(req.arguments.value("injectionMethod", "auto"));

	// args 배열을 공백 구분 문자열로 변환 (Windows CommandLineToArgvW 규칙)
	std::string argStr;
	if (req.arguments.contains("args") && req.arguments["args"].is_array()) {
		for (auto& a : req.arguments["args"]) {
			if (!a.is_string()) continue;
			if (!argStr.empty()) argStr += " ";
			std::string arg = a.get<std::string>();
			if (arg.find_first_of(" \t\\\"") != std::string::npos) {
				std::string quoted = "\"";
				int nbs = 0;
				for (char c : arg) {
					if (c == '\\')
						nbs++;
					else if (c == '\"') {
						for (int j = 0; j < nbs; j++) quoted += "\\\\";
						quoted += "\\\"";
						nbs = 0;
					} else {
						for (int j = 0; j < nbs; j++) quoted += "\\";
						quoted += c;
						nbs = 0;
					}
				}
				for (int j = 0; j < nbs; j++) quoted += "\\\\";
				quoted += "\"";
				argStr += quoted;
			} else {
				argStr += arg;
			}
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "launch";

	if (programPath_.empty()) {
		resp.success = false;
		resp.message = "No 'program' specified in launch configuration";
		SendResponse(resp);
		return;
	}

	// restart 시 재사용을 위해 저장
	launchArgStr_ = argStr;
	launchCwd_ = cwd;

	std::string dllPath = GetDllPath();
	auto result = Injector::LaunchAndInject(programPath_, argStr, cwd, dllPath, injectionMethod_);

	if (result.pid == 0) {
		resp.success = false;
		resp.message = "Failed to launch and inject: " + programPath_;
		SendResponse(resp);
		return;
	}

	targetPid_ = result.pid;
	launchedMainThreadId_ = result.mainThreadId;
	mainThreadResumed_ = false;
	launchedByUs_ = true;

	// 프로세스 핸들 (ReadProcessMemory용 — StepOver CALL 판별 등)
	targetProcess_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPid_);
	if (!targetProcess_) {
		LOG_WARN("OpenProcess for VM_READ failed: %u", GetLastError());
	}

	// PDB 심볼 엔진 초기화 (인라인 프레임 기반 StepOver용)
	if (targetProcess_) {
		symbolEngineReady_ = symbolEngine_.Initialize(targetProcess_);
		if (!symbolEngineReady_) {
			LOG_WARN("SymbolEngine init failed, PDB step will use fallback");
		}
	}

	// VEH DLL과 파이프 연결
	if (!pipeClient_.Connect(targetPid_, 10000)) {
		resp.success = false;
		resp.message = "Failed to connect to VEH DLL pipe";
		SendResponse(resp);
		return;
	}

	// 이벤트 리스너 + 하트비트 시작
	pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();

	resp.success = true;
	SendResponse(resp);

	LOG_INFO("Launched process PID=%u, DLL injected", targetPid_);
}

void DapServer::OnAttach(const Request& req) {
	targetPid_ = req.arguments.value("processId", 0);
	injectionMethod_ = ParseInjectionMethod(req.arguments.value("injectionMethod", "auto"));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "attach";

	if (targetPid_ == 0) {
		resp.success = false;
		resp.message = "No 'processId' specified";
		SendResponse(resp);
		return;
	}

	std::string dllPath = GetDllPath();
	if (!Injector::InjectDll(targetPid_, dllPath, injectionMethod_)) {
		resp.success = false;
		resp.message = "Failed to inject DLL into PID " + std::to_string(targetPid_);
		SendResponse(resp);
		return;
	}

	launchedByUs_ = false;
	targetProcess_ = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, targetPid_);

	// PDB 심볼 엔진 초기화 (인라인 프레임 기반 StepOver용)
	if (targetProcess_) {
		symbolEngineReady_ = symbolEngine_.Initialize(targetProcess_);
		if (!symbolEngineReady_) {
			LOG_WARN("SymbolEngine init failed, PDB step will use fallback");
		}
	}

	if (!pipeClient_.Connect(targetPid_, 10000)) {
		resp.success = false;
		resp.message = "Failed to connect to VEH DLL pipe";
		SendResponse(resp);
		return;
	}

	pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();

	resp.success = true;
	SendResponse(resp);

	LOG_INFO("Attached to PID=%u", targetPid_);
}

void DapServer::OnDisconnect(const Request& req) {
	bool terminateDebuggee = req.arguments.value("terminateDebuggee", launchedByUs_);

	// 응답을 Cleanup보다 먼저 전송한다.
	// Cleanup()은 DLL에 Shutdown/Detach IPC를 보내고 파이프를 닫는데,
	// reader thread join 등으로 수 초간 블로킹될 수 있다.
	// 그 동안 VSCode가 disconnect 응답을 못 받으면 Stop 버튼이 반응 없는 것처럼 보인다.
	// 응답을 먼저 보내면 VSCode는 즉시 세션 종료 UI를 갱신하고,
	// 어댑터는 이후 Cleanup을 정상 수행한 뒤 프로세스를 종료한다.
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "disconnect";
	resp.success = true;
	SendResponse(resp);

	// terminateDebuggee=false (detach): DLL에 Detach 전송 → 파이프 서버 유지 (재연결 가능)
	// terminateDebuggee=true (종료): DLL에 Shutdown 전송 → 파이프 서버도 종료
	bool detachOnly = !terminateDebuggee;
	Cleanup(detachOnly);

	if (terminateDebuggee && targetPid_) {
		HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
		if (proc) {
			TerminateProcess(proc, 0);
			CloseHandle(proc);
		}
	}

	running_ = false;
}

void DapServer::OnTerminate(const Request& req) {
	// VSCode Stop 흐름: terminate 요청 → terminate 응답 → terminated 이벤트 → disconnect 요청
	// terminated 이벤트를 보내지 않으면 VSCode가 disconnect를 보내지 않아
	// 사용자가 Stop을 두 번 눌러야 세션이 종료된다.
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "terminate";
	resp.success = true;
	SendResponse(resp);

	if (targetPid_) {
		HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
		if (proc) {
			TerminateProcess(proc, 0);
			CloseHandle(proc);
		}
	}

	// terminated 이벤트를 보내야 VSCode가 자동으로 disconnect를 이어서 보냄
	SendEvent("terminated");
}

void DapServer::OnConfigurationDone(const Request& req) {
	configured_ = true;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "configurationDone";
	resp.success = true;
	SendResponse(resp);

	// Launch 모드: 메인 스레드가 CREATE_SUSPENDED 상태
	// setBreakpoints가 이미 완료된 상태이므로 이제 안전하게 resume 가능
	if (launchedByUs_ && launchedMainThreadId_ != 0 && !mainThreadResumed_) {
		if (stopOnEntry_) {
			// stopOnEntry: 메인 스레드는 suspended 유지, stopped 이벤트만 전송
			// 사용자가 Continue 누르면 OnContinue에서 resume
			LOG_INFO("stopOnEntry: main thread %u stays suspended", launchedMainThreadId_);
			SendEvent("stopped", {
				{"reason", "entry"},
				{"threadId", 1},
				{"allThreadsStopped", true},
			});
		} else {
			// stopOnEntry=false: 메인 스레드 resume → BP 히트 시 stopped 이벤트
			ResumeMainThread();
		}
	}
}

// --- Breakpoints ---

void DapServer::OnSetBreakpoints(const Request& req) {
	// DAP에서는 setBreakpoints가 전체 교체 방식
	DAP_TRACE("setBreakpoints", req.arguments.dump());
	std::lock_guard<std::mutex> lock(breakpointMutex_);

	std::string sourceFile;
	if (req.arguments.contains("source") && req.arguments["source"].contains("path")) {
		sourceFile = req.arguments["source"]["path"].get<std::string>();
	}

	// 1단계: 새 BP 목록의 주소를 먼저 해석
	auto bps = req.arguments.value("breakpoints", json::array());
	struct ResolvedBp {
		uint64_t address = 0;
		int line = 0;
		std::string condition;
		std::string hitCondition;
		std::string logMessage;
		std::string errorMsg;
	};
	std::vector<ResolvedBp> resolvedBps;
	resolvedBps.reserve(bps.size());

	for (auto& bp : bps) {
		ResolvedBp rb;
		rb.condition = bp.value("condition", "");
		rb.hitCondition = bp.value("hitCondition", "");
		rb.logMessage = bp.value("logMessage", "");

		if (bp.contains("instructionReference")) {
			rb.address = ParseAddress(bp["instructionReference"].get<std::string>());
		} else if (bp.contains("line")) {
			rb.line = bp["line"].get<int>();
			if (!sourceFile.empty() && rb.line > 0) {
				ResolveSourceLineRequest resolveReq = {};
				strncpy_s(resolveReq.fileName, sourceFile.c_str(), sizeof(resolveReq.fileName) - 1);
				resolveReq.line = rb.line;

				std::vector<uint8_t> resolveResp;
				if (pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), resolveResp)
					&& resolveResp.size() >= sizeof(ResolveSourceLineResponse)) {
					auto* resp2 = reinterpret_cast<const ResolveSourceLineResponse*>(resolveResp.data());
					if (resp2->status == IpcStatus::Ok) {
						rb.address = resp2->address;
						DAP_TRACE("resolveSourceLine", sourceFile + ":" + std::to_string(rb.line) + " -> " + FormatAddress(rb.address));
					}
				}
				if (rb.address == 0) {
					rb.errorMsg = "No PDB symbol found for " + sourceFile + ":" + std::to_string(rb.line);
				}
			} else {
				rb.errorMsg = "Source path and line required";
			}
		}
		if (rb.address == 0 && rb.errorMsg.empty()) {
			rb.errorMsg = "Invalid address";
		}
		resolvedBps.push_back(std::move(rb));
	}

	// 2단계: 새 목록에 없는 기존 BP만 제거 (diff 기반)
	std::set<uint64_t> newAddresses;
	for (auto& rb : resolvedBps) {
		if (rb.address != 0) newAddresses.insert(rb.address);
	}

	std::vector<uint64_t> changedAddresses; // BP 설정/해제로 메모리가 변경된 주소
	for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end(); ) {
		if (it->source == sourceFile && newAddresses.find(it->address) == newAddresses.end()) {
			DAP_TRACE("RemoveSourceBP", "vehId=" + std::to_string(it->vehId) + " addr=" + FormatAddress(it->address));
			changedAddresses.push_back(it->address);
			RemoveBreakpointRequest rmReq;
			rmReq.id = it->vehId;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			it = breakpointMappings_.erase(it);
		} else {
			++it;
		}
	}

	// 3단계: 새 BP 설정 (이미 존재하는 주소는 재사용)
	json breakpointsJson = json::array();

	for (auto& rb : resolvedBps) {
		if (!rb.errorMsg.empty()) {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = rb.errorMsg;
			breakpointsJson.push_back(dbp.ToJson());
			continue;
		}

		// 이미 같은 주소에 BP가 있으면 재사용 (조건만 업데이트)
		bool found = false;
		for (auto& m : breakpointMappings_) {
			if (m.source == sourceFile && m.address == rb.address) {
				m.condition = rb.condition;
				m.hitCondition = rb.hitCondition;
				m.logMessage = rb.logMessage;

				Breakpoint dbp;
				dbp.id = m.dapId;
				dbp.verified = true;
				dbp.instructionReference = rb.address;
				breakpointsJson.push_back(dbp.ToJson());
				found = true;
				DAP_TRACE("ReuseBP", "addr=" + FormatAddress(rb.address) + " dapId=" + std::to_string(m.dapId));
				break;
			}
		}
		if (found) continue;

		// 새 BP 설정
		SetBreakpointRequest setReq;
		setReq.address = rb.address;

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &setReq, sizeof(setReq), respData)) {
			if (respData.size() >= sizeof(SetBreakpointResponse)) {
				auto* setResp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
				Breakpoint dbp;
				dbp.id = nextDapBpId_++;
				dbp.verified = (setResp->status == IpcStatus::Ok);
				dbp.instructionReference = rb.address;
				DAP_TRACE("SetBreakpoint", "addr=" + FormatAddress(rb.address) + " vehId=" + std::to_string(setResp->id) + " verified=" + (dbp.verified ? "true" : "false"));

				breakpointMappings_.push_back({dbp.id, setResp->id, rb.address, sourceFile, rb.condition, rb.hitCondition, 0, rb.logMessage});
				breakpointsJson.push_back(dbp.ToJson());
				changedAddresses.push_back(rb.address);
			}
		} else {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "IPC error";
			breakpointsJson.push_back(dbp.ToJson());
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setBreakpoints";
	resp.success = true;
	resp.body = {{"breakpoints", breakpointsJson}};
	SendResponse(resp);

	// BP 설정/해제로 메모리가 변경된 주소에 대해 memory 이벤트 전송
	// → VSCode 디스어셈블리 뷰가 해당 주소를 다시 읽어 0xCC 잔존 문제 해결
	for (uint64_t addr : changedAddresses) {
		SendEvent("memory", {
			{"memoryReference", FormatAddress(addr)},
			{"offset", 0},
			{"count", 1},
		});
	}
}

void DapServer::OnSetFunctionBreakpoints(const Request& req) {
	std::lock_guard<std::mutex> lock(breakpointMutex_);
	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

	// 기존 function breakpoint 제거 (DAP: 전체 교체 방식)
	for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end(); ) {
		if (it->type == BpType::Function) {
			RemoveBreakpointRequest rmReq;
			rmReq.id = it->vehId;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			it = breakpointMappings_.erase(it);
		} else {
			++it;
		}
	}

	for (auto& bp : bps) {
		std::string funcName = bp.value("name", "");
		if (funcName.empty()) {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "Function name required";
			breakpointsJson.push_back(dbp.ToJson());
			continue;
		}

		// PDB 심볼로 함수명 → 주소 해석
		ResolveFunctionRequest resolveReq = {};
		strncpy_s(resolveReq.functionName, funcName.c_str(), sizeof(resolveReq.functionName) - 1);

		uint64_t address = 0;
		std::vector<uint8_t> resolveResp;
		if (pipeClient_.SendAndReceive(IpcCommand::ResolveFunction, &resolveReq, sizeof(resolveReq), resolveResp)) {
			if (resolveResp.size() >= sizeof(ResolveFunctionResponse)) {
				auto* resp2 = reinterpret_cast<const ResolveFunctionResponse*>(resolveResp.data());
				if (resp2->status == IpcStatus::Ok) {
					address = resp2->address;
				}
			}
		}

		if (address == 0) {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "Symbol not found: " + funcName;
			breakpointsJson.push_back(dbp.ToJson());
			continue;
		}

		// INT3 브레이크포인트 설정
		SetBreakpointRequest setReq;
		setReq.address = address;

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &setReq, sizeof(setReq), respData)) {
			if (respData.size() >= sizeof(SetBreakpointResponse)) {
				auto* setResp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
				Breakpoint dbp;
				dbp.id = nextDapBpId_++;
				dbp.verified = (setResp->status == IpcStatus::Ok);
				dbp.instructionReference = address;

				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}, {}, {}, 0, {}, BpType::Function});
				breakpointsJson.push_back(dbp.ToJson());
			}
		} else {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "IPC error setting breakpoint on " + funcName;
			breakpointsJson.push_back(dbp.ToJson());
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setFunctionBreakpoints";
	resp.success = true;
	resp.body = {{"breakpoints", breakpointsJson}};
	SendResponse(resp);
}

void DapServer::OnSetExceptionBreakpoints(const Request& req) {
	// 예외 필터 설정 (all / uncaught)
	// VEH 핸들러에서 처리
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setExceptionBreakpoints";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnSetInstructionBreakpoints(const Request& req) {
	DAP_TRACE("setInstructionBreakpoints", req.arguments.dump());
	std::lock_guard<std::mutex> lock(breakpointMutex_);
	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

	// 기존 instruction breakpoint 제거 (전체 교체 방식)
	for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end(); ) {
		if (it->type == BpType::Instruction) {
			RemoveBreakpointRequest rmReq;
			rmReq.id = it->vehId;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			it = breakpointMappings_.erase(it);
		} else {
			++it;
		}
	}

	LOG_DEBUG("setInstructionBreakpoints: %u breakpoints, raw=%s",
		(unsigned)bps.size(), req.arguments.dump().c_str());

	for (auto& bp : bps) {
		std::string instrRef = bp.value("instructionReference", std::string(""));
		int64_t offset = bp.value("offset", (int64_t)0);
		LOG_DEBUG("  bp instrRef='%s' offset=%lld raw=%s", instrRef.c_str(), offset, bp.dump().c_str());

		uint64_t address = 0;
		if (!instrRef.empty()) {
			try {
				address = std::stoull(instrRef, nullptr, 0);
				// VSCode 디스어셈블리 뷰는 instructionReference + offset으로 실제 주소를 전달
				address = (uint64_t)((int64_t)address + offset);
			} catch (...) {
				LOG_ERROR("  ParseAddress failed for '%s'", instrRef.c_str());
			}
		}

		if (address == 0) {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "Invalid instruction reference";
			breakpointsJson.push_back(dbp.ToJson());
			continue;
		}

		SetBreakpointRequest setReq;
		setReq.address = address;

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &setReq, sizeof(setReq), respData)) {
			if (respData.size() >= sizeof(SetBreakpointResponse)) {
				auto* setResp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
				Breakpoint dbp;
				dbp.id = nextDapBpId_++;
				dbp.verified = (setResp->status == IpcStatus::Ok);
				dbp.instructionReference = address;

				std::string cond = bp.value("condition", "");
				std::string hitCond = bp.value("hitCondition", "");
				std::string logMsg = bp.value("logMessage", "");
				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}, cond, hitCond, 0, logMsg, BpType::Instruction});
				breakpointsJson.push_back(dbp.ToJson());
			}
		} else {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "IPC error";
			breakpointsJson.push_back(dbp.ToJson());
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setInstructionBreakpoints";
	resp.success = true;
	resp.body = {{"breakpoints", breakpointsJson}};
	SendResponse(resp);
}

// --- Execution Control ---

void DapServer::OnContinue(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);

	// Continue 시 이전 스텝의 temp BP 정리
	CleanupStaleTempBp();
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::None;
	}

	// 실행 재개 시 프레임 매핑 초기화 (다음 stopped에서 새로 생성됨)
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		frameMap_.clear();
		nextFrameId_ = 1;
	}

	// Launch + stopOnEntry: 메인 스레드가 아직 OS-suspended 상태
	// VEH Continue 전에 먼저 OS resume 해야 함
	ResumeMainThread();

	ContinueRequest contReq;
	contReq.threadId = threadId;
	DAP_TRACE("Continue", "threadId=" + std::to_string(threadId));
	pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "continue";
	resp.success = true;
	resp.body = {{"allThreadsContinued", true}};
	SendResponse(resp);
}

void DapServer::OnNext(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
	std::string granularity = req.arguments.value("granularity", "statement");
	ResumeMainThread();

	LOG_INFO("OnNext: threadId=%u granularity=%s", threadId, granularity.c_str());

	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::Over;
		steppingThreadId_ = threadId;
		steppingInstruction_ = (granularity == "instruction");
		steppingStartAddr_ = 0;
		steppingNextLineAddr_ = 0;
		steppingSourceLine_ = 0;
		steppingSourceFile_.clear();
	}

	CleanupStaleTempBp();

	// === PDB 경로: 다음 소스 라인 주소에 temp BP → Continue (O(1)) ===
	if (!steppingInstruction_ && symbolEngineReady_) {
		// 현재 RIP 획득 (IPC GetStackTrace)
		uint64_t currentIP = 0;
		{
			GetStackTraceRequest stReq;
			stReq.threadId = threadId;
			stReq.startFrame = 0;
			stReq.maxFrames = 1;
			std::vector<uint8_t> stResp;
			if (pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp)
				&& stResp.size() >= sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo)) {
				auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
				if (hdr->status == IpcStatus::Ok && hdr->count > 0) {
					auto* frame = reinterpret_cast<const StackFrameInfo*>(
						stResp.data() + sizeof(GetStackTraceResponse));
					currentIP = frame->address;
				}
			}
		}

		if (currentIP != 0) {
			auto lineRange = symbolEngine_.GetCurrentLineRange(currentIP);
			if (lineRange.success && lineRange.nextLineAddress != 0
				&& lineRange.nextLineAddress != currentIP) {

				// 조건분기 체크: [currentIP, nextLine) 범위에 Jcc가 있으면 폴백
				// Jcc가 nextLine을 건너뛸 수 있으므로 temp BP가 미히트될 위험
				bool hasJcc = false;
				uint32_t rangeLen = (uint32_t)(lineRange.nextLineAddress - currentIP);
				if (targetProcess_ && rangeLen > 0 && rangeLen <= 256) {
					uint8_t codeBuf[256] = {};
					SIZE_T bytesRead = 0;
					if (ReadProcessMemory(targetProcess_, (LPCVOID)currentIP, codeBuf, rangeLen, &bytesRead)
						&& bytesRead > 0) {
						auto insns = disassembler_->Disassemble(codeBuf, (uint32_t)bytesRead, currentIP, 64);
						for (const auto& insn : insns) {
							if (insn.address >= lineRange.nextLineAddress) break;
							const auto& mn = insn.mnemonic;
							// Jcc: j로 시작 + jmp 제외 (무조건 점프는 안전하지 않지만 별도 처리)
							if (!mn.empty() && (mn[0] == 'j' || mn[0] == 'J') && mn != "jmp" && mn != "JMP") {
								LOG_INFO("OnNext PDB: Jcc '%s' at 0x%llX in range → fallback",
									mn.c_str(), insn.address);
								hasJcc = true;
								break;
							}
						}
					}
				}

				if (hasJcc) {
					// 조건분기 있음 → PDB path 사용 불가, 폴백
					LOG_INFO("OnNext: conditional branch detected, falling back to legacy step");
				} else {
				LOG_INFO("OnNext PDB: IP=0x%llX → next=%s:%u at 0x%llX",
					currentIP, lineRange.sourceFile.c_str(), lineRange.line,
					lineRange.nextLineAddress);

				// temp BP 설정
				SetBreakpointRequest bpReq;
				bpReq.address = lineRange.nextLineAddress;
				std::vector<uint8_t> bpResp;
				if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)
					&& bpResp.size() >= sizeof(SetBreakpointResponse)) {
					auto* r = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
					if (r->status == IpcStatus::Ok) {
						{
							std::lock_guard<std::mutex> stepLock(steppingMutex_);
							stepOverTempBpId_ = r->id;
							stepOverTempBpAddr_ = lineRange.nextLineAddress;
						}
						LOG_INFO("OnNext PDB: temp BP id=%u at 0x%llX", r->id, lineRange.nextLineAddress);

						// Continue → temp BP에서 멈춤 (single-step 0회)
						ContinueRequest contReq;
						contReq.threadId = threadId;
						pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
						goto send_response;
					}
				}
				} // else (no Jcc)
			}
		}
		LOG_INFO("OnNext: PDB path failed, falling back to legacy step");
	}

	// === 폴백: 기존 로직 (IPC ResolveStepRange + single-step + auto-step) ===
	if (!steppingInstruction_) {
		ResolveStepRange(threadId);
		std::string file;
		uint32_t line = 0;
		if (GetTopFrameSourceLine(threadId, file, line)) {
			steppingSourceLine_ = line;
			steppingSourceFile_ = file;
		}
	}

	{
		// CALL 명령어 판별 → 임시 BP로 건너뛰기 (instruction/statement 모두)
		uint64_t nextInsnAddr = 0;
		bool callSkipped = false;
		if (IsCallInstruction(threadId, nextInsnAddr)) {
			LOG_INFO("OnNext fallback: CALL detected, temp BP at 0x%llX", nextInsnAddr);
			SetBreakpointRequest bpReq;
			bpReq.address = nextInsnAddr;
			std::vector<uint8_t> bpResp;
			if (pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)
				&& bpResp.size() >= sizeof(SetBreakpointResponse)) {
				auto* r = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
				if (r->status == IpcStatus::Ok) {
					{
						std::lock_guard<std::mutex> stepLock(steppingMutex_);
						stepOverTempBpId_ = r->id;
						stepOverTempBpAddr_ = nextInsnAddr;
					}
					ContinueRequest contReq;
					contReq.threadId = threadId;
					pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
					callSkipped = true;
				}
			}
		}
		if (!callSkipped) {
			StepRequest stepReq;
			stepReq.threadId = threadId;
			pipeClient_.SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));
		}
	}

send_response:

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "next";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnStepIn(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
	std::string granularity = req.arguments.value("granularity", "statement");
	ResumeMainThread();

	CleanupStaleTempBp();
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::In;
		steppingThreadId_ = threadId;
		steppingInstruction_ = (granularity == "instruction");
		steppingStartAddr_ = 0;
		steppingNextLineAddr_ = 0;
	}
	if (!steppingInstruction_) {
		ResolveStepRange(threadId);
	}

	StepRequest stepReq;
	stepReq.threadId = threadId;
	pipeClient_.SendCommand(IpcCommand::StepInto, &stepReq, sizeof(stepReq));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "stepIn";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnStepOut(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
	ResumeMainThread();

	// StepOut은 라인 비교 불필요 — 함수 리턴까지 실행
	CleanupStaleTempBp();
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::Out;
		steppingThreadId_ = threadId;
		steppingStartAddr_ = 0;
		steppingNextLineAddr_ = 0;
	}

	StepRequest stepReq;
	stepReq.threadId = threadId;
	pipeClient_.SendCommand(IpcCommand::StepOut, &stepReq, sizeof(stepReq));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "stepOut";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnPause(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
	PauseRequest pauseReq;
	pauseReq.threadId = threadId;
	pipeClient_.SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "pause";
	resp.success = true;
	SendResponse(resp);

	// DAP 프로토콜: pause 성공 후 stopped 이벤트를 보내야
	// VSCode가 threads → stackTrace → scopes → variables 시퀀스를 시작한다.
	// 이 이벤트가 없으면 CALL STACK 패널이 갱신되지 않아
	// 스레드를 펼쳐도 스택 프레임이 표시되지 않는다.
	lastStoppedThreadId_.store(threadId);
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		frameMap_.clear();
		nextFrameId_ = 1;
	}

	SendEvent("stopped", {
		{"reason", "pause"},
		{"threadId", (int)threadId},
		{"allThreadsStopped", true},
	});
}

// --- State Queries ---

void DapServer::OnThreads(const Request& req) {
	std::vector<uint8_t> respData;
	json threadsJson = json::array();

	if (pipeClient_.SendAndReceive(IpcCommand::GetThreads, nullptr, 0, respData)) {
		if (respData.size() >= sizeof(GetThreadsResponse)) {
			auto* hdr = reinterpret_cast<const GetThreadsResponse*>(respData.data());
			auto* threads = reinterpret_cast<const ThreadInfo*>(respData.data() + sizeof(GetThreadsResponse));
			uint32_t maxCount = (uint32_t)((respData.size() - sizeof(GetThreadsResponse)) / sizeof(ThreadInfo));
			uint32_t count = std::min(hdr->count, maxCount);
			for (uint32_t i = 0; i < count; i++) {
				Thread t;
				t.id = threads[i].id;
				t.name = threads[i].name[0] ? threads[i].name : ("Thread " + std::to_string(threads[i].id));
				threadsJson.push_back(t.ToJson());
			}
		}
	}

	if (threadsJson.empty()) {
		// 최소한 메인 스레드 하나는 리턴
		threadsJson.push_back(Thread{1, "Main Thread"}.ToJson());
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "threads";
	resp.success = true;
	resp.body = {{"threads", threadsJson}};
	SendResponse(resp);
}

void DapServer::OnStackTrace(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 1);
	int startFrame = req.arguments.value("startFrame", 0);
	int levels = req.arguments.value("levels", 20);

	GetStackTraceRequest stReq;
	stReq.threadId = threadId;
	stReq.startFrame = startFrame;
	stReq.maxFrames = levels;

	json framesJson = json::array();
	std::vector<uint8_t> respData;

	// frameMap_은 stopped/continued 이벤트 시 초기화됨 (OnIpcEvent)
	// 여기서 clear하면 안 됨: VSCode가 여러 스레드의 stackTrace를 순차 요청하므로
	// 앞 스레드의 프레임 매핑이 뒷 스레드 요청 시 삭제되어 scopes/variables가 깨짐

	if (pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), respData)) {
		if (respData.size() >= sizeof(GetStackTraceResponse)) {
			auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(respData.data());
			auto* frames = reinterpret_cast<const StackFrameInfo*>(
				respData.data() + sizeof(GetStackTraceResponse));
			uint32_t maxCount = (uint32_t)((respData.size() - sizeof(GetStackTraceResponse)) / sizeof(StackFrameInfo));
			uint32_t count = std::min(hdr->count, maxCount);
			for (uint32_t i = 0; i < count; i++) {
				// 순차 ID 발급 + 맵에 (threadId, frameIndex) 저장
				// Windows 스레드 ID가 16비트 초과 가능(예: 169644)하므로 비트 패킹 불가
				int fid;
				{
					std::lock_guard<std::mutex> lock(frameMutex_);
					fid = nextFrameId_++;
					if (nextFrameId_ & SCOPE_MASK) nextFrameId_ = 1; // scope 비트 침범 방지
					frameMap_[fid] = {threadId, (int)(startFrame + i), frames[i].address, frames[i].frameBase};
				}

				StackFrameDap f;
				f.id = fid;
				f.instructionPointerReference = FormatAddress(frames[i].address);

				// 프레임 이름: module!func+0xOFFSET (0xADDR) — 오프셋 + 쌩 주소 둘 다 표시
				{
					std::string mod = frames[i].moduleName[0] ? frames[i].moduleName : "";
					std::string func = frames[i].functionName[0] ? frames[i].functionName : "";
					std::string addr = FormatAddress(frames[i].address);
					uint64_t modOffset = (frames[i].moduleBase && frames[i].address >= frames[i].moduleBase)
						? (frames[i].address - frames[i].moduleBase) : 0;
					char offsetStr[32];
					snprintf(offsetStr, sizeof(offsetStr), "+0x%llX", modOffset);

					if (!func.empty() && !mod.empty()) {
						f.name = mod + "!" + func + offsetStr + " (" + addr + ")";
					} else if (!func.empty()) {
						f.name = func + " (" + addr + ")";
					} else if (!mod.empty()) {
						f.name = mod + offsetStr + " (" + addr + ")";
					} else {
						f.name = addr;
					}
				}

				f.line = frames[i].line;
				if (frames[i].sourceFile[0]) {
					f.source.path = frames[i].sourceFile;
					std::string fullPath = frames[i].sourceFile;
					auto pos = fullPath.find_last_of("\\/");
					f.source.name = (pos != std::string::npos) ? fullPath.substr(pos + 1) : fullPath;
				}
				if (frames[i].moduleName[0]) {
					f.moduleId = frames[i].moduleName;
					// 소스 파일이 없으면 모듈+오프셋을 소스로 표시 (Unknown Source 방지)
					if (!frames[i].sourceFile[0]) {
						uint64_t offset = (frames[i].moduleBase && frames[i].address >= frames[i].moduleBase)
							? (frames[i].address - frames[i].moduleBase) : frames[i].address;
						char buf[64];
						snprintf(buf, sizeof(buf), "%s+0x%llX", frames[i].moduleName, offset);
						f.source.name = buf;
						f.source.presentationHint = "deemphasize";
					}
				}
				framesJson.push_back(f.ToJson());
			}
		}
	}

	// Fallback: DLL의 GetStackTrace가 빈 결과를 반환하는 경우 대비
	// (스택 워킹 실패, 심볼 미로드, IPC 타임아웃 등)
	// 빈 stackFrames를 반환하면 VSCode가 스레드 아래에 아무것도 표시하지 않고,
	// 사용자가 Scopes/Variables도 볼 수 없게 됨.
	// → GetRegisters로 현재 RIP를 가져와 합성 프레임 1개를 만들어 최소한의 디버깅 보장.
	if (framesJson.empty() && startFrame == 0) {
		GetRegistersRequest regReq;
		regReq.threadId = threadId;
		std::vector<uint8_t> regData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), regData)) {
			if (regData.size() >= sizeof(GetRegistersResponse)) {
				auto* regResp = reinterpret_cast<const GetRegistersResponse*>(regData.data());
				auto& r = regResp->regs;
				uint64_t ip = r.rip;

				if (ip != 0) {
					int fid;
					{
						std::lock_guard<std::mutex> lock(frameMutex_);
						fid = nextFrameId_++;
						if (nextFrameId_ & SCOPE_MASK) nextFrameId_ = 1;
						frameMap_[fid] = {threadId, 0, ip, r.rbp};
					}

					StackFrameDap f;
					f.id = fid;
					f.name = FormatAddress(ip);
					f.line = 0;
					f.instructionPointerReference = FormatAddress(ip);
					framesJson.push_back(f.ToJson());

					LOG_DEBUG("StackTrace fallback: thread %u, RIP=%s", threadId, FormatAddress(ip).c_str());
				}
			}
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "stackTrace";
	resp.success = true;
	resp.body = {
		{"stackFrames", framesJson},
		{"totalFrames", (int)framesJson.size()},
	};
	SendResponse(resp);
}

void DapServer::OnScopes(const Request& req) {
	int frameId = req.arguments.value("frameId", 0);

	json scopesJson = json::array();

	// 로컬 변수 스코프 (Locals) — Registers보다 먼저 표시
	Scope localScope;
	localScope.name = "Locals";
	localScope.variablesReference = SCOPE_LOCALS | frameId;
	localScope.namedVariables = 0;  // 동적으로 결정됨
	localScope.expensive = false;
	scopesJson.push_back(localScope.ToJson());

	// 레지스터 스코프
	Scope regScope;
	regScope.name = "Registers";
	regScope.variablesReference = SCOPE_REGISTERS | frameId;
	regScope.namedVariables = 26;  // GPR 16~18 + RFLAGS + DR0~DR7
	regScope.expensive = false;
	scopesJson.push_back(regScope.ToJson());

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "scopes";
	resp.success = true;
	resp.body = {{"scopes", scopesJson}};
	SendResponse(resp);
}

void DapServer::OnVariables(const Request& req) {
	int varRef = req.arguments.value("variablesReference", 0);
	json varsJson = json::array();

	int scopeType = varRef & SCOPE_MASK;
	int frameId = varRef & ~SCOPE_MASK;

	// frameMap_에서 threadId 복원 (비트 패킹 대신 맵 사용)
	uint32_t threadId = 1;
	int frameIndex = 0;
	bool frameFound = false;
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		auto it = frameMap_.find(frameId);
		if (it != frameMap_.end()) {
			threadId = it->second.threadId;
			frameIndex = it->second.frameIndex;
			frameFound = true;
		}
	}

	if (scopeType == SCOPE_REGISTERS) {
		// 레지스터 값 가져오기
		GetRegistersRequest regReq;
		regReq.threadId = threadId;

		LOG_INFO("OnVariables: requesting registers for threadId=%u (frameId=%d, mapFound=%d)",
			threadId, frameId, frameFound ? 1 : 0);

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
			if (respData.size() >= sizeof(GetRegistersResponse)) {
				auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
				auto& r = regResp->regs;

				if (r.is32bit) {
					// 32비트 프로세스 레지스터
					auto addReg32 = [&](const char* name, uint64_t val) {
						Variable v;
						v.name = name;
						char buf[16];
						snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
						v.value = buf;
						v.type = "uint32";
						varsJson.push_back(v.ToJson());
					};
					addReg32("EAX", r.rax); addReg32("EBX", r.rbx);
					addReg32("ECX", r.rcx); addReg32("EDX", r.rdx);
					addReg32("ESI", r.rsi); addReg32("EDI", r.rdi);
					addReg32("EBP", r.rbp); addReg32("ESP", r.rsp);
					addReg32("EIP", r.rip); addReg32("EFLAGS", r.rflags);
					// Debug registers
					addReg32("DR0", r.dr0); addReg32("DR1", r.dr1);
					addReg32("DR2", r.dr2); addReg32("DR3", r.dr3);
					addReg32("DR6", r.dr6); addReg32("DR7", r.dr7);
				} else {
					// 64비트 프로세스 레지스터
					auto addReg = [&](const char* name, uint64_t val) {
						Variable v;
						v.name = name;
						char buf[32];
						snprintf(buf, sizeof(buf), "0x%016llX", val);
						v.value = buf;
						v.type = "uint64";
						varsJson.push_back(v.ToJson());
					};
					addReg("RAX", r.rax); addReg("RBX", r.rbx);
					addReg("RCX", r.rcx); addReg("RDX", r.rdx);
					addReg("RSI", r.rsi); addReg("RDI", r.rdi);
					addReg("RBP", r.rbp); addReg("RSP", r.rsp);
					addReg("R8",  r.r8);  addReg("R9",  r.r9);
					addReg("R10", r.r10); addReg("R11", r.r11);
					addReg("R12", r.r12); addReg("R13", r.r13);
					addReg("R14", r.r14); addReg("R15", r.r15);
					addReg("RIP", r.rip); addReg("RFLAGS", r.rflags);
					// Debug registers
					addReg("DR0", r.dr0); addReg("DR1", r.dr1);
					addReg("DR2", r.dr2); addReg("DR3", r.dr3);
					addReg("DR6", r.dr6); addReg("DR7", r.dr7);
				}
				LOG_INFO("OnVariables: got %zu registers", varsJson.size());
			} else {
				LOG_WARN("OnVariables: response too small (%zu < %zu)", respData.size(), sizeof(GetRegistersResponse));
			}
		} else {
			LOG_WARN("OnVariables: GetRegisters IPC failed for threadId=%u", threadId);
			// IPC 실패 시 에러 표시
			Variable v;
			v.name = "error";
			v.value = "Failed to read registers (thread " + std::to_string(threadId) + ")";
			v.type = "string";
			varsJson.push_back(v.ToJson());
		}
	} else if (scopeType == SCOPE_LOCALS) {
		// 로컬 변수 열거 — EnumLocals IPC 호출
		uint64_t instrAddr = 0;
		uint64_t fBase = 0;
		{
			std::lock_guard<std::mutex> lock(frameMutex_);
			auto it = frameMap_.find(frameId);
			if (it != frameMap_.end()) {
				instrAddr = it->second.instructionAddress;
				fBase = it->second.frameBase;
			}
		}

		if (instrAddr == 0) {
			Variable v;
			v.name = "(no frame info)";
			v.value = "Frame data not available";
			v.type = "string";
			varsJson.push_back(v.ToJson());
		} else {
			EnumLocalsRequest locReq;
			locReq.threadId = threadId;
			locReq.instructionAddress = instrAddr;
			locReq.frameBase = fBase;

			std::vector<uint8_t> locData;
			if (pipeClient_.SendAndReceive(IpcCommand::EnumLocals, &locReq, sizeof(locReq), locData)
				&& locData.size() >= sizeof(EnumLocalsResponse)) {
				auto* locResp = reinterpret_cast<const EnumLocalsResponse*>(locData.data());
				auto* locals = reinterpret_cast<const LocalVariableInfo*>(
					locData.data() + sizeof(EnumLocalsResponse));
				uint32_t maxCount = (uint32_t)((locData.size() - sizeof(EnumLocalsResponse)) / sizeof(LocalVariableInfo));
				uint32_t count = std::min(locResp->count, maxCount);

				for (uint32_t i = 0; i < count; i++) {
					// IPC 고정 크기 char[] null 종단 강제 (손상된 데이터 방어)
					char safeName[sizeof(LocalVariableInfo::name) + 1] = {};
					memcpy(safeName, locals[i].name, sizeof(locals[i].name));
					char safeType[sizeof(LocalVariableInfo::typeName) + 1] = {};
					memcpy(safeType, locals[i].typeName, sizeof(locals[i].typeName));

					Variable v;
					v.name = safeName;
					v.type = safeType[0] ? safeType : "unknown";

					// Format value based on type name and size
					if (locals[i].valueSize == 0) {
						v.value = "(unreadable)";
					} else {
						std::string tn = v.type;
						bool isPointer = (tn.size() > 0 && tn.back() == '*');
						bool isFloat = (tn == "float");
						bool isDouble = (tn == "double");
						bool isBool = (tn == "bool");
						bool isChar = (tn == "char");
						char buf[64];

						if (isPointer && locals[i].valueSize >= sizeof(void*)) {
							// Pointer: show as hex address
							uint64_t ptr;
							memcpy(&ptr, locals[i].value, sizeof(ptr));
							snprintf(buf, sizeof(buf), "0x%llX", ptr);

							if (tn.find("char*") != std::string::npos && ptr != 0) {
								// char*: read pointed-to string via ReadMemory IPC
								ReadMemoryRequest rmReq;
								rmReq.address = ptr;
								rmReq.size = 128;
								std::vector<uint8_t> rmData;
								if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &rmReq, sizeof(rmReq), rmData)
									&& rmData.size() > sizeof(IpcStatus)) {
									auto* rmStatus = reinterpret_cast<const IpcStatus*>(rmData.data());
									if (*rmStatus == IpcStatus::Ok) {
										const char* strData = reinterpret_cast<const char*>(rmData.data() + sizeof(IpcStatus));
										size_t strLen = rmData.size() - sizeof(IpcStatus);
										// Find null terminator
										size_t len = strnlen(strData, strLen);
										if (len > 0) {
											std::string preview(strData, std::min(len, (size_t)80));
											v.value = std::string(buf) + " \"" + preview + "\"";
										} else {
											v.value = std::string(buf) + " \"\"";
										}
									} else {
										v.value = buf;
									}
								} else {
									v.value = buf;
								}
								v.memoryReference = buf;
							} else {
								v.value = buf;
							}
						} else if (isFloat && locals[i].valueSize >= 4) {
							float val;
							memcpy(&val, locals[i].value, 4);
							snprintf(buf, sizeof(buf), "%.6g", val);
							v.value = buf;
						} else if (isDouble && locals[i].valueSize >= 8) {
							double val;
							memcpy(&val, locals[i].value, 8);
							snprintf(buf, sizeof(buf), "%.10g", val);
							v.value = buf;
						} else if (isBool && locals[i].valueSize >= 1) {
							v.value = locals[i].value[0] ? "true" : "false";
						} else if (isChar && locals[i].size == 1) {
							char ch = (char)locals[i].value[0];
							if (ch >= 32 && ch < 127)
								snprintf(buf, sizeof(buf), "'%c' (%d)", ch, (int)(uint8_t)ch);
							else
								snprintf(buf, sizeof(buf), "%d (0x%02X)", (int)(uint8_t)ch, (uint8_t)ch);
							v.value = buf;
						} else if (locals[i].size <= 1) {
							snprintf(buf, sizeof(buf), "%u (0x%02X)", locals[i].value[0], locals[i].value[0]);
							v.value = buf;
						} else if (locals[i].size <= 4) {
							uint32_t val = 0;
							memcpy(&val, locals[i].value, std::min(locals[i].valueSize, (uint32_t)4));
							int32_t sval;
							memcpy(&sval, &val, 4);
							snprintf(buf, sizeof(buf), "%d (0x%08X)", sval, val);
							v.value = buf;
						} else if (locals[i].size <= 8) {
							uint64_t val = 0;
							memcpy(&val, locals[i].value, std::min(locals[i].valueSize, (uint32_t)8));
							int64_t sval;
							memcpy(&sval, &val, 8);
							snprintf(buf, sizeof(buf), "%lld (0x%llX)", sval, val);
							v.value = buf;
						} else {
							// Large type: show hex bytes
							std::string hex;
							uint32_t showBytes = std::min(locals[i].valueSize, (uint32_t)16);
							for (uint32_t b = 0; b < showBytes; b++) {
								char byte[4];
								snprintf(byte, sizeof(byte), "%02X ", locals[i].value[b]);
								hex += byte;
							}
							if (locals[i].valueSize > 16) hex += "...";
							v.value = hex;
						}
					}

					// Show address as evaluateName for hover
					char addrBuf[24];
					snprintf(addrBuf, sizeof(addrBuf), "*0x%llX", locals[i].address);
					v.evaluateName = addrBuf;

					// Flags info: parameter vs local
					if (locals[i].flags & 0x00000008) { // SYMFLAG_PARAMETER
						v.name = "[param] " + v.name;
					}

					varsJson.push_back(v.ToJson());
				}

				if (count == 0) {
					Variable v;
					v.name = "(no locals)";
					v.value = "No local variables found in this frame";
					v.type = "string";
					varsJson.push_back(v.ToJson());
				}
			} else {
				Variable v;
				v.name = "(error)";
				v.value = "Failed to enumerate local variables";
				v.type = "string";
				varsJson.push_back(v.ToJson());
			}
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "variables";
	resp.success = true;
	resp.body = {{"variables", varsJson}};
	SendResponse(resp);
}

void DapServer::OnEvaluate(const Request& req) {
	std::string expression = req.arguments.value("expression", "");
	std::string context = req.arguments.value("context", "repl");
	int frameId = req.arguments.value("frameId", 0);

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "evaluate";

	// 표현식 앞뒤 공백 제거
	auto trim = [](std::string s) {
		while (!s.empty() && s.front() == ' ') s.erase(s.begin());
		while (!s.empty() && s.back() == ' ') s.pop_back();
		return s;
	};
	expression = trim(expression);

	// threadId 결정: frameMap_에서 복원, 없으면 lastStoppedThreadId_
	uint32_t threadId = 0;
	if (frameId != 0) {
		std::lock_guard<std::mutex> lock(frameMutex_);
		auto it = frameMap_.find(frameId);
		if (it != frameMap_.end()) threadId = it->second.threadId;
	}
	if (threadId == 0) threadId = lastStoppedThreadId_.load();
	if (threadId == 0) threadId = 1;

	// 1) 레지스터 이름 인식 (hover에서 레지스터 값 표시)
	if (TryParseRegisterName(expression)) {
		GetRegistersRequest regReq;
		regReq.threadId = threadId;

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
			if (respData.size() >= sizeof(GetRegistersResponse)) {
				auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
				uint64_t val = ResolveRegisterByName(expression, regResp->regs);
				char buf[32];
				if (regResp->regs.is32bit) {
					snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
				} else {
					snprintf(buf, sizeof(buf), "0x%016llX", val);
				}
				resp.success = true;
				resp.body = {
					{"result", buf},
					{"type", regResp->regs.is32bit ? "uint32" : "uint64"},
					{"variablesReference", 0},
				};
				SendResponse(resp);
				return;
			}
		}
	}

	// 2) 순수 hex 주소 (0x...) — 메모리 미리보기
	if (expression.size() > 2 && expression[0] == '0' && (expression[1] == 'x' || expression[1] == 'X')) {
		try {
			uint64_t addr = std::stoull(expression, nullptr, 16);
			ReadMemoryRequest readReq;
			readReq.address = addr;
			readReq.size = 8;

			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)) {
				if (respData.size() >= sizeof(IpcStatus) + 8 &&
					*reinterpret_cast<const IpcStatus*>(respData.data()) == IpcStatus::Ok) {
					uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
					char buf[64];
					snprintf(buf, sizeof(buf), "[0x%llX] = 0x%016llX", addr, val);
					resp.success = true;
					resp.body = {
						{"result", buf},
						{"type", "memory"},
						{"variablesReference", 0},
					};
					SendResponse(resp);
					return;
				}
			}
		} catch (...) {}
	}

	// 3) *addr / [addr] 문법 — 메모리 읽기
	if (!expression.empty() && (expression[0] == '*' || expression[0] == '[')) {
		std::string addrStr = expression.substr(1);
		if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();

		try {
			uint64_t addr = std::stoull(addrStr, nullptr, 0);
			ReadMemoryRequest readReq;
			readReq.address = addr;
			readReq.size = 8;

			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)) {
				if (respData.size() >= sizeof(IpcStatus) + 8 &&
					*reinterpret_cast<const IpcStatus*>(respData.data()) == IpcStatus::Ok) {
					uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
					char buf[32];
					snprintf(buf, sizeof(buf), "0x%016llX", val);
					resp.success = true;
					resp.body = {
						{"result", buf},
						{"type", "uint64"},
						{"variablesReference", 0},
					};
					SendResponse(resp);
					return;
				}
			}
		} catch (...) {}
	}

	resp.success = false;
	resp.message = "Use register name (RAX, RCX, ...) or *<address> / 0x<address> to evaluate.";
	SendResponse(resp);
}

void DapServer::OnSetVariable(const Request& req) {
	int varRef = req.arguments.value("variablesReference", 0);
	std::string name = req.arguments.value("name", "");
	std::string value = req.arguments.value("value", "");

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setVariable";

	int scopeType = varRef & SCOPE_MASK;

	if (scopeType != SCOPE_REGISTERS) {
		resp.success = false;
		resp.message = "Only register modification is supported";
		SendResponse(resp);
		return;
	}

	// 레지스터 이름 → regIndex 변환
	std::string upperName = name;
	std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);

	// regIndex: RegisterSet 내 uint64_t 배열 순서
	// rax=0, rbx=1, rcx=2, rdx=3, rsi=4, rdi=5, rbp=6, rsp=7,
	// r8=8, r9=9, r10=10, r11=11, r12=12, r13=13, r14=14, r15=15,
	// rip=16, rflags=17
	static const std::pair<std::string, uint32_t> regMap[] = {
		{"RAX", 0}, {"EAX", 0}, {"RBX", 1}, {"EBX", 1},
		{"RCX", 2}, {"ECX", 2}, {"RDX", 3}, {"EDX", 3},
		{"RSI", 4}, {"ESI", 4}, {"RDI", 5}, {"EDI", 5},
		{"RBP", 6}, {"EBP", 6}, {"RSP", 7}, {"ESP", 7},
		{"R8",  8}, {"R9",  9}, {"R10", 10}, {"R11", 11},
		{"R12", 12}, {"R13", 13}, {"R14", 14}, {"R15", 15},
		{"RIP", 16}, {"EIP", 16},
		{"RFLAGS", 17}, {"EFLAGS", 17},
	};

	uint32_t regIndex = UINT32_MAX;
	for (auto& [rn, ri] : regMap) {
		if (upperName == rn) { regIndex = ri; break; }
	}

	if (regIndex == UINT32_MAX) {
		resp.success = false;
		resp.message = "Unknown register: " + name;
		SendResponse(resp);
		return;
	}

	// 값 파싱
	uint64_t newVal = 0;
	try {
		newVal = std::stoull(value, nullptr, 0);
	} catch (...) {
		resp.success = false;
		resp.message = "Invalid value: " + value;
		SendResponse(resp);
		return;
	}

	// frameMap_에서 threadId 복원
	int frameId = varRef & ~SCOPE_MASK;
	uint32_t threadId = 0;
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		auto it = frameMap_.find(frameId);
		if (it != frameMap_.end()) threadId = it->second.threadId;
	}
	if (threadId == 0) threadId = lastStoppedThreadId_.load();
	if (threadId == 0) threadId = 1;

	// IPC로 레지스터 수정 요청
	SetRegisterRequest setReq;
	setReq.threadId = threadId;
	setReq.regIndex = regIndex;
	setReq.value = newVal;

	std::vector<uint8_t> respData;
	if (pipeClient_.SendAndReceive(IpcCommand::SetRegister, &setReq, sizeof(setReq), respData)) {
		if (respData.size() >= sizeof(SetRegisterResponse)) {
			auto* setResp = reinterpret_cast<const SetRegisterResponse*>(respData.data());
			if (setResp->status == IpcStatus::Ok) {
				// 32비트 레지스터명(EAX, EBX 등)이면 32비트 포맷
				// EFLAGS는 64비트 프로세스에서 RFLAGS와 같은 레지스터이지만
				// 사용자가 EFLAGS로 입력하면 32비트로 취급
				bool is32 = (upperName[0] == 'E' && upperName != "EFLAGS") ||
					(upperName == "EFLAGS" && (newVal <= 0xFFFFFFFF));
				char buf[32];
				if (is32) {
					newVal &= 0xFFFFFFFF;
					snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)newVal);
				} else {
					snprintf(buf, sizeof(buf), "0x%016llX", newVal);
				}
				resp.success = true;
				resp.body = {
					{"value", buf},
					{"type", is32 ? "uint32" : "uint64"},
					{"variablesReference", 0},
				};
				SendResponse(resp);
				return;
			}
		}
	}

	resp.success = false;
	resp.message = "Failed to set register (DLL may not support SetRegister command)";
	SendResponse(resp);
}

void DapServer::OnModules(const Request& req) {
	std::vector<uint8_t> respData;
	json modulesJson = json::array();

	if (pipeClient_.SendAndReceive(IpcCommand::GetModules, nullptr, 0, respData)) {
		if (respData.size() >= sizeof(GetModulesResponse)) {
			auto* hdr = reinterpret_cast<const GetModulesResponse*>(respData.data());
			auto* modules = reinterpret_cast<const ModuleInfo*>(
				respData.data() + sizeof(GetModulesResponse));
			uint32_t maxCount = (uint32_t)((respData.size() - sizeof(GetModulesResponse)) / sizeof(ModuleInfo));
			uint32_t count = std::min(hdr->count, maxCount);
			for (uint32_t i = 0; i < count; i++) {
				Module m;
				m.id = std::to_string(i);
				m.name = modules[i].name;
				m.path = modules[i].path;
				char buf[64];
				snprintf(buf, sizeof(buf), "0x%llX-0x%llX",
					modules[i].baseAddress,
					modules[i].baseAddress + modules[i].size);
				m.addressRange = buf;
				modulesJson.push_back(m.ToJson());
			}
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "modules";
	resp.success = true;
	resp.body = {
		{"modules", modulesJson},
		{"totalModules", (int)modulesJson.size()},
	};
	SendResponse(resp);
}

void DapServer::OnLoadedSources(const Request& req) {
	// 로드된 소스 없음 (바이너리 디버거)
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "loadedSources";
	resp.success = true;
	resp.body = {{"sources", json::array()}};
	SendResponse(resp);
}

void DapServer::OnExceptionInfo(const Request& req) {
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "exceptionInfo";
	resp.success = true;

	char codeBuf[32];
	std::string desc;
	{
		std::lock_guard<std::mutex> lock(exceptionMutex_);
		snprintf(codeBuf, sizeof(codeBuf), "0x%08X", lastException_.code);
		desc = lastException_.description;
	}

	resp.body = {
		{"exceptionId", codeBuf},
		{"description", desc},
		{"breakMode", "always"},
	};
	SendResponse(resp);
}

// --- Memory ---

void DapServer::OnReadMemory(const Request& req) {
	std::string memRef = req.arguments.value("memoryReference", "");
	int64_t offset = req.arguments.value("offset", 0);
	int count = req.arguments.value("count", 256);
	if (count <= 0) count = 256;
	if (count > 1048576) count = 1048576;  // 최대 1MB

	if (memRef.empty()) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "readMemory";
		resp.success = false;
		resp.message = "memoryReference is required";
		SendResponse(resp);
		return;
	}
	uint64_t addr = 0;
	if (!ParseAddress(memRef, addr)) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "readMemory";
		resp.success = false;
		resp.message = "Invalid memoryReference: " + memRef;
		SendResponse(resp);
		return;
	}
	addr += offset;

	ReadMemoryRequest readReq;
	readReq.address = addr;
	readReq.size = count;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "readMemory";

	std::vector<uint8_t> respData;
	if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData) &&
		respData.size() >= sizeof(IpcStatus) &&
		*reinterpret_cast<const IpcStatus*>(respData.data()) == IpcStatus::Ok) {
		const uint8_t* memData = respData.data() + sizeof(IpcStatus);
		size_t memLen = respData.size() - sizeof(IpcStatus);
		resp.success = true;
		resp.body = {
			{"address", FormatAddress(addr)},
			{"data", Base64Encode(memData, memLen)},
			{"unreadableBytes", count - (int)memLen},
		};
	} else {
		resp.success = false;
		resp.message = "Failed to read memory at " + FormatAddress(addr);
	}
	SendResponse(resp);
}

void DapServer::OnWriteMemory(const Request& req) {
	std::string memRef = req.arguments.value("memoryReference", "");
	int64_t offset = req.arguments.value("offset", 0);
	std::string data = req.arguments.value("data", "");

	if (memRef.empty()) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "writeMemory";
		resp.success = false;
		resp.message = "memoryReference is required";
		SendResponse(resp);
		return;
	}
	uint64_t addr = 0;
	if (!ParseAddress(memRef, addr)) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "writeMemory";
		resp.success = false;
		resp.message = "Invalid memoryReference: " + memRef;
		SendResponse(resp);
		return;
	}
	addr += offset;
	auto bytes = Base64Decode(data);

	WriteMemoryRequest writeReq;
	writeReq.address = addr;
	writeReq.size = (uint32_t)bytes.size();

	// writeReq + data를 하나의 버퍼로
	std::vector<uint8_t> payload(sizeof(writeReq) + bytes.size());
	memcpy(payload.data(), &writeReq, sizeof(writeReq));
	memcpy(payload.data() + sizeof(writeReq), bytes.data(), bytes.size());

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "writeMemory";

	if (pipeClient_.SendCommand(IpcCommand::WriteMemory, payload.data(), (uint32_t)payload.size())) {
		resp.success = true;
		resp.body = {{"bytesWritten", (int)bytes.size()}};
	} else {
		resp.success = false;
		resp.message = "Failed to write memory";
	}
	SendResponse(resp);
}

void DapServer::OnDisassemble(const Request& req) {
	std::string memRef = req.arguments.value("memoryReference", "");
	int64_t offset = req.arguments.value("offset", 0);
	int64_t instrOffset = req.arguments.value("instructionOffset", 0);
	int instrCount = req.arguments.value("instructionCount", 50);
	if (instrCount < 0) instrCount = 50;
	if (instrCount > 10000) instrCount = 10000;

	uint64_t addr = 0;
	if (!ParseAddress(memRef, addr)) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disassemble";
		resp.success = false;
		resp.message = "Invalid memoryReference: " + memRef;
		SendResponse(resp);
		return;
	}
	addr += offset;

	// [CRITICAL FIX] instructionOffset 처리
	// VSCode 디스어셈블리 뷰는 instructionOffset:-200, instructionCount:400 으로 요청하여
	// 현재 RIP 기준 앞뒤 명령어를 표시한다. instructionOffset을 무시하면
	// 주소-라인 매핑이 완전히 어긋나서 F9 브포가 항상 RIP에 설정되는 버그 발생.
	uint64_t startAddr = addr;
	int totalNeeded = instrCount;
	int skipCount = 0; // 앞쪽 여분에서 버릴 명령어 수

	if (instrOffset < 0) {
		// 뒤로 갈 바이트 수 추정 (평균 명령어 크기 ~4바이트 + 여유)
		uint64_t backBytes = (uint64_t)((-instrOffset) * 5 + 64);
		if (backBytes > addr) backBytes = addr; // underflow 방지
		startAddr = addr - backBytes;
		// 여분 포함해서 더 많이 디스어셈블 후 정확한 위치 찾기
		totalNeeded = instrCount + (int)(-instrOffset) + 64;
	} else if (instrOffset > 0) {
		// 앞쪽 명령어 건너뛰기: 먼저 instrOffset만큼 디스어셈블 후 스킵
		skipCount = (int)instrOffset;
		totalNeeded = instrCount + skipCount;
	}

	uint32_t readSize = (uint32_t)totalNeeded * 15;
	ReadMemoryRequest readReq;
	readReq.address = startAddr;
	readReq.size = readSize;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "disassemble";

	std::vector<uint8_t> memData;
	if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), memData) &&
		memData.size() >= sizeof(IpcStatus) &&
		*reinterpret_cast<const IpcStatus*>(memData.data()) == IpcStatus::Ok) {
		const uint8_t* code = memData.data() + sizeof(IpcStatus);
		uint32_t codeLen = (uint32_t)(memData.size() - sizeof(IpcStatus));
		auto allInstructions = disassembler_->Disassemble(code, codeLen, startAddr, totalNeeded);

		// instrOffset < 0: addr(원래 memRef+offset) 위치를 찾아서 그 앞 |instrOffset|개부터 시작
		size_t startIdx = 0;
		if (instrOffset < 0) {
			// addr와 같거나 넘는 첫 명령어 위치 찾기
			size_t addrIdx = 0;
			for (size_t i = 0; i < allInstructions.size(); i++) {
				if (allInstructions[i].address >= addr) {
					addrIdx = i;
					break;
				}
			}
			// addrIdx에서 |instrOffset|만큼 뒤로
			int backCount = (int)(-instrOffset);
			startIdx = (addrIdx >= (size_t)backCount) ? (addrIdx - backCount) : 0;
		} else if (instrOffset > 0) {
			startIdx = (size_t)skipCount;
			if (startIdx >= allInstructions.size()) startIdx = allInstructions.size();
		}

		json instrsJson = json::array();
		for (size_t i = startIdx; i < allInstructions.size() && (int)instrsJson.size() < instrCount; i++) {
			DisassembledInstruction di;
			di.address = FormatAddress(allInstructions[i].address);
			di.instructionBytes = allInstructions[i].bytes;
			di.instruction = allInstructions[i].mnemonic;
			instrsJson.push_back(di.ToJson());
		}

		{
			std::string traceMsg = "startAddr=" + FormatAddress(startAddr)
				+ " addr=" + FormatAddress(addr)
				+ " instrOffset=" + std::to_string(instrOffset)
				+ " totalDisasm=" + std::to_string(allInstructions.size())
				+ " startIdx=" + std::to_string(startIdx)
				+ " returned=" + std::to_string(instrsJson.size());
			// 처음 5개 주소 덤프
			for (size_t di = 0; di < instrsJson.size() && di < 5; di++) {
				traceMsg += "\n  [" + std::to_string(di) + "] " + instrsJson[di]["address"].get<std::string>()
					+ " " + instrsJson[di]["instruction"].get<std::string>();
			}
			// RIP 근처 찾아서 덤프
			for (size_t di = 0; di < instrsJson.size(); di++) {
				if (instrsJson[di]["address"].get<std::string>() == FormatAddress(addr)) {
					traceMsg += "\n  === RIP at index " + std::to_string(di) + " ===";
					for (size_t k = (di > 2 ? di - 2 : 0); k < instrsJson.size() && k <= di + 2; k++) {
						traceMsg += "\n  [" + std::to_string(k) + "] " + instrsJson[k]["address"].get<std::string>()
							+ " " + instrsJson[k]["instruction"].get<std::string>();
					}
					break;
				}
			}
			DAP_TRACE("disassemble", traceMsg);
		}

		resp.success = true;
		resp.body = {{"instructions", instrsJson}};
	} else {
		DAP_TRACE("disassemble", "FAILED - ReadMemory error for 0x" + FormatAddress(startAddr));
		resp.success = false;
		resp.message = "Failed to read memory for disassembly";
	}
	SendResponse(resp);
}

// --- Data Breakpoints (Hardware Watchpoints) ---

void DapServer::OnDataBreakpointInfo(const Request& req) {
	std::string dataId = req.arguments.value("variablesReference", 0) > 0
		? req.arguments.value("name", "")
		: req.arguments.value("name", "");

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "dataBreakpointInfo";
	resp.success = true;

	// 주소 형태면 data breakpoint 가능
	uint64_t address = 0;
	try {
		if (!dataId.empty()) address = ParseAddress(dataId);
	} catch (...) {}

	if (address) {
		resp.body = {
			{"dataId", dataId},
			{"description", "Watch " + dataId},
			{"accessTypes", json::array({"write", "readWrite"})},
			{"canPersist", false},
		};
	} else {
		resp.body = {
			{"dataId", nullptr},
			{"description", "Cannot set data breakpoint on this expression"},
		};
	}
	SendResponse(resp);
}

void DapServer::OnSetDataBreakpoints(const Request& req) {
	std::lock_guard<std::mutex> lock(breakpointMutex_);

	// 기존 data breakpoints 제거
	for (auto& m : dataBreakpointMappings_) {
		RemoveHwBreakpointRequest rmReq;
		rmReq.id = m.vehId;
		pipeClient_.SendCommand(IpcCommand::RemoveHwBreakpoint, &rmReq, sizeof(rmReq));
	}
	dataBreakpointMappings_.clear();

	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

	for (auto& bp : bps) {
		std::string dataId = bp.value("dataId", "");
		std::string accessType = bp.value("accessType", "write");

		uint64_t address = 0;
		try {
			if (!dataId.empty()) address = ParseAddress(dataId);
		} catch (...) {}

		if (address == 0) {
			json dbp = {{"id", nextDapBpId_++}, {"verified", false}, {"message", "Invalid address"}};
			breakpointsJson.push_back(dbp);
			continue;
		}

		SetHwBreakpointRequest hwReq;
		hwReq.address = address;
		hwReq.type = (accessType == "readWrite") ? 3 : 1; // 1=write, 3=readwrite (DR7 R/W field)
		hwReq.size = 8; // 기본 8바이트 감시

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::SetHwBreakpoint, &hwReq, sizeof(hwReq), respData)) {
			if (respData.size() >= sizeof(SetHwBreakpointResponse)) {
				auto* hwResp = reinterpret_cast<const SetHwBreakpointResponse*>(respData.data());
				int dapId = nextDapBpId_++;
				bool ok = (hwResp->status == IpcStatus::Ok);

				if (ok) {
					dataBreakpointMappings_.push_back({dapId, hwResp->id, address, hwReq.type, hwReq.size});
				}

				json dbp = {
					{"id", dapId},
					{"verified", ok},
				};
				if (!ok) dbp["message"] = "Hardware breakpoint slots full (max 4)";
				breakpointsJson.push_back(dbp);
			}
		} else {
			json dbp = {{"id", nextDapBpId_++}, {"verified", false}, {"message", "IPC error"}};
			breakpointsJson.push_back(dbp);
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setDataBreakpoints";
	resp.success = true;
	resp.body = {{"breakpoints", breakpointsJson}};
	SendResponse(resp);
}

// --- Additional DAP Commands ---

void DapServer::OnRestart(const Request& req) {
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "restart";

	if (!launchedByUs_) {
		// attach 모드: Detach 전송 → DLL 파이프 서버 유지 → 재연결
		Cleanup(/*detachOnly=*/true);

		std::string dllPath = GetDllPath();
		if (!Injector::InjectDll(targetPid_, dllPath, injectionMethod_)) {
			resp.success = false;
			resp.message = "Failed to re-inject DLL";
			SendResponse(resp);
			return;
		}

		if (!pipeClient_.Connect(targetPid_, 3000)) {
			resp.success = false;
			resp.message = "Failed to reconnect pipe";
			SendResponse(resp);
			return;
		}

		pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
			OnIpcEvent(eventId, payload, size);
		});
		pipeClient_.StartHeartbeat();

		// targetProcess_ + symbolEngine_ 재초기화 (attach 모드)
		if (targetProcess_) CloseHandle(targetProcess_);
		targetProcess_ = OpenProcess(
			PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
			FALSE, targetPid_);
		if (targetProcess_) {
			symbolEngineReady_ = symbolEngine_.Initialize(targetProcess_);
		} else {
			symbolEngineReady_ = false;
		}

		resp.success = true;
		SendResponse(resp);
	} else {
		// launch 모드: 프로세스 재시작
		Cleanup();

		// 기존 프로세스 종료
		if (targetPid_) {
			HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
			if (proc) {
				TerminateProcess(proc, 0);
				WaitForSingleObject(proc, 3000);
				CloseHandle(proc);
			}
		}

		// 재시작 — 원래 launch 시의 args/cwd를 사용
		std::string dllPath = GetDllPath();
		auto relaunch = Injector::LaunchAndInject(programPath_, launchArgStr_, launchCwd_, dllPath, injectionMethod_);
		targetPid_ = relaunch.pid;
		launchedMainThreadId_ = relaunch.mainThreadId;
		mainThreadResumed_ = false;

		if (targetPid_ == 0) {
			resp.success = false;
			resp.message = "Failed to relaunch";
			SendResponse(resp);
			return;
		}

		if (!pipeClient_.Connect(targetPid_, 3000)) {
			resp.success = false;
			resp.message = "Failed to connect pipe after relaunch";
			SendResponse(resp);
			return;
		}

		pipeClient_.StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
			OnIpcEvent(eventId, payload, size);
		});
		pipeClient_.StartHeartbeat();

		// targetProcess_ + symbolEngine_ 재초기화
		targetProcess_ = OpenProcess(
			PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
			FALSE, targetPid_);
		if (targetProcess_) {
			symbolEngineReady_ = symbolEngine_.Initialize(targetProcess_);
		} else {
			symbolEngineReady_ = false;
			LOG_WARN("OnRestart: OpenProcess failed for pid %u: %u", targetPid_, GetLastError());
		}

		resp.success = true;
		SendResponse(resp);
		// DAP 스펙: initialized는 initialize 응답에서만 1회 전송, restart에서 재전송하면 안 됨
	}
}

void DapServer::OnCancel(const Request& req) {
	// 현재 모든 IPC 호출은 짧은 타임아웃이므로 특별히 취소할 것 없음
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "cancel";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnTerminateThreads(const Request& req) {
	auto threadIds = req.arguments.value("threadIds", json::array());

	bool allOk = true;
	for (auto& tid : threadIds) {
		if (!tid.is_number()) continue;
		TerminateThreadRequest termReq;
		termReq.threadId = tid.get<uint32_t>();

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::TerminateThread, &termReq, sizeof(termReq), respData)) {
			if (respData.size() >= sizeof(IpcStatus)) {
				auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
				if (status != IpcStatus::Ok) allOk = false;
			}
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "terminateThreads";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnGotoTargets(const Request& req) {
	// source + line → 가능한 goto 대상 반환
	// 바이너리 디버거이므로 주소 기반으로만 제공
	json targets = json::array();

	// 주소가 직접 지정된 경우
	if (req.arguments.contains("column")) {
		// column에 주소가 올 수 있음 (비표준이지만 유용)
	}

	// 현재는 빈 목록 반환 — PDB 지원 시 확장
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "gotoTargets";
	resp.success = true;
	resp.body = {{"targets", targets}};
	SendResponse(resp);
}

void DapServer::OnGoto(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
	int targetId = req.arguments.value("targetId", 0);

	// targetId를 주소로 해석 (gotoTargets에서 반환한 ID)
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "goto";

	if (threadId == 0) {
		resp.success = false;
		resp.message = "threadId required";
		SendResponse(resp);
		return;
	}

	// targetId가 유효한 주소인 경우 RIP 설정
	if (targetId > 0) {
		SetInstructionPointerRequest ipReq;
		ipReq.threadId = threadId;
		ipReq.address = static_cast<uint64_t>(targetId);

		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::SetInstructionPointer, &ipReq, sizeof(ipReq), respData)) {
			resp.success = true;
		} else {
			resp.success = false;
			resp.message = "Failed to set instruction pointer";
		}
	} else {
		resp.success = false;
		resp.message = "Invalid target";
	}
	SendResponse(resp);
}

void DapServer::OnSource(const Request& req) {
	// 소스 참조 → 디스어셈블리 반환
	int sourceReference = req.arguments.value("sourceReference", 0);

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "source";
	resp.success = true;
	resp.body = {
		{"content", "; Source not available (binary debugger)\n; Use disassemble request for assembly view"},
		{"mimeType", "text/x-asm"},
	};
	SendResponse(resp);
}

void DapServer::OnCompletions(const Request& req) {
	std::string text = req.arguments.value("text", "");
	int column = req.arguments.value("column", 0);

	json targets = json::array();

	// 레지스터 이름 자동완성
	const char* regs64[] = {
		"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RFLAGS"
	};
	// 메모리 접근 패턴
	const char* patterns[] = {"*0x", "[0x"};

	size_t col = (column > 1) ? static_cast<size_t>(column - 1) : 0; // DAP column is 1-based
	std::string prefix = text.substr(0, std::min(col, text.size()));
	for (auto& reg : regs64) {
		if (prefix.empty() || std::string(reg).find(prefix) == 0) {
			targets.push_back({{"label", reg}, {"type", "property"}});
		}
	}
	if (prefix.empty() || prefix[0] == '*' || prefix[0] == '[') {
		targets.push_back({{"label", "*0x<address>"}, {"type", "text"}, {"text", "*0x"}});
		targets.push_back({{"label", "[0x<address>]"}, {"type", "text"}, {"text", "[0x"}});
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "completions";
	resp.success = true;
	resp.body = {{"targets", targets}};
	SendResponse(resp);
}

// --- IPC Event Handling ---

void DapServer::OnIpcEvent(uint32_t eventId, const uint8_t* payload, uint32_t size) {
	auto event = static_cast<IpcEvent>(eventId);

	DAP_TRACE("IpcEvent", "eventId=" + std::to_string(eventId) + " size=" + std::to_string(size));

	switch (event) {
	case IpcEvent::BreakpointHit: {
		if (size >= sizeof(BreakpointHitEvent)) {
			auto* e = reinterpret_cast<const BreakpointHitEvent*>(payload);
			DAP_TRACE("BreakpointHit", "bpId=" + std::to_string(e->breakpointId) + " addr=" + FormatAddress(e->address) + " thread=" + std::to_string(e->threadId));
			lastStoppedThreadId_.store(e->threadId);

			// StepOver 임시 BP 히트 처리 (ID 또는 주소 매칭)
			bool isTempBp = false;
			{
				std::lock_guard<std::mutex> stepLock(steppingMutex_);
				if (stepOverTempBpId_ != 0 && e->breakpointId == stepOverTempBpId_) {
					isTempBp = true;
				} else if (stepOverTempBpAddr_ != 0 && e->address == stepOverTempBpAddr_) {
					isTempBp = true;
				}
			}
			if (isTempBp) {
				LOG_INFO("Temp BP hit (stepOver call skip): id=%u addr=0x%llX", e->breakpointId, e->address);
				// 임시 BP 제거 — 단, 사용자 BP와 같은 주소면 제거하지 않음
				bool isUserBp = false;
				{
					std::lock_guard<std::mutex> bpLock(breakpointMutex_);
					for (const auto& m : breakpointMappings_) {
						if (m.vehId == e->breakpointId) {
							isUserBp = true;
							break;
						}
					}
				}
				if (!isUserBp) {
					RemoveBreakpointRequest rmReq;
					rmReq.id = e->breakpointId;
					pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
				}
				bool sameLine = false;
				{
					std::lock_guard<std::mutex> stepLock(steppingMutex_);
					stepOverTempBpId_ = 0;
					stepOverTempBpAddr_ = 0;

					// 소스 라인 스텝 중이면 라인 변경 확인 (instruction 모드는 스킵)
					if (steppingMode_ == SteppingMode::Over && !steppingInstruction_
						&& steppingSourceLine_ != 0
						&& steppingStartAddr_ != 0 && steppingNextLineAddr_ != 0
						&& e->address >= steppingStartAddr_ && e->address < steppingNextLineAddr_) {
						sameLine = true;
					}
				}
				if (sameLine) {
					// 같은 라인 → 계속 스텝
					LOG_DEBUG("Temp BP: still same line, auto-stepping");
					StepRequest stepReq;
					stepReq.threadId = e->threadId;
					pipeClient_.SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));
					break;
				}

				// 라인 변경됨 → stopped(step) 이벤트
				{
					std::lock_guard<std::mutex> stepLock(steppingMutex_);
					steppingMode_ = SteppingMode::None;
				}
				SendEvent("stopped", {
					{"reason", "step"},
					{"threadId", (int)e->threadId},
					{"allThreadsStopped", true},
				});
				break;
			}

			// 매칭된 BP 검색 — mutex 안에서 정보 복사만, IPC 호출은 밖에서 (데드락 방지)
			json hitBps = json::array();
			bool shouldStop = true;
			std::string bpCondition, bpLogMessage;
			{
				std::lock_guard<std::mutex> bpLock(breakpointMutex_);
				for (auto& m : breakpointMappings_) {
					if (m.vehId == e->breakpointId) {
						hitBps.push_back(m.dapId);
						if (!m.hitCondition.empty()) {
							m.hitCount++;
							try {
								uint32_t target = std::stoul(m.hitCondition, nullptr, 0);
								if (m.hitCount < target) shouldStop = false;
							} catch (...) {}
						}
						bpCondition = m.condition;
						bpLogMessage = m.logMessage;
						break;
					}
				}
			}
			// mutex 해제 후 — 이벤트 내장 레지스터 사용 (Reader 스레드에서 SendAndReceive 데드락 방지)
			if (shouldStop && !bpCondition.empty()) {
				shouldStop = EvaluateCondition(bpCondition, e->threadId, &e->regs);
			}
			if (shouldStop && !bpLogMessage.empty()) {
				std::string expanded = ExpandLogMessage(bpLogMessage, e->threadId, &e->regs);
				SendEvent("output", {
					{"category", "console"},
					{"output", expanded + "\n"},
				});
				shouldStop = false;
			}

			if (shouldStop) {
				// 스텝 중 BP 히트 → 스텝 종료 + 좀비 temp BP 정리
				CleanupStaleTempBp();
				{
					std::lock_guard<std::mutex> stepLock(steppingMutex_);
					steppingMode_ = SteppingMode::None;
				}
				SendEvent("stopped", {
					{"reason", "breakpoint"},
					{"threadId", (int)e->threadId},
					{"allThreadsStopped", true},
					{"hitBreakpointIds", hitBps},
				});
			} else {
				// 조건 불만족 or Log Point → 자동 Continue
				ContinueRequest contReq;
				contReq.threadId = e->threadId;
				pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
			}
		}
		break;
	}

	case IpcEvent::StepCompleted: {
		if (size >= sizeof(StepCompletedEvent)) {
			auto* e = reinterpret_cast<const StepCompletedEvent*>(payload);

			// 스텝핑 상태 안전하게 복사 (steppingMutex_ 보호)
			SteppingMode curMode;
			uint32_t curThreadId;
			bool curInstruction;
			uint64_t curStartAddr, curNextLineAddr;
			{
				std::lock_guard<std::mutex> stepLock(steppingMutex_);
				curMode = steppingMode_;
				curThreadId = steppingThreadId_;
				curInstruction = steppingInstruction_;
				curStartAddr = steppingStartAddr_;
				curNextLineAddr = steppingNextLineAddr_;
			}
			LOG_INFO("StepCompleted: threadId=%u addr=0x%llX mode=%d", e->threadId, e->address, (int)curMode);

			// 소스 라인 스텝 중이면 CALL 스킵 + 라인이 바뀔 때까지 자동 반복
			// instruction 모드면 auto-step 안 함 → 바로 stopped
			if (curMode == SteppingMode::Over && !curInstruction
				&& e->threadId == curThreadId) {
				// 주소 범위로 판별: steppingStartAddr_ <= addr < steppingNextLineAddr_이면 같은 라인
				bool sameLine = false;
				if (curStartAddr != 0 && curNextLineAddr != 0) {
					sameLine = (e->address >= curStartAddr && e->address < curNextLineAddr);
				}

				// 범위 resolve 실패 시에도 CALL 감지하여 스킵 (함수 안으로 빠지는 것 방지)
				if (!sameLine && targetProcess_) {
					uint8_t codeBuf[16] = {};
					SIZE_T bytesRead = 0;
					if (ReadProcessMemory(targetProcess_, (LPCVOID)e->address, codeBuf, 16, &bytesRead)
						&& bytesRead >= 2) {
						auto insns = disassembler_->Disassemble(codeBuf, (uint32_t)bytesRead, e->address, 1);
						if (!insns.empty()) {
							const auto& mn = insns[0].mnemonic;
							if (mn.size() >= 4 && (mn[0]=='c'||mn[0]=='C') && (mn[1]=='a'||mn[1]=='A')
								&& (mn[2]=='l'||mn[2]=='L') && (mn[3]=='l'||mn[3]=='L')) {
								uint64_t retAddr = e->address + insns[0].length;
								LOG_INFO("StepOver fallback: CALL at 0x%llX, temp BP at 0x%llX", e->address, retAddr);
								SetBreakpointRequest bpReq;
								bpReq.address = retAddr;
								pipeClient_.SendCommand(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq));
								{
									std::lock_guard<std::mutex> stepLock(steppingMutex_);
									stepOverTempBpAddr_ = retAddr;
								}
								ContinueRequest contReq;
								contReq.threadId = e->threadId;
								pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
								break;
							}
						}
					}
				}

				if (sameLine) {
					LOG_DEBUG("StepCompleted: still in same line (0x%llX in [0x%llX, 0x%llX)), auto-stepping",
						e->address, curStartAddr, curNextLineAddr);

					// CALL 명령어 감지: ReadProcessMemory (직접 Win32, IPC 불필요)
					bool isCall = false;
					uint64_t callRetAddr = 0;
					if (targetProcess_) {
						uint8_t codeBuf[16] = {};
						SIZE_T bytesRead = 0;
						if (ReadProcessMemory(targetProcess_, (LPCVOID)e->address, codeBuf, 16, &bytesRead)
							&& bytesRead >= 2) {
							auto insns = disassembler_->Disassemble(codeBuf, (uint32_t)bytesRead, e->address, 1);
							if (!insns.empty()) {
								const auto& mn = insns[0].mnemonic;
								if (mn.size() >= 4 && (mn[0]=='c'||mn[0]=='C') && (mn[1]=='a'||mn[1]=='A')
									&& (mn[2]=='l'||mn[2]=='L') && (mn[3]=='l'||mn[3]=='L')) {
									isCall = true;
									callRetAddr = e->address + insns[0].length;
								}
							}
						}
					}

					if (isCall) {
						LOG_INFO("Auto-step: CALL at 0x%llX, temp BP at 0x%llX", e->address, callRetAddr);
						// 임시 BP 설정 (fire-and-forget) + Continue
						SetBreakpointRequest bpReq;
						bpReq.address = callRetAddr;
						pipeClient_.SendCommand(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq));
						{
							std::lock_guard<std::mutex> stepLock(steppingMutex_);
							stepOverTempBpAddr_ = callRetAddr;
						}

						ContinueRequest contReq;
						contReq.threadId = e->threadId;
						pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
					} else {
						StepRequest stepReq;
						stepReq.threadId = e->threadId;
						pipeClient_.SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));
					}
					break; // DAP stopped 이벤트 보내지 않음
				}

				LOG_INFO("StepCompleted: line changed (addr=0x%llX outside [0x%llX, 0x%llX))",
					e->address, curStartAddr, curNextLineAddr);
			}

			{
				std::lock_guard<std::mutex> stepLock(steppingMutex_);
				steppingMode_ = SteppingMode::None;
			}
			lastStoppedThreadId_.store(e->threadId);
			SendEvent("stopped", {
				{"reason", "step"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
			});
		} else {
			LOG_ERROR("StepCompleted: payload too small (%u < %zu)", size, sizeof(StepCompletedEvent));
		}
		break;
	}

	case IpcEvent::ExceptionOccurred: {
		if (size >= sizeof(ExceptionEvent)) {
			auto* e = reinterpret_cast<const ExceptionEvent*>(payload);
			lastStoppedThreadId_.store(e->threadId);
			{
				std::lock_guard<std::mutex> lock(exceptionMutex_);
				lastException_.threadId = e->threadId;
				lastException_.code = e->exceptionCode;
				{
					char safeBuf[sizeof(e->description)];
					memcpy(safeBuf, e->description, sizeof(e->description));
					safeBuf[sizeof(e->description) - 1] = '\0';
					lastException_.description = safeBuf;
				}
			}

			SendEvent("stopped", {
				{"reason", "exception"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
				{"description", lastException_.description},
			});
		}
		break;
	}

	case IpcEvent::ThreadCreated: {
		if (size >= sizeof(ThreadEvent)) {
			auto* e = reinterpret_cast<const ThreadEvent*>(payload);
			SendEvent("thread", {
				{"reason", "started"},
				{"threadId", (int)e->threadId},
			});
		}
		break;
	}

	case IpcEvent::ThreadExited: {
		if (size >= sizeof(ThreadEvent)) {
			auto* e = reinterpret_cast<const ThreadEvent*>(payload);
			SendEvent("thread", {
				{"reason", "exited"},
				{"threadId", (int)e->threadId},
			});
		}
		break;
	}

	case IpcEvent::ModuleLoaded: {
		if (size >= sizeof(ModuleEvent)) {
			auto* e = reinterpret_cast<const ModuleEvent*>(payload);
			Module m;
			m.id = std::to_string(e->module.baseAddress);
			m.name = e->module.name;
			m.path = e->module.path;
			SendEvent("module", {
				{"reason", "new"},
				{"module", m.ToJson()},
			});

			// PDB 심볼 엔진에 모듈 로드
			if (symbolEngineReady_) {
				char safePath[sizeof(e->module.path)];
				memcpy(safePath, e->module.path, sizeof(e->module.path));
				safePath[sizeof(e->module.path) - 1] = '\0';
				symbolEngine_.LoadModule(safePath, e->module.baseAddress, e->module.size);
			}
		}
		break;
	}

	case IpcEvent::ModuleUnloaded: {
		if (size >= sizeof(ModuleEvent)) {
			auto* e = reinterpret_cast<const ModuleEvent*>(payload);
			SendEvent("module", {
				{"reason", "removed"},
				{"module", {{"id", std::to_string(e->module.baseAddress)}}},
			});

			// PDB 심볼 엔진에서 모듈 언로드
			if (symbolEngineReady_) {
				symbolEngine_.UnloadModule(e->module.baseAddress);
			}
		}
		break;
	}

	case IpcEvent::ProcessExited: {
		if (size >= sizeof(ProcessExitEvent)) {
			auto* e = reinterpret_cast<const ProcessExitEvent*>(payload);
			SendEvent("exited", {{"exitCode", (int)e->exitCode}});
			SendEvent("terminated");
		}
		break;
	}

	case IpcEvent::Ready:
		LOG_INFO("VEH DLL ready");
		break;

	case IpcEvent::Error:
		LOG_ERROR("VEH DLL error event received");
		break;

	case IpcEvent::HeartbeatAck:
		LOG_DEBUG("Heartbeat ack received");
		break;

	case IpcEvent::Paused:
		// OnPause에서 이미 선제적으로 stopped 이벤트를 보냄.
		// DLL에서 오는 Paused 이벤트는 중복 방지를 위해 로깅만 한다.
		LOG_DEBUG("IPC Paused event received (already handled by OnPause)");
		break;

	default:
		LOG_WARN("Unknown IPC event: 0x%X", eventId);
		break;
	}
}

// --- Helpers ---

std::string DapServer::GetDllPath() {
	wchar_t exePathW[MAX_PATH];
	GetModuleFileNameW(nullptr, exePathW, MAX_PATH);

	std::filesystem::path dir = std::filesystem::path(exePathW).parent_path();

	if (targetPid_ != 0) {
		return Injector::SelectDllForTarget(targetPid_, dir.string());
	}

	return (dir / "vcruntime_net.dll").string();
}

bool DapServer::TryParseRegisterName(const std::string& name) {
	std::string upper = name;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	static const char* regNames[] = {
		"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
		"RIP", "RFLAGS",
		"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
		"EIP", "EFLAGS",
	};
	for (auto* rn : regNames) {
		if (upper == rn) return true;
	}
	return false;
}

uint64_t DapServer::ResolveRegisterByName(const std::string& name, const RegisterSet& regs) {
	std::string upper = name;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	if (upper == "RAX" || upper == "EAX") return regs.rax;
	if (upper == "RBX" || upper == "EBX") return regs.rbx;
	if (upper == "RCX" || upper == "ECX") return regs.rcx;
	if (upper == "RDX" || upper == "EDX") return regs.rdx;
	if (upper == "RSI" || upper == "ESI") return regs.rsi;
	if (upper == "RDI" || upper == "EDI") return regs.rdi;
	if (upper == "RBP" || upper == "EBP") return regs.rbp;
	if (upper == "RSP" || upper == "ESP") return regs.rsp;
	if (upper == "R8")  return regs.r8;
	if (upper == "R9")  return regs.r9;
	if (upper == "R10") return regs.r10;
	if (upper == "R11") return regs.r11;
	if (upper == "R12") return regs.r12;
	if (upper == "R13") return regs.r13;
	if (upper == "R14") return regs.r14;
	if (upper == "R15") return regs.r15;
	if (upper == "RIP" || upper == "EIP") return regs.rip;
	if (upper == "RFLAGS" || upper == "EFLAGS") return regs.rflags;
	return 0;
}

bool DapServer::EvaluateCondition(const std::string& condition, uint32_t threadId, const RegisterSet* cachedRegs) {
	// 조건 문법: REG==VAL, REG!=VAL, REG>VAL, REG<VAL, REG>=VAL, REG<=VAL
	// 또는 *ADDR==VAL (메모리 비교)
	// 파싱 실패 시 true 반환 (항상 중단)

	// 연산자 검색
	struct { const char* op; size_t len; } ops[] = {
		{"==", 2}, {"!=", 2}, {">=", 2}, {"<=", 2}, {">", 1}, {"<", 1},
	};

	std::string lhs, rhs;
	std::string opStr;

	for (auto& [op, len] : ops) {
		auto pos = condition.find(op);
		if (pos != std::string::npos) {
			lhs = condition.substr(0, pos);
			rhs = condition.substr(pos + len);
			opStr = op;
			break;
		}
	}

	if (opStr.empty() || lhs.empty() || rhs.empty()) {
		LOG_WARN("Condition parse failed: '%s'", condition.c_str());
		return true; // 파싱 실패 → 항상 중단
	}

	// 앞뒤 공백 제거
	auto trim = [](std::string s) {
		while (!s.empty() && s.front() == ' ') s.erase(s.begin());
		while (!s.empty() && s.back() == ' ') s.pop_back();
		return s;
	};
	lhs = trim(lhs);
	rhs = trim(rhs);

	// LHS 값 해석
	uint64_t lhsVal = 0;
	if (lhs[0] == '*' || lhs[0] == '[') {
		// 메모리 읽기 — ReadProcessMemory 직접 사용 (Reader 스레드 데드락 방지)
		std::string addrStr = lhs.substr(1);
		if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
		try {
			uint64_t addr = std::stoull(addrStr, nullptr, 0);
			if (targetProcess_) {
				SIZE_T bytesRead = 0;
				ReadProcessMemory(targetProcess_, (LPCVOID)addr, &lhsVal, 8, &bytesRead);
			}
		} catch (...) { return true; }
	} else if (TryParseRegisterName(lhs)) {
		// 레지스터 — cachedRegs 우선 사용 (Reader 스레드에서 SendAndReceive 데드락 방지)
		if (cachedRegs) {
			lhsVal = ResolveRegisterByName(lhs, *cachedRegs);
		} else {
			GetRegistersRequest regReq;
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
				if (respData.size() >= sizeof(GetRegistersResponse)) {
					auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
					lhsVal = ResolveRegisterByName(lhs, regResp->regs);
				}
			}
		}
	} else {
		try { lhsVal = std::stoull(lhs, nullptr, 0); } catch (...) { return true; }
	}

	// RHS 값 해석
	uint64_t rhsVal = 0;
	if (TryParseRegisterName(rhs)) {
		if (cachedRegs) {
			rhsVal = ResolveRegisterByName(rhs, *cachedRegs);
		} else {
			GetRegistersRequest regReq;
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
				if (respData.size() >= sizeof(GetRegistersResponse)) {
					auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
					rhsVal = ResolveRegisterByName(rhs, regResp->regs);
				}
			}
		}
	} else {
		try { rhsVal = std::stoull(rhs, nullptr, 0); } catch (...) { return true; }
	}

	// 비교
	if (opStr == "==") return lhsVal == rhsVal;
	if (opStr == "!=") return lhsVal != rhsVal;
	if (opStr == ">=") return lhsVal >= rhsVal;
	if (opStr == "<=") return lhsVal <= rhsVal;
	if (opStr == ">")  return lhsVal > rhsVal;
	if (opStr == "<")  return lhsVal < rhsVal;
	return true;
}

std::string DapServer::ExpandLogMessage(const std::string& msg, uint32_t threadId, const RegisterSet* cachedRegs) {
	// {표현식}을 실제 값으로 치환
	// 예: "RAX={RAX}, mem={*0x7FF600}" → "RAX=0x0000000000001234, mem=0x00000000DEADBEEF"
	std::string result;
	result.reserve(msg.size());

	// 레지스터 캐시 — cachedRegs 우선 사용 (Reader 스레드 데드락 방지)
	bool regsLoaded = (cachedRegs != nullptr);
	RegisterSet regs = cachedRegs ? *cachedRegs : RegisterSet{};
	auto ensureRegs = [&]() {
		if (!regsLoaded) {
			GetRegistersRequest regReq;
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
				if (respData.size() >= sizeof(GetRegistersResponse)) {
					auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
					regs = regResp->regs;
				}
			}
			regsLoaded = true;
		}
	};

	size_t i = 0;
	while (i < msg.size()) {
		if (msg[i] == '{') {
			auto end = msg.find('}', i + 1);
			if (end == std::string::npos) {
				result += msg[i++];
				continue;
			}

			std::string expr = msg.substr(i + 1, end - i - 1);
			// 앞뒤 공백 제거
			while (!expr.empty() && expr.front() == ' ') expr.erase(expr.begin());
			while (!expr.empty() && expr.back() == ' ') expr.pop_back();

			char buf[32];
			if (TryParseRegisterName(expr)) {
				ensureRegs();
				uint64_t val = ResolveRegisterByName(expr, regs);
				if (regs.is32bit)
					snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
				else
					snprintf(buf, sizeof(buf), "0x%016llX", val);
				result += buf;
			} else if (!expr.empty() && (expr[0] == '*' || expr[0] == '[')) {
				// 메모리 읽기 — ReadProcessMemory 직접 사용 (Reader 스레드 데드락 방지)
				std::string addrStr = expr.substr(1);
				if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
				try {
					uint64_t addr = std::stoull(addrStr, nullptr, 0);
					uint64_t val = 0;
					SIZE_T bytesRead = 0;
					if (targetProcess_ && ReadProcessMemory(targetProcess_, (LPCVOID)addr, &val, 8, &bytesRead) && bytesRead >= 8) {
						snprintf(buf, sizeof(buf), "0x%016llX", val);
						result += buf;
					} else {
						result += "???";
					}
				} catch (...) {
					result += "???";
				}
			} else {
				// 해석 불가 → 그대로 유지
				result += '{';
				result += expr;
				result += '}';
			}
			i = end + 1;
		} else {
			result += msg[i++];
		}
	}
	return result;
}

bool DapServer::IsCallInstruction(uint32_t threadId, uint64_t& nextInsnAddr) {
	if (!targetProcess_) return false;

	// 현재 RIP 가져오기 (GetStackTrace IPC)
	GetStackTraceRequest stReq;
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
		return false;
	if (stResp.size() < sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo))
		return false;
	auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
	if (hdr->status != IpcStatus::Ok || hdr->count == 0)
		return false;
	auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + sizeof(GetStackTraceResponse));
	uint64_t rip = frame->address;

	// ReadProcessMemory 직접 호출 (IPC 우회 — BP에 의한 0xCC 패치 영향 없음)
	uint8_t codeBuf[16] = {};
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(targetProcess_, (LPCVOID)rip, codeBuf, 16, &bytesRead) || bytesRead < 1) {
		LOG_WARN("IsCallInstruction: ReadProcessMemory at 0x%llX failed: %u", rip, GetLastError());
		return false;
	}

	auto insns = disassembler_->Disassemble(codeBuf, (uint32_t)bytesRead, rip, 1);
	if (insns.empty()) {
		LOG_WARN("IsCallInstruction: disassemble failed at 0x%llX", rip);
		return false;
	}

	const auto& insn = insns[0];
	LOG_DEBUG("IsCallInstruction: RIP=0x%llX insn='%s' len=%u", rip, insn.mnemonic.c_str(), insn.length);

	// mnemonic이 "call"로 시작하는지 확인
	if (insn.mnemonic.size() >= 4
		&& (insn.mnemonic[0] == 'c' || insn.mnemonic[0] == 'C')
		&& (insn.mnemonic[1] == 'a' || insn.mnemonic[1] == 'A')
		&& (insn.mnemonic[2] == 'l' || insn.mnemonic[2] == 'L')
		&& (insn.mnemonic[3] == 'l' || insn.mnemonic[3] == 'L')) {
		nextInsnAddr = rip + insn.length;
		return true;
	}
	return false;
}

void DapServer::CleanupStaleTempBp() {
	// 사용자 BP와 같은 ID이면 제거하지 않음 (BP 충돌 방지)
	auto isUserBpId = [&](uint32_t vehId) -> bool {
		std::lock_guard<std::mutex> bpLock(breakpointMutex_);
		for (const auto& m : breakpointMappings_) {
			if (m.vehId == vehId) return true;
		}
		return false;
	};
	auto isUserBpAddr = [&](uint64_t addr) -> bool {
		std::lock_guard<std::mutex> bpLock(breakpointMutex_);
		for (const auto& m : breakpointMappings_) {
			if (m.address == addr) return true;
		}
		return false;
	};

	uint32_t tempId;
	uint64_t tempAddr;
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		tempId = stepOverTempBpId_;
		tempAddr = stepOverTempBpAddr_;
	}

	if (tempId != 0) {
		if (!isUserBpId(tempId)) {
			LOG_INFO("CleanupStaleTempBp: removing id=%u", tempId);
			RemoveBreakpointRequest rmReq;
			rmReq.id = tempId;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
		} else {
			LOG_INFO("CleanupStaleTempBp: id=%u is user BP, skipping removal", tempId);
		}
	} else if (tempAddr != 0) {
		if (!isUserBpAddr(tempAddr)) {
			LOG_INFO("CleanupStaleTempBp: removing by addr=0x%llX", tempAddr);
			RemoveBreakpointByAddrRequest rmReq;
			rmReq.address = tempAddr;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpointByAddr, &rmReq, sizeof(rmReq));
		} else {
			LOG_INFO("CleanupStaleTempBp: addr=0x%llX is user BP, skipping removal", tempAddr);
		}
	}
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		stepOverTempBpId_ = 0;
		stepOverTempBpAddr_ = 0;
	}
}

bool DapServer::GetTopFrameSourceLine(uint32_t threadId, std::string& file, uint32_t& line) {
	GetStackTraceRequest stReq;
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
		return false;

	if (stResp.size() < sizeof(GetStackTraceResponse))
		return false;

	auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
	if (hdr->status != IpcStatus::Ok || hdr->count == 0)
		return false;

	size_t frameOffset = sizeof(GetStackTraceResponse);
	if (stResp.size() < frameOffset + sizeof(StackFrameInfo))
		return false;

	auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + frameOffset);
	if (frame->line == 0 || frame->sourceFile[0] == '\0')
		return false;

	char safeBuf[sizeof(frame->sourceFile)];
	memcpy(safeBuf, frame->sourceFile, sizeof(frame->sourceFile));
	safeBuf[sizeof(frame->sourceFile) - 1] = '\0';
	file = safeBuf;
	line = frame->line;
	return true;
}

void DapServer::ResolveStepRange(uint32_t threadId) {
	std::string file;
	uint32_t line = 0;
	if (!GetTopFrameSourceLine(threadId, file, line))
		return;

	// 현재 라인의 주소 = steppingStartAddr_
	ResolveSourceLineRequest resolveReq = {};
	strncpy_s(resolveReq.fileName, file.c_str(), sizeof(resolveReq.fileName) - 1);
	resolveReq.line = line;

	std::vector<uint8_t> respData;
	if (pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), respData)
		&& respData.size() >= sizeof(ResolveSourceLineResponse)) {
		auto* r = reinterpret_cast<const ResolveSourceLineResponse*>(respData.data());
		if (r->status == IpcStatus::Ok) {
			std::lock_guard<std::mutex> stepLock(steppingMutex_);
			steppingStartAddr_ = r->address;
		}
	}

	// 다음 라인의 주소 = steppingNextLineAddr_
	resolveReq.line = line + 1;
	if (pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), respData)
		&& respData.size() >= sizeof(ResolveSourceLineResponse)) {
		auto* r = reinterpret_cast<const ResolveSourceLineResponse*>(respData.data());
		if (r->status == IpcStatus::Ok) {
			std::lock_guard<std::mutex> stepLock(steppingMutex_);
			steppingNextLineAddr_ = r->address;
		}
	}

	uint64_t snapStart, snapNext;
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		snapStart = steppingStartAddr_;
		snapNext = steppingNextLineAddr_;
	}
	DAP_TRACE("ResolveStepRange", file + ":" + std::to_string(line)
		+ " start=" + FormatAddress(snapStart)
		+ " nextLine=" + FormatAddress(snapNext));
}

void DapServer::ResumeMainThread() {
	if (mainThreadResumed_ || launchedMainThreadId_ == 0) return;

	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, launchedMainThreadId_);
	if (hThread) {
		DWORD prevCount = ResumeThread(hThread);
		CloseHandle(hThread);
		mainThreadResumed_ = true;
		LOG_INFO("Resumed main thread %u (prev suspend count: %u)",
			launchedMainThreadId_, prevCount);
	} else {
		LOG_ERROR("Failed to open main thread %u for resume: %u",
			launchedMainThreadId_, GetLastError());
	}
}

void DapServer::Cleanup(bool detachOnly) {
	// 메인 스레드가 아직 suspended이면 resume (안 하면 프로세스가 좀비로 남음)
	ResumeMainThread();

	if (pipeClient_.IsConnected()) {
		// detachOnly=true: Detach 명령 → DLL 파이프 서버는 유지 (재연결 가능)
		// detachOnly=false: Shutdown 명령 → DLL 파이프 서버도 종료
		auto cmd = detachOnly ? IpcCommand::Detach : IpcCommand::Shutdown;
		pipeClient_.SendCommand(cmd);
		LOG_INFO("Sent %s to DLL", detachOnly ? "Detach" : "Shutdown");
	}
	// Disconnect는 항상 호출 (파이프 닫기 + 스레드 정리)
	pipeClient_.Disconnect();

	{
		std::lock_guard<std::mutex> lock(breakpointMutex_);
		breakpointMappings_.clear();
		dataBreakpointMappings_.clear();
	}
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		frameMap_.clear();
		nextFrameId_ = 1;
	}

	// SymbolEngine 정리 (targetProcess_ close 전에 — SymCleanup이 핸들 사용)
	if (symbolEngineReady_) {
		symbolEngine_.Cleanup();
		symbolEngineReady_ = false;
	}

	if (targetProcess_) {
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
	}
}

} // namespace veh::dap
