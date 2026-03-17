#include "dap_server.h"
#include "logger.h"
#include <filesystem>
#include <sstream>
#include <algorithm>

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

	std::string dllPath = GetDllPath();
	targetPid_ = Injector::LaunchAndInject(programPath_, argStr, cwd, dllPath, stopOnEntry_, injectionMethod_);

	if (targetPid_ == 0) {
		resp.success = false;
		resp.message = "Failed to launch and inject: " + programPath_;
		SendResponse(resp);
		return;
	}

	launchedByUs_ = true;

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

	// stopOnEntry이면 stopped 이벤트 전송
	if (stopOnEntry_) {
		SendEvent("stopped", {
			{"reason", "entry"},
			{"threadId", 1},
			{"allThreadsStopped", true},
		});
	}
}

// --- Breakpoints ---

void DapServer::OnSetBreakpoints(const Request& req) {
	// DAP에서는 setBreakpoints가 전체 교체 방식
	std::lock_guard<std::mutex> lock(breakpointMutex_);

	std::string sourceFile;
	if (req.arguments.contains("source") && req.arguments["source"].contains("path")) {
		sourceFile = req.arguments["source"]["path"].get<std::string>();
	}

	// 기존 source BP 제거 (같은 source에 대해)
	for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end(); ) {
		if (it->source == sourceFile) {
			RemoveBreakpointRequest rmReq;
			rmReq.id = it->vehId;
			pipeClient_.SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			it = breakpointMappings_.erase(it);
		} else {
			++it;
		}
	}

	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

	// 주소 기반 브레이크포인트 (instructionReference)
	// source가 있으면 소스 브레이크포인트, 없으면 주소 기반
	for (auto& bp : bps) {
		uint64_t address = 0;

		// 소스 파일 기반이면 PDB 심볼을 사용하여 주소 해석
		if (bp.contains("instructionReference")) {
			address = ParseAddress(bp["instructionReference"].get<std::string>());
		} else if (bp.contains("line")) {
			int line = bp["line"].get<int>();
			std::string sourceFile;
			if (req.arguments.contains("source") && req.arguments["source"].contains("path")) {
				sourceFile = req.arguments["source"]["path"].get<std::string>();
			}

			if (!sourceFile.empty() && line > 0) {
				// PDB를 통한 소스 라인 → 주소 해석
				ResolveSourceLineRequest resolveReq = {};
				strncpy_s(resolveReq.fileName, sourceFile.c_str(), sizeof(resolveReq.fileName) - 1);
				resolveReq.line = line;

				std::vector<uint8_t> resolveResp;
				if (pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), resolveResp)) {
					if (resolveResp.size() >= sizeof(ResolveSourceLineResponse)) {
						auto* resp2 = reinterpret_cast<const ResolveSourceLineResponse*>(resolveResp.data());
						if (resp2->status == IpcStatus::Ok) {
							address = resp2->address;
							LOG_INFO("Source BP: %s:%d -> 0x%llX", sourceFile.c_str(), line, address);
						}
					}
				}

				if (address == 0) {
					Breakpoint dbp;
					dbp.id = nextDapBpId_++;
					dbp.verified = false;
					dbp.message = "No PDB symbol found for " + sourceFile + ":" + std::to_string(line);
					breakpointsJson.push_back(dbp.ToJson());
					continue;
				}
			} else {
				Breakpoint dbp;
				dbp.id = nextDapBpId_++;
				dbp.verified = false;
				dbp.message = "Source path and line required";
				breakpointsJson.push_back(dbp.ToJson());
				continue;
			}
		}

		if (address == 0) {
			Breakpoint dbp;
			dbp.id = nextDapBpId_++;
			dbp.verified = false;
			dbp.message = "Invalid address";
			breakpointsJson.push_back(dbp.ToJson());
			continue;
		}

		// VEH DLL에 브레이크포인트 설정 요청
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
				breakpointMappings_.push_back({dbp.id, setResp->id, address, sourceFile, cond, hitCond, 0, logMsg});
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
	resp.command = "setBreakpoints";
	resp.success = true;
	resp.body = {{"breakpoints", breakpointsJson}};
	SendResponse(resp);
}

void DapServer::OnSetFunctionBreakpoints(const Request& req) {
	std::lock_guard<std::mutex> lock(breakpointMutex_);
	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

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

				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}, {}, {}, 0, {}});
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
	std::lock_guard<std::mutex> lock(breakpointMutex_);
	json breakpointsJson = json::array();
	auto bps = req.arguments.value("breakpoints", json::array());

	// 기존 instruction breakpoint 제거 (전체 교체 방식)
	for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end(); ) {
		if (it->source.empty()) {
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
				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}, cond, hitCond, 0, logMsg});
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

	// 실행 재개 시 프레임 매핑 초기화 (다음 stopped에서 새로 생성됨)
	{
		std::lock_guard<std::mutex> lock(frameMutex_);
		frameMap_.clear();
		nextFrameId_ = 1;
	}

	ContinueRequest contReq;
	contReq.threadId = threadId;
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
	StepRequest stepReq;
	stepReq.threadId = threadId;
	pipeClient_.SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "next";
	resp.success = true;
	SendResponse(resp);
}

void DapServer::OnStepIn(const Request& req) {
	uint32_t threadId = req.arguments.value("threadId", 0);
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
					frameMap_[fid] = {threadId, (int)(startFrame + i)};
				}

				StackFrameDap f;
				f.id = fid;
				f.name = frames[i].functionName[0] ? frames[i].functionName :
					FormatAddress(frames[i].address);
				f.line = frames[i].line;
				f.instructionPointerReference = FormatAddress(frames[i].address);
				if (frames[i].sourceFile[0]) {
					f.source.path = frames[i].sourceFile;
					std::string fullPath = frames[i].sourceFile;
					auto pos = fullPath.find_last_of("\\/");
					f.source.name = (pos != std::string::npos) ? fullPath.substr(pos + 1) : fullPath;
				}
				if (frames[i].moduleName[0]) {
					f.moduleId = frames[i].moduleName;
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

				int fid;
				{
					std::lock_guard<std::mutex> lock(frameMutex_);
					fid = nextFrameId_++;
					frameMap_[fid] = {threadId, 0};
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

	// 레지스터 스코프
	Scope regScope;
	regScope.name = "Registers";
	regScope.variablesReference = SCOPE_REGISTERS | frameId;
	regScope.namedVariables = 26;  // 레지스터 대략 개수: GPR 16~18 + RFLAGS + DR0~DR7 (VSCode가 펼침 가능하다고 인식하게 함)
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

	// 충분한 바이트를 읽어서 디스어셈블
	uint32_t readSize = instrCount * 15; // x86 최대 명령어 길이 15바이트
	ReadMemoryRequest readReq;
	readReq.address = addr;
	readReq.size = readSize;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "disassemble";

	std::vector<uint8_t> memData;
	if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), memData)) {
		auto instructions = disassembler_->Disassemble(
			memData.data(), (uint32_t)memData.size(), addr, instrCount);

		json instrsJson = json::array();
		for (auto& insn : instructions) {
			DisassembledInstruction di;
			di.address = FormatAddress(insn.address);
			di.instructionBytes = insn.bytes;
			di.instruction = insn.mnemonic;
			instrsJson.push_back(di.ToJson());
		}

		resp.success = true;
		resp.body = {{"instructions", instrsJson}};
	} else {
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

		// 재시작
		std::string dllPath = GetDllPath();
		std::string argStr;
		targetPid_ = Injector::LaunchAndInject(programPath_, argStr, "", dllPath, stopOnEntry_, injectionMethod_);

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

		resp.success = true;
		SendResponse(resp);
		SendEvent("initialized");
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

	switch (event) {
	case IpcEvent::BreakpointHit: {
		if (size >= sizeof(BreakpointHitEvent)) {
			auto* e = reinterpret_cast<const BreakpointHitEvent*>(payload);
			lastStoppedThreadId_.store(e->threadId);

			// 매칭된 BP 검색 + 조건 평가
			std::lock_guard<std::mutex> bpLock(breakpointMutex_);
			json hitBps = json::array();
			bool shouldStop = true;
			for (auto& m : breakpointMappings_) {
				if (m.vehId == e->breakpointId) {
					hitBps.push_back(m.dapId);

					// hitCondition 평가 (히트 카운터)
					if (!m.hitCondition.empty()) {
						m.hitCount++;
						try {
							uint32_t target = std::stoul(m.hitCondition, nullptr, 0);
							if (m.hitCount < target) {
								shouldStop = false;
							}
						} catch (...) {
							// 파싱 실패시 무시, 항상 중단
						}
					}

					// condition 평가 (레지스터/메모리 조건식)
					if (shouldStop && !m.condition.empty()) {
						shouldStop = EvaluateCondition(m.condition, e->threadId);
					}

					// Log Point: condition 통과 시에만 메시지 출력 후 Continue (중단하지 않음)
					if (shouldStop && !m.logMessage.empty()) {
						std::string expanded = ExpandLogMessage(m.logMessage, e->threadId);
						SendEvent("output", {
							{"category", "console"},
							{"output", expanded + "\n"},
						});
						shouldStop = false;
					}
					break;
				}
			}

			if (shouldStop) {
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
			lastStoppedThreadId_.store(e->threadId);
			SendEvent("stopped", {
				{"reason", "step"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
			});
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

bool DapServer::EvaluateCondition(const std::string& condition, uint32_t threadId) {
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
		// 메모리 읽기
		std::string addrStr = lhs.substr(1);
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
					lhsVal = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
				}
			}
		} catch (...) { return true; }
	} else if (TryParseRegisterName(lhs)) {
		// 레지스터
		GetRegistersRequest regReq;
		regReq.threadId = threadId;
		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
			if (respData.size() >= sizeof(GetRegistersResponse)) {
				auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
				lhsVal = ResolveRegisterByName(lhs, regResp->regs);
			}
		}
	} else {
		try { lhsVal = std::stoull(lhs, nullptr, 0); } catch (...) { return true; }
	}

	// RHS 값 해석
	uint64_t rhsVal = 0;
	if (TryParseRegisterName(rhs)) {
		GetRegistersRequest regReq;
		regReq.threadId = threadId;
		std::vector<uint8_t> respData;
		if (pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
			if (respData.size() >= sizeof(GetRegistersResponse)) {
				auto* regResp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
				rhsVal = ResolveRegisterByName(rhs, regResp->regs);
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

std::string DapServer::ExpandLogMessage(const std::string& msg, uint32_t threadId) {
	// {표현식}을 실제 값으로 치환
	// 예: "RAX={RAX}, mem={*0x7FF600}" → "RAX=0x0000000000001234, mem=0x00000000DEADBEEF"
	std::string result;
	result.reserve(msg.size());

	// 레지스터 캐시 (한 번만 IPC 호출)
	bool regsLoaded = false;
	RegisterSet regs = {};
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
				// 메모리 읽기
				std::string addrStr = expr.substr(1);
				if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();
				try {
					uint64_t addr = std::stoull(addrStr, nullptr, 0);
					ReadMemoryRequest readReq;
					readReq.address = addr;
					readReq.size = 8;
					std::vector<uint8_t> respData;
					if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData) &&
						respData.size() >= sizeof(IpcStatus) + 8 &&
						*reinterpret_cast<const IpcStatus*>(respData.data()) == IpcStatus::Ok) {
						uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data() + sizeof(IpcStatus));
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

void DapServer::Cleanup(bool detachOnly) {
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
}

} // namespace veh::dap
