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
		{"seq", seq_++},
		{"type", "response"},
		{"request_seq", resp.request_seq},
		{"success", resp.success},
		{"command", resp.command},
		{"body", resp.body},
	};
	if (!resp.success && !resp.message.empty()) {
		j["message"] = resp.message;
	}
	transport_->Send(j.dump());
}

void DapServer::SendEvent(const std::string& event, const json& body) {
	json j = {
		{"seq", seq_++},
		{"type", "event"},
		{"event", event},
		{"body", body},
	};
	transport_->Send(j.dump());
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

	// args 배열을 공백 구분 문자열로 변환
	std::string argStr;
	if (req.arguments.contains("args") && req.arguments["args"].is_array()) {
		for (auto& a : req.arguments["args"]) {
			if (!argStr.empty()) argStr += " ";
			argStr += a.get<std::string>();
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

	Cleanup();

	if (terminateDebuggee && targetPid_) {
		HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
		if (proc) {
			TerminateProcess(proc, 0);
			CloseHandle(proc);
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "disconnect";
	resp.success = true;
	SendResponse(resp);

	running_ = false;
}

void DapServer::OnTerminate(const Request& req) {
	if (targetPid_) {
		HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
		if (proc) {
			TerminateProcess(proc, 0);
			CloseHandle(proc);
		}
	}

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "terminate";
	resp.success = true;
	SendResponse(resp);
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

				breakpointMappings_.push_back({dbp.id, setResp->id, address, sourceFile});
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

				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}});
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
		LOG_DEBUG("  bp instrRef='%s' raw=%s", instrRef.c_str(), bp.dump().c_str());

		uint64_t address = 0;
		if (!instrRef.empty()) {
			try {
				address = std::stoull(instrRef, nullptr, 0);
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

				breakpointMappings_.push_back({dbp.id, setResp->id, address, {}});
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

	if (pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), respData)) {
		if (respData.size() >= sizeof(GetStackTraceResponse)) {
			auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(respData.data());
			auto* frames = reinterpret_cast<const StackFrameInfo*>(
				respData.data() + sizeof(GetStackTraceResponse));
			uint32_t maxCount = (uint32_t)((respData.size() - sizeof(GetStackTraceResponse)) / sizeof(StackFrameInfo));
			uint32_t count = std::min(hdr->count, maxCount);
			for (uint32_t i = 0; i < count; i++) {
				StackFrameDap f;
				f.id = (threadId << 16) | (startFrame + i);
				f.name = frames[i].functionName[0] ? frames[i].functionName :
					FormatAddress(frames[i].address);
				f.line = frames[i].line;
				f.instructionPointerReference = FormatAddress(frames[i].address);
				if (frames[i].sourceFile[0]) {
					f.source.path = frames[i].sourceFile;
					// 파일명만 추출하여 source.name에 설정
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
	int threadId = (frameId >> 16) & 0x3FFF;
	int frameIndex = frameId & 0xFFFF;
	if (threadId == 0) threadId = 1;

	if (scopeType == SCOPE_REGISTERS) {
		// 레지스터 값 가져오기
		GetRegistersRequest regReq;
		regReq.threadId = threadId;

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
				}
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

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "evaluate";

	// 간단한 메모리 읽기 표현식 지원: *0xADDRESS 또는 [0xADDRESS]
	if (!expression.empty() && (expression[0] == '*' || expression[0] == '[')) {
		std::string addrStr = expression.substr(1);
		if (!addrStr.empty() && addrStr.back() == ']') addrStr.pop_back();

		try {
			uint64_t addr = std::stoull(addrStr, nullptr, 0);
			ReadMemoryRequest readReq;
			readReq.address = addr;
			readReq.size = 8; // 8바이트 읽기

			std::vector<uint8_t> respData;
			if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)) {
				if (respData.size() >= 8) {
					uint64_t val = *reinterpret_cast<const uint64_t*>(respData.data());
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
	resp.message = "Evaluation not supported. Use *<address> to read memory.";
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
	snprintf(codeBuf, sizeof(codeBuf), "0x%08X", lastException_.code);

	resp.body = {
		{"exceptionId", codeBuf},
		{"description", lastException_.description},
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

	uint64_t addr = ParseAddress(memRef) + offset;

	ReadMemoryRequest readReq;
	readReq.address = addr;
	readReq.size = count;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "readMemory";

	std::vector<uint8_t> respData;
	if (pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData)) {
		resp.success = true;
		resp.body = {
			{"address", FormatAddress(addr)},
			{"data", Base64Encode(respData.data(), respData.size())},
			{"unreadableBytes", count - (int)respData.size()},
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

	uint64_t addr = ParseAddress(memRef) + offset;
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

	uint64_t addr = ParseAddress(memRef) + offset;

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
		hwReq.type = (accessType == "readWrite") ? 2 : 1; // 1=write, 2=readwrite
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
		// attach 모드에서는 detach 후 재연결
		Cleanup();

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

	std::string prefix = text.substr(0, column);
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

			json hitBps = json::array();
			for (auto& m : breakpointMappings_) {
				if (m.vehId == e->breakpointId) {
					hitBps.push_back(m.dapId);
					break;
				}
			}

			SendEvent("stopped", {
				{"reason", "breakpoint"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
				{"hitBreakpointIds", hitBps},
			});
		}
		break;
	}

	case IpcEvent::StepCompleted: {
		if (size >= sizeof(StepCompletedEvent)) {
			auto* e = reinterpret_cast<const StepCompletedEvent*>(payload);
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
			lastException_.threadId = e->threadId;
			lastException_.code = e->exceptionCode;
			lastException_.description = e->description;

			SendEvent("stopped", {
				{"reason", "exception"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
				{"description", std::string(e->description)},
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

	default:
		LOG_WARN("Unknown IPC event: 0x%X", eventId);
		break;
	}
}

// --- Helpers ---

std::string DapServer::GetDllPath() {
	char exePath[MAX_PATH];
	GetModuleFileNameA(nullptr, exePath, MAX_PATH);

	std::filesystem::path dir = std::filesystem::path(exePath).parent_path();

	if (targetPid_ != 0) {
		return Injector::SelectDllForTarget(targetPid_, dir.string());
	}

	return (dir / "vcruntime_net.dll").string();
}

void DapServer::Cleanup() {
	if (pipeClient_.IsConnected()) {
		pipeClient_.SendCommand(IpcCommand::Shutdown);
		pipeClient_.Disconnect();
	}
	breakpointMappings_.clear();
	dataBreakpointMappings_.clear();
}

} // namespace veh::dap
