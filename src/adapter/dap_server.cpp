#include "dap_server.h"
#include "expr_eval.h"
#include "pipe_client.h"
#include "logger.h"
#include "ipc_response_validation.h"
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <set>
#include <bcrypt.h>

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
std::wstring Utf8ToWide(const std::string& value) {
	if (value.empty()) return {};
	const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
		value.data(), static_cast<int>(value.size()), nullptr, 0);
	if (size <= 0) return {};
	std::wstring wide(size, L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
		value.data(), static_cast<int>(value.size()), wide.data(), size) != size) return {};
	return wide;
}

std::wstring QuoteWindowsArg(const std::wstring& value) {
	std::wstring result(1, L'"');
	size_t slashes = 0;
	for (wchar_t ch : value) {
		if (ch == L'\\') { ++slashes; continue; }
		if (ch == L'"') {
			result.append(slashes * 2 + 1, L'\\');
			result += ch;
		} else {
			result.append(slashes, L'\\');
			result += ch;
		}
		slashes = 0;
	}
	result.append(slashes * 2, L'\\');
	result += L'"';
	return result;
}

std::string ModuleName(std::string value) {
	const auto slash = value.find_last_of("\\\\/");
	if (slash != std::string::npos) value.erase(0, slash + 1);
	for (char& c : value) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
	return value;
}

std::string FunctionModule(const std::string& function) {
	const auto bang = function.find('!');
	if (bang == std::string::npos || bang == 0) return {};
	std::string module = ModuleName(function.substr(0, bang));
	if (module.size() > 250 || module.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_.-") != std::string::npos)
		return {};
	if (module.find('.') == std::string::npos) module += ".dll";
	return module;
}

bool AddAddressOffset(uint64_t base, int64_t offset, uint64_t& result) {
	if (offset >= 0) {
		const auto amount = static_cast<uint64_t>(offset);
		if (base > UINT64_MAX - amount) return false;
		result = base + amount;
	} else {
		const auto amount = static_cast<uint64_t>(-(offset + 1)) + 1;
		if (base < amount) return false;
		result = base - amount;
	}
	return true;
}
} // anonymous namespace

namespace veh::dap {

DapServer::DapServer() : ipcTransport_(std::make_unique<PipeClient>()) {}

void DapServer::SetTransport(Transport* transport) {
	transport_ = transport;
	transport_->SetMessageCallback([this](const std::string& json) {
		OnMessage(json);
	});
}

bool DapServer::ReceiveBackendReply(IpcCommand command, const void* payload, uint32_t size,
    std::vector<uint8_t>& response, std::string& error) {
    PipeExchangeDiagnostics diagnostics{};
    if (!ipcTransport_->SendAndReceive(command, payload, size, response, 3000, &diagnostics)) {
        error = diagnostics.failure == PipeExchangeFailure::WaitTimeout ?
            "Backend request timed out; outcome not confirmed" : "Backend IPC exchange failed";
        if (diagnostics.systemError)
            error += " (Win32 error " + std::to_string(diagnostics.systemError) + ")";
        return false;
    }
    return ValidateBackendStatus(response, "Backend request", error);
}

bool DapServer::SendStatusCommand(IpcCommand command, const void* payload, uint32_t size,
    std::string& error) {
    const auto stopCutoff = visibleStopVersion_.load();
    std::vector<uint8_t> response;
    if (!ReceiveBackendReply(command, payload, size, response, error)) return false;
    if (response.size() != sizeof(IpcStatus)) {
        error = "Malformed backend status response";
        return false;
    }
    if (command == IpcCommand::TerminateThread && size == sizeof(TerminateThreadRequest)) {
        TerminateThreadRequest request{};
        std::memcpy(&request, payload, sizeof(request));
        ClearVisibleStops(request.threadId, stopCutoff);
    }
    error.clear();
    return true;
}

bool DapServer::ContinueBackend(uint32_t threadId, bool& allContinued, std::string& error, uint64_t resumeCutoff) {
    if (resumeCutoff == UINT64_MAX) resumeCutoff = visibleStopVersion_.load();
    ContinueRequest request{};
    request.threadId = threadId;
    request.wantDetails = 1;
    std::vector<uint8_t> response;
    if (!ReceiveBackendReply(IpcCommand::Continue, &request, sizeof(request), response, error)) return false;
    ContinueResponse header{};
    if (response.size() < sizeof(header)) {
        error = "Incomplete Continue details";
        return false;
    }
    std::memcpy(&header, response.data(), sizeof(header));
    const uint64_t count = uint64_t(header.resumedCount) + header.stillStoppedCount;
    if (count != (response.size() - sizeof(header)) / sizeof(uint32_t) ||
        (response.size() - sizeof(header)) % sizeof(uint32_t)) {
        error = "Malformed Continue thread lists";
        return false;
    }
    allContinued = header.stillStoppedCount == 0;
    if (header.resumedCount == 0 && header.stillStoppedCount != 0) {
        error = "No thread resumed; backend reports threads still stopped";
        return false;
    }
    for (uint32_t i = 0; threadId && i < header.stillStoppedCount; ++i) {
        uint32_t stopped{};
        std::memcpy(&stopped, response.data() + sizeof(header) +
            (size_t(header.resumedCount) + i) * sizeof(stopped), sizeof(stopped));
        if (stopped == threadId) {
            error = "Requested thread is still stopped";
            return false;
        }
    }
    if (allContinued || threadId) ClearVisibleStops(threadId, resumeCutoff);
    else for (uint32_t i = 0; i < header.resumedCount; ++i) {
        uint32_t resumed{};
        std::memcpy(&resumed, response.data() + sizeof(header) + size_t(i) * sizeof(resumed), sizeof(resumed));
        ClearVisibleStops(resumed, resumeCutoff);
    }
    error.clear();
    return true;
}

void DapServer::ClearVisibleStops(uint32_t threadId, uint64_t cutoff) {
    std::lock_guard<std::mutex> lock(retryMutex_);
    for (auto it = visibleStops_.begin(); it != visibleStops_.end();) {
        if ((!threadId || it->first == threadId) && it->second <= cutoff) it = visibleStops_.erase(it);
        else ++it;
    }
}

void DapServer::SendPauseStopped(uint32_t threadId) {
    lastStoppedThreadId_.store(threadId);
    {
        std::lock_guard<std::mutex> lock(frameMutex_);
        frameMap_.clear();
        nextFrameId_ = 1;
    }
    SendEvent("stopped", {
        {"reason", "pause"}, {"threadId", threadId}, {"allThreadsStopped", !guestTarget_},
    });
}

bool DapServer::GuestSupports(IpcCommand command) const {
	return guestTarget_ && IsCommandSupported(guestCommands_, command);
}

bool DapServer::AttachGuestAgent(const Request& req, std::string& error) {
	if (ipcTransport_->IsConnected()) {
		error = "Disconnect the current target before attaching another";
		return false;
	}
	if (!req.arguments.contains("processId") || !req.arguments["processId"].is_number_integer()) {
		error = "Guest attach requires a numeric processId";
		return false;
	}
	const int64_t rawPid = req.arguments["processId"].get<int64_t>();
	if (rawPid <= 0 || rawPid > UINT32_MAX) {
		error = "Guest processId is outside the 32-bit PID range";
		return false;
	}
	const uint32_t pid = static_cast<uint32_t>(rawPid);
	if (!req.arguments.contains("agent") || !req.arguments["agent"].is_string()) {
		error = "Guest attach requires an agent executable path";
		return false;
	}
	const std::string agentPath = req.arguments["agent"].get<std::string>();
	const std::wstring widePath = Utf8ToWide(agentPath);
	std::error_code ec;
	if (widePath.empty() || !std::filesystem::path(widePath).is_absolute() ||
		!std::filesystem::is_regular_file(std::filesystem::path(widePath), ec)) {
		error = "Guest agent must be an existing absolute executable path";
		return false;
	}
	std::vector<std::wstring> args;
	if (req.arguments.contains("agentArgs")) {
		if (!req.arguments["agentArgs"].is_array()) {
			error = "agentArgs must be an array of strings";
			return false;
		}
		for (const auto& arg : req.arguments["agentArgs"]) {
			if (!arg.is_string()) {
				error = "agentArgs must be an array of strings";
				return false;
			}
			const std::string narrow = arg.get<std::string>();
			const std::wstring wide = Utf8ToWide(narrow);
			if (wide.empty() && !narrow.empty()) {
				error = "agentArgs must contain valid UTF-8 strings";
				return false;
			}
			args.push_back(wide);
		}
	}
	if (req.arguments.contains("stopOnModuleLoad") &&
		!req.arguments["stopOnModuleLoad"].empty()) {
		error = "Guest stopOnModuleLoad is not supported by this DAP adapter";
		return false;
	}
	uint64_t nonce = 0;
	if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&nonce), sizeof(nonce),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
		error = "Could not create a guest agent pipe name";
		return false;
	}
	wchar_t pipe[100];
	swprintf_s(pipe, L"\\\\.\\pipe\\veh-dap-guest-%u-%016llx",
		pid, static_cast<unsigned long long>(nonce));
	std::wstring command = QuoteWindowsArg(widePath) + L" --pid " + std::to_wstring(pid) +
		L" --pipe " + QuoteWindowsArg(pipe);
	for (const auto& arg : args) command += L" " + QuoteWindowsArg(arg);
	STARTUPINFOW startup{sizeof(startup)};
	PROCESS_INFORMATION process{};
	if (!CreateProcessW(widePath.c_str(), command.data(), nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
		error = "Could not start guest agent (Win32 error " + std::to_string(GetLastError()) + ")";
		return false;
	}
	CloseHandle(process.hThread);
	ipcTransport_ = std::make_unique<PipeClient>(pipe, 30000);
	auto abort = [&] {
		ipcTransport_->Disconnect();
		ipcTransport_ = std::make_unique<PipeClient>();
		if (WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
			TerminateProcess(process.hProcess, 1); // only the child just started for this failed attach
		}
		CloseHandle(process.hProcess);
	};
	if (!ipcTransport_->Connect(pid, 5000)) {
		error = "Guest agent pipe did not come up";
		abort();
		return false;
	}
	if (ipcTransport_->PeerProcessId() != process.dwProcessId) {
		error = "Guest agent pipe is served by a different process";
		abort();
		return false;
	}
	// Ready is consumed by PipeClient. Stop events (breakpoint, step, exception)
	// become DAP stopped events like a host session; only advertised commands
	// can produce them.
	ipcTransport_->StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	if (!ipcTransport_->WaitForReady(3000)) {
		error = "Guest agent did not send Ready";
		abort();
		return false;
	}
	std::vector<uint8_t> bytes;
	GetCapabilitiesResponse caps{};
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetCapabilities, nullptr, 0, bytes) ||
		bytes.size() != sizeof(caps)) {
		error = "Guest agent did not provide complete capabilities";
		abort();
		return false;
	}
	std::memcpy(&caps, bytes.data(), sizeof(caps));
	if (caps.status != IpcStatus::Ok || caps.backend != IpcBackend::Hypervisor ||
		(caps.flags & kCapGuestTarget) == 0 || (caps.flags & kCapVirtualMachineTarget) != 0 ||
		!IsCommandSupported(caps.commands, IpcCommand::GetTargetInfo) ||
		!IsCommandSupported(caps.commands, IpcCommand::Detach)) {
		error = "Agent did not declare a detachable guest process backend";
		abort();
		return false;
	}
	bytes.clear();
	GetTargetInfoResponse target{};
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetTargetInfo, nullptr, 0, bytes) ||
		bytes.size() != sizeof(target)) {
		error = "Guest agent did not provide complete target metadata";
		abort();
		return false;
	}
	std::memcpy(&target, bytes.data(), sizeof(target));
	if (target.status != IpcStatus::Ok || target.scope != IpcTargetScope::Guest ||
		target.pid != pid || (target.addressBits != 32 && target.addressBits != 64)) {
		error = "Guest target PID, scope or address width did not match";
		abort();
		return false;
	}
	targetPid_ = pid;
	launchedByUs_ = false;
	guestTarget_ = true;
	guestAddressBits_ = target.addressBits;
	stopOnModuleLoadPatterns_.clear();
	guestAgentProcess_ = process.hProcess;
	std::memcpy(guestCommands_, caps.commands, sizeof(guestCommands_));
	disassembler_ = veh::CreateDisassembler(target.addressBits == 64);
	ipcTransport_->StartHeartbeat();
	return true;
}

void DapServer::Run() {
	running_ = true;
	StartRetryThread();
	transport_->Start();

	// Stop/disconnect signals this wait; no periodic adapter state polling.
	{
		std::unique_lock<std::mutex> lock(runMutex_);
		runCv_.wait(lock, [this] { return !running_.load(); });
	}

	// Join the transport reader before destroying its callback target (this server).
	transport_->Stop();
	Cleanup();
	StopRetryThread();
}

void DapServer::Stop() {
	{
		std::lock_guard<std::mutex> lock(runMutex_);
		running_ = false;
	}
	runCv_.notify_all();
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
	std::lock_guard<std::recursive_mutex> transaction(deferredMutex_);
	LOG_DEBUG("Request: %s (seq=%d)", req.command.c_str(), req.seq);
	DAP_TRACE("REQUEST", req.command + " | " + req.arguments.dump());

	if (guestTarget_) {
		const bool allowed = req.command == "disconnect" ||
			req.command == "configurationDone" || req.command == "cancel" ||
			(req.command == "threads" && GuestSupports(IpcCommand::GetThreads)) ||
			(req.command == "readMemory" && GuestSupports(IpcCommand::ReadMemory)) ||
			(req.command == "writeMemory" && GuestSupports(IpcCommand::WriteMemory)) ||
			(req.command == "disassemble" && GuestSupports(IpcCommand::ReadMemory)) ||
			// Execution control on the backend's selected-thread stops. Steps are
			// instruction steps (no guest symbols); frames come from registers.
			(req.command == "setInstructionBreakpoints" && GuestSupports(IpcCommand::SetBreakpoint) &&
				GuestSupports(IpcCommand::RemoveBreakpoint)) ||
			// Host-side PDB symbols of the guest backend: source and function breakpoints.
			(req.command == "setBreakpoints" && GuestSupports(IpcCommand::ResolveSourceLine) &&
				GuestSupports(IpcCommand::SetBreakpoint) && GuestSupports(IpcCommand::RemoveBreakpoint)) ||
			(req.command == "setFunctionBreakpoints" && GuestSupports(IpcCommand::ResolveFunction) &&
				GuestSupports(IpcCommand::SetBreakpoint) && GuestSupports(IpcCommand::RemoveBreakpoint)) ||
			(req.command == "source" && GuestSupports(IpcCommand::Symbolize)) ||
			((req.command == "setDataBreakpoints" || req.command == "dataBreakpointInfo") &&
				GuestSupports(IpcCommand::SetHwBreakpoint) && GuestSupports(IpcCommand::RemoveHwBreakpoint)) ||
			(req.command == "continue" && GuestSupports(IpcCommand::Continue)) ||
			(req.command == "pause" && GuestSupports(IpcCommand::Pause)) ||
			(req.command == "next" && GuestSupports(IpcCommand::StepOver)) ||
			(req.command == "stepIn" && GuestSupports(IpcCommand::StepInto)) ||
			(req.command == "stepOut" && GuestSupports(IpcCommand::StepOut)) ||
			(req.command == "stackTrace" && GuestSupports(IpcCommand::GetStackTrace)) ||
			((req.command == "scopes" || req.command == "variables") && GuestSupports(IpcCommand::GetRegisters)) ||
			req.command == "exceptionInfo" ||
			// ExceptionEvent lacks chance metadata; only the all filter is accepted.
			(req.command == "setExceptionBreakpoints" && GuestSupports(IpcCommand::Continue)) ||
			(req.command == "terminate" && GuestSupports(IpcCommand::Terminate)) ||
			(req.command == "terminateThreads" && GuestSupports(IpcCommand::TerminateThread)) ||
			((req.command == "evaluate" || req.command == "completions") && GuestSupports(IpcCommand::GetRegisters)) ||
			(req.command == "setVariable" && GuestSupports(IpcCommand::SetRegister)) ||
			(req.command == "modules" && GuestSupports(IpcCommand::GetModules)) ||
			(req.command == "loadedSources" && GuestSupports(IpcCommand::Symbolize)) ||
			((req.command == "goto" || req.command == "gotoTargets") && GuestSupports(IpcCommand::SetInstructionPointer));
		if (!allowed) {
			Response resp;
			resp.request_seq = req.seq;
			resp.command = req.command;
			resp.success = false;
			resp.message = "DAP command is not supported for this guest session: " + req.command;
			SendResponse(resp);
			return;
		}
	}

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

void DapServer::SendEvent(const std::string& event, const json& body, bool onlyIfUnknown) {
    // Publish stopped state and its wire event in one serialization order.
    // In particular a deferred pause cannot overwrite a newer exception/BP.
    std::lock_guard<std::mutex> sending(sendMutex_);
    if (event == "stopped") {
        std::lock_guard<std::mutex> state(retryMutex_);
        const auto threadId = body.value("threadId", 0u);
        if (onlyIfUnknown && visibleStops_.count(threadId)) return;
        visibleStops_[threadId] = ++visibleStopVersion_;
        lastStoppedThreadId_.store(threadId);
    }
    json message = {{"seq", seq_++}, {"type", "event"}, {"event", event}, {"body", body}};
    if (guestTarget_ && event == "stopped") message["body"]["allThreadsStopped"] = false;
    transport_->Send(message.dump());
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
	if (req.arguments.value("targetScope", "host") != "host") {
		// A guest process can only be attached: starting one inside the guest
		// would need an in-guest agent, and the program path names no host file.
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "launch";
		resp.success = false;
		resp.message = "guest targets are attach-only: launch requires targetScope=host";
		SendResponse(resp);
		return;
	}
	programPath_ = req.arguments.value("program", "");
	std::string cwd = req.arguments.value("cwd", "");
	stopOnEntry_ = req.arguments.value("stopOnEntry", false);
	injectionMethod_ = ParseInjectionMethod(req.arguments.value("injectionMethod", "auto"));
	runAsInvoker_ = req.arguments.value("runAsInvoker", false);

	// Module-load breakpoints: stop when a DLL whose name matches is loaded.
	stopOnModuleLoadPatterns_.clear();
	if (req.arguments.contains("stopOnModuleLoad") && req.arguments["stopOnModuleLoad"].is_array()) {
		for (auto& m : req.arguments["stopOnModuleLoad"]) {
			if (m.is_string() && !m.get<std::string>().empty())
				stopOnModuleLoadPatterns_.push_back(m.get<std::string>());
		}
	}

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
	auto result = Injector::LaunchAndInject(programPath_, argStr, cwd, dllPath, injectionMethod_, runAsInvoker_);

	if (result.pid == 0) {
		resp.success = false;
		resp.message = "Failed to launch and inject: " + programPath_;
		if (!result.error.empty()) resp.message += " - " + result.error;
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
	if (!ipcTransport_->Connect(targetPid_, 10000)) {
		resp.success = false;
		resp.message = "Failed to connect to VEH DLL pipe";
		SendResponse(resp);
		return;
	}

	// 이벤트 리스너 + 하트비트 시작
	ipcTransport_->StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	// VEH 설치 완료(Ready) 대기 (reader 시작 후 -- condvar). 실패해도 진행(보수적).
	if (!ipcTransport_->WaitForReady(3000)) {
		LOG_WARN("No Ready after connect (pid=%u); proceeding (VEH may not be installed yet)", targetPid_);
	}
	ipcTransport_->StartHeartbeat();

	// 타겟 비트니스에 맞게 디스어셈블러 재생성
	{
		bool is64 = !Injector::IsExe32Bit(programPath_);
		disassembler_ = veh::CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	resp.success = true;
	SendResponse(resp);

	StartProcessMonitor();

	LOG_INFO("Launched process PID=%u, DLL injected", targetPid_);
}

void DapServer::OnAttach(const Request& req) {
	const std::string scope = req.arguments.value("targetScope", "host");
	if (scope != "host") {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "attach";
		if (scope == "guest") resp.success = AttachGuestAgent(req, resp.message);
		else {
			resp.success = false;
			resp.message = "DAP targetScope must be host or guest";
		}
		SendResponse(resp);
		return;
	}
	if (req.arguments.contains("agent") || req.arguments.contains("agentArgs")) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "attach";
		resp.success = false;
		resp.message = "External agent attachment requires targetScope=guest";
		SendResponse(resp);
		return;
	}
	targetPid_ = req.arguments.value("processId", 0);
	injectionMethod_ = ParseInjectionMethod(req.arguments.value("injectionMethod", "auto"));

	// Module-load breakpoints also work in attach mode (catches future loads).
	stopOnModuleLoadPatterns_.clear();
	if (req.arguments.contains("stopOnModuleLoad") && req.arguments["stopOnModuleLoad"].is_array()) {
		for (auto& m : req.arguments["stopOnModuleLoad"]) {
			if (m.is_string() && !m.get<std::string>().empty())
				stopOnModuleLoadPatterns_.push_back(m.get<std::string>());
		}
	}

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

	if (!ipcTransport_->Connect(targetPid_, 10000)) {
		resp.success = false;
		resp.message = "Failed to connect to VEH DLL pipe";
		SendResponse(resp);
		return;
	}

	ipcTransport_->StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		OnIpcEvent(eventId, payload, size);
	});
	// VEH 설치 완료(Ready) 대기 (reader 시작 후 -- condvar). 실패해도 진행(보수적).
	if (!ipcTransport_->WaitForReady(3000)) {
		LOG_WARN("No Ready after connect (pid=%u); proceeding (VEH may not be installed yet)", targetPid_);
	}
	ipcTransport_->StartHeartbeat();

	// 타겟 비트니스에 맞게 디스어셈블러 재생성
	{
		BOOL isWow64 = FALSE;
		if (targetProcess_) IsWow64Process(targetProcess_, &isWow64);
		bool is64 = (isWow64 == FALSE);
		disassembler_ = veh::CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	resp.success = true;
	SendResponse(resp);

	StartProcessMonitor();

	LOG_INFO("Attached to PID=%u", targetPid_);
}

void DapServer::OnDisconnect(const Request& req) {
	bool terminateDebuggee = req.arguments.value("terminateDebuggee", launchedByUs_);
	if (guestTarget_ && terminateDebuggee) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disconnect";
		resp.success = false;
		resp.message = "Guest process termination is not supported by this DAP adapter";
		SendResponse(resp);
		return;
	}
	if (guestTarget_) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disconnect";
		std::vector<uint8_t> reply;
		IpcStatus status{};
		if (!GuestSupports(IpcCommand::Detach) ||
			!ipcTransport_->SendAndReceive(IpcCommand::Detach, nullptr, 0, reply, 5000) ||
			reply.size() != sizeof(status)) {
			resp.success = false;
			resp.message = "Guest backend detach reply is unavailable; session retained";
			SendResponse(resp);
			return;
		}
		std::memcpy(&status, reply.data(), sizeof(status));
		if (status != IpcStatus::Ok) {
			resp.success = false;
			resp.message = "Guest backend detach failed; session retained";
			SendResponse(resp);
			return;
		}
		resp.success = true;
		SendResponse(resp);
		Cleanup(/*detachOnly=*/true, /*backendDetached=*/true);
		Stop();
		return;
	}

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

	Stop();
}

void DapServer::OnTerminate(const Request& req) {
	// VSCode Stop 흐름: terminate 요청 → terminate 응답 → terminated 이벤트 → disconnect 요청
	// terminated 이벤트를 보내지 않으면 VSCode가 disconnect를 보내지 않아
	// 사용자가 Stop을 두 번 눌러야 세션이 종료된다.
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "terminate";
	resp.success = true;
	if (guestTarget_) {
		// A guest PID names no host process: the backend ends the target
		// itself (Ok only after it attested the exit).
		TerminateRequest term{0};
		std::vector<uint8_t> reply;
		resp.success = ipcTransport_->SendAndReceive(IpcCommand::Terminate, &term, sizeof(term), reply) &&
			reply.size() >= sizeof(IpcStatus) && *reinterpret_cast<const IpcStatus*>(reply.data()) == IpcStatus::Ok;
		if (!resp.success) resp.message = "guest target termination failed";
		SendResponse(resp);
		if (resp.success && !terminated_.exchange(true)) SendEvent("terminated");
		return;
	}
	SendResponse(resp);

	if (targetPid_) {
		HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
		if (proc) {
			TerminateProcess(proc, 0);
			CloseHandle(proc);
		}
	}

	// terminated 이벤트를 보내야 VSCode가 자동으로 disconnect를 이어서 보냄
	if (!terminated_.exchange(true)) {
		SendEvent("terminated");
	}
}

void DapServer::OnConfigurationDone(const Request& req) {
	configured_ = true;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "configurationDone";
	resp.success = true;
	SendResponse(resp);

	// Register module-load breakpoints (launch.json "stopOnModuleLoad") before resuming,
	// so a match during startup is not missed.
	for (const auto& pat : stopOnModuleLoadPatterns_) {
		SetModuleLoadStopRequest mreq{};
		mreq.action = 0;
		strncpy_s(mreq.name, sizeof(mreq.name), pat.c_str(), _TRUNCATE);
		std::vector<uint8_t> mresp;
		bool ok = ipcTransport_->SendAndReceive(IpcCommand::SetModuleLoadStop, &mreq, sizeof(mreq), mresp)
			&& mresp.size() >= sizeof(SetModuleLoadStopResponse)
			&& reinterpret_cast<const SetModuleLoadStopResponse*>(mresp.data())->status == IpcStatus::Ok;
		if (ok) LOG_INFO("stopOnModuleLoad: registered pattern '%s'", pat.c_str());
		else LOG_WARN("stopOnModuleLoad: FAILED to register pattern '%s'", pat.c_str());
	}

	// Launch 모드: 메인 스레드가 CREATE_SUSPENDED 상태
	// setBreakpoints가 이미 완료된 상태이므로 이제 안전하게 resume 가능
	if (launchedByUs_ && launchedMainThreadId_ != 0 && !mainThreadResumed_) {
		if (stopOnEntry_) {
			// stopOnEntry: 메인 스레드는 suspended 유지, stopped 이벤트만 전송
			// 사용자가 Continue 누르면 OnContinue에서 resume
			LOG_INFO("stopOnEntry: main thread %u stays suspended", launchedMainThreadId_);
			SendEvent("stopped", {
				{"reason", "entry"},
				{"threadId", launchedMainThreadId_},
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

		if (bp.contains("instructionReference") || bp.contains("instruction_reference")) {
			auto key = bp.contains("instructionReference") ? "instructionReference" : "instruction_reference";
			rb.address = ParseAddress(bp[key].get<std::string>());
		} else if (bp.contains("line")) {
			rb.line = bp["line"].get<int>();
			if (!sourceFile.empty() && rb.line > 0) {
				ResolveSourceLineRequest resolveReq = {};
				strncpy_s(resolveReq.fileName, sourceFile.c_str(), sizeof(resolveReq.fileName) - 1);
				resolveReq.line = rb.line;

				std::vector<uint8_t> resolveResp;
				if (ipcTransport_->SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), resolveResp)
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
			// pending(vehId==0)은 실제 DLL BP가 없으므로 RemoveBreakpoint 생략
			if (it->vehId != 0) {
				DAP_TRACE("RemoveSourceBP", "vehId=" + std::to_string(it->vehId) + " addr=" + FormatAddress(it->address));
				changedAddresses.push_back(it->address);
				RemoveBreakpointRequest rmReq{};
				rmReq.id = it->vehId;
				ipcTransport_->SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			}
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
			// 모듈 미로드로 인한 미해결일 수 있으면 deferred로 보관 (file+line 필요).
			// 모듈이 나중에 로드되면 ModuleLoaded 핸들러가 재해석해 실제 BP로 전환.
			if (!sourceFile.empty() && rb.line > 0) {
				BreakpointMapping m{};
				m.dapId = dbp.id;
				m.vehId = 0;
				m.address = 0;
				m.source = sourceFile;
				m.condition = rb.condition;
				m.hitCondition = rb.hitCondition;
				m.logMessage = rb.logMessage;
				m.type = BpType::Source;
				m.line = rb.line;
				m.pending = true;
				breakpointMappings_.push_back(m);
				DAP_TRACE("PendingSourceBP", sourceFile + ":" + std::to_string(rb.line));
			}
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
		SetBreakpointRequest setReq{};
		setReq.address = rb.address;

		std::vector<uint8_t> respData;
		if (ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &setReq, sizeof(setReq), respData)) {
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
    std::set<uint32_t> obsolete;
    json breakpointsJson = json::array();
    {
        std::lock_guard<std::mutex> lock(breakpointMutex_);
        for (auto it = breakpointMappings_.begin(); it != breakpointMappings_.end();) {
            if (it->type == BpType::Function) {
                if (it->vehId) obsolete.insert(it->vehId);
                it = breakpointMappings_.erase(it);
            } else ++it;
        }
        for (const auto& bp : req.arguments.value("breakpoints", json::array())) {
            const std::string name = bp.value("name", "");
            Breakpoint dbp;
            dbp.id = nextDapBpId_++;
            dbp.verified = false;
            if (name.empty()) dbp.message = "Function name required";
            else {
                BreakpointMapping mapping{};
                mapping.dapId = dbp.id;
                mapping.type = BpType::Function;
                mapping.functionName = name;
                mapping.condition = bp.value("condition", "");
                mapping.hitCondition = bp.value("hitCondition", "");
                mapping.pending = true;
                breakpointMappings_.push_back(mapping);
            }
            breakpointsJson.push_back(dbp.ToJson());
        }
    }
    for (auto id : obsolete) RemoveUnreferencedBreakpoint(id);
    // Arm first, then recheck symbols. This closes the registration/load race.
    SyncInternalModuleStops();
    RetryPendingBreakpointsOnce(false);
    {
        std::lock_guard<std::mutex> lock(breakpointMutex_);
        for (auto& bp : breakpointsJson) {
            for (const auto& mapping : breakpointMappings_) {
                if (mapping.dapId != bp["id"].get<int>()) continue;
                bp["verified"] = !mapping.pending;
                if (mapping.pending) bp["message"] = "Function breakpoint pending: " + mapping.functionName;
                else bp["instructionReference"] = FormatAddress(mapping.address);
            }
        }
    }
    Response response;
    response.request_seq = req.seq;
    response.command = "setFunctionBreakpoints";
    response.success = true;
    response.body = {{"breakpoints", breakpointsJson}};
    SendResponse(response);
}

// Deferred BP: single persistent worker; reader callbacks only enqueue.
void DapServer::RemoveUnreferencedBreakpoint(uint32_t id) {
    if (!id) return;
    {
        std::lock_guard<std::mutex> lock(breakpointMutex_);
        for (const auto& mapping : breakpointMappings_)
            if (mapping.vehId == id) return;
    }
    const RemoveBreakpointRequest request{id};
    ipcTransport_->SendCommand(IpcCommand::RemoveBreakpoint, &request, sizeof(request));
}

void DapServer::SyncInternalModuleStops() {
    if (!guestTarget_ || !GuestSupports(IpcCommand::SetModuleLoadStop) ||
        !GuestSupports(IpcCommand::Continue) || !GuestSupports(IpcCommand::IsThreadStopped)) return;
    std::set<std::string> desired, current;
    {
        std::lock_guard<std::mutex> lock(breakpointMutex_);
        for (const auto& mapping : breakpointMappings_) {
            if (mapping.type != BpType::Function) continue;
            const auto module = FunctionModule(mapping.functionName);
            if (!module.empty()) desired.insert(module);
        }
    }
    { std::lock_guard<std::mutex> lock(retryMutex_); current = internalModuleStops_; }
    for (const auto& module : desired) {
        if (current.count(module)) continue;
        // Publish ownership before the request: the stop can precede its reply.
        { std::lock_guard<std::mutex> lock(retryMutex_); internalModuleStops_.insert(module); }
        SetModuleLoadStopRequest request{};
        strncpy_s(request.name, module.c_str(), sizeof(request.name) - 1);
        std::string error;
        if (!SendStatusCommand(IpcCommand::SetModuleLoadStop, &request, sizeof(request), error)) {
            std::lock_guard<std::mutex> lock(retryMutex_);
            internalModuleStops_.erase(module);
            for (auto& queued : deferredModuleStops_)
                if (ModuleName(queued.event.name).find(module) != std::string::npos) queued.owned = false;
            LOG_WARN("Deferred module guard could not be registered: %s", error.c_str());
        }
    }
    for (const auto& module : current) {
        if (desired.count(module)) continue;
        SetModuleLoadStopRequest request{};
        request.action = 1; // remove our pattern only; never clear all backend patterns
        strncpy_s(request.name, module.c_str(), sizeof(request.name) - 1);
        std::string error;
        if (SendStatusCommand(IpcCommand::SetModuleLoadStop, &request, sizeof(request), error)) {
            std::lock_guard<std::mutex> lock(retryMutex_);
            internalModuleStops_.erase(module);
        } else LOG_WARN("Deferred module guard removal failed: %s", error.c_str());
    }
}

void DapServer::QueueDeferredModuleStop(const ModuleLoadStopEvent& event) {
    std::lock_guard<std::mutex> lock(retryMutex_);
    const auto name = ModuleName(event.name);
    // The backend pattern contract is a case-insensitive substring match.
    const bool owned = std::any_of(internalModuleStops_.begin(), internalModuleStops_.end(),
        [&](const auto& pattern) { return name.find(pattern) != std::string::npos; });
    deferredModuleStops_.push_back({event, owned});
    retryWake_ = true;
    retryCv_.notify_one();
}

void DapServer::HandleDeferredModuleStop(const DeferredModuleStop& stop) {
    if (!running_ || !ipcTransport_->IsConnected()) return;
    // A queued event is historical. An explicit Continue/Step can have consumed
    // its hold before this worker acquires the transaction mutex.
    std::vector<uint8_t> bytes;
    std::string error;
    const IsThreadStoppedRequest request{stop.event.threadId};
    if (!stop.event.threadId || !GuestSupports(IpcCommand::IsThreadStopped) ||
        !ReceiveBackendReply(IpcCommand::IsThreadStopped, &request, sizeof(request), bytes, error) ||
        bytes.size() != sizeof(IsThreadStoppedResponse)) {
        SendEvent("output", {{"category", "stderr"},
            {"output", "Deferred binding skipped: current thread stop could not be confirmed.\n"}});
        return;
    }
    IsThreadStoppedResponse state{};
    std::memcpy(&state, bytes.data(), sizeof(state));
    if (state.stopped == 0) return; // already resumed; do not rebind or invent a stop
    if (state.stopped != 1) {
        SendEvent("output", {{"category", "stderr"}, {"output", "Invalid backend thread-stop state.\n"}});
        return;
    }
    const auto module = ModuleName(stop.event.name);
    if (stop.owned) {
        std::set<uint32_t> obsolete;
        {
            std::lock_guard<std::mutex> lock(breakpointMutex_);
            for (auto& mapping : breakpointMappings_) {
                if (mapping.type != BpType::Function || FunctionModule(mapping.functionName) != module) continue;
                if (mapping.vehId) obsolete.insert(mapping.vehId);
                mapping.vehId = 0;
                mapping.address = 0;
                mapping.pending = true;
            }
        }
        for (auto id : obsolete) RemoveUnreferencedBreakpoint(id);
    }
    RetryPendingBreakpointsOnce(true, module);
    bool pending = false;
    {
        std::lock_guard<std::mutex> lock(breakpointMutex_);
        for (const auto& mapping : breakpointMappings_)
            if (mapping.type == BpType::Function && FunctionModule(mapping.functionName) == module && mapping.pending)
                pending = true;
    }
    // The current IPC proves only "stopped", not the identity/reason of the
    // current hold. Binding is allowed; automatic continuation is not.
    SendEvent("stopped", {
        {"reason", "pause"}, {"threadId", stop.event.threadId}, {"allThreadsStopped", false},
        {"description", std::string("Backend confirms stopped thread; ") +
            (pending ? "function breakpoint remains pending for " : "deferred binding checked for ") + module},
    }, true);
}

void DapServer::StartRetryThread() {
	retryStop_ = false;
	retryThread_ = std::thread(&DapServer::RetryThreadLoop, this);
}

void DapServer::StopRetryThread() {
	{
		std::lock_guard<std::mutex> lk(retryMutex_);
		retryStop_ = true;
	}
	retryCv_.notify_one();
	if (retryThread_.joinable()) retryThread_.join();
}

// reader 스레드(ModuleLoaded)에서 호출: breakpointMutex_나 std::thread 객체를 절대
// 건드리지 않고 wake signal만 보낸다 -> reader<->main 데드락/thread race 원천 차단.
void DapServer::NotifyRetry() {
	{
		std::lock_guard<std::mutex> lk(retryMutex_);
		retryWake_ = true;
	}
	retryCv_.notify_one();
}

void DapServer::RetryThreadLoop() {
	for (;;) {
		{
			std::unique_lock<std::mutex> lk(retryMutex_);
			retryCv_.wait(lk, [this] { return retryWake_ || retryStop_; });
			if (retryStop_) return;
			retryWake_ = false;   // wake 소비. 처리 중 새 signal이 오면 다시 set되어 재실행됨(lost-wakeup 방지)
		}
		try {
			std::lock_guard<std::recursive_mutex> transaction(deferredMutex_);
			std::deque<DeferredModuleStop> stops;
			{ std::lock_guard<std::mutex> lock(retryMutex_); stops.swap(deferredModuleStops_); }
			for (const auto& stop : stops) HandleDeferredModuleStop(stop);
			RetryPendingBreakpointsOnce();
		} catch (...) {
			LOG_ERROR("RetryPendingBreakpointsOnce threw");
		}
	}
}

// pending BP를 DLL 심볼로 재해석하고, 성공하면 실제 BP 설정 +
// DAP breakpoint(reason=changed, verified=true) 이벤트로 통지한다.
// 워커 스레드에서만 호출되므로 IPC(SendAndReceive)를 안전하게 쓸 수 있다.
void DapServer::RetryPendingBreakpointsOnce(bool notify, const std::string& heldModule) {
	// pending이 소진되거나 더 이상 해석되지 않을 때까지 반복.
	for (;;) {
		if (!running_ || !ipcTransport_->IsConnected()) return;

		struct Retry {
			int dapId;
			bool isFunc;
			std::string source;
			uint32_t line;
			std::string functionName;
		};
		std::vector<Retry> todo;
		std::set<std::string> guards;
		{ std::lock_guard<std::mutex> lock(retryMutex_); guards = internalModuleStops_; }
		{
			std::lock_guard<std::mutex> lock(breakpointMutex_);
			for (auto& m : breakpointMappings_) {
				if (!m.pending || (!notify && m.type != BpType::Function)) continue;
				// Ordinary inventory notifications must not bypass the guarded
				// module stop query, including after that query failed.
				if (notify && m.type == BpType::Function && guards.count(FunctionModule(m.functionName)) &&
					FunctionModule(m.functionName) != heldModule) continue;
				todo.push_back({m.dapId, m.type == BpType::Function, m.source, m.line, m.functionName});
			}
		}
		if (todo.empty()) return;

		bool anyResolved = false;
		for (auto& r : todo) {
			uint64_t addr = 0;
			if (r.isFunc) {
				ResolveFunctionRequest rq = {};
				strncpy_s(rq.functionName, r.functionName.c_str(), sizeof(rq.functionName) - 1);
				std::vector<uint8_t> resp;
				if (ipcTransport_->SendAndReceive(IpcCommand::ResolveFunction, &rq, sizeof(rq), resp)
					&& resp.size() >= sizeof(ResolveFunctionResponse)) {
					auto* r2 = reinterpret_cast<const ResolveFunctionResponse*>(resp.data());
					if (r2->status == IpcStatus::Ok) addr = r2->address;
				}
			} else {
				ResolveSourceLineRequest rq = {};
				strncpy_s(rq.fileName, r.source.c_str(), sizeof(rq.fileName) - 1);
				rq.line = r.line;
				std::vector<uint8_t> resp;
				if (ipcTransport_->SendAndReceive(IpcCommand::ResolveSourceLine, &rq, sizeof(rq), resp)
					&& resp.size() >= sizeof(ResolveSourceLineResponse)) {
					auto* r2 = reinterpret_cast<const ResolveSourceLineResponse*>(resp.data());
					if (r2->status == IpcStatus::Ok) addr = r2->address;
				}
			}
			if (addr == 0) continue;  // 아직 해석 불가 (이 모듈이 아님)

			// 실제 BP 설정
			SetBreakpointRequest sreq{};
			sreq.address = addr;
			std::vector<uint8_t> sresp;
			uint32_t newVehId = 0;
			bool ok = false;
			if (ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &sreq, sizeof(sreq), sresp)
				&& sresp.size() >= sizeof(SetBreakpointResponse)) {
				auto* s2 = reinterpret_cast<const SetBreakpointResponse*>(sresp.data());
				if (s2->status == IpcStatus::Ok) { ok = true; newVehId = s2->id; }
			}
			if (!ok) continue;

			// 매핑 갱신 (dapId로 추적; 동시 재설정으로 사라졌을 수 있음)
			bool updated = false;
			{
				std::lock_guard<std::mutex> lock(breakpointMutex_);
				for (auto& m : breakpointMappings_) {
					if (m.dapId == r.dapId && m.pending) {
						m.vehId = newVehId;
						m.address = addr;
						m.pending = false;
						updated = true;
						break;
					}
				}
			}
			if (updated) {
				anyResolved = true;
				Breakpoint dbp;
				dbp.id = r.dapId;
				dbp.verified = true;
				dbp.instructionReference = addr;
				if (notify) SendEvent("breakpoint", {
					{"reason", "changed"},
					{"breakpoint", dbp.ToJson()},
				});
				DAP_TRACE("DeferredBPResolved", (r.isFunc ? r.functionName : (r.source + ":" + std::to_string(r.line))) + " -> " + FormatAddress(addr));
			} else {
				// 매핑이 사라짐(동시 재설정) -> 방금 설정한 BP 정리
				RemoveUnreferencedBreakpoint(newVehId);
			}
		}
		if (!anyResolved) return;  // 이번 라운드에 아무것도 못 풀면 종료
	}
}

void DapServer::OnSetExceptionBreakpoints(const Request& req) {
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "setExceptionBreakpoints";
	const auto filters = req.arguments.value("filters", json::array());
	// ExceptionEvent carries no first/second-chance field. Accept only the
	// policy this adapter actually implements, rather than silently ignoring it.
	const auto filterOptions = req.arguments.value("filterOptions", json::array());
	const auto exceptionOptions = req.arguments.value("exceptionOptions", json::array());
	resp.success = filters == json::array({"all"}) &&
		filterOptions.is_array() && filterOptions.empty() &&
		exceptionOptions.is_array() && exceptionOptions.empty();
	if (!resp.success)
		resp.message = "Only filters=[all] is supported; exception chance/filter options are unavailable";
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
			RemoveBreakpointRequest rmReq{};
			rmReq.id = it->vehId;
			ipcTransport_->SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
			it = breakpointMappings_.erase(it);
		} else {
			++it;
		}
	}

	LOG_DEBUG("setInstructionBreakpoints: %u breakpoints, raw=%s",
		(unsigned)bps.size(), req.arguments.dump().c_str());

	for (auto& bp : bps) {
		std::string instrRef = bp.value("instructionReference", std::string(""));
		if (instrRef.empty()) instrRef = bp.value("instruction_reference", std::string(""));
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

		SetBreakpointRequest setReq{};
		setReq.address = address;

		std::vector<uint8_t> respData;
		if (ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &setReq, sizeof(setReq), respData)) {
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
	const auto resumeCutoff = visibleStopVersion_.load();
	// DAP: continue resumes every thread unless the client asks for singleThread.
	const bool singleThread = req.arguments.value("singleThread", false);
	uint32_t threadId = singleThread ? req.arguments.value("threadId", 0u) : 0;

	// Continue 시 이전 스텝의 temp BP 정리
	CleanupStaleTempBp();
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::None;
	}

	// Launch + stopOnEntry: 메인 스레드가 아직 OS-suspended 상태
	// VEH Continue 전에 먼저 OS resume 해야 함
	ResumeMainThread(threadId);

	bool allContinued = false;
	std::string error;
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "continue";
	resp.success = ContinueBackend(threadId, allContinued, error, resumeCutoff);
	if (resp.success) {
		std::lock_guard<std::mutex> lock(frameMutex_);
		frameMap_.clear();
		nextFrameId_ = 1;
		resp.body = {{"allThreadsContinued", threadId == 0 && allContinued}};
	} else resp.message = error;
	SendResponse(resp);
}

void DapServer::OnNext(const Request& req) {
	const auto resumeCutoff = visibleStopVersion_.load();
	uint32_t threadId = req.arguments.value("threadId", 0);
	std::string granularity = req.arguments.value("granularity", "statement");
	bool executionOk = false, allContinued = false;
	std::string executionError;
	ResumeMainThread();

	LOG_INFO("OnNext: threadId=%u granularity=%s", threadId, granularity.c_str());

	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::Over;
		steppingThreadId_ = threadId;
		steppingInstruction_ = guestTarget_ || (granularity == "instruction");
		steppingStartAddr_ = 0;
		steppingNextLineAddr_ = 0;
		steppingSourceLine_ = 0;
		steppingSourceFile_.clear();
	}

	CleanupStaleTempBp();
	if (guestTarget_) {
		const StepRequest request{threadId};
		executionOk = SendStatusCommand(IpcCommand::StepOver, &request, sizeof(request), executionError);
		goto send_response;
	}

	// === PDB 경로: 다음 소스 라인 주소에 temp BP → Continue (O(1)) ===
	if (!steppingInstruction_ && symbolEngineReady_) {
		// 현재 RIP 획득 (IPC GetStackTrace)
		uint64_t currentIP = 0;
		{
			GetStackTraceRequest stReq{};
			stReq.threadId = threadId;
			stReq.startFrame = 0;
			stReq.maxFrames = 1;
			std::vector<uint8_t> stResp;
			if (ipcTransport_->SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp)
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
				SetBreakpointRequest bpReq{};
				bpReq.address = lineRange.nextLineAddress;
				std::vector<uint8_t> bpResp;
				if (ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)
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
						ContinueRequest contReq{};
						contReq.threadId = threadId;
						executionOk = ContinueBackend(threadId, allContinued, executionError, resumeCutoff);
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
		// CALL 명령어 판별 -> 임시 BP로 건너뛰기 (instruction/statement 모두)
		uint64_t nextInsnAddr = 0;
		uint64_t callAfterAddr = 0;
		bool callSkipped = false;

		// (1) 현재 명령어가 CALL
		if (IsCallInstruction(threadId, nextInsnAddr)) {
			LOG_INFO("OnNext fallback: CALL detected, temp BP at 0x%llX", nextInsnAddr);
			callAfterAddr = nextInsnAddr;
		}
		// (2) BP rearm 시 다음 명령어가 CALL (2-instruction 실행 문제)
		else if (IsNextInstructionCall(threadId, callAfterAddr)) {
			LOG_INFO("OnNext fallback: next insn is CALL (BP rearm), temp BP at 0x%llX", callAfterAddr);
		}

		if (callAfterAddr != 0) {
			SetBreakpointRequest bpReq{};
			bpReq.address = callAfterAddr;
			std::vector<uint8_t> bpResp;
			if (ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq), bpResp)
				&& bpResp.size() >= sizeof(SetBreakpointResponse)) {
				auto* r = reinterpret_cast<const SetBreakpointResponse*>(bpResp.data());
				if (r->status == IpcStatus::Ok) {
					{
						std::lock_guard<std::mutex> stepLock(steppingMutex_);
						stepOverTempBpId_ = r->id;
						stepOverTempBpAddr_ = callAfterAddr;
					}
					ContinueRequest contReq{};
					contReq.threadId = threadId;
					executionOk = ContinueBackend(threadId, allContinued, executionError, resumeCutoff);
					callSkipped = true;
				}
			}
		}
		if (!callSkipped) {
			StepRequest stepReq{};
			stepReq.threadId = threadId;
			executionOk = SendStatusCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq), executionError);
		}
	}

send_response:

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "next";
	resp.success = executionOk;
	if (executionOk) ClearVisibleStops(threadId, resumeCutoff);
	if (!executionOk) {
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::None;
		resp.message = executionError;
	}
	SendResponse(resp);
}

void DapServer::OnStepIn(const Request& req) {
	const auto resumeCutoff = visibleStopVersion_.load();
	uint32_t threadId = req.arguments.value("threadId", 0);
	std::string granularity = req.arguments.value("granularity", "statement");
	ResumeMainThread();

	CleanupStaleTempBp();
	{
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::In;
		steppingThreadId_ = threadId;
		steppingInstruction_ = guestTarget_ || (granularity == "instruction");
		steppingStartAddr_ = 0;
		steppingNextLineAddr_ = 0;
	}
	if (!steppingInstruction_) {
		ResolveStepRange(threadId);
	}

	StepRequest stepReq{};
	stepReq.threadId = threadId;
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "stepIn";
	resp.success = SendStatusCommand(IpcCommand::StepInto, &stepReq, sizeof(stepReq), resp.message);
	if (resp.success) ClearVisibleStops(threadId, resumeCutoff);
	if (!resp.success) {
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::None;
	}
	SendResponse(resp);
}

void DapServer::OnStepOut(const Request& req) {
	const auto resumeCutoff = visibleStopVersion_.load();
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

	StepRequest stepReq{};
	stepReq.threadId = threadId;
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "stepOut";
	resp.success = SendStatusCommand(IpcCommand::StepOut, &stepReq, sizeof(stepReq), resp.message);
	if (resp.success) ClearVisibleStops(threadId, resumeCutoff);
	if (!resp.success) {
		std::lock_guard<std::mutex> stepLock(steppingMutex_);
		steppingMode_ = SteppingMode::None;
	}
	SendResponse(resp);
}

void DapServer::OnPause(const Request& req) {
    const uint32_t threadId = req.arguments.value("threadId", 0u);
    const PauseRequest pauseReq{threadId};
    Response resp;
    resp.request_seq = req.seq;
    resp.command = "pause";
    resp.success = SendStatusCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq), resp.message);
    SendResponse(resp);
    // The local VEH DLL acknowledges its suspension synchronously and sends no
    // Paused event. Guest backends report the actual selected thread via Paused.
    if (resp.success && !guestTarget_) SendPauseStopped(threadId);
}

// --- State Queries ---

void DapServer::OnThreads(const Request& req) {
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "threads";
	std::vector<uint8_t> data;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetThreads, nullptr, 0, data)) {
		resp.success = false;
		resp.message = "GetThreads IPC failed";
		SendResponse(resp);
		return;
	}
	if (data.size() < sizeof(IpcStatus)) {
		resp.success = false;
		resp.message = "GetThreads response is incomplete";
		SendResponse(resp);
		return;
	}
	IpcStatus status{};
	std::memcpy(&status, data.data(), sizeof(status));
	if (status != IpcStatus::Ok) {
		resp.success = false;
		resp.message = "GetThreads backend status " + std::to_string(static_cast<uint32_t>(status));
		SendResponse(resp);
		return;
	}
	GetThreadsResponse header{};
	if (data.size() < sizeof(header)) {
		resp.success = false;
		resp.message = "GetThreads response is incomplete";
		SendResponse(resp);
		return;
	}
	std::memcpy(&header, data.data(), sizeof(header));
	const size_t payloadSize = data.size() - sizeof(header);
	if (payloadSize % sizeof(ThreadInfo) != 0 ||
		header.count != payloadSize / sizeof(ThreadInfo)) {
		resp.success = false;
		resp.message = "GetThreads response length mismatch";
		SendResponse(resp);
		return;
	}
	json threadsJson = json::array();
	for (uint32_t i = 0; i < header.count; ++i) {
		ThreadInfo info{};
		std::memcpy(&info, data.data() + sizeof(header) + static_cast<size_t>(i) * sizeof(info), sizeof(info));
		const auto* end = static_cast<const char*>(std::memchr(info.name, '\0', sizeof(info.name)));
		if (!end) {
			resp.success = false;
			resp.message = "GetThreads name is unterminated";
			SendResponse(resp);
			return;
		}
		Thread thread;
		thread.id = info.id;
		thread.name = info.name[0] ? std::string(info.name, static_cast<size_t>(end - info.name)) : "Thread " + std::to_string(info.id);
		threadsJson.push_back(thread.ToJson());
	}
	resp.body = {{"threads", threadsJson}};
	SendResponse(resp);
}

void DapServer::OnStackTrace(const Request& req) {
    uint32_t threadId = req.arguments.value("threadId", 0u);
    if (!threadId) threadId = lastStoppedThreadId_.load();
    const int startFrame = req.arguments.value("startFrame", 0);
    const int levels = req.arguments.value("levels", 20);
    Response resp;
    resp.request_seq = req.seq;
    resp.command = "stackTrace";
    if (startFrame < 0 || levels < 0) {
        resp.success = false;
        resp.message = "Stack frame bounds must be nonnegative";
        SendResponse(resp);
        return;
    }
    GetStackTraceRequest stReq{threadId, static_cast<uint32_t>(startFrame),
        levels == 0 ? 200u : static_cast<uint32_t>(std::min(levels, 200))};
    std::vector<uint8_t> respData;
    GetStackTraceResponse header{};
    if (!ReceiveBackendReply(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), respData, resp.message) ||
        !ValidateStackTraceReply(respData, stReq.maxFrames, header, resp.message)) {
        resp.success = false;
        SendResponse(resp);
        return;
    }
    // A valid empty stack stays empty; failures never become synthetic frames.
    json framesJson = json::array();
    const auto* frames = reinterpret_cast<const StackFrameInfo*>(respData.data() + sizeof(header));
    const uint32_t count = header.count;
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

    resp.success = true;
    resp.message.clear();
    resp.body = {{"stackFrames", framesJson}, {"totalFrames", header.totalFrames}};
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
	uint32_t threadId = 0;
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
	if (threadId == 0) threadId = lastStoppedThreadId_.load();

	if (scopeType == SCOPE_REGISTERS) {
		// 레지스터 값 가져오기
		GetRegistersRequest regReq{};
		regReq.threadId = threadId;

		LOG_INFO("OnVariables: requesting registers for threadId=%u (frameId=%d, mapFound=%d)",
			threadId, frameId, frameFound ? 1 : 0);

		std::vector<uint8_t> respData;
		if (ipcTransport_->SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
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
			EnumLocalsRequest locReq{};
			locReq.threadId = threadId;
			locReq.instructionAddress = instrAddr;
			locReq.frameBase = fBase;

			std::vector<uint8_t> locData;
			if (ipcTransport_->SendAndReceive(IpcCommand::EnumLocals, &locReq, sizeof(locReq), locData)
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
								ReadMemoryRequest rmReq{};
								rmReq.address = ptr;
								rmReq.size = 128;
								std::vector<uint8_t> rmData;
								if (ipcTransport_->SendAndReceive(IpcCommand::ReadMemory, &rmReq, sizeof(rmReq), rmData)
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

	uint32_t threadId = 0;
	if (frameId != 0) {
		std::lock_guard<std::mutex> lock(frameMutex_);
		auto it = frameMap_.find(frameId);
		if (it != frameMap_.end()) threadId = it->second.threadId;
	}
	if (threadId == 0) threadId = lastStoppedThreadId_.load();
	if (threadId == 0) threadId = launchedMainThreadId_;

	auto evaluated = EvaluateExpression(*ipcTransport_, targetProcess_, expression, threadId,
		ExprEvalFrontend::Dap);
	resp.success = evaluated.ok;
	if (evaluated.ok) {
		resp.body = {
			{"result", evaluated.value},
			{"type", evaluated.type},
			{"variablesReference", 0},
		};
	} else {
		resp.message = evaluated.error;
	}
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
	if (threadId == 0) threadId = launchedMainThreadId_;

	// IPC로 레지스터 수정 요청
	SetRegisterRequest setReq{};
	setReq.threadId = threadId;
	setReq.regIndex = regIndex;
	setReq.value = newVal;

	std::vector<uint8_t> respData;
	if (ipcTransport_->SendAndReceive(IpcCommand::SetRegister, &setReq, sizeof(setReq), respData)) {
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

	if (ipcTransport_->SendAndReceive(IpcCommand::GetModules, nullptr, 0, respData)) {
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
	Response resp;
	resp.request_seq = req.seq;
	resp.command = "readMemory";
	if (!AddAddressOffset(addr, offset, addr) ||
		addr > UINT64_MAX - static_cast<uint64_t>(count - 1) ||
		(guestAddressBits_ == 32 &&
			(addr > UINT32_MAX || static_cast<uint64_t>(count - 1) > UINT32_MAX - addr))) {
		resp.success = false;
		resp.message = "Memory address range is outside the target address space";
		SendResponse(resp);
		return;
	}

	ReadMemoryRequest readReq{};
	readReq.address = addr;
	readReq.size = count;

	std::vector<uint8_t> respData;
	if (ipcTransport_->SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), respData) &&
		respData.size() >= sizeof(IpcStatus) &&
		respData.size() <= sizeof(IpcStatus) + static_cast<size_t>(count) &&
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

	WriteMemoryRequest writeReq{};
	writeReq.address = addr;
	writeReq.size = (uint32_t)bytes.size();

	// writeReq + data를 하나의 버퍼로
	std::vector<uint8_t> payload(sizeof(writeReq) + bytes.size());
	memcpy(payload.data(), &writeReq, sizeof(writeReq));
	memcpy(payload.data() + sizeof(writeReq), bytes.data(), bytes.size());

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "writeMemory";

	if (SendStatusCommand(IpcCommand::WriteMemory, payload.data(), (uint32_t)payload.size(), resp.message)) {
		resp.success = true;
		resp.body = {{"bytesWritten", (int)bytes.size()}};
	} else {
		resp.success = false;
		// Preserve the transport/backend reason; bytesWritten is unconfirmed.
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
	if (instrOffset < -10000 || instrOffset > 10000) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disassemble";
		resp.success = false;
		resp.message = "instructionOffset is outside the supported range";
		SendResponse(resp);
		return;
	}

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
	if (!AddAddressOffset(addr, offset, addr) ||
		(guestAddressBits_ == 32 && addr > UINT32_MAX)) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disassemble";
		resp.success = false;
		resp.message = "Disassembly address is outside the target address space";
		SendResponse(resp);
		return;
	}

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
	if (readSize && (startAddr > UINT64_MAX - (readSize - 1) ||
		(guestAddressBits_ == 32 &&
			(startAddr > UINT32_MAX || static_cast<uint64_t>(readSize - 1) > UINT32_MAX - startAddr)))) {
		Response resp;
		resp.request_seq = req.seq;
		resp.command = "disassemble";
		resp.success = false;
		resp.message = "Disassembly range is outside the target address space";
		SendResponse(resp);
		return;
	}
	ReadMemoryRequest readReq{};
	readReq.address = startAddr;
	readReq.size = readSize;

	Response resp;
	resp.request_seq = req.seq;
	resp.command = "disassemble";

	std::vector<uint8_t> memData;
	if (ipcTransport_->SendAndReceive(IpcCommand::ReadMemory, &readReq, sizeof(readReq), memData) &&
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
		RemoveHwBreakpointRequest rmReq{};
		rmReq.id = m.vehId;
		ipcTransport_->SendCommand(IpcCommand::RemoveHwBreakpoint, &rmReq, sizeof(rmReq));
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

		SetHwBreakpointRequest hwReq{};
		hwReq.address = address;
		hwReq.type = (accessType == "readWrite") ? 3 : 1; // 1=write, 3=readwrite (DR7 R/W field)
		hwReq.size = 8; // 기본 8바이트 감시

		std::vector<uint8_t> respData;
		if (ipcTransport_->SendAndReceive(IpcCommand::SetHwBreakpoint, &hwReq, sizeof(hwReq), respData)) {
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

		if (!ipcTransport_->Connect(targetPid_, 3000)) {
			resp.success = false;
			resp.message = "Failed to reconnect pipe";
			SendResponse(resp);
			return;
		}

		ipcTransport_->StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
			OnIpcEvent(eventId, payload, size);
		});
		// VEH 설치 완료(Ready) 대기 (reader 시작 후 -- condvar). 실패해도 진행(보수적).
		if (!ipcTransport_->WaitForReady(3000)) {
			LOG_WARN("No Ready after reconnect (pid=%u); proceeding", targetPid_);
		}
		ipcTransport_->StartHeartbeat();

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

		// 타겟 비트니스에 맞게 디스어셈블러 재생성
		{
			BOOL isWow64 = FALSE;
			if (targetProcess_) IsWow64Process(targetProcess_, &isWow64);
			bool is64 = (isWow64 == FALSE);
			disassembler_ = veh::CreateDisassembler(is64);
		}

		StartProcessMonitor();

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
		auto relaunch = Injector::LaunchAndInject(programPath_, launchArgStr_, launchCwd_, dllPath, injectionMethod_, runAsInvoker_);

		if (relaunch.pid == 0) {
			resp.success = false;
			resp.message = "Failed to relaunch";
			if (!relaunch.error.empty()) resp.message += " - " + relaunch.error;
			SendResponse(resp);
			return;
		}

		targetPid_ = relaunch.pid;
		launchedMainThreadId_ = relaunch.mainThreadId;
		mainThreadResumed_ = false;

		if (!ipcTransport_->Connect(targetPid_, 3000)) {
			// 새로 launch한 프로세스 종료 (고아 방지)
			HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, targetPid_);
			if (proc) {
				TerminateProcess(proc, 1);
				CloseHandle(proc);
			}
			targetPid_ = 0;
			resp.success = false;
			resp.message = "Failed to connect pipe after relaunch";
			SendResponse(resp);
			return;
		}

		ipcTransport_->StartEventListener([this](uint32_t eventId, const uint8_t* payload, uint32_t size) {
			OnIpcEvent(eventId, payload, size);
		});
		// VEH 설치 완료(Ready) 대기 (reader 시작 후 -- condvar). 실패해도 진행(보수적).
		if (!ipcTransport_->WaitForReady(3000)) {
			LOG_WARN("No Ready after reconnect (pid=%u); proceeding", targetPid_);
		}
		ipcTransport_->StartHeartbeat();

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

		// 타겟 비트니스에 맞게 디스어셈블러 재생성
		{
			bool is64 = !Injector::IsExe32Bit(programPath_);
			disassembler_ = veh::CreateDisassembler(is64);
		}

		StartProcessMonitor();

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
    Response resp;
    resp.request_seq = req.seq;
    resp.command = "terminateThreads";
    const auto ids = req.arguments.value("threadIds", json::array());
    resp.success = ids.is_array();
    for (const auto& id : ids) {
        if (!id.is_number_integer() || id.get<int64_t>() <= 0 ||
            id.get<int64_t>() > UINT32_MAX) {
            resp.success = false;
            resp.message = "threadIds must contain positive 32-bit thread IDs";
            SendResponse(resp);
            return;
        }
    }
    if (!resp.success) {
        resp.message = "threadIds must be an array";
        SendResponse(resp);
        return;
    }
    for (const auto& id : ids) {
        const TerminateThreadRequest request{id.get<uint32_t>()};
        std::string error;
        if (!SendStatusCommand(IpcCommand::TerminateThread, &request, sizeof(request), error)) {
            resp.success = false;
            if (resp.message.empty())
                resp.message = "Thread " + std::to_string(request.threadId) + ": " + error;
        }
    }
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
		SetInstructionPointerRequest ipReq{};
		ipReq.threadId = threadId;
		ipReq.address = static_cast<uint64_t>(targetId);

		std::vector<uint8_t> respData;
		if (ipcTransport_->SendAndReceive(IpcCommand::SetInstructionPointer, &ipReq, sizeof(ipReq), respData)) {
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
					RemoveBreakpointRequest rmReq{};
					rmReq.id = e->breakpointId;
					ipcTransport_->SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
				}
				bool lineStep = false;
				uint64_t startAddr = 0, nextLineAddr = 0;
				std::string sourceFile;
				uint32_t sourceLine = 0;
				{
					std::lock_guard<std::mutex> stepLock(steppingMutex_);
					stepOverTempBpId_ = 0;
					stepOverTempBpAddr_ = 0;

					// 소스 라인 스텝 중이면 라인 변경 확인 (instruction 모드는 스킵)
					lineStep = steppingMode_ == SteppingMode::Over && !steppingInstruction_
						&& steppingSourceLine_ != 0;
					startAddr = steppingStartAddr_;
					nextLineAddr = steppingNextLineAddr_;
					sourceFile = steppingSourceFile_;
					sourceLine = steppingSourceLine_;
				}
				const bool sameLine = lineStep &&
					IsSameStepLine(e->address, startAddr, nextLineAddr, sourceFile, sourceLine);
				if (sameLine) {
					// 같은 라인 → 계속 스텝
					LOG_DEBUG("Temp BP: still same line, auto-stepping");
					StepRequest stepReq{};
					stepReq.threadId = e->threadId;
					ipcTransport_->SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));
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
				ContinueRequest contReq{};
				contReq.threadId = e->threadId;
				ipcTransport_->SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
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
			std::string curSourceFile;
			uint32_t curSourceLine;
			{
				std::lock_guard<std::mutex> stepLock(steppingMutex_);
				curMode = steppingMode_;
				curThreadId = steppingThreadId_;
				curInstruction = steppingInstruction_;
				curStartAddr = steppingStartAddr_;
				curNextLineAddr = steppingNextLineAddr_;
				curSourceFile = steppingSourceFile_;
				curSourceLine = steppingSourceLine_;
			}
			LOG_INFO("StepCompleted: threadId=%u addr=0x%llX mode=%d", e->threadId, e->address, (int)curMode);

			// 소스 라인 스텝 중이면 CALL 스킵 + 라인이 바뀔 때까지 자동 반복
			// instruction 모드면 auto-step 안 함 → 바로 stopped
			if (curMode == SteppingMode::Over && !curInstruction
				&& e->threadId == curThreadId) {
				bool sameLine = IsSameStepLine(e->address, curStartAddr, curNextLineAddr,
					curSourceFile, curSourceLine);

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
								SetBreakpointRequest bpReq{};
								bpReq.address = retAddr;
								ipcTransport_->SendCommand(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq));
								{
									std::lock_guard<std::mutex> stepLock(steppingMutex_);
									stepOverTempBpAddr_ = retAddr;
								}
								ContinueRequest contReq{};
								contReq.threadId = e->threadId;
								ipcTransport_->SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
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
						SetBreakpointRequest bpReq{};
						bpReq.address = callRetAddr;
						ipcTransport_->SendCommand(IpcCommand::SetBreakpoint, &bpReq, sizeof(bpReq));
						{
							std::lock_guard<std::mutex> stepLock(steppingMutex_);
							stepOverTempBpAddr_ = callRetAddr;
						}

						ContinueRequest contReq{};
						contReq.threadId = e->threadId;
						ipcTransport_->SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
					} else {
						StepRequest stepReq{};
						stepReq.threadId = e->threadId;
						ipcTransport_->SendCommand(IpcCommand::StepOver, &stepReq, sizeof(stepReq));
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

	case IpcEvent::ModuleLoadStopped: {
		if (size >= sizeof(ModuleLoadStopEvent)) {
			ModuleLoadStopEvent copy{};
			std::memcpy(&copy, payload, sizeof(copy));
			copy.name[sizeof(copy.name) - 1] = '\0';
			if (guestTarget_) {
				QueueDeferredModuleStop(copy);
				break;
			}
			const auto* e = &copy;
			NotifyRetry();
			lastStoppedThreadId_.store(e->threadId);
			char nameBuf[sizeof(e->name)];
			memcpy(nameBuf, e->name, sizeof(e->name));
			nameBuf[sizeof(e->name) - 1] = '\0';
			SendEvent("stopped", {
				{"reason", "module load"},
				{"threadId", (int)e->threadId},
				{"allThreadsStopped", true},
				{"description", std::string("Module loaded: ") + nameBuf},
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
			ClearVisibleStops(e->threadId, visibleStopVersion_.load());
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

			// Deferred BP: 새 모듈 심볼로 미해결 BP 재해석.
			// 이 콜백은 Reader 스레드 -> SendAndReceive/락 금지. NotifyRetry는 wake signal만
			// 보내고, 영속 워커 스레드가 재해석을 수행한다(데드락/race 차단).
			NotifyRetry();
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
		if (guestTarget_ && size == sizeof(uint32_t)) {
			uint32_t threadId{};
			std::memcpy(&threadId, payload, sizeof(threadId));
			SendPauseStopped(threadId);
		}
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

	// 실행 중인 프로세스가 있으면 pid 기반 판별
	if (targetPid_ != 0) {
		return Injector::SelectDllForTarget(targetPid_, dir.string());
	}

	// 프로세스 생성 전 (launch)이면 PE 헤더 기반 판별
	if (!programPath_.empty()) {
		return Injector::SelectDllForExe(programPath_, dir.string());
	}

	return (dir / "vcruntime_net.dll").string();
}

bool DapServer::TryParseRegisterName(const std::string& name) {
	return TryParseExpressionRegister(name);
}

uint64_t DapServer::ResolveRegisterByName(const std::string& name, const RegisterSet& regs) {
	return ResolveExpressionRegister(name, regs, ExprEvalFrontend::Dap);
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
			// 읽지 못한 메모리(게스트 대상 포함)는 0 으로 비교하지 않고 중단한다.
			SIZE_T bytesRead = 0;
			if (!targetProcess_ ||
				!ReadProcessMemory(targetProcess_, (LPCVOID)addr, &lhsVal, 8, &bytesRead) || bytesRead != 8)
				return true;
		} catch (...) { return true; }
	} else if (TryParseRegisterName(lhs)) {
		// 레지스터 — cachedRegs 우선 사용 (Reader 스레드에서 SendAndReceive 데드락 방지)
		if (cachedRegs) {
			lhsVal = ResolveRegisterByName(lhs, *cachedRegs);
		} else {
			GetRegistersRequest regReq{};
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (ipcTransport_->SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
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
			GetRegistersRequest regReq{};
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (ipcTransport_->SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
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
			GetRegistersRequest regReq{};
			regReq.threadId = threadId;
			std::vector<uint8_t> respData;
			if (ipcTransport_->SendAndReceive(IpcCommand::GetRegisters, &regReq, sizeof(regReq), respData)) {
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
	GetStackTraceRequest stReq{};
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
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

bool DapServer::IsNextInstructionCall(uint32_t threadId, uint64_t& addrAfterCall) {
	if (!targetProcess_) return false;

	// 현재 RIP 가져오기
	GetStackTraceRequest stReq{};
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
		return false;
	if (stResp.size() < sizeof(GetStackTraceResponse) + sizeof(StackFrameInfo))
		return false;
	auto* hdr = reinterpret_cast<const GetStackTraceResponse*>(stResp.data());
	if (hdr->status != IpcStatus::Ok || hdr->count == 0)
		return false;
	auto* frame = reinterpret_cast<const StackFrameInfo*>(stResp.data() + sizeof(GetStackTraceResponse));
	uint64_t rip = frame->address;

	// 현재 주소가 BP 위에 있는지 확인 (rearm 시에만 2-instruction 문제 발생)
	bool onBp = false;
	{
		std::lock_guard<std::mutex> bpLock(breakpointMutex_);
		for (const auto& m : breakpointMappings_) {
			if (m.address == rip) { onBp = true; break; }
		}
	}
	if (!onBp) return false;

	// BP 위에 있으면 2개 명령어를 디코딩하여 두 번째가 CALL인지 확인
	uint8_t codeBuf[32] = {};
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(targetProcess_, (LPCVOID)rip, codeBuf, 32, &bytesRead) || bytesRead < 2)
		return false;

	auto insns = disassembler_->Disassemble(codeBuf, (uint32_t)bytesRead, rip, 2);
	if (insns.size() < 2) return false;

	const auto& secondInsn = insns[1];
	if (secondInsn.mnemonic.size() >= 4
		&& (secondInsn.mnemonic[0] == 'c' || secondInsn.mnemonic[0] == 'C')
		&& (secondInsn.mnemonic[1] == 'a' || secondInsn.mnemonic[1] == 'A')
		&& (secondInsn.mnemonic[2] == 'l' || secondInsn.mnemonic[2] == 'L')
		&& (secondInsn.mnemonic[3] == 'l' || secondInsn.mnemonic[3] == 'L')) {
		addrAfterCall = secondInsn.address + secondInsn.length;
		LOG_INFO("IsNextInstructionCall: BP at 0x%llX, next insn is CALL at 0x%llX, skip to 0x%llX",
			rip, secondInsn.address, addrAfterCall);
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
			RemoveBreakpointRequest rmReq{};
			rmReq.id = tempId;
			ipcTransport_->SendCommand(IpcCommand::RemoveBreakpoint, &rmReq, sizeof(rmReq));
		} else {
			LOG_INFO("CleanupStaleTempBp: id=%u is user BP, skipping removal", tempId);
		}
	} else if (tempAddr != 0) {
		if (!isUserBpAddr(tempAddr)) {
			LOG_INFO("CleanupStaleTempBp: removing by addr=0x%llX", tempAddr);
			RemoveBreakpointByAddrRequest rmReq{};
			rmReq.address = tempAddr;
			ipcTransport_->SendCommand(IpcCommand::RemoveBreakpointByAddr, &rmReq, sizeof(rmReq));
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

// Step-over line test. [startAddr, nextLineAddr) is empty when the next source line has
// no code (e.g. a function's closing brace), so compare the real source line when the
// adapter's symbols know it and fall back to the address range otherwise.
bool DapServer::IsSameStepLine(uint64_t address, uint64_t startAddr, uint64_t nextLineAddr,
	const std::string& file, uint32_t line) {
	std::string curFile;
	uint32_t curLine = 0;
	if (line != 0 && symbolEngineReady_ && symbolEngine_.GetSourceLine(address, curFile, curLine)) {
		if (curLine == 0xFEEFEE) return true;  // compiler-generated hidden line: keep stepping
		return curLine == line && (file.empty() || _stricmp(curFile.c_str(), file.c_str()) == 0);
	}
	return startAddr != 0 && nextLineAddr != 0 && address >= startAddr && address < nextLineAddr;
}

bool DapServer::GetTopFrameSourceLine(uint32_t threadId, std::string& file, uint32_t& line) {
	GetStackTraceRequest stReq{};
	stReq.threadId = threadId;
	stReq.startFrame = 0;
	stReq.maxFrames = 1;

	std::vector<uint8_t> stResp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetStackTrace, &stReq, sizeof(stReq), stResp))
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
	if (ipcTransport_->SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), respData)
		&& respData.size() >= sizeof(ResolveSourceLineResponse)) {
		auto* r = reinterpret_cast<const ResolveSourceLineResponse*>(respData.data());
		if (r->status == IpcStatus::Ok) {
			std::lock_guard<std::mutex> stepLock(steppingMutex_);
			steppingStartAddr_ = r->address;
		}
	}

	// 다음 라인의 주소 = steppingNextLineAddr_
	resolveReq.line = line + 1;
	if (ipcTransport_->SendAndReceive(IpcCommand::ResolveSourceLine, &resolveReq, sizeof(resolveReq), respData)
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

void DapServer::ResumeMainThread(uint32_t requestedThreadId) {
	if (mainThreadResumed_ || launchedMainThreadId_ == 0) return;
	if (requestedThreadId != 0 && requestedThreadId != launchedMainThreadId_) return;

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

void DapServer::Cleanup(bool detachOnly, bool backendDetached) {
	std::lock_guard<std::recursive_mutex> transaction(deferredMutex_);
	// 모니터 스레드 먼저 정리 (double-close 방지)
	StopProcessMonitor();

	// 메인 스레드가 아직 suspended이면 resume (안 하면 프로세스가 좀비로 남음)
	ResumeMainThread();

	if (ipcTransport_->IsConnected() && !backendDetached) {
		// detachOnly=true: Detach 명령 → DLL 파이프 서버는 유지 (재연결 가능)
		// detachOnly=false: Shutdown 명령 → DLL 파이프 서버도 종료
		auto cmd = (guestTarget_ || detachOnly) ? IpcCommand::Detach : IpcCommand::Shutdown;
		ipcTransport_->SendCommand(cmd);
		LOG_INFO("Sent %s to backend", cmd == IpcCommand::Detach ? "Detach" : "Shutdown");
	}
	// Disconnect는 항상 호출 (파이프 닫기 + 스레드 정리)
	ipcTransport_->Disconnect();
	if (guestAgentProcess_) {
		CloseHandle(guestAgentProcess_);
		guestAgentProcess_ = nullptr;
	}
	if (guestTarget_) {
		guestTarget_ = false;
		guestAddressBits_ = 0;
		std::memset(guestCommands_, 0, sizeof(guestCommands_));
		ipcTransport_ = std::make_unique<PipeClient>();
	}

	// 주: deferred 재시도 워커(retryThread_)는 Run() 생애 동안 유지되며 Run() 종료 시
	// StopRetryThread()로 정리한다. Cleanup은 detach/restart에서도 불리므로 여기서 워커를
	// 멈추지 않는다. 워커는 ipcTransport_->IsConnected()를 확인하므로 Disconnect 후에도 안전.
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

	{
		std::lock_guard<std::mutex> lock(retryMutex_);
		deferredModuleStops_.clear();
		internalModuleStops_.clear();
		visibleStops_.clear();
		retryWake_ = false;
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

void DapServer::StartProcessMonitor() {
	StopProcessMonitor();
	if (!targetProcess_) return;

	HANDLE hWait = OpenProcess(SYNCHRONIZE, FALSE, targetPid_);
	if (!hWait) {
		LOG_WARN("Cannot open process %u for SYNCHRONIZE, exit monitor disabled", targetPid_);
		return;
	}

	terminated_ = false;
	monitorStopEvent_ = CreateEvent(nullptr, TRUE, FALSE, nullptr);

	processMonitorThread_ = std::thread([this, hWait, stopEv = monitorStopEvent_]() {
		HANDLE handles[2] = { hWait, stopEv };
		DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
		CloseHandle(hWait);

		// WAIT_OBJECT_0 = process exited, WAIT_OBJECT_0+1 = stop requested
		if (result == WAIT_OBJECT_0 && running_) {
			DWORD exitCode = 0;
			if (targetProcess_) {
				GetExitCodeProcess(targetProcess_, &exitCode);
			}

			LOG_INFO("DAP: Target process %u exited (code: %lu)", targetPid_, exitCode);

			// Pipe cleanup
			ipcTransport_->StopHeartbeat();
			ipcTransport_->StopEventListener();
			ipcTransport_->Disconnect();

			// Notify VSCode (only once)
			if (!terminated_.exchange(true)) {
				SendEvent("terminated");
			}
		}
	});
}

void DapServer::StopProcessMonitor() {
	if (monitorStopEvent_) {
		SetEvent(monitorStopEvent_);
	}
	if (processMonitorThread_.joinable()) {
		processMonitorThread_.join();
	}
	if (monitorStopEvent_) {
		CloseHandle(monitorStopEvent_);
		monitorStopEvent_ = nullptr;
	}
}

} // namespace veh::dap
