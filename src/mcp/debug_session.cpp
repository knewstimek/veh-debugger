#include "debug_session.h"
#include "common/trace_path_compressor.h"
#include "adapter/expr_eval.h"
#include "adapter/pipe_client.h"
#include "common/logger.h"
#include "common/ipc_response_validation.h"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>
#include <utility>
#include <nlohmann/json.hpp>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace veh {

// --- Static helpers (no JSON dependency) ---

// Check if process is in CREATE_SUSPENDED state (loader not initialized)
static bool IsProcessUninitializedSuspended(uint32_t pid) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	bool foundAny = false;
	bool allSuspended = true;

	if (Thread32First(snap, &te)) {
		do {
			if (te.th32OwnerProcessID != pid) continue;
			foundAny = true;
			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
			if (!hThread) { allSuspended = false; break; }
			DWORD prevCount = SuspendThread(hThread);
			if (prevCount == (DWORD)-1) {
				CloseHandle(hThread);
				allSuspended = false;
				break;
			}
			ResumeThread(hThread);
			if (prevCount == 0) {
				allSuspended = false;
				CloseHandle(hThread);
				break;
			}
			CloseHandle(hThread);
		} while (Thread32Next(snap, &te));
	}
	CloseHandle(snap);

	if (!foundAny || !allSuspended) return false;

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProc) return false;

	HMODULE modules[8];
	DWORD needed = 0;
	BOOL ok = EnumProcessModules(hProc, modules, sizeof(modules), &needed);
	CloseHandle(hProc);

	if (!ok) return true;
	DWORD moduleCount = needed / sizeof(HMODULE);
	return moduleCount <= 4;
}

static bool IsPipeAvailable(uint32_t pid) {
	std::wstring pipeName = GetPipeName(pid);
	return WaitNamedPipeW(pipeName.c_str(), 0) != 0;
}

// --- DebugSession lifecycle ---

DebugSession::DebugSession() : ipcTransport_(std::make_unique<PipeClient>()) {}

DebugSession::~DebugSession() {
	StopProcessMonitor();
	if (attached_) {
		try {
			ipcTransport_->SendCommand(IpcCommand::Detach);
		} catch (...) {}
		ipcTransport_->Disconnect();
		attached_ = false;
	}
	if (launchedByUs_ && targetProcess_) {
		TerminateProcess(targetProcess_, 0);
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
		launchedByUs_ = false;
	}
}

void DebugSession::UseTransport(const std::wstring& pipeName, int minimumTimeoutMs) {
	if (pipeName == transportPipe_ && !ipcTransport_->IsRemote()) return;
	// A guest backend's pipe (named) gets the DAP adapter's 30 s floor: it
	// pauses the VM and runs guest-owned calls (live: a WoW64 stack walk with
	// page fault-ins outlasted the 3 s default and returned no frames).
	ipcTransport_ = std::make_unique<PipeClient>(pipeName, minimumTimeoutMs);
	transportPipe_ = pipeName;
}

static std::wstring Widen(const std::string& s) {
	std::wstring w(MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), static_cast<int>(w.size()));
	if (!w.empty()) w.pop_back();
	return w;
}

static std::wstring QuoteArg(const std::wstring& a) {
	return a.find_first_of(L" \t\"") == std::wstring::npos ? a : L"\"" + a + L"\"";
}

// Out-of-process server of this IPC protocol: started as
//   <agent> --pid <pid> --pipe <name> [extra args]
// on a pipe name chosen here, and accepted only if the process serving that
// pipe is the one we started. An agent still running for the PID is reused.
bool DebugSession::ConnectExternalAgent(uint32_t pid, const ExternalAgent& agent) {
	std::error_code ec;
	if (agent.path.empty() || !std::filesystem::exists(Widen(agent.path), ec)) {
		lastAttachError_ = "External backend: agent not found at '" + agent.path + "'.";
		return false;
	}
	auto running = externalAgents_.find(pid);
	if (running != externalAgents_.end()) {
		const auto process = running->second.process.get();
		const bool alive = process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
		if (!alive || running->second.path != agent.path || running->second.args != agent.args ||
            running->second.guestTarget != agent.guestTarget || running->second.vmTarget != agent.vmTarget) externalAgents_.erase(running);
	}
	running = externalAgents_.find(pid);
    const bool reusing = running != externalAgents_.end();
	if (running == externalAgents_.end()) {
		uint64_t nonce = 0;
		BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&nonce), sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		wchar_t pipe[96];
		swprintf_s(pipe, L"\\\\.\\pipe\\veh-ext-%u-%016llx", pid, static_cast<unsigned long long>(nonce));
		std::wstring cmd = QuoteArg(Widen(agent.path));
        if(!agent.vmTarget)cmd += L" --pid " + std::to_wstring(pid);
        cmd += L" --pipe " + std::wstring(pipe);
		for (const auto& a : agent.args) cmd += L" " + QuoteArg(Widen(a));
		STARTUPINFOW si = {sizeof(si)};
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
			lastAttachError_ = "External backend: failed to start agent (Win32 error " + std::to_string(GetLastError()) + ").";
			return false;
		}
		CloseHandle(pi.hThread);
		std::shared_ptr<void> process(pi.hProcess, [](void* handle) { CloseHandle(handle); });
		running = externalAgents_.emplace(pid, RunningAgent{agent.path, pipe, pi.dwProcessId,
			agent.args, agent.guestTarget, agent.vmTarget, std::move(process)}).first;
	}
	UseTransport(running->second.pipe, (agent.guestTarget || agent.vmTarget) ? 30000 : 0);
    auto* pipe = dynamic_cast<PipeClient*>(ipcTransport_.get());
    const bool connected = pipe && pipe->ConnectToPeer(pid, 5000, running->second.process.get());
    if (!connected) {
        const bool exited = WaitForSingleObject(running->second.process.get(), 0) == WAIT_OBJECT_0;
        DWORD exitCode = 0;
        if (exited) GetExitCodeProcess(running->second.process.get(), &exitCode);
        externalAgents_.erase(running);
        // A previously acknowledged agent may exit just after its liveness check.
        // Retry only a confirmed-dead cached peer, never a live/ambiguous startup.
        if (reusing && exited) return ConnectExternalAgent(pid, agent);
        lastAttachError_ = exited ? "External backend agent exited before accepting its pipe (exit code " +
            std::to_string(exitCode) + ")" : "External backend: agent pipe for PID " +
            std::to_string(pid) + " did not come up within 5s.";
        return false;
    }
	if (ipcTransport_->PeerProcessId() != running->second.processId) {
		ipcTransport_->Disconnect();
		lastAttachError_ = "External backend: the pipe is served by another process; refusing it.";
		externalAgents_.erase(running);
		return false;
	}
	return true;
}

void DebugSession::QueryBackendInfo() {
	backendInfo_ = {};
	std::vector<uint8_t> resp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetCapabilities, nullptr, 0, resp, 1500)) return;
	if (resp.size() < sizeof(GetCapabilitiesResponse)) return;   // older DLL: bare InvalidArgs
	GetCapabilitiesResponse caps;
	memcpy(&caps, resp.data(), sizeof(caps));
	if (caps.status != IpcStatus::Ok) return;
	backendInfo_.reported = true;
	backendInfo_.backend = caps.backend;
	backendInfo_.flags = caps.flags;
	memcpy(backendInfo_.commands, caps.commands, sizeof(caps.commands));
	backendInfo_.name.assign(caps.name, strnlen(caps.name, sizeof(caps.name)));
}

bool DebugSession::Attach(uint32_t pid, const ExternalAgent* agent) {
	lastAttachError_.clear();
    if (agent && agent->remote) return ConnectRemoteWork(pid, *agent, nullptr);
	if ((!pid && (!agent || !agent->vmTarget)) || (pid && agent && agent->vmTarget)) { lastAttachError_ = "VM scope requires no PID; process scopes require a nonzero PID"; return false; }
	backendInfo_ = {};

	if (agent) {
		if (!ConnectExternalAgent(pid, *agent)) return false;
		guestTarget_ = agent->guestTarget;
        vmTarget_ = agent->vmTarget;
		externalAttachPending_ = true;
		FinishAttach(pid);
		return true;
	}
	guestTarget_ = false;vmTarget_ = false;
	externalAttachPending_ = false;
	UseTransport({});

	if (IsProcessUninitializedSuspended(pid)) {
		LOG_ERROR("Process %u appears to be in CREATE_SUSPENDED state", pid);
		lastAttachError_ = "Process " + std::to_string(pid) + " is CREATE_SUSPENDED / uninitialized. "
			"Attach needs a running process (the DLL init thread cannot execute while the process is suspended). "
			"If a launcher spawns it suspended (common on hidden desktops), use veh_launch to debug from the start instead.";
		return false;
	}

	bool pipeExists = IsPipeAvailable(pid);

	// Fresh attach must inject -- probe access first so we can report *why* it fails precisely
	// (self-protected/higher-integrity targets deny OpenProcess even for injection rights).
	if (!pipeExists) {
		HANDLE probe = OpenProcess(
			PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
			FALSE, pid);
		if (!probe) {
			DWORD e = GetLastError();
			LOG_ERROR("OpenProcess(inject rights) failed for PID %u: %lu", pid, e);
			if (e == ERROR_ACCESS_DENIED) {
				lastAttachError_ = "Access denied opening PID " + std::to_string(pid) + " for injection. "
					"The target likely self-protects its process object (deny-DACL) or runs at higher integrity, "
					"so a fresh attach is impossible. Launch it under the debugger (veh_launch) so injection happens "
					"before it hardens, or run the debugger elevated.";
			} else {
				lastAttachError_ = "OpenProcess failed for PID " + std::to_string(pid) +
					" (Win32 error " + std::to_string(e) + ").";
			}
			return false;
		}
		CloseHandle(probe);
	}

	std::string dllPath = GetDllPath(pid);
	if (dllPath.empty()) {
		lastAttachError_ = "Could not locate the VEH DLL for the target's bitness (veh_dll_x64.dll / veh_dll_x86.dll) "
			"next to the server, or failed to query the process architecture.";
		return false;
	}

	if (pipeExists) {
		LOG_INFO("Pipe already exists for PID %u, skipping injection (re-attach)", pid);
	} else {
		LOG_INFO("Injecting into PID %u: %s", pid, dllPath.c_str());
		std::string injectionError;
		if (!Injector::InjectDll(pid, dllPath, InjectionMethod::Auto, &injectionError)) {
			LOG_ERROR("DLL injection failed for PID %u", pid);
			lastAttachError_ = "DLL injection into PID " + std::to_string(pid) + " failed (all methods exhausted). "
				"The target may block remote thread creation or the DLL failed to load. See logs for details.";
			if (!injectionError.empty()) lastAttachError_ += " Details: " + injectionError;
			return false;
		}
	}

	if (!ipcTransport_->Connect(pid, 3500)) {
		LOG_ERROR("Pipe connection failed (pid=%u)", pid);
		lastAttachError_ = "Injected into PID " + std::to_string(pid) + " but the IPC pipe did not come up within 3.5s. "
			"The DLL may have failed to initialize inside the target.";
		return false;
	}
	// 주: Ready 대기는 이벤트 리스너(reader) 시작 후에 해야 하므로 McpServer가
	// SetEventCallback 직후 GetPipeClient().WaitForReady()를 호출한다(condvar 방식).
	FinishAttach(pid);
	return true;
}

void DebugSession::FinishAttach(uint32_t pid) {
	targetPid_ = pid;
	attached_ = true;
	// External attach is provisional until the authenticated backend reports scope.
	if (externalAttachPending_ || guestTarget_ || vmTarget_ || IsRemoteTarget()) return;
	// VM_READ: 조건부 BP의 [addr]/value 평가가 이벤트 콜백 스레드에서 ReadProcessMemory로
	// 값을 읽는다(IPC ReadMemory는 콜백 스레드에서 재진입 불가). 실패 시 VM_READ 없이 폴백.
	targetProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_VM_READ, FALSE, pid);
	if (!targetProcess_) {
		targetProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
		if (!targetProcess_) LOG_WARN("Cannot open process %u for monitoring", pid);
	}
	attached_ = true;

	// Set disassembler bitness
	{
		BOOL isWow64 = FALSE;
		if (targetProcess_) {
			IsWow64Process(targetProcess_, &isWow64);
		}
		bool is64 = (isWow64 == FALSE);
		targetAddressBits_ = is64 ? 64 : 32;
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}
}

bool DebugSession::CompleteBackendAttach() {
    if (IsRemoteTarget() && !backendInfo_.reported) {
        lastAttachError_ = "Remote backend did not negotiate capabilities"; return false;
    }
    const bool peerGuest = backendInfo_.reported && (backendInfo_.flags & kCapGuestTarget);
    const bool peerVm = backendInfo_.reported && (backendInfo_.flags & kCapVirtualMachineTarget);
    if (!externalAttachPending_) {
        if(peerGuest||peerVm)lastAttachError_="External guest/VM backend requires explicit matching target_scope; launch is unsupported.";
        return !peerGuest&&!peerVm;
    }
    if (guestTarget_ != peerGuest || vmTarget_ != peerVm || (peerGuest && peerVm)) {
        lastAttachError_ = "External backend target scope mismatch; select matching host, guest or vm scope.";
        return false;
    }
    if(vmTarget_) {
        std::vector<uint8_t> bytes;GetTargetInfoResponse info{};
        if(!backendInfo_.Supports(IpcCommand::GetTargetInfo)||
           !ipcTransport_->SendAndReceive(IpcCommand::GetTargetInfo,nullptr,0,bytes)||bytes.size()!=sizeof(info)) {
            lastAttachError_="VM backend did not provide complete scope metadata.";return false;
        }
        std::memcpy(&info,bytes.data(),sizeof(info));
        if(info.status!=IpcStatus::Ok||info.scope!=IpcTargetScope::VirtualMachine||info.pid||info.addressBits) {
            lastAttachError_="VM metadata must declare VM scope, no PID and no process address width.";return false;
        }
        targetAddressBits_=0;disassembler_=CreateDisassembler(true); // Pure computation default, not CPU metadata.
        externalAttachPending_=false;return true; // No host target handle or process monitor.
    }
    if (guestTarget_ || IsRemoteTarget()) {
        std::vector<uint8_t> bytes;
        GetTargetInfoResponse info{};
        if (!backendInfo_.Supports(IpcCommand::GetTargetInfo) ||
            !ipcTransport_->SendAndReceive(IpcCommand::GetTargetInfo, nullptr, 0, bytes) ||
            bytes.size() != sizeof(info)) {
            lastAttachError_ = "Backend did not provide complete target metadata.";
            return false;
        }
        memcpy(&info, bytes.data(), sizeof(info));
        if (info.status != IpcStatus::Ok || info.scope != (guestTarget_ ? IpcTargetScope::Guest : IpcTargetScope::Host) ||
            info.pid != targetPid_ || (info.addressBits != 32 && info.addressBits != 64)) {
            lastAttachError_ = "Backend target identity or address width validation failed.";
            return false;
        }
        targetAddressBits_ = info.addressBits;
        disassembler_ = CreateDisassembler(info.addressBits == 64);
        externalAttachPending_ = false;
        return true;
    }
    externalAttachPending_ = false;
    FinishAttach(targetPid_);
    return true;
}

DebugSession::LaunchResult DebugSession::Launch(const LaunchOptions& opts) {
	LaunchResult result;
    if (opts.agent && opts.agent->remote) {
        result.ok = ConnectRemoteWork(0, *opts.agent, &opts);
        result.pid = result.ok ? targetPid_ : 0;
        result.error = result.ok ? std::string() : lastAttachError_;
        return result;
    }
    // Reject before local file lookup, process creation, or session mutation.
    if(opts.agent&&opts.agent->vmTarget){result.error="VM sessions do not create host processes.";return result;}
    if (opts.agent && opts.agent->guestTarget) {
        result.error = "Guest process launch is not supported by this frontend yet. Start the program in the guest and use veh_attach with target_scope=guest.";
        return result;
    }
    guestTarget_ = false;
    externalAttachPending_ = false;
	backendInfo_ = {};
	UseTransport({});

	if (opts.program.empty()) {
		result.error = "program is required";
		return result;
	}

	{
		std::error_code ec;
		if (!std::filesystem::exists(opts.program, ec)) {
			result.error = "File not found: " + opts.program;
			return result;
		}
	}

	// An external backend serves the process from outside: create it suspended, nothing injected.
	std::string dllPath = opts.agent ? std::string() : GetDllPathForExe(opts.program);
	if (!opts.agent && dllPath.empty()) {
		result.error = "VEH DLL not found";
		return result;
	}

	// Build command line args string
	std::string argsStr;
	for (auto& a : opts.args) {
		if (!argsStr.empty()) argsStr += " ";
		if (a.find_first_of(" \t\"") != std::string::npos) {
			std::string quoted = "\"";
			int numBackslashes = 0;
			for (char c : a) {
				if (c == '\\') {
					numBackslashes++;
				} else if (c == '"') {
					for (int j = 0; j < numBackslashes; j++) quoted += "\\\\";
					quoted += "\\\"";
					numBackslashes = 0;
				} else {
					for (int j = 0; j < numBackslashes; j++) quoted += "\\";
					quoted += c;
					numBackslashes = 0;
				}
			}
			for (int j = 0; j < numBackslashes; j++) quoted += "\\\\";
			quoted += "\"";
			argsStr += quoted;
		} else {
			argsStr += a;
		}
	}

	InjectionMethod injMethod = ParseInjectionMethod(opts.injectionMethod);
	auto lr = Injector::LaunchAndInject(opts.program, argsStr, opts.cwd, dllPath, injMethod, opts.runAsInvoker, opts.env);
	if (lr.pid == 0) {
		result.error = "Launch failed: " + opts.program;
		if (!lr.error.empty()) result.error += " - " + lr.error;
		return result;
	}

	launchedMainThreadId_ = lr.mainThreadId;
	mainThreadResumed_ = false;
    targetAddressBits_ = Injector::IsExe32Bit(opts.program) ? 32 : 64;

	if (opts.agent) {
		// The agent serves a suspended process (no loader run yet); the main
		// thread stays suspended until resumed, as with the DLL.
		if (!ConnectExternalAgent(lr.pid, *opts.agent)) {
			if (HANDLE p = OpenProcess(PROCESS_TERMINATE, FALSE, lr.pid)) {
				TerminateProcess(p, 1);
				CloseHandle(p);
			}
			launchedMainThreadId_ = 0;
			result.error = lastAttachError_.empty() ? "External backend did not come up" : lastAttachError_;
			return result;
		}
		FinishAttach(lr.pid);
		// Ours: ended with the session (FinishAttach opened it for monitoring only).
		if (HANDLE own = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE | PROCESS_VM_READ,
				FALSE, lr.pid)) {
			if (targetProcess_) CloseHandle(targetProcess_);
			targetProcess_ = own;
		}
		launchedByUs_ = true;
		result.ok = true;
		result.pid = lr.pid;
		return result;
	}

	// VM_READ: 조건부 BP 값 평가용(위 Attach 주석 참조). 우리가 만든 자식이라 항상 성공.
	targetProcess_ = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, lr.pid);
	if (!targetProcess_) {
		LOG_WARN("OpenProcess(TERMINATE) failed for pid=%u", lr.pid);
	}
	launchedByUs_ = true;

	if (!ipcTransport_->Connect(lr.pid, 3500)) {
		if (targetProcess_) {
			TerminateProcess(targetProcess_, 1);
			CloseHandle(targetProcess_);
			targetProcess_ = nullptr;
		}
		launchedByUs_ = false;
		launchedMainThreadId_ = 0;
		result.error = "Pipe connection failed after launch";
		return result;
	}

	// 주: Ready 대기는 reader 시작 후라야 하므로 McpServer가 SetEventCallback 뒤에 수행.
	targetPid_ = lr.pid;
	attached_ = true;

	// Set disassembler bitness
	{
		bool is64 = targetAddressBits_ == 64;
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	// NOTE: stopOnEntry=false 의 메인스레드 재개는 여기서 하지 않는다.
	// VEH 설치 완료(Ready) 이전에 재개하면 타겟이 핸들러 없이 조기 실행되는 레이스가 생긴다.
	// 호출자(McpServer::ToolLaunch)가 WaitForReady 이후 ResumeMainThread()를 호출한다.

	result.ok = true;
	result.pid = lr.pid;
	return result;
}

bool DebugSession::Detach() {
	lastDetachBackendConfirmed_ = false;
	if (!attached_) return false;

	auto* remote = dynamic_cast<TcpIpcTransport*>(ipcTransport_.get());
	const bool wasConnected = ipcTransport_->IsConnected();
	bool detachConfirmed = true;
	if (remote) {
		// A remote work ends when the resident closes it, acknowledged or not.
		attached_ = false;
		ResumeMainThread();
		StopProcessMonitor();
		ipcTransport_->StopHeartbeat();
		ipcTransport_->StopEventListener();
		try {
			const bool sent = ipcTransport_->SendCommand(IpcCommand::Detach);
			detachConfirmed = !wasConnected || (sent && remote->WaitForWorkClose(5000));
		} catch (...) { detachConfirmed = false; }
        // Resident work closure is not an acknowledgement of backend cleanup.
	} else {
        auto currentAgent = externalAgents_.find(targetPid_);
        if (currentAgent != externalAgents_.end() && currentAgent->second.pipe != transportPipe_)
            currentAgent = externalAgents_.end(); // an old external agent is not the current VEH DLL
        const auto backendGone = [&] {
            if (!ipcTransport_->IsConnected()) return true;
            return currentAgent != externalAgents_.end() && currentAgent->second.process &&
                WaitForSingleObject(currentAgent->second.process.get(), 0) == WAIT_OBJECT_0;
        };
        bool acknowledged = false;
        if (!backendGone()) {
            std::vector<uint8_t> reply;
            const bool received = backendInfo_.Supports(IpcCommand::Detach) &&
                ipcTransport_->SendAndReceive(IpcCommand::Detach, nullptr, 0, reply, 5000);
            IpcStatus status{};
            if (received && reply.size() == sizeof(status)) {
                std::memcpy(&status, reply.data(), sizeof(status));
                acknowledged = status == IpcStatus::Ok;
            }
            // A live connected peer's rejection/lost reply must retain the
            // session. Death/disconnection during the exchange permits recovery.
            if (!acknowledged && !backendGone()) {
                lastAttachError_ = received && reply.size() == sizeof(status) ?
                    "Backend refused detach (status " + std::to_string(static_cast<uint32_t>(status)) + "); session retained" :
                    "Backend detach failed or its reply is unavailable; session retained";
                return false;
            }
        }
        lastDetachBackendConfirmed_ = acknowledged;
        if (!acknowledged && currentAgent != externalAgents_.end())
            externalAgents_.erase(currentAgent); // retire only this exact stale pipe/agent record
        ResumeMainThread();
        attached_ = false;
        StopProcessMonitor();
        ipcTransport_->StopHeartbeat();
        ipcTransport_->StopEventListener();
	}
	ipcTransport_->Disconnect();

	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		swBreakpoints_.clear();
		hwBreakpoints_.clear();
	}
	targetPid_ = 0;
	launchedMainThreadId_ = 0;
	mainThreadResumed_ = false;

	if (targetProcess_) {
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
	}
	launchedByUs_ = false;
	guestTarget_ = false;vmTarget_ = false;
	externalAttachPending_ = false;
	targetAddressBits_ = 0;
	if (!detachConfirmed) lastAttachError_ = "Remote detach completion was not confirmed; reconnect after the resident closes the old work";
	return detachConfirmed;
}

bool DebugSession::Terminate(uint32_t exitCode) {
	if (!attached_ || (!launchedByUs_ && !backendInfo_.Supports(IpcCommand::Terminate))) return false;

	// 1) 인-프로세스 종료 요청. 타겟 DLL 이 TerminateProcess(GetCurrentProcess()) 를 호출하므로
	//    외부 OpenProcess(TERMINATE) 를 막는 자기보호 타겟도 확실히 죽는다.
	//    프로세스가 곧 사라지므로 응답을 기다리지 않는 fire-and-forget.
	TerminateRequest req{ exitCode };
	try { ipcTransport_->SendCommand(IpcCommand::Terminate, &req, sizeof(req)); } catch (...) {}

	// 2) 우리가 띄운 프로세스면 TERMINATE 핸들을 이미 쥐고 있으니 백업으로 직접 종료(1 실패 대비).
	if (launchedByUs_ && targetProcess_) {
		TerminateProcess(targetProcess_, exitCode);
	}

	// 3) 세션 정리. Detach 명령은 보내지 않는다 -- 타겟이 사라지는 중이라 파이프도 곧 끊긴다.
	attached_ = false;
	StopProcessMonitor();
	ipcTransport_->StopHeartbeat();
	ipcTransport_->StopEventListener();
	ipcTransport_->Disconnect();
	{
		std::lock_guard<std::mutex> lock(bpMutex_);
		swBreakpoints_.clear();
		hwBreakpoints_.clear();
	}
	targetPid_ = 0;
	launchedMainThreadId_ = 0;
	mainThreadResumed_ = false;
	if (targetProcess_) {
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
	}
	launchedByUs_ = false;
	return true;
}

bool DebugSession::IsTargetAlive() {
	if (guestTarget_ || vmTarget_ || IsRemoteTarget()) {
        std::vector<uint8_t> bytes;
        GetTargetInfoResponse info{};
        if (!attached_ || externalAttachPending_ || !ipcTransport_->SendAndReceive(
                IpcCommand::GetTargetInfo, nullptr, 0, bytes) || bytes.size() != sizeof(info)) return false;
        memcpy(&info, bytes.data(), sizeof(info));
        return info.status == IpcStatus::Ok && info.scope == (vmTarget_ ? IpcTargetScope::VirtualMachine : guestTarget_ ? IpcTargetScope::Guest : IpcTargetScope::Host) &&
            info.pid == targetPid_ && info.addressBits == targetAddressBits_;
    }
	if (!targetProcess_) return false;
	DWORD exitCode = 0;
	if (!GetExitCodeProcess(targetProcess_, &exitCode)) return false;
	return exitCode == STILL_ACTIVE;
}

// --- Breakpoints ---

BpResult DebugSession::SetBreakpoint(uint64_t address) {
	BpResult result;
	SetBreakpointRequest req{};
	req.address = address;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SetBreakpoint, &req, sizeof(req), respData))
		return result;

    if (respData.size() == sizeof(IpcStatus) || respData.size() == sizeof(SetBreakpointResponse)) {
        IpcStatus status{}; std::memcpy(&status, respData.data(), sizeof(status));
        result.full = status == IpcStatus::LimitReached;
    }
	if (respData.size() == sizeof(SetBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok && resp->id != 0) {
			result.ok = true;
			result.id = resp->id;
		}
		result.full = resp->status == IpcStatus::LimitReached;
	}
	return result;
}

bool DebugSession::SetModuleLoadStop(const std::string& name, int action) {
	SetModuleLoadStopRequest req{};
	req.action = static_cast<uint8_t>(action);
	strncpy_s(req.name, sizeof(req.name), name.c_str(), _TRUNCATE);

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SetModuleLoadStop, &req, sizeof(req), respData))
		return false;

	if (respData.size() >= sizeof(SetModuleLoadStopResponse)) {
		auto* resp = reinterpret_cast<const SetModuleLoadStopResponse*>(respData.data());
		return resp->status == IpcStatus::Ok;
	}
	return false;
}

std::optional<IpcStatus> DebugSession::RemoveBreakpointStatus(uint32_t id, bool hardware,
    std::string* error) {
    if (error) error->clear();
    const auto command = hardware ? IpcCommand::RemoveHwBreakpoint : IpcCommand::RemoveBreakpoint;
    const std::string operation = hardware ? "RemoveHwBreakpoint" : "RemoveBreakpoint";
    const auto fail = [&](const std::string& reason) {
        if (error) *error = operation + ": " + reason;
    };
    if (!attached_) { fail("target is not attached; removal was not confirmed"); return std::nullopt; }
    if (!backendInfo_.Supports(command)) {
        fail(BackendStatusText(IpcStatus::Unsupported)); return IpcStatus::Unsupported;
    }
    if (!id) { fail(BackendStatusText(IpcStatus::InvalidArgs)); return IpcStatus::InvalidArgs; }
    const RemoveBreakpointRequest softwareRequest{id};
    const RemoveHwBreakpointRequest hardwareRequest{id};
    const void* request = hardware ? static_cast<const void*>(&hardwareRequest) :
        static_cast<const void*>(&softwareRequest);
    const auto requestSize = hardware ? sizeof(hardwareRequest) : sizeof(softwareRequest);
    std::vector<uint8_t> response;
    PipeExchangeDiagnostics diagnostics{};
    if (!ipcTransport_->SendAndReceive(command, request, static_cast<uint32_t>(requestSize),
        response, 3000, &diagnostics)) {
        fail(DescribeIpcFailure(&diagnostics) + "; removal was not confirmed"); return std::nullopt;
    }
    if (response.size() != sizeof(IpcStatus)) {
        fail("malformed or incomplete backend response; removal was not confirmed"); return std::nullopt;
    }
    IpcStatus status{};
    std::memcpy(&status, response.data(), sizeof(status));
    if (status != IpcStatus::Ok) fail(BackendStatusText(status));
    return status;
}

bool DebugSession::RemoveBreakpoint(uint32_t id) {
    const auto status = RemoveBreakpointStatus(id);
    return status && *status == IpcStatus::Ok;
}

bool DebugSession::RemoveBreakpointByAddress(uint64_t address) {
	std::lock_guard<std::mutex> lock(bpMutex_);
	for (auto& bp : swBreakpoints_) {
		if (bp.address == address) {
			return RemoveBreakpoint(bp.id);
		}
	}
	return false;
}

HwBpResult DebugSession::SetHwBreakpoint(uint64_t address, uint8_t type, uint8_t size) {
	HwBpResult result;
	SetHwBreakpointRequest req{};
	req.address = address;
	req.type = type;
	req.size = size;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SetHwBreakpoint, &req, sizeof(req), respData))
		return result;

	if (respData.size() >= sizeof(SetHwBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetHwBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			result.ok = true;
			result.id = resp->id;
			result.slot = resp->slot;
		}
		result.full = resp->status == IpcStatus::LimitReached;
	}
	return result;
}

bool DebugSession::RemoveHwBreakpoint(uint32_t id) {
    const auto status = RemoveBreakpointStatus(id, true);
    return status && *status == IpcStatus::Ok;
}

// --- Execution control ---

bool DebugSession::Continue(uint32_t threadId, bool passException) {
	ResumeMainThread(threadId);
	ContinueRequest req{};
	req.threadId = threadId;
	req.passException = passException ? 1 : 0;
	req.wantDetails = 0;
	// Keep this path fire-and-forget: exception auto-continue can run on the pipe
	// reader thread, which cannot synchronously wait for a response it must read.
	return ipcTransport_->SendCommand(IpcCommand::Continue, &req, sizeof(req));
}

ContinueResult DebugSession::ContinueWithDetails(uint32_t threadId, bool passException) {
	ContinueResult result;
	uint32_t resumedLaunchThread = ResumeMainThread(threadId);
	uint64_t seqBefore;
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		seqBefore = stopSeq_;
	}
	ContinueRequest req{};
	req.threadId = threadId;
	req.passException = passException ? 1 : 0;
	req.wantDetails = 1;
	std::vector<uint8_t> response;
	if (!ipcTransport_->SendAndReceive(IpcCommand::Continue, &req, sizeof(req), response)) {
		return result;
	}
	if (response.size() < sizeof(IpcStatus)) return result;
	IpcStatus status{};
	memcpy(&status, response.data(), sizeof(status));
	result.ok = status == IpcStatus::Ok;
	if (!result.ok) return result;

	if (response.size() >= sizeof(ContinueResponse)) {
		ContinueResponse header{};
		memcpy(&header, response.data(), sizeof(header));
		const uint64_t totalCount = static_cast<uint64_t>(header.resumedCount) + header.stillStoppedCount;
		if (totalCount <= (response.size() - sizeof(header)) / sizeof(uint32_t)) {
			const uint8_t* cursor = response.data() + sizeof(header);
			result.resumedThreadIds.resize(header.resumedCount);
			result.stillStoppedThreadIds.resize(header.stillStoppedCount);
			if (header.resumedCount != 0) {
				memcpy(result.resumedThreadIds.data(), cursor,
					header.resumedCount * sizeof(uint32_t));
				cursor += header.resumedCount * sizeof(uint32_t);
			}
			if (header.stillStoppedCount != 0) {
				memcpy(result.stillStoppedThreadIds.data(), cursor,
					header.stillStoppedCount * sizeof(uint32_t));
			}
		}
	}
	// A stop recorded before this continue, of a thread it resumed, is over: a
	// later wait (or a cached-stop check) must not report that thread stopped.
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		const bool listed = !result.resumedThreadIds.empty() || !result.stillStoppedThreadIds.empty();
		const bool resumed = listed
			? std::find(result.resumedThreadIds.begin(), result.resumedThreadIds.end(), lastStop_.threadId) !=
				result.resumedThreadIds.end()
			: threadId == 0 || lastStop_.threadId == threadId; // a peer without details
		if (stopOccurred_ && stopSeq_ <= seqBefore && resumed)
			stopOccurred_ = false;
	}

	if (resumedLaunchThread != 0) result.resumedThreadIds.push_back(resumedLaunchThread);
	if (launchedMainThreadId_ != 0 && !mainThreadResumed_) {
		result.stillStoppedThreadIds.push_back(launchedMainThreadId_);
	}
	auto sortUnique = [](std::vector<uint32_t>& ids) {
		std::sort(ids.begin(), ids.end());
		ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
	};
	sortUnique(result.resumedThreadIds);
	sortUnique(result.stillStoppedThreadIds);
	return result;
}

IpcStatus DebugSession::StepIn(uint32_t threadId) {
	StepRequest req{};
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::StepInto, &req, sizeof(req), respData))
		return IpcStatus::Error;
	return respData.size() == sizeof(IpcStatus) ? *reinterpret_cast<const IpcStatus*>(respData.data()) : IpcStatus::Error;
}

IpcStatus DebugSession::StepOver(uint32_t threadId) {
	StepRequest req{};
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::StepOver, &req, sizeof(req), respData))
		return IpcStatus::Error;
	return respData.size() == sizeof(IpcStatus) ? *reinterpret_cast<const IpcStatus*>(respData.data()) : IpcStatus::Error;
}

IpcStatus DebugSession::StepOut(uint32_t threadId) {
	StepRequest req{};
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::StepOut, &req, sizeof(req), respData))
		return IpcStatus::Error;
	return respData.size() == sizeof(IpcStatus) ? *reinterpret_cast<const IpcStatus*>(respData.data()) : IpcStatus::Error;
}

bool DebugSession::Pause(uint32_t threadId) {
	PauseRequest req{};
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::Pause, &req, sizeof(req), respData) ||
        respData.size() < sizeof(IpcStatus)) return false;
    IpcStatus status{};
    memcpy(&status, respData.data(), sizeof(status));
    return status == IpcStatus::Ok;
}

uint32_t DebugSession::ResumeMainThread(uint32_t requestedThreadId) {
    if (IsRemoteTarget()) return 0;
	if (mainThreadResumed_ || launchedMainThreadId_ == 0) return 0;
	if (requestedThreadId != 0 && requestedThreadId != launchedMainThreadId_) return 0;

	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, launchedMainThreadId_);
	if (hThread) {
		DWORD prevCount = ResumeThread(hThread);
		DWORD resumeError = prevCount == static_cast<DWORD>(-1) ? GetLastError() : ERROR_SUCCESS;
		CloseHandle(hThread);
		if (prevCount == static_cast<DWORD>(-1)) {
			LOG_ERROR("DebugSession: Failed to resume main thread %u: %u",
				launchedMainThreadId_, resumeError);
			return 0;
		}
		mainThreadResumed_ = true;
		LOG_INFO("DebugSession: Resumed main thread %u (prev suspend count: %u)",
			launchedMainThreadId_, prevCount);
		return launchedMainThreadId_;
	} else {
		LOG_ERROR("DebugSession: Failed to open main thread %u for resume: %u",
			launchedMainThreadId_, GetLastError());
	}
	return 0;
}

// --- Stop event synchronization ---

StopEvent DebugSession::WaitForStop(int timeoutSec, uint64_t expectedGeneration) {
	StopEvent ev;
	std::unique_lock<std::mutex> lock(stopMutex_);
	if (!stopCv_.wait_for(lock, std::chrono::seconds(timeoutSec),
			[this, expectedGeneration]{
				return stopOccurred_ || !attached_ ||
					(expectedGeneration != 0 && sessionGeneration_.load() != expectedGeneration);
			})) {
		ev.timeout = true;
		return ev;
	}
	if (expectedGeneration != 0 && sessionGeneration_.load() != expectedGeneration) {
		ev.sessionChanged = true;
		return ev;
	}
	stopOccurred_ = false;
	if (!attached_ && lastStop_.reason != "exit") {
		ev.stopped = true;
		ev.reason = "exit";
		return ev;
	}
	return lastStop_;
}

std::optional<StopEvent> DebugSession::ConsumeCachedStop() {
	std::lock_guard<std::mutex> lock(stopMutex_);
	if (stopOccurred_) {
		stopOccurred_ = false;
		return lastStop_;
	}
	return std::nullopt;
}

void DebugSession::ResetStopState() {
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		sessionGeneration_.fetch_add(1);
		stopOccurred_ = false;
		lastStop_ = StopEvent{};
	}
	// Wake waits that belong to the previous process. They detect the generation
	// change instead of consuming a stop produced by the new process.
	stopCv_.notify_all();
}

bool DebugSession::IsThreadOwnedByTarget(uint32_t threadId) const {
	if (threadId == 0 || targetPid_ == 0) return false;
    // The authenticated guest backend owns CID validation for its events. Calling
    // host Toolhelp here would validate an unrelated namespace; IPC reentry from
    // the event reader would deadlock.
    if (IsRemoteTarget()) return attached_ && !externalAttachPending_ && backendInfo_.reported;
    if (guestTarget_) return !externalAttachPending_ && backendInfo_.reported &&
        (backendInfo_.flags & kCapGuestTarget) != 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		// A transient snapshot failure should not make a valid stop disappear.
		LOG_WARN("Thread ownership validation unavailable for TID %u: %lu",
			threadId, GetLastError());
		return true;
	}

	THREADENTRY32 te = {};
	te.dwSize = sizeof(te);
	bool owned = false;
	if (Thread32First(snapshot, &te)) {
		do {
			if (te.th32ThreadID == threadId) {
				owned = te.th32OwnerProcessID == targetPid_;
				break;
			}
		} while (Thread32Next(snapshot, &te));
	}
	CloseHandle(snapshot);
	return owned;
}

void DebugSession::SignalStop(const std::string& reason, uint64_t addr, uint32_t threadId,
                              uint32_t bpId, const std::string& bpType) {
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		stopOccurred_ = true;
		++stopSeq_;
		lastStop_.stopped = true;
		lastStop_.reason = reason;
		lastStop_.address = addr;
		lastStop_.threadId = threadId;
		lastStop_.breakpointId = bpId;
		lastStop_.bpType = bpType;
		lastStop_.sessionGeneration = sessionGeneration_.load();
	}
	stopCv_.notify_all();
}

// --- State queries ---

bool DebugSession::FreezeThread(FreezeOp op, uint32_t threadId, std::vector<uint32_t>& frozen) {
	FreezeThreadRequest req{};
	req.threadId = threadId;
	req.op = op;
	std::vector<uint8_t> respData;
	frozen.clear();
	if (!ipcTransport_->SendAndReceive(IpcCommand::FreezeThread, &req, sizeof(req), respData))
		return false;
	if (respData.size() < sizeof(FreezeThreadResponse)) return false;
	auto* resp = reinterpret_cast<const FreezeThreadResponse*>(respData.data());
	size_t count = (std::min)(static_cast<size_t>(resp->count),
		(respData.size() - sizeof(FreezeThreadResponse)) / sizeof(uint32_t));
	auto* ids = reinterpret_cast<const uint32_t*>(respData.data() + sizeof(FreezeThreadResponse));
	frozen.assign(ids, ids + count);
	return resp->status == IpcStatus::Ok;
}

std::string DebugSession::DescribeIpcFailure(const PipeExchangeDiagnostics* diagnostics) const {
	if (GetTargetProcess() && WaitForSingleObject(GetTargetProcess(), 0) == WAIT_OBJECT_0) {
		DWORD code = 0;
		if (GetExitCodeProcess(GetTargetProcess(), &code))
			return "Target process exited (code " + std::to_string(code) + ")";
		return "Target process exited (exit code unavailable)";
	}
	if (!ipcTransport_->IsConnected())
		return ipcTransport_->IsRemote() ? "Remote backend connection closed; target state is unknown"
			: "Backend IPC connection closed; target state is unknown";
	if (diagnostics) {
		switch (diagnostics->failure) {
			case PipeExchangeFailure::WaitTimeout: return "Backend response timed out";
			case PipeExchangeFailure::SendFailed: return "Could not send request to backend";
			case PipeExchangeFailure::HeaderReadFailed: return "Could not read backend response header";
			case PipeExchangeFailure::PayloadReadFailed: return "Could not read complete backend response";
			case PipeExchangeFailure::PayloadTooLarge: return "Backend response exceeds IPC payload limit";
			case PipeExchangeFailure::NotRunning:
			case PipeExchangeFailure::ReaderAborted: return "Backend IPC reader stopped";
			default: break;
		}
	}
	return "Backend IPC exchange failed (no valid response)";
}

bool DebugSession::ReceiveBackendReply(IpcCommand command, const void* payload, uint32_t size,
	std::vector<uint8_t>& response, const char* operation, std::string& error, int timeoutMs) {
	error.clear();
	PipeExchangeDiagnostics diagnostics{};
	if (!ipcTransport_->SendAndReceive(command, payload, size, response, timeoutMs, &diagnostics)) {
		error = std::string(operation) + ": " + DescribeIpcFailure(&diagnostics);
		return false;
	}
	error = std::string(operation) + ": malformed or incomplete backend response";
	if (response.size() < sizeof(IpcStatus)) return false;
	IpcStatus status{};
	memcpy(&status, response.data(), sizeof(status));
	const char* reason = nullptr;
	switch (status) {
		case IpcStatus::Ok: return true; // caller validates the complete successful payload
		case IpcStatus::Error: reason = "backend execution error"; break;
		case IpcStatus::NotFound: reason = "requested object or state not found"; break;
		case IpcStatus::InvalidArgs: reason = "backend rejected arguments"; break;
		case IpcStatus::Unsupported: reason = "request unsupported by backend"; break;
		case IpcStatus::LimitReached: reason = "backend resource limit reached"; break;
		case IpcStatus::InvalidState: reason = "operation refused in the current target state"; break;
		default: break;
	}
	error = std::string(operation) + ": " + (reason ? std::string(reason) :
		"unknown backend status " + std::to_string(static_cast<uint32_t>(status)));
	return false;
}


std::vector<ThreadEntry> DebugSession::GetThreads(std::string* error) {
	std::vector<ThreadEntry> result;
	std::vector<uint8_t> respData;
	std::string detail;
	if (error) error->clear();
	if (!ReceiveBackendReply(IpcCommand::GetThreads, nullptr, 0, respData, "GetThreads", detail)) {
		if (error) *error = detail;
		return result;
	}

	// The whole list or nothing: the count must match the payload exactly
	// (no short or extra rows) and every name must end inside its field.
	GetThreadsResponse header{};
	if (respData.size() < sizeof(header)) { if (error) *error = detail; return result; }
	std::memcpy(&header, respData.data(), sizeof(header));
	const size_t payloadSize = respData.size() - sizeof(header);
	if (payloadSize % sizeof(ThreadInfo) != 0 || header.count != payloadSize / sizeof(ThreadInfo)) {
		if (error) *error = "GetThreads: incomplete or malformed list (count does not match the payload)";
		return result;
	}

	result.reserve(header.count);
	for (uint32_t i = 0; i < header.count; ++i) {
		ThreadInfo info{};
		std::memcpy(&info, respData.data() + sizeof(header) + static_cast<size_t>(i) * sizeof(info), sizeof(info));
		const auto* end = static_cast<const char*>(std::memchr(info.name, '\0', sizeof(info.name)));
		if (!end) {
			result.clear();
			if (error) *error = "GetThreads: malformed list (unterminated thread name)";
			return result;
		}
		result.push_back({info.id, std::string(info.name, static_cast<size_t>(end - info.name))});
	}
	return result;
}

std::vector<StackFrame> DebugSession::GetStackTrace(uint32_t threadId, uint32_t maxFrames, std::string* error) {
	std::vector<StackFrame> result;
	GetStackTraceRequest req{};
	req.threadId = threadId;
	req.startFrame = 0;
	req.maxFrames = maxFrames;

	std::vector<uint8_t> respData;
	std::string detail;
	if (error) error->clear();
	GetStackTraceResponse header{};
	if (!ReceiveBackendReply(IpcCommand::GetStackTrace, &req, sizeof(req), respData, "GetStackTrace", detail) ||
		!ValidateStackTraceReply(respData, maxFrames, header, detail)) {
		if (error) *error = detail;
		return result;
	}
	auto* infos = reinterpret_cast<const StackFrameInfo*>(respData.data() + sizeof(header));
	const uint32_t count = header.count;

	result.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		StackFrame f;
		f.address = infos[i].address;
		f.returnAddress = 0; // not in IPC struct
		f.frameBase = infos[i].frameBase;
		f.moduleBase = infos[i].moduleBase;
		f.moduleName = infos[i].moduleName;
		f.functionName = infos[i].functionName;
		f.sourceFile = infos[i].sourceFile;
		f.line = infos[i].line;
		result.push_back(std::move(f));
	}
	return result;
}

std::optional<RegisterSet> DebugSession::GetRegisters(uint32_t threadId) {
	GetRegistersRequest req{};
	req.threadId = threadId;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::GetRegisters, &req, sizeof(req), respData))
		return std::nullopt;

	if (respData.size() < sizeof(GetRegistersResponse)) return std::nullopt;
	auto* resp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return std::nullopt;

	return resp->regs;
}

bool DebugSession::SetRegister(uint32_t threadId, uint32_t regIndex, uint64_t value) {
	SetRegisterRequest req{};
	req.threadId = threadId;
	req.regIndex = regIndex;
	req.value = value;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SetRegister, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(SetRegisterResponse)) {
		auto* resp = reinterpret_cast<const SetRegisterResponse*>(respData.data());
		return resp->status == IpcStatus::Ok;
	}
	return false;
}

bool DebugSession::SetRegisters(uint32_t threadId, const RegisterSet& regs) {
	SetRegistersRequest req{};
	req.threadId = threadId;
	req.regs = regs;
	std::vector<uint8_t> response;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SetRegisters, &req, sizeof(req), response)) return false;
	if (response.size() < sizeof(SetRegistersResponse)) return false;
	return reinterpret_cast<const SetRegistersResponse*>(response.data())->status == IpcStatus::Ok;
}

std::optional<bool> DebugSession::QueryThreadStopped(uint32_t threadId, std::string* error) {
    if (error) error->clear();
    const auto fail = [&](const std::string& reason) {
        if (error) *error = "IsThreadStopped: " + reason;
    };
    if (!attached_) { fail("target is not attached"); return std::nullopt; }
    if (!backendInfo_.Supports(IpcCommand::IsThreadStopped)) {
        fail(BackendStatusText(IpcStatus::Unsupported)); return std::nullopt;
    }
    if (!threadId) { fail(BackendStatusText(IpcStatus::InvalidArgs)); return std::nullopt; }
    const IsThreadStoppedRequest request{threadId};
    std::vector<uint8_t> response;
    PipeExchangeDiagnostics diagnostics{};
    if (!ipcTransport_->SendAndReceive(IpcCommand::IsThreadStopped, &request, sizeof(request),
        response, 3000, &diagnostics)) {
        fail(DescribeIpcFailure(&diagnostics)); return std::nullopt;
    }
    if (response.size() < sizeof(IpcStatus)) {
        fail("malformed or incomplete backend response"); return std::nullopt;
    }
    IpcStatus status{};
    std::memcpy(&status, response.data(), sizeof(status));
    if (status != IpcStatus::Ok) { fail(BackendStatusText(status)); return std::nullopt; }
    if (response.size() != sizeof(IsThreadStoppedResponse)) {
        fail("malformed or incomplete backend response"); return std::nullopt;
    }
    IsThreadStoppedResponse result{};
    std::memcpy(&result, response.data(), sizeof(result));
    if (result.stopped > 1) {
        fail("invalid stopped-state value from backend"); return std::nullopt;
    }
    return result.stopped != 0;
}

bool DebugSession::IsThreadStopped(uint32_t threadId) {
    return QueryThreadStopped(threadId).value_or(false);
}

std::vector<ModuleEntry> DebugSession::GetModules(std::string* error) {
	std::vector<ModuleEntry> result;
	std::vector<uint8_t> respData;
	std::string detail;
	if (error) error->clear();
	// The capability is authoritative: an unadvertised command is refused,
	// never reported as an empty list.
    const bool extended = backendInfo_.reported && backendInfo_.Supports(IpcCommand::GetModulesEx);
    const auto command = extended ? IpcCommand::GetModulesEx : IpcCommand::GetModules;
	if (!backendInfo_.Supports(command)) {
		if (error) *error = "GetModules: request unsupported by backend (not advertised)";
		return result;
	}
	if (!ReceiveBackendReply(command, nullptr, 0, respData, "GetModules", detail)) {
		if (error) *error = detail;
		return result;
	}

	// The whole list or nothing: the count must match the payload exactly and
	// every name and path must end inside its field.
	GetModulesResponse header{};
	if (respData.size() < sizeof(header)) { if (error) *error = detail; return result; }
	std::memcpy(&header, respData.data(), sizeof(header));
	const size_t payloadSize = respData.size() - sizeof(header);
    const size_t stride = extended ? sizeof(ModuleInfoEx) : sizeof(ModuleInfo);
	if (payloadSize % stride != 0 || header.count != payloadSize / stride) {
		if (error) *error = "GetModules: incomplete or malformed list (count does not match the payload)";
		return result;
	}

	result.reserve(header.count);
	for (uint32_t i = 0; i < header.count; ++i) {
		ModuleInfo info{};
        const auto* row = respData.data() + sizeof(header) + static_cast<size_t>(i) * stride;
		std::memcpy(&info, row, sizeof(info));
        uint32_t bits = 0;
        if (extended) std::memcpy(&bits, row + sizeof(info), sizeof(bits));
        if (bits != 0 && bits != 32 && bits != 64) {
            result.clear(); if (error) *error = "GetModules: invalid image addressBits"; return result;
        }
		const auto* nameEnd = static_cast<const char*>(std::memchr(info.name, '\0', sizeof(info.name)));
		const auto* pathEnd = static_cast<const char*>(std::memchr(info.path, '\0', sizeof(info.path)));
		if (!nameEnd || !pathEnd) {
			result.clear();
			if (error) *error = "GetModules: malformed list (unterminated module name or path)";
			return result;
		}
		result.push_back({std::string(info.name, static_cast<size_t>(nameEnd - info.name)),
			std::string(info.path, static_cast<size_t>(pathEnd - info.path)),
			info.baseAddress, info.size, bits});
	}
	return result;
}

std::vector<SymbolizeEntry> DebugSession::Symbolize(const std::vector<uint64_t>& addresses) {
	std::vector<SymbolizeEntry> result;
	if (addresses.empty() || addresses.size() > kSymbolizeMaxAddresses) return result;
	std::vector<uint8_t> payload(sizeof(SymbolizeRequest) + addresses.size() * sizeof(uint64_t));
	SymbolizeRequest req{};
	req.count = static_cast<uint32_t>(addresses.size());
	memcpy(payload.data(), &req, sizeof(req));
	memcpy(payload.data() + sizeof(req), addresses.data(), addresses.size() * sizeof(uint64_t));

	std::vector<uint8_t> respData;
	// The first lookup in a module may load its PDB.
	if (!ipcTransport_->SendAndReceive(IpcCommand::Symbolize, payload.data(),
			static_cast<uint32_t>(payload.size()), respData, 30000))
		return result;
	if (respData.size() < sizeof(SymbolizeResponse)) return result;
	auto* resp = reinterpret_cast<const SymbolizeResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;
	size_t count = (std::min)(static_cast<size_t>(resp->count),
		(respData.size() - sizeof(SymbolizeResponse)) / sizeof(SymbolizeEntry));
	auto* entries = reinterpret_cast<const SymbolizeEntry*>(respData.data() + sizeof(SymbolizeResponse));
	result.assign(entries, entries + count);
	return result;
}

bool DebugSession::DisplayType(const DisplayTypeRequest& request, DisplayTypeResponse& header,
	std::vector<DisplayTypeMember>& members) {
	members.clear();
	std::vector<uint8_t> respData;
	// The first lookup in a module may load its PDB.
	if (!ipcTransport_->SendAndReceive(IpcCommand::DisplayType, &request, sizeof(request), respData, 30000))
		return false;
	if (respData.size() < sizeof(DisplayTypeResponse)) return false;
	memcpy(&header, respData.data(), sizeof(header));
	if (header.status != IpcStatus::Ok) return false;
	size_t count = (std::min)(static_cast<size_t>(header.count),
		(respData.size() - sizeof(DisplayTypeResponse)) / sizeof(DisplayTypeMember));
	auto* entries = reinterpret_cast<const DisplayTypeMember*>(respData.data() + sizeof(DisplayTypeResponse));
	members.assign(entries, entries + count);
	return true;
}

std::vector<LocalVarEntry> DebugSession::EnumLocals(uint32_t threadId, uint64_t instrAddr, uint64_t frameBase) {
	std::vector<LocalVarEntry> result;

	// If not provided, get from top frame
	if (instrAddr == 0 || frameBase == 0) {
		auto frames = GetStackTrace(threadId, 1);
		if (!frames.empty()) {
			if (instrAddr == 0) instrAddr = frames[0].address;
			if (frameBase == 0) frameBase = frames[0].frameBase;
		}
		if (instrAddr == 0) return result;
	}

	EnumLocalsRequest req{};
	req.threadId = threadId;
	req.instructionAddress = instrAddr;
	req.frameBase = frameBase;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::EnumLocals, &req, sizeof(req), respData))
		return result;

	if (respData.size() < sizeof(EnumLocalsResponse)) return result;
	auto* resp = reinterpret_cast<const EnumLocalsResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;

	auto* locals = reinterpret_cast<const LocalVariableInfo*>(respData.data() + sizeof(EnumLocalsResponse));
	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(EnumLocalsResponse))
		? (respData.size() - sizeof(EnumLocalsResponse)) / sizeof(LocalVariableInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	result.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		LocalVarEntry entry;
		// Safe null-terminated copy
		char safeName[sizeof(LocalVariableInfo::name) + 1] = {};
		memcpy(safeName, locals[i].name, sizeof(locals[i].name));
		char safeType[sizeof(LocalVariableInfo::typeName) + 1] = {};
		memcpy(safeType, locals[i].typeName, sizeof(locals[i].typeName));

		entry.name = safeName;
		entry.typeName = safeType;
		entry.address = locals[i].address;
		entry.size = locals[i].size;
		entry.flags = locals[i].flags;
		if (locals[i].valueSize > 0 && locals[i].valueSize <= sizeof(locals[i].value)) {
			entry.value.assign(locals[i].value, locals[i].value + locals[i].valueSize);
		}
		result.push_back(std::move(entry));
	}
	return result;
}

// --- Memory ---

std::vector<uint8_t> DebugSession::ReadMemory(uint64_t address, uint32_t size) {
	ReadMemoryRequest req{};
	req.address = address;
	req.size = size;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ReadMemory, &req, sizeof(req), respData))
		return {};

	if (respData.size() < sizeof(IpcStatus)) return {};
	auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
	if (status != IpcStatus::Ok) return {};

	const uint8_t* data = respData.data() + sizeof(IpcStatus);
	size_t dataLen = respData.size() - sizeof(IpcStatus);
	return std::vector<uint8_t>(data, data + dataLen);
}

DebugSession::MemoryMapResult DebugSession::QueryMemoryMap(uint64_t start, uint64_t end,
	uint32_t maxRegions, bool includeFree) {
	QueryMemoryMapRequest req{};
	req.startAddress = start;
	req.endAddress = end;
	req.maxRegions = maxRegions;
	req.includeFree = includeFree ? 1 : 0;

	MemoryMapResult result;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::QueryMemoryMap, &req, sizeof(req), respData, 10000))
		return result;
	if (respData.size() < sizeof(QueryMemoryMapResponse)) return result;
	auto* resp = reinterpret_cast<const QueryMemoryMapResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;
	size_t count = (std::min)(static_cast<size_t>(resp->count),
		(respData.size() - sizeof(QueryMemoryMapResponse)) / sizeof(MemoryRegionEntry));
	auto* entries = reinterpret_cast<const MemoryRegionEntry*>(respData.data() + sizeof(QueryMemoryMapResponse));
	result.regions.assign(entries, entries + count);
	result.nextAddress = resp->truncated ? resp->nextAddress : 0;
	result.ok = true;
	return result;
}

DebugSession::MemorySearchResult DebugSession::SearchMemory(const SearchMemoryRequest& request,
	const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask) {
	MemorySearchResult result;
	if (pattern.empty() || pattern.size() != mask.size()) return result;
	std::vector<uint8_t> payload(sizeof(SearchMemoryRequest) + pattern.size() * 2);
	SearchMemoryRequest req = request;
	req.patternSize = static_cast<uint32_t>(pattern.size());
	memcpy(payload.data(), &req, sizeof(req));
	memcpy(payload.data() + sizeof(req), pattern.data(), pattern.size());
	memcpy(payload.data() + sizeof(req) + pattern.size(), mask.data(), mask.size());

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::SearchMemory, payload.data(),
			static_cast<uint32_t>(payload.size()), respData, 120000))
		return result;
	if (respData.size() < sizeof(SearchMemoryResponse)) return result;
	auto* resp = reinterpret_cast<const SearchMemoryResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;
	size_t count = (std::min)(static_cast<size_t>(resp->count),
		(respData.size() - sizeof(SearchMemoryResponse)) / sizeof(uint64_t));
	auto* hits = reinterpret_cast<const uint64_t*>(respData.data() + sizeof(SearchMemoryResponse));
	result.matches.assign(hits, hits + count);
	result.nextAddress = resp->truncated ? resp->nextAddress : 0;
	result.scannedBytes = resp->scannedBytes;
	result.regionsScanned = resp->regionsScanned;
	result.ok = true;
	return result;
}

DebugSession::ValueScanResult DebugSession::ValueScan(const ValueScanRequest& request) {
	ValueScanResult result;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ValueScan, &request, sizeof(request), respData, 120000))
		return result;
	if (respData.size() < sizeof(ValueScanResponse)) return result;
	const auto* resp = reinterpret_cast<const ValueScanResponse*>(respData.data());
	result.failure = resp->failure;
	result.mode = resp->mode;
	result.valueType = resp->valueType;
	result.candidates = resp->candidates;
	result.scannedBytes = resp->scannedBytes;
	const size_t count = (std::min)(static_cast<size_t>(resp->count),
		(respData.size() - sizeof(ValueScanResponse)) / sizeof(ValueScanEntry));
	const auto* entries = reinterpret_cast<const ValueScanEntry*>(respData.data() + sizeof(ValueScanResponse));
	result.entries.assign(entries, entries + count);
	result.ok = resp->status == IpcStatus::Ok;
	return result;
}

DebugSession::ValueScanResultV2 DebugSession::ValueScanV2(const ValueScanRequestV2& request) {
    ValueScanResultV2 result;
    if(!backendInfo_.reported || !(backendInfo_.flags&kCapValueScanV2)) {
        result.error="Backend does not support value scan protocol 2";return result;
    }
    std::vector<uint8_t> bytes;
    // Async admission/status/cancel are short exchanges, not scan-duration waits.
    const int timeout=(request.flags&kValueScanAsync) || request.scan.operation>=ValueScanOperation::Status ? 10000 : 120000;
    if(!ipcTransport_->SendAndReceive(IpcCommand::ValueScan,&request,sizeof(request),bytes,timeout)) {
        result.error="Value scan control response lost; operation outcome is unknown; do not retry start blindly";return result;
    }
    if(bytes.size()<sizeof(ValueScanResponseV2)) { result.error="Short value scan v2 response";return result; }
    memcpy(&result.header,bytes.data(),sizeof(result.header));
    const auto& h=result.header;
    if(h.version!=2 || h.headerSize!=sizeof(h) || h.scan.count>request.scan.maxResults ||
        bytes.size()!=sizeof(h)+size_t(h.scan.count)*sizeof(ValueScanEntry) ||
        h.state>ValueScanJobState::Failed || h.phase>ValueScanPhase::Finished ||
        h.storage>ValueScanStorage::File || h.scan.mode>ValueScanMode::Disk ||
        h.scan.valueType>ValueScanType::F64 || h.reserved || h.scan.reserved || h.undoAvailable>8 ||
        h.scan.failure>ValueScanFailure::StaleJob || h.scan.count>h.scan.candidates ||
        (h.scan.count&&(!h.generationId||!h.sessionId||!h.jobId||h.scan.valueType==ValueScanType::None)) ||
        (h.scan.status==IpcStatus::Ok&&
         ((h.state==ValueScanJobState::Completed&&h.scan.failure!=ValueScanFailure::None)||
          (h.state==ValueScanJobState::Failed&&h.scan.failure==ValueScanFailure::None))) ||
        (h.total && h.processed>h.total) ||
        ((h.state==ValueScanJobState::Running||h.state==ValueScanJobState::Cancelling) && (!h.jobId||!h.sessionId))) {
        result.error="Malformed value scan v2 receipt";return result;
    }
    if(request.jobId && h.scan.status==IpcStatus::Ok && h.jobId!=request.jobId) {
        result.error="Value scan job identity mismatch";return result;
    }
    const auto* entries=reinterpret_cast<const ValueScanEntry*>(bytes.data()+sizeof(h));
    result.entries.assign(entries,entries+h.scan.count);
    result.ok=h.scan.status==IpcStatus::Ok;
    return result;
}

bool DebugSession::WriteMemory(uint64_t address, const uint8_t* data, uint32_t size) {
	std::vector<uint8_t> payload(sizeof(WriteMemoryRequest) + size);
	auto* req = reinterpret_cast<WriteMemoryRequest*>(payload.data());
	req->address = address;
	req->size = size;
	memcpy(payload.data() + sizeof(WriteMemoryRequest), data, size);

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::WriteMemory, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData))
		return false;

	if (respData.size() == sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		return status == IpcStatus::Ok;
	}
	return false;
}

DebugSession::CodePatchResult DebugSession::PatchCode(uint64_t address, const std::vector<uint8_t>& code,
    uint32_t overwriteSize, bool nopFill, uint32_t addressBits) {
    CodePatchResult result;
    if (!backendInfo_.reported || !backendInfo_.Supports(IpcCommand::PatchCode)) {
        result.backendStatus = IpcStatus::Unsupported;
        result.error = "PatchCode: instruction-aware patching unsupported by backend; update the backend or explicitly use raw_write";
        return result;
    }
    PatchCodeRequest request{1, nopFill ? kPatchCodeNopFill : 0, address,
        static_cast<uint32_t>(code.size()), overwriteSize, addressBits};
    std::vector<uint8_t> payload(sizeof(request) + code.size()), reply;
    std::memcpy(payload.data(), &request, sizeof(request));
    std::memcpy(payload.data() + sizeof(request), code.data(), code.size());
    PipeExchangeDiagnostics diagnostics{};
    if (!ipcTransport_->SendAndReceive(IpcCommand::PatchCode, payload.data(),
        static_cast<uint32_t>(payload.size()), reply, 5000, &diagnostics)) {
        result.error = "PatchCode: " + DescribeIpcFailure(&diagnostics) +
            "; write outcome may be unknown, inspect memory before retrying";
        return result;
    }
    result.error = "PatchCode: malformed or incomplete backend response; inspect memory before retrying";
    if (reply.size() < sizeof(IpcStatus)) return result;
    IpcStatus status{};
    std::memcpy(&status, reply.data(), sizeof(status));
    result.backendStatus = status;
    if (reply.size() >= sizeof(result.header)) std::memcpy(&result.header, reply.data(), sizeof(result.header));
    if (status != IpcStatus::Ok) {
        const char* detail = nullptr;
        switch (result.header.detail) {
        case PatchCodeDetail::TooLarge: detail = "assembled code exceeds the overwrite range; specify a larger whole-instruction overwrite_size"; break;
        case PatchCodeDetail::SplitInstruction: detail = "overwrite_size ends inside an original instruction"; break;
        case PatchCodeDetail::Unreadable: detail = "overwrite range must be readable within one committed memory region"; break;
        case PatchCodeDetail::InvalidInstruction: detail = "original instruction cannot be decoded"; break;
        case PatchCodeDetail::BreakpointOverlap: detail = "remove software breakpoints from the overwrite range first"; break;
        case PatchCodeDetail::WriteFailed: detail = "code patch write failed; memory may have changed"; break;
        case PatchCodeDetail::ArchitectureMismatch: detail = "arch does not match the target address width"; break;
        case PatchCodeDetail::OriginalChanged: detail = "original bytes changed before the write"; break;
        default: break;
        }
        result.error = "PatchCode: " + (detail ? std::string(detail) : BackendStatusText(status));
        return result;
    }
    const auto& header = result.header;
    const auto span = header.overwriteSize;
    if (reply.size() < sizeof(header) || header.detail != PatchCodeDetail::None ||
        !span || span > kPatchCodeMaxBytes || span < code.size() ||
        !header.instructionCount || header.instructionCount > span ||
        (overwriteSize ? span != overwriteSize : span > code.size() + 14) ||
        reply.size() != sizeof(header) + 2 * static_cast<size_t>(span)) return result;
    const auto start = reply.begin() + sizeof(header);
    result.original.assign(start, start + span);
    result.patched.assign(start + span, reply.end());
    if (!std::equal(code.begin(), code.end(), result.patched.begin())) return result;
    for (size_t index = code.size(); index < span; ++index)
        if (result.patched[index] != (nopFill ? 0x90 : result.original[index])) return result;
    result.ok = true;
    result.error.clear();
    return result;
}

uint64_t DebugSession::AllocateMemory(uint32_t size, uint32_t protection) {
	AllocateMemoryRequest req{};
	req.size = size;
	req.protection = protection;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::AllocateMemory, &req, sizeof(req), respData))
		return 0;
	if (respData.size() < sizeof(AllocateMemoryResponse)) return 0;

	auto* resp = reinterpret_cast<const AllocateMemoryResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return 0;
	return resp->address;
}

bool DebugSession::FreeMemory(uint64_t address) {
	FreeMemoryRequest req{};
	req.address = address;
	req.size = 0;

	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::FreeMemory, &req, sizeof(req), respData))
		return false;
	if (respData.size() == sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		return status == IpcStatus::Ok;
	}
	return false;
}

DebugSession::ProtectMemoryResult DebugSession::ProtectMemory(uint64_t address, uint64_t size,
	uint32_t protection, ProtectMemoryMethod method) {
	ProtectMemoryRequest req{};
	req.address = address;
	req.size = size;
	req.protection = protection;
	req.method = method;

	ProtectMemoryResult result;
	result.method = method;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ProtectMemory, &req, sizeof(req), respData))
		return result;
	if (respData.size() < sizeof(ProtectMemoryResponse)) return result;

	auto* resp = reinterpret_cast<const ProtectMemoryResponse*>(respData.data());
	result.oldProtection = resp->oldProtection;
	result.errorCode = resp->errorCode;
	result.method = resp->method;
	result.ok = resp->status == IpcStatus::Ok;
	return result;
}

ShellcodeResult DebugSession::ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs) {
	ShellcodeResult result;

	std::vector<uint8_t> payload(sizeof(ExecuteShellcodeRequest) + size);
	auto* req = reinterpret_cast<ExecuteShellcodeRequest*>(payload.data());
	req->size = size;
	req->timeoutMs = timeoutMs;
	memcpy(payload.data() + sizeof(ExecuteShellcodeRequest), code, size);

	std::vector<uint8_t> respData;
	// Include backend setup and confirmed-termination cleanup in the IPC budget.
	// The default 3-second exchange timeout can expire before the requested run.
	const int ipcTimeout = static_cast<int>(std::min<uint64_t>(
		static_cast<uint64_t>(timeoutMs) + 20000, 0x7FFFFFFF));
	PipeExchangeDiagnostics diagnostics{};
	if (!ipcTransport_->SendAndReceive(IpcCommand::ExecuteShellcode, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData, ipcTimeout, &diagnostics)) {
		result.error = "ExecuteShellcode: " + DescribeIpcFailure(&diagnostics);
		return result;
	}
	if (respData.size() >= sizeof(IpcStatus)) {
		IpcStatus status{};
		std::memcpy(&status, respData.data(), sizeof(status));
		result.backendStatus = status;
		if (status != IpcStatus::Ok) {
			result.error = "ExecuteShellcode: " + BackendStatusText(status);
			return result;
		}
	}
	if (respData.size() != sizeof(ExecuteShellcodeResponse)) {
		result.error = "ExecuteShellcode: malformed or incomplete backend response";
		return result;
	}
	auto* resp = reinterpret_cast<const ExecuteShellcodeResponse*>(respData.data());
	if (resp->crashed > 1) {
		result.error = "ExecuteShellcode: invalid backend crash flag";
		return result;
	}

	result.ok = true;
	result.exitCode = resp->exitCode;
	result.allocatedAddress = resp->allocatedAddress;
	result.crashed = resp->crashed;
	result.exceptionCode = resp->exceptionCode;
	result.exceptionAddress = resp->exceptionAddress;
	return result;
}

// --- Analysis ---

std::vector<DisasmInsn> DebugSession::Disassemble(uint64_t address, uint32_t count) {
	std::vector<DisasmInsn> result;

	uint32_t readSize = count * 15;
	auto mem = ReadMemory(address, readSize);
	if (mem.empty()) return result;

	if (!disassembler_) return result;
	auto insns = disassembler_->Disassemble(mem.data(), (uint32_t)mem.size(), address, count);

	result.reserve(insns.size());
	for (auto& insn : insns) {
		result.push_back({insn.address, insn.bytes, insn.mnemonic});
	}
	return result;
}

bool DebugSession::ResolveAddrExpr(const std::string& innerIn, const RegisterSet* regs, uint64_t& out) {
	return ResolveExpressionAddress(innerIn, regs, out, ExprEvalFrontend::Mcp);
}

EvalResult DebugSession::Evaluate(const std::string& expression, uint32_t threadId) {
	auto evaluated = EvaluateExpression(*ipcTransport_, targetProcess_, expression, threadId,
		ExprEvalFrontend::Mcp);
	EvalResult result;
	result.ok = evaluated.ok;
	result.value = std::move(evaluated.value);
	result.type = std::move(evaluated.type);
	result.address = evaluated.address;
	result.tebAddress = std::move(evaluated.tebAddress);
	result.error = std::move(evaluated.error);
	return result;
}

TraceResult DebugSession::TraceCallers(uint64_t address, uint32_t durationMs) {
	TraceResult result;

	// Auto-resume, and pause again after. Only the DLL's INT3 trace needs the
	// target running: the hypervisor's hook sees calls whatever the target's
	// state, and its Pause would leave a running target suspended afterwards.
	const bool stops = backendInfo_.backend != IpcBackend::Hypervisor && backendInfo_.Supports(IpcCommand::Continue);
	ResumeMainThread();
	if (stops) {
		ContinueRequest contReq = {};
		contReq.threadId = 0;
		ipcTransport_->SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));
	}

	TraceCallersRequest req{};
	req.address = address;
	req.durationMs = durationMs;

	std::vector<uint8_t> respData;
	int timeoutMs = static_cast<int>(durationMs) + 10000;
	const bool received = ReceiveBackendReply(IpcCommand::TraceCallers, &req, sizeof(req), respData, "TraceCallers", result.error, timeoutMs);
	// Auto-pause after collection
	if (stops) {
		PauseRequest pauseReq{}; pauseReq.threadId = 0;
		ipcTransport_->SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));
	}
	if (!received) return result;
	result.received = true;

	// Drain stale stop events
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		stopOccurred_ = false;
	}

	if (respData.size() < sizeof(TraceCallersResponse)) return result;
	const auto* hdr = reinterpret_cast<const TraceCallersResponse*>(respData.data());
	if (hdr->status != IpcStatus::Ok) return result;

	if (hdr->uniqueCallers > (respData.size() - sizeof(TraceCallersResponse)) / sizeof(TraceCallerEntry)) return result;
	result.ok = true;
	result.error.clear();
	result.totalHits = hdr->totalHits;
	result.uniqueCallers = hdr->uniqueCallers;

	const auto* entries = reinterpret_cast<const TraceCallerEntry*>(respData.data() + sizeof(TraceCallersResponse));
	size_t count = hdr->uniqueCallers;
	if (count > 100000) count = 100000;
	if (respData.size() >= sizeof(TraceCallersResponse) + count * sizeof(TraceCallerEntry)) {
		result.callers.reserve(count);
		for (size_t i = 0; i < count; i++) {
			result.callers.push_back({entries[i].callerAddress, entries[i].hitCount});
		}
	}
	return result;
}

// --- Dynamic tracing ---

DebugSession::TraceRegResult DebugSession::TraceRegister(uint32_t threadId, uint32_t regIndex,
                                                          uint32_t maxSteps, uint8_t mode, uint64_t compareValue) {
	TraceRegResult result;
	TraceRegisterRequest req{};
	req.threadId = threadId;
	req.regIndex = regIndex;
	req.maxSteps = maxSteps;
	req.mode = mode;
	req.compareValue = compareValue;

	int timeoutMs = static_cast<int>(maxSteps) * 10 + 10000;
	std::vector<uint8_t> respData;
	if (!ReceiveBackendReply(IpcCommand::TraceRegister, &req, sizeof(req), respData, "TraceRegister", result.error, timeoutMs)) {
		return result;
	}
	if (respData.size() < sizeof(TraceRegisterResponse)) return result;
	auto* resp = reinterpret_cast<const TraceRegisterResponse*>(respData.data());
	result.ok = true;
	result.error.clear();
	result.found = resp->found != 0;
	result.stepsExecuted = resp->stepsExecuted;
	result.address = resp->address;
	result.oldValue = resp->oldValue;
	result.newValue = resp->newValue;
	return result;
}

DebugSession::TraceMemResult DebugSession::TraceMemoryWrite(uint64_t address, uint32_t size, uint32_t timeoutMs) {
	TraceMemResult result;
	TraceMemoryRequest req{};
	req.address = address;
	req.size = size;
	req.timeoutMs = timeoutMs;

	int ipcTimeout = static_cast<int>(timeoutMs) + 10000;
	std::vector<uint8_t> respData;
	if (!ReceiveBackendReply(IpcCommand::TraceMemory, &req, sizeof(req), respData, "TraceMemory", result.error, ipcTimeout)) {
		return result;
	}
	if (respData.size() < sizeof(TraceMemoryResponse)) return result;
	auto* resp = reinterpret_cast<const TraceMemoryResponse*>(respData.data());
	result.ok = true;
	result.error.clear();
	result.found = resp->found != 0;
	result.threadId = resp->threadId;
	result.instructionAddress = resp->instructionAddress;
	result.oldValue = resp->oldValue;
	result.newValue = resp->newValue;
	return result;
}

DebugSession::TraceCollectResult DebugSession::TraceMemoryCollect(uint64_t address, uint32_t size,
	uint32_t durationMs, uint8_t access, uint32_t maxEntries) {
	TraceCollectResult result;
	TraceMemoryCollectRequest req{};
	req.address = address;
	req.size = size;
	req.durationMs = durationMs;
	req.access = access;
	req.maxEntries = maxEntries;
	std::vector<uint8_t> respData;
	if (!ReceiveBackendReply(IpcCommand::TraceMemoryCollect, &req, sizeof(req), respData,
		"TraceMemoryCollect", result.error, static_cast<int>(durationMs) + 10000))
		return result;
	if (respData.size() < sizeof(TraceMemoryCollectResponse)) return result;
	TraceMemoryCollectResponse head{};
	memcpy(&head, respData.data(), sizeof(head));
	if (head.entryCount > (respData.size() - sizeof(head)) / sizeof(TraceMemoryCollectEntry)) return result;
	result.ok = true;
	result.error.clear();
	result.totalHits = head.totalHits;
	result.droppedHits = head.droppedHits;
	const size_t room = (respData.size() - sizeof(head)) / sizeof(TraceMemoryCollectEntry);
	result.entries.resize(head.entryCount < room ? head.entryCount : room);
	if (!result.entries.empty())
		memcpy(result.entries.data(), respData.data() + sizeof(head), result.entries.size() * sizeof(TraceMemoryCollectEntry));
	return result;
}

// --- Import resolution ---

std::vector<DebugSession::ImportEntry> DebugSession::ResolveImports(
	uint32_t threadId, const std::vector<uint64_t>& thunks, uint32_t maxStepsPerThunk,
	bool followExceptions, bool systemOnly, const std::vector<std::string>& targetModules) {

	std::vector<ImportEntry> result;
	if (thunks.empty()) return result;

	uint8_t tmCount = static_cast<uint8_t>(targetModules.size() > 255 ? 255 : targetModules.size());
	size_t payloadSize = sizeof(ResolveImportRequest) + thunks.size() * sizeof(uint64_t) + tmCount * 64;
	std::vector<uint8_t> payload(payloadSize, 0);
	auto* req = reinterpret_cast<ResolveImportRequest*>(payload.data());
	req->threadId = threadId;
	req->count = static_cast<uint32_t>(thunks.size());
	req->maxStepsPerThunk = maxStepsPerThunk;
	req->followExceptions = followExceptions ? 1 : 0;
	req->systemOnly = systemOnly ? 1 : 0;
	req->targetModuleCount = tmCount;
	req->reserved = 0;
	memcpy(payload.data() + sizeof(ResolveImportRequest), thunks.data(), thunks.size() * sizeof(uint64_t));
	// Append target module names (64 bytes each, null-terminated)
	char* modDest = reinterpret_cast<char*>(payload.data() + sizeof(ResolveImportRequest) + thunks.size() * sizeof(uint64_t));
	for (uint8_t m = 0; m < tmCount; m++) {
		strncpy(modDest + m * 64, targetModules[m].c_str(), 63);
	}

	int timeoutMs = static_cast<int>(thunks.size()) * maxStepsPerThunk / 10 + 30000;
	std::vector<uint8_t> respData;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ResolveImport, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData, timeoutMs)) {
		return result;
	}

	if (respData.size() < sizeof(ResolveImportResponse)) return result;
	auto* resp = reinterpret_cast<const ResolveImportResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;

	auto* entries = reinterpret_cast<const ResolveImportEntry*>(
		respData.data() + sizeof(ResolveImportResponse));
	uint32_t count = resp->count;
	if (respData.size() < sizeof(ResolveImportResponse) + count * sizeof(ResolveImportEntry))
		count = static_cast<uint32_t>((respData.size() - sizeof(ResolveImportResponse)) / sizeof(ResolveImportEntry));

	for (uint32_t i = 0; i < count; i++) {
		ImportEntry e;
		e.thunkAddress = entries[i].thunkAddress;
		e.targetAddress = entries[i].targetAddress;
		char modBuf[129] = {}; memcpy(modBuf, entries[i].moduleName, 128);
		char funcBuf[129] = {}; memcpy(funcBuf, entries[i].functionName, 128);
		e.moduleName = modBuf;
		e.functionName = funcBuf;
		e.resolved = entries[i].resolved != 0;
		e.stepsExecuted = entries[i].stepsExecuted;
		e.exceptionsPassed = entries[i].exceptionsPassed;
		for (uint8_t t = 0; t < entries[i].traceCount && t < 16; t++) {
			e.trace.push_back({entries[i].traceAddresses[t], entries[i].traceExcCodes[t]});
		}
		result.push_back(e);
	}
	return result;
}

// --- TraceCalls ---

DebugSession::TraceCallsResult DebugSession::TraceCalls(
	const std::vector<uint64_t>& addresses, uint32_t durationMs,
	bool resolve, bool systemOnly, uint32_t resolveMaxSteps) {

	TraceCallsResult result = {};
	if (addresses.empty()) return result;

	std::vector<uint8_t> payload(sizeof(TraceCallsRequest) + addresses.size() * sizeof(uint64_t));
	auto* req = reinterpret_cast<TraceCallsRequest*>(payload.data());
	req->durationMs = durationMs;
	req->resolve = resolve ? 1 : 0;
	req->systemOnly = systemOnly ? 1 : 0;
	req->resolveMaxSteps = static_cast<uint16_t>(resolveMaxSteps > 0xFFFF ? 0xFFFF : resolveMaxSteps);
	req->count = static_cast<uint32_t>(addresses.size());
	memcpy(payload.data() + sizeof(TraceCallsRequest), addresses.data(), addresses.size() * sizeof(uint64_t));

	int timeoutMs = static_cast<int>(durationMs) + 30000;
	std::vector<uint8_t> respData;
	if (!ReceiveBackendReply(IpcCommand::TraceCalls, payload.data(),
		static_cast<uint32_t>(payload.size()), respData, "TraceCalls", result.error, timeoutMs))
		return result;

	if (respData.size() < sizeof(TraceCallsResponse)) return result;
	auto* resp = reinterpret_cast<const TraceCallsResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;

	result.totalHits = resp->totalHits;
	auto* entries = reinterpret_cast<const TraceCallsEntry*>(respData.data() + sizeof(TraceCallsResponse));
	uint32_t count = resp->uniqueCount;
	if (respData.size() < sizeof(TraceCallsResponse) + count * sizeof(TraceCallsEntry))
		return result;
	result.ok = true;
	result.error.clear();

	for (uint32_t i = 0; i < count; i++) {
		TraceCallEntry e;
		e.callSite = entries[i].callSite;
		e.target = entries[i].target;
		e.hitCount = entries[i].hitCount;
		char modBuf[65] = {}; memcpy(modBuf, entries[i].moduleName, 64); e.moduleName = modBuf;
		char funcBuf[65] = {}; memcpy(funcBuf, entries[i].functionName, 64); e.functionName = funcBuf;
		result.entries.push_back(e);
	}
	return result;
}

DebugSession::TraceBasicBlocksResult DebugSession::TraceBasicBlocks(
		uint32_t threadId, uint64_t rangeStart, uint64_t rangeEnd,
		uint32_t maxBlocks, uint32_t maxEdges, uint32_t maxSteps,
		uint32_t timeoutMs, uint16_t stackBytes, bool followExceptions,
		bool collectMemoryWrites, uint32_t maxMemoryWrites,
		bool collectMemoryReads, uint32_t maxMemoryReads,
		bool collectEvents, uint32_t maxEvents,
		bool collectCode, uint32_t maxCodeBytes, uint32_t maxCodeVersions,
		TraceCodeOutputMode codeOutputMode, uint32_t codeChunkBytes,
		const std::string& codeOutputPath,
		TraceEventOutputMode eventOutputMode, uint64_t maxEventFileBytes,
		const std::string& eventOutputPath,
		bool collectMemoryEvents, uint32_t maxMemoryEvents,
		bool collectRegisterEvents, uint32_t maxRegisterEvents,
		const std::vector<TraceDependencySource>& dependencySources,
		const TraceCondition& startCondition, const TraceCondition& stopCondition,
		const TraceCondition& collectCondition, const TraceOccurrenceWindow& occurrenceWindow,
		bool stopOnReturn, const TraceTargetWindow& targetWindow, uint32_t collectionFlags) {
	TraceBasicBlocksResult result;
	if (collectionFlags && (!backendInfo_.reported || !(backendInfo_.flags & kCapBasicTracePolicies))) {
		result.controlFailure = "backend_does_not_support_trace_collection_policies";
		return result;
	}
	TraceCodeArtifactReceiver codeArtifactReceiver;
	TraceEventArtifactReceiver eventArtifactReceiver;
	const bool fileCodeOutput = collectCode && codeOutputMode == TraceCodeOutputMode::File;
	const bool fileEventOutput = eventOutputMode == TraceEventOutputMode::File;
	if (fileCodeOutput && !codeArtifactReceiver.Start(codeOutputPath, codeChunkBytes,
			maxCodeBytes, rangeStart, rangeEnd)) {
		result.codeArtifact = codeArtifactReceiver.Finish(false);
		return result;
	}
	if (fileEventOutput && !eventArtifactReceiver.Start(eventOutputPath,
			kTraceEventDefaultChunkBytes, maxEventFileBytes, (collectionFlags & kTraceCompressPaths) ? 2 : 1)) {
		result.eventArtifact = eventArtifactReceiver.Finish(false);
		if (fileCodeOutput) result.codeArtifact = codeArtifactReceiver.Finish(false);
		return result;
	}
	TraceBasicBlocksRequest req{};
	req.wireVersion = collectionFlags ? kTraceBasicBlocksWireVersion : 10;
	req.requestSize = collectionFlags ? sizeof(req) : kTraceBasicBlocksRequestV10Size;
	req.collectionFlags = collectionFlags;
	req.threadId = threadId;
	req.rangeStart = rangeStart;
	req.rangeEnd = rangeEnd;
	req.maxBlocks = maxBlocks;
	req.maxEdges = maxEdges;
	req.maxSteps = maxSteps;
	req.timeoutMs = timeoutMs;
	req.stackBytes = stackBytes;
	req.followExceptions = followExceptions ? 1 : 0;
	req.collectMemoryWrites = collectMemoryWrites ? 1 : 0;
	req.maxMemoryWrites = maxMemoryWrites;
	req.collectMemoryReads = collectMemoryReads ? 1 : 0;
	req.maxMemoryReads = maxMemoryReads;
	req.collectEvents = (collectEvents || collectCode || collectMemoryEvents || collectRegisterEvents) ? 1 : 0;
	req.maxEvents = maxEvents;
	req.collectCode = collectCode ? 1 : 0;
	req.maxCodeBytes = maxCodeBytes;
	req.maxCodeVersions = maxCodeVersions;
	req.collectMemoryEvents = collectMemoryEvents ? 1 : 0;
	req.maxMemoryEvents = maxMemoryEvents;
	req.collectRegisterEvents = collectRegisterEvents ? 1 : 0;
	req.maxRegisterEvents = maxRegisterEvents;
	req.codeOutputMode = static_cast<uint8_t>(codeOutputMode);
	req.codeChunkBytes = fileCodeOutput ? codeChunkBytes : 0;
	req.codeStreamOwnerPid = fileCodeOutput ? codeArtifactReceiver.OwnerPid() : 0;
	req.codeStreamToken = fileCodeOutput ? codeArtifactReceiver.Token() : 0;
	req.eventOutputMode = static_cast<uint8_t>(eventOutputMode);
	req.eventChunkBytes = fileEventOutput ? kTraceEventDefaultChunkBytes : 0;
	req.eventStreamOwnerPid = fileEventOutput ? eventArtifactReceiver.OwnerPid() : 0;
	req.eventStreamToken = fileEventOutput ? eventArtifactReceiver.Token() : 0;
	req.maxEventFileBytes = fileEventOutput ? maxEventFileBytes : 0;
	req.dependencySourceCount = static_cast<uint8_t>(std::min<size_t>(dependencySources.size(), kTraceDependencyMaxSources));
	if (req.dependencySourceCount) memcpy(req.dependencySources, dependencySources.data(),
		static_cast<size_t>(req.dependencySourceCount) * sizeof(req.dependencySources[0]));
	req.startCondition = startCondition;
	req.stopCondition = stopCondition;
	req.collectCondition = collectCondition;
	req.occurrenceWindow = occurrenceWindow;
	req.stopOnReturn = stopOnReturn ? 1 : 0;
	req.targetWindow = targetWindow;

	std::vector<uint8_t> data;
	PipeExchangeDiagnostics exchangeDiagnostics;
	const bool received = ipcTransport_->SendAndReceive(IpcCommand::TraceBasicBlocks, &req, req.requestSize, data,
		static_cast<int>(timeoutMs) + 15000, &exchangeDiagnostics);
	result.controlResponseReceived = received;
	result.controlResponseBytes = static_cast<uint32_t>(std::min<size_t>(data.size(), UINT32_MAX));
	result.advertisedPayloadBytes = exchangeDiagnostics.advertisedPayloadSize;
	result.controlSystemError = exchangeDiagnostics.systemError;
	auto exchangeFailureName = [](PipeExchangeFailure failure) {
		switch (failure) {
		case PipeExchangeFailure::NotRunning: return "control_reader_not_running";
		case PipeExchangeFailure::SendFailed: return "control_send_failed";
		case PipeExchangeFailure::HeaderReadFailed: return "control_header_read_failed";
		case PipeExchangeFailure::PayloadTooLarge: return "control_payload_too_large";
		case PipeExchangeFailure::PayloadReadFailed: return "control_payload_read_failed";
		case PipeExchangeFailure::WaitTimeout: return "control_response_timeout";
		case PipeExchangeFailure::ReaderAborted: return "control_reader_aborted";
		default: return "";
		}
	};
	if (!received) result.controlFailure = exchangeFailureName(exchangeDiagnostics.failure);
	const bool streamExpected = received && data.size() >= sizeof(IpcStatus) &&
		*reinterpret_cast<const IpcStatus*>(data.data()) == IpcStatus::Ok;
	if (fileCodeOutput) {
		result.codeArtifact = codeArtifactReceiver.Finish(streamExpected);
		if (!received && result.codeArtifact.error.empty())
			result.codeArtifact.error = "trace control response failed";
	}
	if (fileEventOutput) {
		result.eventArtifact = eventArtifactReceiver.Finish(streamExpected);
		if (!received && result.eventArtifact.error.empty())
			result.eventArtifact.error = "trace control response failed";
	}
	if (!received) return result;
	if (data.size() < sizeof(IpcStatus)) {
		result.controlFailure = "response_too_small_for_status";
		return result;
	}
	result.status = *reinterpret_cast<const IpcStatus*>(data.data());
	if (fileCodeOutput && result.status == IpcStatus::InvalidArgs && result.codeArtifact.error.empty())
		result.codeArtifact.error = "injected DLL does not support code_output=file";
	if (fileEventOutput && (!result.eventArtifact.success || result.status == IpcStatus::InvalidArgs) &&
		result.eventArtifact.error.empty())
		result.eventArtifact.error = "injected DLL does not support events_output=file";
	if (data.size() < kTraceBasicBlocksResponseV3Size) {
		result.controlFailure = "response_too_small_for_trace_header";
		return result;
	}
	auto* header = reinterpret_cast<const TraceBasicBlocksResponse*>(data.data());
	size_t headerSize = header->headerSize;
	result.responseHeaderSize = header->headerSize;
	auto requiredSize = [&](size_t candidate) {
		uint32_t registerEventCount = candidate >= kTraceBasicBlocksResponseV4Size &&
			data.size() >= kTraceBasicBlocksResponseV4Size ? header->registerEventCount : 0;
		return candidate +
		static_cast<size_t>(header->blockCount) * sizeof(TraceBasicBlockEntry) +
		static_cast<size_t>(header->edgeCount) * sizeof(TraceBasicBlockEdgeEntry) +
		static_cast<size_t>(header->snapshotCount) * sizeof(TraceBasicBlockSnapshot) +
		static_cast<size_t>(header->memoryWriteCount) * sizeof(TraceBasicBlockMemoryWriteEntry) +
		static_cast<size_t>(header->memoryReadCount) * sizeof(TraceBasicBlockMemoryReadEntry) +
		static_cast<size_t>(header->exceptionEventCount) * sizeof(TraceBasicBlockExceptionEntry) +
		static_cast<size_t>(header->eventCount) * sizeof(TraceBasicBlockEventEntry) +
		static_cast<size_t>(header->memoryEventCount) * sizeof(TraceBasicBlockMemoryEventEntry) +
		static_cast<size_t>(registerEventCount) * sizeof(TraceBasicBlockRegisterEventEntry) +
		static_cast<size_t>(header->codeVersionCount) * sizeof(TraceBasicBlockCodeVersionEntry) +
		header->codeByteCount;
	};
	if (headerSize == 0) {
		if (data.size() >= kTraceBasicBlocksResponseV4Size &&
			requiredSize(kTraceBasicBlocksResponseV4Size) == data.size())
			headerSize = kTraceBasicBlocksResponseV4Size;
		else if (requiredSize(kTraceBasicBlocksResponseV3Size) == data.size())
			headerSize = kTraceBasicBlocksResponseV3Size;
		else {
			result.controlFailure = "legacy_response_size_mismatch";
			result.expectedResponseBytes = requiredSize(kTraceBasicBlocksResponseV4Size);
			return result;
		}
	}
	result.responseHeaderSize = static_cast<uint16_t>(headerSize);
	if (headerSize < kTraceBasicBlocksResponseV3Size || headerSize > data.size()) {
		result.controlFailure = "invalid_response_header_size";
		return result;
	}
	result.expectedResponseBytes = requiredSize(headerSize);
	if (result.expectedResponseBytes != data.size()) {
		result.controlFailure = "response_size_mismatch";
		return result;
	}
	if (result.status == IpcStatus::Ok && collectionFlags && (headerSize < kTraceBasicBlocksResponseV9Size ||
		header->appliedCollectionFlags != collectionFlags ||
		((collectionFlags & kTraceCompressPaths) && header->eventSchemaVersion != 3))) {
		result.controlFailure = "trace_collection_policy_not_acknowledged";
		return result;
	}
	if (headerSize >= kTraceBasicBlocksResponseV9Size) {
		result.appliedCollectionFlags = header->appliedCollectionFlags;
		result.decodeIncomplete = header->decodeIncomplete != 0;
		result.expandedEventCount = header->expandedEventCount;
	}
	result.stopReason = header->stopReason;
	result.truncated = header->truncated != 0;
	result.elapsedMs = header->elapsedMs;
	result.stepsExecuted = header->stepsExecuted;
	result.finalAddress = header->finalAddress;
	result.threadId = header->threadId;
	if (headerSize >= kTraceBasicBlocksResponseV5Size) {
		result.startFailure = static_cast<TraceBasicBlocksStartFailure>(header->startFailureReason);
		result.stopped = header->stopped != 0;
		result.ipInRange = header->ipInRange != 0;
		result.decodeSucceeded = header->decodeSucceeded != 0;
		result.decodedInstructionCount = header->decodedInstructionCount;
		result.normalizedIp = header->normalizedIp;
		result.normalizedRangeStart = header->normalizedRangeStart;
		result.normalizedRangeEnd = header->normalizedRangeEnd;
	}
	if (headerSize >= kTraceBasicBlocksResponseV6Size) {
		result.occurrenceSupported = true;
		result.occurrenceWindow = header->occurrenceWindow;
		result.occurrenceHits = header->occurrenceHits;
		result.occurrenceWindowStarted = header->occurrenceWindowStarted != 0;
		result.occurrenceWindowCompleted = header->occurrenceWindowCompleted != 0;
	}
	if (headerSize >= kTraceBasicBlocksResponseV7Size) {
		result.functionScopeSupported = true;
		result.stopOnReturn = header->functionScopeEnabled != 0;
		result.functionReturned = header->functionReturned != 0;
		result.returnSnapshot = header->returnSnapshot;
		result.entryStackPointer = header->entryStackPointer;
		result.returnAddress = header->returnAddress;
		result.externalSteps = header->externalSteps;
	}
	if (headerSize >= kTraceBasicBlocksResponseV8Size) {
		result.targetWindowSupported = true;
		result.targetWindow = header->targetWindow;
		result.targetOccurrenceHits = header->targetOccurrenceHits;
		result.targetTriggerSequence = header->targetTriggerSequence;
		result.targetCaptureStartSequence = header->targetCaptureStartSequence;
		result.targetCaptureEndSequence = header->targetCaptureEndSequence;
		result.eventsDropped = header->eventsDropped;
		result.targetMatched = header->targetMatched != 0;
	}
	if (header->status != IpcStatus::Ok) {
		result.controlFailure = header->stopReason == TraceBasicBlockStopReason::Timeout ?
			"collector_timeout" : "control_status_error";
		return result;
	}

	result.exceptionsFollowed = header->exceptionsFollowed;
	result.unsupportedMemoryWrites = header->unsupportedMemoryWrites;
	result.memoryWritesTruncated = header->memoryWritesTruncated != 0;
	result.filteredSteps = header->filteredSteps;
	result.startConditionMet = header->startConditionMet != 0;
	result.unsupportedMemoryReads = header->unsupportedMemoryReads;
	result.memoryReadsTruncated = header->memoryReadsTruncated != 0;
	result.dependencyIncomplete = header->dependencyIncomplete != 0;
	result.eventCollectionEnabled = header->eventCollectionEnabled != 0;
	result.eventsTruncated = header->eventsTruncated != 0;
	result.eventSchemaVersion = header->eventSchemaVersion;
	result.codeCollectionEnabled = header->codeCollectionEnabled != 0;
	result.codeTruncated = header->codeTruncated != 0;
	result.codeSchemaVersion = header->codeSchemaVersion;
	result.memoryEventCollectionEnabled = header->memoryEventCollectionEnabled != 0;
	result.memoryEventsTruncated = header->memoryEventsTruncated != 0;
	result.memoryEventSchemaVersion = header->memoryEventSchemaVersion;
	result.memoryEventsDropped = header->memoryEventsDropped;
	if (headerSize >= kTraceBasicBlocksResponseV4Size) {
		result.registerEventCollectionEnabled = header->registerEventCollectionEnabled != 0;
		result.registerEventsTruncated = header->registerEventsTruncated != 0;
		result.registerEventSchemaVersion = header->registerEventSchemaVersion;
		result.registerEventsDropped = header->registerEventsDropped;
	}
	memcpy(result.finalRegisterDependencies, header->finalRegisterDependencies,
		sizeof(result.finalRegisterDependencies));
	result.finalFlagsDependencies = header->finalFlagsDependencies;
	const uint8_t* cursor = data.data() + headerSize;
	auto* blocks = reinterpret_cast<const TraceBasicBlockEntry*>(cursor);
	result.blocks.assign(blocks, blocks + header->blockCount);
	cursor += static_cast<size_t>(header->blockCount) * sizeof(*blocks);
	auto* edges = reinterpret_cast<const TraceBasicBlockEdgeEntry*>(cursor);
	result.edges.assign(edges, edges + header->edgeCount);
	cursor += static_cast<size_t>(header->edgeCount) * sizeof(*edges);
	auto* snapshots = reinterpret_cast<const TraceBasicBlockSnapshot*>(cursor);
	result.snapshots.assign(snapshots, snapshots + header->snapshotCount);
	cursor += static_cast<size_t>(header->snapshotCount) * sizeof(*snapshots);
	auto* memoryWrites = reinterpret_cast<const TraceBasicBlockMemoryWriteEntry*>(cursor);
	result.memoryWrites.assign(memoryWrites, memoryWrites + header->memoryWriteCount);
	cursor += static_cast<size_t>(header->memoryWriteCount) * sizeof(*memoryWrites);
	auto* memoryReads = reinterpret_cast<const TraceBasicBlockMemoryReadEntry*>(cursor);
	result.memoryReads.assign(memoryReads, memoryReads + header->memoryReadCount);
	cursor += static_cast<size_t>(header->memoryReadCount) * sizeof(*memoryReads);
	auto* exceptionEvents = reinterpret_cast<const TraceBasicBlockExceptionEntry*>(cursor);
	result.exceptionEvents.assign(exceptionEvents, exceptionEvents + header->exceptionEventCount);
	cursor += static_cast<size_t>(header->exceptionEventCount) * sizeof(*exceptionEvents);
	auto* events = reinterpret_cast<const TraceBasicBlockEventEntry*>(cursor);
	result.events.assign(events, events + header->eventCount);
	if (collectionFlags & kTraceCompressPaths) {
		if (fileEventOutput && result.eventArtifact.success &&
			(result.eventArtifact.expandedEvents != result.expandedEventCount ||
			(result.eventArtifact.basicBlockEvents && result.eventArtifact.threadId != threadId))) {
			result.status = IpcStatus::Error;
			result.controlFailure = "compressed_file_count_mismatch";
			return result;
		}
		TracePathValidator validator;
		for (const auto& event : result.events) {
			if (event.threadId != threadId || !validator.Accept(event)) {
				result.status = IpcStatus::Error;
				result.controlFailure = "invalid_compressed_path";
				return result;
			}
		}
		if (!fileEventOutput && validator.ExpandedCount() != result.expandedEventCount) {
			result.status = IpcStatus::Error;
			result.controlFailure = "compressed_path_count_mismatch";
			return result;
		}
	}
	cursor += static_cast<size_t>(header->eventCount) * sizeof(*events);
	auto* memoryEvents = reinterpret_cast<const TraceBasicBlockMemoryEventEntry*>(cursor);
	result.memoryEvents.assign(memoryEvents, memoryEvents + header->memoryEventCount);
	cursor += static_cast<size_t>(header->memoryEventCount) * sizeof(*memoryEvents);
	if (headerSize >= kTraceBasicBlocksResponseV4Size) {
		auto* registerEvents = reinterpret_cast<const TraceBasicBlockRegisterEventEntry*>(cursor);
		result.registerEvents.assign(registerEvents, registerEvents + header->registerEventCount);
		cursor += static_cast<size_t>(header->registerEventCount) * sizeof(*registerEvents);
	}
	auto* codeVersions = reinterpret_cast<const TraceBasicBlockCodeVersionEntry*>(cursor);
	result.codeVersions.assign(codeVersions, codeVersions + header->codeVersionCount);
	cursor += static_cast<size_t>(header->codeVersionCount) * sizeof(*codeVersions);
	result.codeBytes.assign(cursor, cursor + header->codeByteCount);
	result.ok = true;
	return result;
}

// --- PDB resolve ---

uint64_t DebugSession::ResolveSourceLine(const std::string& file, uint32_t line) {
	ResolveSourceLineRequest req = {};
	strncpy_s(req.fileName, file.c_str(), sizeof(req.fileName) - 1);
	req.line = line;

	std::vector<uint8_t> resp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ResolveSourceLine, &req, sizeof(req), resp))
		return 0;
	if (resp.size() < sizeof(ResolveSourceLineResponse)) return 0;
	auto* resolved = reinterpret_cast<const ResolveSourceLineResponse*>(resp.data());
	if (resolved->status != IpcStatus::Ok) return 0;
	return resolved->address;
}


DebugSession::SymbolMatches DebugSession::FindSymbols(const std::string& name, uint32_t maximum, uint64_t moduleBase) {
    SymbolMatches result;
    if (name.empty() || name.size() >= sizeof(FindSymbolsRequest::name) ||
        name.find('\0') != std::string::npos || !maximum || maximum > kFindSymbolsMaxResults) {
        result.error = "Symbol name must be 1-255 bytes and max_results must be 1-10"; return result;
    }
    const auto command = moduleBase ? IpcCommand::FindSymbolsInModule : IpcCommand::FindSymbols;
    if (!attached_ || !backendInfo_.reported || !backendInfo_.Supports(command)) {
        result.error = moduleBase ? "Backend does not advertise base-scoped symbol lookup (FindSymbolsInModule 0x47)" :
            "Backend does not advertise bounded symbol-name lookup (FindSymbols 0x45)"; return result;
    }
    if (moduleBase && (name.find('!') != std::string::npos || (TargetAddressBits() == 32 && moduleBase > UINT32_MAX))) {
        result.error = "Use an unqualified symbol and a module base within the target address width"; return result;
    }
    FindSymbolsRequest request{}; request.maxResults = maximum;
    std::memcpy(request.name, name.data(), name.size());
    std::vector<uint8_t> bytes;
    PipeExchangeDiagnostics diagnostics{};
    FindSymbolsInModuleRequest scoped{moduleBase, request};
    if (!ipcTransport_->SendAndReceive(command, moduleBase ? static_cast<const void*>(&scoped) : static_cast<const void*>(&request),
            moduleBase ? sizeof(scoped) : sizeof(request), bytes, 10000, &diagnostics)) {
        result.error = "FindSymbols: " + DescribeIpcFailure(&diagnostics); return result;
    }
    if (!ValidateBackendStatus(bytes, "FindSymbols", result.error)) return result;
    FindSymbolsResponse header{};
    if (bytes.size() < sizeof(header)) { result.error = "FindSymbols: incomplete response"; return result; }
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.count > maximum || (header.flags & ~(kFindSymbolsTruncated | kFindSymbolsIncomplete)) ||
        bytes.size() != sizeof(header) + static_cast<size_t>(header.count) * sizeof(FindSymbolEntry)) {
        result.error = "FindSymbols: malformed candidate list"; return result;
    }
    for (uint32_t i = 0; i < header.count; ++i) {
        FindSymbolEntry entry{};
        std::memcpy(&entry, bytes.data() + sizeof(header) + i * sizeof(entry), sizeof(entry));
        if ((entry.flags & ~(kFindSymbolForwarder | kFindSymbolExport)) || !entry.moduleBase ||
            (moduleBase && entry.moduleBase != moduleBase) ||
            !std::memchr(entry.functionName, 0, sizeof(entry.functionName)) || !entry.functionName[0] ||
            !std::memchr(entry.moduleName, 0, sizeof(entry.moduleName)) ||
            (!entry.moduleName[0] && !(header.flags & kFindSymbolsIncomplete)) ||
            ((entry.flags & kFindSymbolForwarder) ? entry.address != 0 : entry.address < entry.moduleBase) ||
            (TargetAddressBits() == 32 && (entry.address > UINT32_MAX || entry.moduleBase > UINT32_MAX))) {
            result.error = "FindSymbols: invalid candidate metadata"; return result;
        }
        result.matches.push_back(entry);
    }
    result.truncated = (header.flags & kFindSymbolsTruncated) != 0;
    result.incomplete = (header.flags & kFindSymbolsIncomplete) != 0;
    result.ok = true; result.error.clear();
    return result;
}

uint64_t DebugSession::ResolveFunction(const std::string& name) {
	ResolveFunctionRequest req = {};
	strncpy_s(req.functionName, name.c_str(), sizeof(req.functionName) - 1);

	std::vector<uint8_t> resp;
	if (!ipcTransport_->SendAndReceive(IpcCommand::ResolveFunction, &req, sizeof(req), resp))
		return 0;
	if (resp.size() < sizeof(ResolveFunctionResponse)) return 0;
	auto* resolved = reinterpret_cast<const ResolveFunctionResponse*>(resp.data());
	if (resolved->status != IpcStatus::Ok) return 0;
	return resolved->address;
}

// --- IPC event handling ---

void DebugSession::SetEventCallback(EventCallback cb) {
    eventCallback_ = cb;
	ipcTransport_->StartEventListener([this, cb](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		if (cb) cb(eventId, payload, size);
	});
	ipcTransport_->StartHeartbeat();
}

// --- Process monitor ---

void DebugSession::StartProcessMonitor() {
	StopProcessMonitor();
    if (IsRemoteTarget()) return;
	if (!targetProcess_) return;

	HANDLE hWait = OpenProcess(SYNCHRONIZE, FALSE, targetPid_);
	if (!hWait) {
		LOG_WARN("Cannot open process %u for SYNCHRONIZE", targetPid_);
		return;
	}

	monitorStopEvent_ = CreateEvent(nullptr, TRUE, FALSE, nullptr);

	processMonitorThread_ = std::thread([this, hWait, stopEv = monitorStopEvent_, callback = eventCallback_]() {
		HANDLE handles[2] = { hWait, stopEv };
		DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
		CloseHandle(hWait);

		if (result == WAIT_OBJECT_0) {
			attached_ = false;

			DWORD exitCode = 0;
			if (targetProcess_) {
				GetExitCodeProcess(targetProcess_, &exitCode);
			}

			LOG_INFO("DebugSession: Target process %u exited (code: %lu)", targetPid_, exitCode);

			// Signal stop event
			SignalStop("exit", 0, 0, 0);
            if (callback) {
                const ProcessExitEvent event{exitCode};
                callback(static_cast<uint32_t>(IpcEvent::ProcessExited),
                    reinterpret_cast<const uint8_t*>(&event), sizeof(event));
            }

			// Pipe cleanup
			ipcTransport_->StopHeartbeat();
			ipcTransport_->StopEventListener();
			ipcTransport_->Disconnect();

			{
				std::lock_guard<std::mutex> lock(bpMutex_);
				swBreakpoints_.clear();
				hwBreakpoints_.clear();
			}
			if (targetProcess_) {
				CloseHandle(targetProcess_);
				targetProcess_ = nullptr;
			}
			targetPid_ = 0;
			launchedMainThreadId_ = 0;
			mainThreadResumed_ = false;
			launchedByUs_ = false;
		}
	});
}

void DebugSession::StopProcessMonitor() {
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

// --- Register helpers (static) ---

bool DebugSession::TryParseRegisterName(const std::string& name) {
	return TryParseExpressionRegister(name);
}

uint64_t DebugSession::ResolveRegisterByName(const std::string& name, const RegisterSet& regs) {
	return ResolveExpressionRegister(name, regs, ExprEvalFrontend::Mcp);
}

uint32_t DebugSession::GetRegisterIndex(const std::string& name) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	static const std::pair<const char*, uint32_t> map[] = {
		{"RAX",0},{"EAX",0},{"RBX",1},{"EBX",1},{"RCX",2},{"ECX",2},{"RDX",3},{"EDX",3},
		{"RSI",4},{"ESI",4},{"RDI",5},{"EDI",5},{"RBP",6},{"EBP",6},{"RSP",7},{"ESP",7},
		{"R8",8},{"R9",9},{"R10",10},{"R11",11},{"R12",12},{"R13",13},{"R14",14},{"R15",15},
		{"RIP",16},{"EIP",16},{"RFLAGS",17},{"EFLAGS",17},
	};
	for (auto& [rn, idx] : map) {
		if (upper == rn) return idx;
	}
	return UINT32_MAX;
}

// --- Path helpers ---

std::string DebugSession::GetExeDir() {
	wchar_t exePathW[MAX_PATH];
	DWORD exeLen = GetModuleFileNameW(nullptr, exePathW, MAX_PATH);
	if (exeLen == 0 || exeLen >= MAX_PATH) {
		LOG_ERROR("GetModuleFileName failed or path too long");
		return "";
	}
	std::filesystem::path exePath(exePathW);
	std::string dir = exePath.parent_path().string() + "\\";
	return dir;
}

std::string DebugSession::ResolveDll(const std::string& dir, bool use32) {
	if (use32) {
		std::string path32 = dir + "vcruntime_net32.dll";
		if (std::filesystem::exists(path32)) return path32;
	}

	std::string path64 = dir + "vcruntime_net.dll";
	if (std::filesystem::exists(path64)) return path64;

	if (!use32) {
		std::string path32 = dir + "vcruntime_net32.dll";
		if (std::filesystem::exists(path32)) return path32;
	}

	LOG_ERROR("DLL not found in %s (need %s)", dir.c_str(),
		use32 ? "vcruntime_net32.dll (x86)" : "vcruntime_net.dll (x64)");
	return "";
}

std::string DebugSession::GetDllPath(uint32_t pid) {
	std::string dir = GetExeDir();
	if (dir.empty()) return "";

	bool use32 = false;
	if (pid != 0) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (hProc) {
			BOOL isWow64 = FALSE;
			IsWow64Process(hProc, &isWow64);
			CloseHandle(hProc);
			use32 = (isWow64 != FALSE);
		}
	}

	return ResolveDll(dir, use32);
}

std::string DebugSession::GetDllPathForExe(const std::string& exePath) {
	std::string dir = GetExeDir();
	if (dir.empty()) return "";

	bool use32 = Injector::IsExe32Bit(exePath);
	return ResolveDll(dir, use32);
}

} // namespace veh
