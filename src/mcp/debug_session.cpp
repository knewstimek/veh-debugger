#include "debug_session.h"
#include "common/logger.h"
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <TlHelp32.h>
#include <Psapi.h>

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

DebugSession::DebugSession() {}

DebugSession::~DebugSession() {
	StopProcessMonitor();
	if (attached_) {
		try {
			pipeClient_.SendCommand(IpcCommand::Detach);
		} catch (...) {}
		pipeClient_.Disconnect();
		attached_ = false;
	}
	if (launchedByUs_ && targetProcess_) {
		TerminateProcess(targetProcess_, 0);
		CloseHandle(targetProcess_);
		targetProcess_ = nullptr;
		launchedByUs_ = false;
	}
}

bool DebugSession::Attach(uint32_t pid) {
	if (pid == 0) return false;

	if (IsProcessUninitializedSuspended(pid)) {
		LOG_ERROR("Process %u appears to be in CREATE_SUSPENDED state", pid);
		return false;
	}

	std::string dllPath = GetDllPath(pid);
	if (dllPath.empty()) return false;

	bool pipeExists = IsPipeAvailable(pid);

	if (pipeExists) {
		LOG_INFO("Pipe already exists for PID %u, skipping injection (re-attach)", pid);
	} else {
		LOG_INFO("Injecting into PID %u: %s", pid, dllPath.c_str());
		if (!Injector::InjectDll(pid, dllPath)) {
			LOG_ERROR("DLL injection failed for PID %u", pid);
			return false;
		}
	}

	if (!pipeClient_.Connect(pid, 3500)) {
		LOG_ERROR("Pipe connection failed (pid=%u)", pid);
		return false;
	}

	targetPid_ = pid;
	targetProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
	if (!targetProcess_) {
		LOG_WARN("Cannot open process %u for monitoring", pid);
	}
	attached_ = true;

	// Set disassembler bitness
	{
		BOOL isWow64 = FALSE;
		if (targetProcess_) {
			IsWow64Process(targetProcess_, &isWow64);
		}
		bool is64 = (isWow64 == FALSE);
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	return true;
}

DebugSession::LaunchResult DebugSession::Launch(const LaunchOptions& opts) {
	LaunchResult result;

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

	std::string dllPath = GetDllPathForExe(opts.program);
	if (dllPath.empty()) {
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
	auto lr = Injector::LaunchAndInject(opts.program, argsStr, "", dllPath, injMethod, opts.runAsInvoker);
	if (lr.pid == 0) {
		result.error = "Launch failed: " + opts.program;
		if (!lr.error.empty()) result.error += " - " + lr.error;
		return result;
	}

	launchedMainThreadId_ = lr.mainThreadId;
	mainThreadResumed_ = false;

	targetProcess_ = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lr.pid);
	if (!targetProcess_) {
		LOG_WARN("OpenProcess(TERMINATE) failed for pid=%u", lr.pid);
	}
	launchedByUs_ = true;

	if (!pipeClient_.Connect(lr.pid, 3500)) {
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

	targetPid_ = lr.pid;
	attached_ = true;

	// Set disassembler bitness
	{
		bool is64 = !Injector::IsExe32Bit(opts.program);
		disassembler_ = CreateDisassembler(is64);
		LOG_INFO("Disassembler set to %s mode", is64 ? "x64" : "x86");
	}

	if (!opts.stopOnEntry) {
		ResumeMainThread();
	}

	result.ok = true;
	result.pid = lr.pid;
	return result;
}

bool DebugSession::Detach() {
	if (!attached_) return false;

	attached_ = false;
	ResumeMainThread();
	StopProcessMonitor();

	pipeClient_.StopHeartbeat();
	pipeClient_.StopEventListener();
	try {
		pipeClient_.SendCommand(IpcCommand::Detach);
	} catch (...) {}
	pipeClient_.Disconnect();

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
	if (!targetProcess_) return false;
	DWORD exitCode = 0;
	if (!GetExitCodeProcess(targetProcess_, &exitCode)) return false;
	return exitCode == STILL_ACTIVE;
}

// --- Breakpoints ---

BpResult DebugSession::SetBreakpoint(uint64_t address) {
	BpResult result;
	SetBreakpointRequest req;
	req.address = address;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetBreakpoint, &req, sizeof(req), respData))
		return result;

	if (respData.size() >= sizeof(SetBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			result.ok = true;
			result.id = resp->id;
		}
	}
	return result;
}

bool DebugSession::RemoveBreakpoint(uint32_t id) {
	RemoveBreakpointRequest req;
	req.id = id;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::RemoveBreakpoint, &req, sizeof(req), respData))
		return false;

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) return false;
	}
	return true;
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
	SetHwBreakpointRequest req;
	req.address = address;
	req.type = type;
	req.size = size;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetHwBreakpoint, &req, sizeof(req), respData))
		return result;

	if (respData.size() >= sizeof(SetHwBreakpointResponse)) {
		auto* resp = reinterpret_cast<const SetHwBreakpointResponse*>(respData.data());
		if (resp->status == IpcStatus::Ok) {
			result.ok = true;
			result.id = resp->id;
			result.slot = resp->slot;
		}
	}
	return result;
}

bool DebugSession::RemoveHwBreakpoint(uint32_t id) {
	RemoveHwBreakpointRequest req;
	req.id = id;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::RemoveHwBreakpoint, &req, sizeof(req), respData))
		return false;

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) return false;
	}
	return true;
}

// --- Execution control ---

bool DebugSession::Continue(uint32_t threadId, bool passException) {
	ContinueRequest req;
	req.threadId = threadId;
	req.passException = passException ? 1 : 0;
	return pipeClient_.SendCommand(IpcCommand::Continue, &req, sizeof(req));
}

bool DebugSession::StepIn(uint32_t threadId) {
	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepInto, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) return false;
	}
	return true;
}

bool DebugSession::StepOver(uint32_t threadId) {
	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepOver, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) return false;
	}
	return true;
}

bool DebugSession::StepOut(uint32_t threadId) {
	StepRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::StepOut, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		if (status == IpcStatus::NotFound) return false;
	}
	return true;
}

bool DebugSession::Pause(uint32_t threadId) {
	PauseRequest req;
	req.threadId = threadId;
	std::vector<uint8_t> respData;
	return pipeClient_.SendAndReceive(IpcCommand::Pause, &req, sizeof(req), respData);
}

void DebugSession::ResumeMainThread() {
	if (mainThreadResumed_ || launchedMainThreadId_ == 0) return;

	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, launchedMainThreadId_);
	if (hThread) {
		DWORD prevCount = ResumeThread(hThread);
		CloseHandle(hThread);
		mainThreadResumed_ = true;
		LOG_INFO("DebugSession: Resumed main thread %u (prev suspend count: %u)",
			launchedMainThreadId_, prevCount);
	} else {
		LOG_ERROR("DebugSession: Failed to open main thread %u for resume: %u",
			launchedMainThreadId_, GetLastError());
	}
}

// --- Stop event synchronization ---

StopEvent DebugSession::WaitForStop(int timeoutSec) {
	StopEvent ev;
	std::unique_lock<std::mutex> lock(stopMutex_);
	if (!stopCv_.wait_for(lock, std::chrono::seconds(timeoutSec),
			[this]{ return stopOccurred_ || !attached_; })) {
		ev.timeout = true;
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

void DebugSession::SignalStop(const std::string& reason, uint64_t addr, uint32_t threadId,
                              uint32_t bpId, const std::string& bpType) {
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		stopOccurred_ = true;
		lastStop_.stopped = true;
		lastStop_.reason = reason;
		lastStop_.address = addr;
		lastStop_.threadId = threadId;
		lastStop_.breakpointId = bpId;
		lastStop_.bpType = bpType;
	}
	stopCv_.notify_all();
}

// --- State queries ---

std::vector<ThreadEntry> DebugSession::GetThreads() {
	std::vector<ThreadEntry> result;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetThreads, nullptr, 0, respData))
		return result;

	if (respData.size() < sizeof(GetThreadsResponse)) return result;
	auto* resp = reinterpret_cast<const GetThreadsResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;

	auto* infos = reinterpret_cast<const ThreadInfo*>(respData.data() + sizeof(GetThreadsResponse));
	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetThreadsResponse))
		? (respData.size() - sizeof(GetThreadsResponse)) / sizeof(ThreadInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	result.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		result.push_back({infos[i].id, infos[i].name});
	}
	return result;
}

std::vector<StackFrame> DebugSession::GetStackTrace(uint32_t threadId, uint32_t maxFrames) {
	std::vector<StackFrame> result;
	GetStackTraceRequest req;
	req.threadId = threadId;
	req.startFrame = 0;
	req.maxFrames = maxFrames;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetStackTrace, &req, sizeof(req), respData))
		return result;

	if (respData.size() < sizeof(GetStackTraceResponse)) return result;
	auto* resp = reinterpret_cast<const GetStackTraceResponse*>(respData.data());
	auto* infos = reinterpret_cast<const StackFrameInfo*>(respData.data() + sizeof(GetStackTraceResponse));

	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetStackTraceResponse))
		? (respData.size() - sizeof(GetStackTraceResponse)) / sizeof(StackFrameInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	result.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		StackFrame f;
		f.address = infos[i].address;
		f.returnAddress = 0; // not in IPC struct
		f.frameBase = infos[i].frameBase;
		f.moduleBase = 0;
		f.moduleName = infos[i].moduleName;
		f.functionName = infos[i].functionName;
		f.sourceFile = infos[i].sourceFile;
		f.line = infos[i].line;
		result.push_back(std::move(f));
	}
	return result;
}

std::optional<RegisterSet> DebugSession::GetRegisters(uint32_t threadId) {
	GetRegistersRequest req;
	req.threadId = threadId;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetRegisters, &req, sizeof(req), respData))
		return std::nullopt;

	if (respData.size() < sizeof(GetRegistersResponse)) return std::nullopt;
	auto* resp = reinterpret_cast<const GetRegistersResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return std::nullopt;

	return resp->regs;
}

bool DebugSession::SetRegister(uint32_t threadId, uint32_t regIndex, uint64_t value) {
	SetRegisterRequest req;
	req.threadId = threadId;
	req.regIndex = regIndex;
	req.value = value;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::SetRegister, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(SetRegisterResponse)) {
		auto* resp = reinterpret_cast<const SetRegisterResponse*>(respData.data());
		return resp->status == IpcStatus::Ok;
	}
	return false;
}

std::vector<ModuleEntry> DebugSession::GetModules() {
	std::vector<ModuleEntry> result;
	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::GetModules, nullptr, 0, respData))
		return result;

	if (respData.size() < sizeof(GetModulesResponse)) return result;
	auto* resp = reinterpret_cast<const GetModulesResponse*>(respData.data());
	auto* infos = reinterpret_cast<const ModuleInfo*>(respData.data() + sizeof(GetModulesResponse));

	uint32_t count = resp->count;
	const size_t maxItems = (respData.size() > sizeof(GetModulesResponse))
		? (respData.size() - sizeof(GetModulesResponse)) / sizeof(ModuleInfo) : 0;
	if (count > maxItems) count = static_cast<uint32_t>(maxItems);

	result.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		result.push_back({infos[i].name, infos[i].path, infos[i].baseAddress, infos[i].size});
	}
	return result;
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

	EnumLocalsRequest req;
	req.threadId = threadId;
	req.instructionAddress = instrAddr;
	req.frameBase = frameBase;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::EnumLocals, &req, sizeof(req), respData))
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
	ReadMemoryRequest req;
	req.address = address;
	req.size = size;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::ReadMemory, &req, sizeof(req), respData))
		return {};

	if (respData.size() < sizeof(IpcStatus)) return {};
	auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
	if (status != IpcStatus::Ok) return {};

	const uint8_t* data = respData.data() + sizeof(IpcStatus);
	size_t dataLen = respData.size() - sizeof(IpcStatus);
	return std::vector<uint8_t>(data, data + dataLen);
}

bool DebugSession::WriteMemory(uint64_t address, const uint8_t* data, uint32_t size) {
	std::vector<uint8_t> payload(sizeof(WriteMemoryRequest) + size);
	auto* req = reinterpret_cast<WriteMemoryRequest*>(payload.data());
	req->address = address;
	req->size = size;
	memcpy(payload.data() + sizeof(WriteMemoryRequest), data, size);

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::WriteMemory, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData))
		return false;

	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		return status == IpcStatus::Ok;
	}
	return false;
}

uint64_t DebugSession::AllocateMemory(uint32_t size, uint32_t protection) {
	AllocateMemoryRequest req;
	req.size = size;
	req.protection = protection;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::AllocateMemory, &req, sizeof(req), respData))
		return 0;
	if (respData.size() < sizeof(AllocateMemoryResponse)) return 0;

	auto* resp = reinterpret_cast<const AllocateMemoryResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return 0;
	return resp->address;
}

bool DebugSession::FreeMemory(uint64_t address) {
	FreeMemoryRequest req;
	req.address = address;
	req.size = 0;

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::FreeMemory, &req, sizeof(req), respData))
		return false;
	if (respData.size() >= sizeof(IpcStatus)) {
		auto status = *reinterpret_cast<const IpcStatus*>(respData.data());
		return status == IpcStatus::Ok;
	}
	return false;
}

ShellcodeResult DebugSession::ExecuteShellcode(const uint8_t* code, uint32_t size, uint32_t timeoutMs) {
	ShellcodeResult result;

	std::vector<uint8_t> payload(sizeof(ExecuteShellcodeRequest) + size);
	auto* req = reinterpret_cast<ExecuteShellcodeRequest*>(payload.data());
	req->size = size;
	req->timeoutMs = timeoutMs;
	memcpy(payload.data() + sizeof(ExecuteShellcodeRequest), code, size);

	std::vector<uint8_t> respData;
	if (!pipeClient_.SendAndReceive(IpcCommand::ExecuteShellcode, payload.data(),
	                                 static_cast<uint32_t>(payload.size()), respData))
		return result;
	if (respData.size() < sizeof(ExecuteShellcodeResponse)) return result;

	auto* resp = reinterpret_cast<const ExecuteShellcodeResponse*>(respData.data());
	if (resp->status != IpcStatus::Ok) return result;

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

EvalResult DebugSession::Evaluate(const std::string& expression, uint32_t threadId) {
	EvalResult result;

	std::string expr = expression;
	// Trim
	while (!expr.empty() && expr.front() == ' ') expr.erase(expr.begin());
	while (!expr.empty() && expr.back() == ' ') expr.pop_back();

	// 1) Register name
	if (TryParseRegisterName(expr)) {
		if (threadId == 0) {
			result.error = "threadId is required for register evaluation";
			return result;
		}
		auto regs = GetRegisters(threadId);
		if (!regs) {
			result.error = "Failed to read registers";
			return result;
		}
		uint64_t val = ResolveRegisterByName(expr, *regs);
		char buf[32];
		if (regs->is32bit)
			snprintf(buf, sizeof(buf), "0x%08X", (uint32_t)val);
		else
			snprintf(buf, sizeof(buf), "0x%016llX", val);
		result.ok = true;
		result.value = buf;
		result.type = regs->is32bit ? "uint32" : "uint64";
		return result;
	}

	// 2) Hex address (0x...) -> memory preview
	if (expr.size() > 2 && expr[0] == '0' && (expr[1] == 'x' || expr[1] == 'X')) {
		try {
			uint64_t addr = std::stoull(expr, nullptr, 16);
			auto mem = ReadMemory(addr, 8);
			if (mem.size() >= 8) {
				uint64_t val = *reinterpret_cast<const uint64_t*>(mem.data());
				char buf[64];
				snprintf(buf, sizeof(buf), "[0x%llX] = 0x%016llX", addr, val);
				result.ok = true;
				result.value = buf;
				result.type = "memory";
				return result;
			}
		} catch (...) {}
		result.error = "Failed to read memory at " + expr;
		return result;
	}

	// 3) gs:[offset] or fs:[offset]
	{
		std::string upper = expr;
		std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
		bool isGs = (upper.substr(0, 4) == "GS:[");
		bool isFs = (upper.substr(0, 4) == "FS:[");
		if (isGs || isFs) {
			std::string offsetStr = expr.substr(4);
			if (!offsetStr.empty() && offsetStr.back() == ']') offsetStr.pop_back();
			while (!offsetStr.empty() && offsetStr.front() == ' ') offsetStr.erase(offsetStr.begin());
			try {
				uint64_t offset = std::stoull(offsetStr, nullptr, 0);
				if (threadId == 0) {
					result.error = "threadId is required for segment register evaluation";
					return result;
				}
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
				if (!hThread) {
					result.error = "Failed to open thread";
					return result;
				}

				typedef struct {
					LONG ExitStatus;
					PVOID TebBaseAddress;
					struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId;
					ULONG_PTR AffinityMask;
					LONG Priority;
					LONG BasePriority;
				} THREAD_BASIC_INFORMATION;

				typedef LONG(NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
				auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(
					GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
				if (!NtQueryInformationThread) {
					CloseHandle(hThread);
					result.error = "NtQueryInformationThread not found";
					return result;
				}

				BOOL isWow64 = FALSE;
				IsWow64Process(targetProcess_ ? targetProcess_ : GetCurrentProcess(), &isWow64);
				if ((!isWow64 && isFs) || (isWow64 && isGs)) {
					CloseHandle(hThread);
					result.error = isFs ? "fs:[] is x86 only (use gs:[] for x64)" : "gs:[] is x64 only (use fs:[] for x86)";
					return result;
				}

				THREAD_BASIC_INFORMATION tbi = {};
				LONG ntStatus = NtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), nullptr);
				CloseHandle(hThread);

				if (ntStatus != 0) {
					result.error = "NtQueryInformationThread failed";
					return result;
				}

				uint64_t tebAddr = reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
				uint64_t targetAddr = tebAddr + offset;

				auto mem = ReadMemory(targetAddr, 8);
				if (mem.size() >= 8) {
					uint64_t val = *reinterpret_cast<const uint64_t*>(mem.data());
					char buf[80];
					snprintf(buf, sizeof(buf), "0x%016llX (TEB=0x%llX + 0x%llX)", val, tebAddr, offset);
					result.ok = true;
					result.value = buf;
					result.type = "segment";
					result.tebAddress = (std::ostringstream() << "0x" << std::hex << tebAddr).str();
					return result;
				}
				result.error = "Failed to read memory at segment base + offset";
				return result;
			} catch (...) {}
			result.error = "Invalid offset in segment expression";
			return result;
		}
	}

	// 4) *expr or [expr] -> pointer dereference
	if (!expr.empty() && (expr[0] == '*' || expr[0] == '[')) {
		std::string inner = expr.substr(1);
		if (!inner.empty() && inner.back() == ']') inner.pop_back();
		while (!inner.empty() && inner.front() == ' ') inner.erase(inner.begin());
		while (!inner.empty() && inner.back() == ' ') inner.pop_back();

		uint64_t addr = 0;
		bool resolved = false;
		try {
			addr = std::stoull(inner, nullptr, 0);
			resolved = true;
		} catch (...) {}

		if (!resolved && threadId != 0) {
			auto regs = GetRegisters(threadId);
			if (regs) {
				// Find + or - operator
				size_t opPos = std::string::npos;
				char opChar = 0;
				for (size_t i = 1; i < inner.size(); i++) {
					if (inner[i] == '+' || inner[i] == '-') {
						opPos = i;
						opChar = inner[i];
						break;
					}
				}

				if (opPos != std::string::npos) {
					std::string lhs = inner.substr(0, opPos);
					std::string rhs = inner.substr(opPos + 1);
					while (!lhs.empty() && lhs.back() == ' ') lhs.pop_back();
					while (!rhs.empty() && rhs.front() == ' ') rhs.erase(rhs.begin());

					uint64_t lhsVal = 0, rhsVal = 0;
					bool lhsOk = false, rhsOk = false;

					if (TryParseRegisterName(lhs)) {
						lhsVal = ResolveRegisterByName(lhs, *regs);
						lhsOk = true;
					} else {
						try { lhsVal = std::stoull(lhs, nullptr, 0); lhsOk = true; } catch (...) {}
					}

					if (TryParseRegisterName(rhs)) {
						rhsVal = ResolveRegisterByName(rhs, *regs);
						rhsOk = true;
					} else {
						try { rhsVal = std::stoull(rhs, nullptr, 0); rhsOk = true; } catch (...) {}
					}

					if (lhsOk && rhsOk) {
						addr = (opChar == '+') ? (lhsVal + rhsVal) : (lhsVal - rhsVal);
						resolved = true;
					}
				} else {
					if (TryParseRegisterName(inner)) {
						addr = ResolveRegisterByName(inner, *regs);
						resolved = true;
					}
				}
			}
		}

		if (!resolved) {
			result.error = "Cannot parse address expression: " + inner;
			return result;
		}

		result.address = addr;
		auto mem = ReadMemory(addr, 8);
		if (mem.size() >= 8) {
			uint64_t val = *reinterpret_cast<const uint64_t*>(mem.data());
			char buf[64];
			snprintf(buf, sizeof(buf), "0x%016llX", val);
			result.ok = true;
			result.value = buf;
			result.type = "pointer";
			return result;
		}
		result.error = "Failed to read memory at computed address";
		return result;
	}

	result.error = "Supported: register (RAX), 0x<addr>, [addr], [reg+offset], gs:[offset], fs:[offset]";
	return result;
}

TraceResult DebugSession::TraceCallers(uint64_t address, uint32_t durationSec) {
	TraceResult result;

	// Auto-resume
	ResumeMainThread();
	ContinueRequest contReq = {};
	contReq.threadId = 0;
	pipeClient_.SendCommand(IpcCommand::Continue, &contReq, sizeof(contReq));

	TraceCallersRequest req;
	req.address = address;
	req.durationMs = durationSec * 1000;

	std::vector<uint8_t> respData;
	int timeoutMs = (durationSec + 10) * 1000;
	if (!pipeClient_.SendAndReceive(IpcCommand::TraceCallers, &req, sizeof(req), respData, timeoutMs)) {
		PauseRequest pauseReq; pauseReq.threadId = 0;
		pipeClient_.SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));
		return result;
	}

	// Auto-pause after collection
	PauseRequest pauseReq; pauseReq.threadId = 0;
	pipeClient_.SendCommand(IpcCommand::Pause, &pauseReq, sizeof(pauseReq));

	// Drain stale stop events
	{
		std::lock_guard<std::mutex> lock(stopMutex_);
		stopOccurred_ = false;
	}

	if (respData.size() < sizeof(TraceCallersResponse)) return result;
	const auto* hdr = reinterpret_cast<const TraceCallersResponse*>(respData.data());
	if (hdr->status != IpcStatus::Ok) return result;

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

// --- PDB resolve ---

uint64_t DebugSession::ResolveSourceLine(const std::string& file, uint32_t line) {
	ResolveSourceLineRequest req = {};
	strncpy_s(req.fileName, file.c_str(), sizeof(req.fileName) - 1);
	req.line = line;

	std::vector<uint8_t> resp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ResolveSourceLine, &req, sizeof(req), resp))
		return 0;
	if (resp.size() < sizeof(ResolveSourceLineResponse)) return 0;
	auto* resolved = reinterpret_cast<const ResolveSourceLineResponse*>(resp.data());
	if (resolved->status != IpcStatus::Ok) return 0;
	return resolved->address;
}

uint64_t DebugSession::ResolveFunction(const std::string& name) {
	ResolveFunctionRequest req = {};
	strncpy_s(req.functionName, name.c_str(), sizeof(req.functionName) - 1);

	std::vector<uint8_t> resp;
	if (!pipeClient_.SendAndReceive(IpcCommand::ResolveFunction, &req, sizeof(req), resp))
		return 0;
	if (resp.size() < sizeof(ResolveFunctionResponse)) return 0;
	auto* resolved = reinterpret_cast<const ResolveFunctionResponse*>(resp.data());
	if (resolved->status != IpcStatus::Ok) return 0;
	return resolved->address;
}

// --- IPC event handling ---

void DebugSession::SetEventCallback(EventCallback cb) {
	pipeClient_.StartEventListener([this, cb](uint32_t eventId, const uint8_t* payload, uint32_t size) {
		if (cb) cb(eventId, payload, size);
	});
	pipeClient_.StartHeartbeat();
}

// --- Process monitor ---

void DebugSession::StartProcessMonitor() {
	StopProcessMonitor();
	if (!targetProcess_) return;

	HANDLE hWait = OpenProcess(SYNCHRONIZE, FALSE, targetPid_);
	if (!hWait) {
		LOG_WARN("Cannot open process %u for SYNCHRONIZE", targetPid_);
		return;
	}

	monitorStopEvent_ = CreateEvent(nullptr, TRUE, FALSE, nullptr);

	processMonitorThread_ = std::thread([this, hWait, stopEv = monitorStopEvent_]() {
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

			// Pipe cleanup
			pipeClient_.StopHeartbeat();
			pipeClient_.StopEventListener();
			pipeClient_.Disconnect();

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
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
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

uint64_t DebugSession::ResolveRegisterByName(const std::string& name, const RegisterSet& regs) {
	std::string upper = name;
	if (!upper.empty() && upper[0] == '$') upper = upper.substr(1);
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
	const uint64_t* r = &regs.rax;
	static const std::pair<const char*, int> map[] = {
		{"RAX",0},{"EAX",0},{"RBX",1},{"EBX",1},{"RCX",2},{"ECX",2},{"RDX",3},{"EDX",3},
		{"RSI",4},{"ESI",4},{"RDI",5},{"EDI",5},{"RBP",6},{"EBP",6},{"RSP",7},{"ESP",7},
		{"R8",8},{"R9",9},{"R10",10},{"R11",11},{"R12",12},{"R13",13},{"R14",14},{"R15",15},
		{"RIP",16},{"EIP",16},{"RFLAGS",17},{"EFLAGS",17},
	};
	for (auto& [rn, idx] : map) {
		if (upper == rn) {
			uint64_t val = r[idx];
			if (upper[0] == 'E' && upper != "EFLAGS") val &= 0xFFFFFFFF;
			return val;
		}
	}
	return 0;
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
