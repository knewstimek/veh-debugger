#include <windows.h>
#include "pipe_server.h"
#include "veh_handler.h"
#include "breakpoint.h"
#include "hw_breakpoint.h"
#include "threads.h"
#include "stack_walk.h"
#include "memory.h"
#include "../common/ipc_protocol.h"
#include "../common/logger.h"

#include <tlhelp32.h>
#include <dbghelp.h>
#include <cstring>
#pragma comment(lib, "dbghelp.lib")

namespace veh {

PipeServer& PipeServer::Instance() {
	static PipeServer instance;
	return instance;
}

// --- Overlapped I/O helpers ---

bool PipeServer::AsyncReadExact(void* buf, DWORD size, DWORD timeoutMs) {
	DWORD totalRead = 0;
	while (totalRead < size) {
		OVERLAPPED ov = {};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;

		DWORD bytesRead = 0;
		BOOL ok = ReadFile(pipe_, static_cast<uint8_t*>(buf) + totalRead,
		                   size - totalRead, &bytesRead, &ov);

		if (!ok && GetLastError() != ERROR_IO_PENDING) {
			CloseHandle(ov.hEvent);
			return false;
		}

		if (ok) {
			CloseHandle(ov.hEvent);
			if (bytesRead == 0) return false;
			totalRead += bytesRead;
			continue;
		}

		HANDLE events[] = { ov.hEvent, stopEvent_ };
		DWORD nEvents = stopEvent_ ? 2 : 1;
		DWORD wait = WaitForMultipleObjects(nEvents, events, FALSE, timeoutMs);

		if (wait == WAIT_OBJECT_0) {
			GetOverlappedResult(pipe_, &ov, &bytesRead, FALSE);
			CloseHandle(ov.hEvent);
			if (bytesRead == 0) return false;
			totalRead += bytesRead;
		} else {
			CancelIoEx(pipe_, &ov);
			CloseHandle(ov.hEvent);
			return false;  // 타임아웃 or stop
		}
	}
	return true;
}

bool PipeServer::AsyncWriteExact(const void* buf, DWORD size, DWORD timeoutMs) {
	DWORD totalWritten = 0;
	while (totalWritten < size) {
		OVERLAPPED ov = {};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;

		DWORD bytesWritten = 0;
		BOOL ok = WriteFile(pipe_, static_cast<const uint8_t*>(buf) + totalWritten,
		                    size - totalWritten, &bytesWritten, &ov);

		if (!ok && GetLastError() != ERROR_IO_PENDING) {
			CloseHandle(ov.hEvent);
			return false;
		}

		if (ok) {
			CloseHandle(ov.hEvent);
			if (bytesWritten == 0) return false;
			totalWritten += bytesWritten;
			continue;
		}

		HANDLE events[] = { ov.hEvent, stopEvent_ };
		DWORD nEvents = stopEvent_ ? 2 : 1;
		DWORD wait = WaitForMultipleObjects(nEvents, events, FALSE, timeoutMs);

		if (wait == WAIT_OBJECT_0) {
			GetOverlappedResult(pipe_, &ov, &bytesWritten, FALSE);
			CloseHandle(ov.hEvent);
			if (bytesWritten == 0) return false;
			totalWritten += bytesWritten;
		} else {
			CancelIoEx(pipe_, &ov);
			CloseHandle(ov.hEvent);
			return false;
		}
	}
	return true;
}

// --- Lifecycle ---

bool PipeServer::Start(uint32_t targetPid) {
	if (running_) {
		LOG_WARN("PipeServer already running");
		return true;
	}

	targetPid_ = targetPid;
	std::wstring pipeName = GetPipeName(targetPid);

	stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!stopEvent_) {
		LOG_ERROR("CreateEventW for stopEvent_ failed: %lu", GetLastError());
		return false;
	}

	// Overlapped Named pipe
	pipe_ = CreateNamedPipeW(
		pipeName.c_str(),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1, 64 * 1024, 64 * 1024, 0, NULL
	);

	if (pipe_ == INVALID_HANDLE_VALUE) {
		LOG_ERROR("CreateNamedPipeW failed: %lu", GetLastError());
		return false;
	}

	running_ = true;
	serverThread_ = std::thread(&PipeServer::ServerThread, this);

	LOG_INFO("PipeServer started: %ls [overlapped]", pipeName.c_str());
	return true;
}

void PipeServer::Stop() {
	if (!running_) return;
	running_ = false;

	if (stopEvent_) SetEvent(stopEvent_);
	if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);

	if (serverThread_.joinable()) {
		serverThread_.join();
	}

	if (connected_) {
		DisconnectNamedPipe(pipe_);
		connected_ = false;
	}
	if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
	if (stopEvent_) { CloseHandle(stopEvent_); stopEvent_ = nullptr; }

	LOG_INFO("PipeServer stopped");
}

void PipeServer::EmergencyCleanup() {
	LOG_WARN("Emergency cleanup: adapter presumed dead");
	BreakpointManager::Instance().RemoveAll();
	HwBreakpointManager::Instance().RemoveAll();
	VehHandler::Instance().Uninstall();
	ThreadManager::Instance().ResumeAll();
	LOG_INFO("Emergency cleanup done: VEH uninstalled, all BPs removed, threads resumed");
}

void PipeServer::ServerThread() {
	LOG_INFO("Server thread started");

	// DbgHelp 심볼 엔진 초기화
	StackWalker::Instance().Initialize();

	// 외부 루프: running_ 동안 클라이언트 연결을 반복 수락한다.
	// Detach 시 내부 커맨드 루프만 탈출하고 여기서 새 클라이언트를 기다린다.
	// Shutdown 시 running_=false가 되어 외부 루프도 종료된다.
	while (running_) {
		LOG_INFO("Waiting for client connection...");

		// Overlapped ConnectNamedPipe
		{
			OVERLAPPED ov = {};
			ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			BOOL ok = ConnectNamedPipe(pipe_, &ov);
			if (!ok) {
				DWORD err = GetLastError();
				if (err == ERROR_PIPE_CONNECTED) {
					// 이미 연결됨 — 정상
				} else if (err == ERROR_IO_PENDING) {
					HANDLE events[] = { ov.hEvent, stopEvent_ };
					// 재연결 대기: 타임아웃 없이 무한 대기 (stopEvent_로 깨움)
					DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
					if (wait != WAIT_OBJECT_0) {
						CloseHandle(ov.hEvent);
						if (running_) LOG_ERROR("ConnectNamedPipe stopped");
						break;
					}
					DWORD dummy;
					GetOverlappedResult(pipe_, &ov, &dummy, FALSE);
				} else {
					CloseHandle(ov.hEvent);
					LOG_ERROR("ConnectNamedPipe failed: %lu", err);
					break;
				}
			}
			CloseHandle(ov.hEvent);
		}

		if (!running_) break;

		connected_ = true;
		lastCommandTime_ = GetTickCount64();
		LOG_INFO("Client connected");

		// Detach 후 재연결 시 VEH 재설치 (최초 연결은 InitThread가 처리)
		if (!VehHandler::Instance().IsInstalled()) {
			VehHandler::Instance().Install();
			LOG_INFO("VEH handler re-installed for new session");
		}

		// Ready 이벤트 전송
		SendEvent(static_cast<uint32_t>(IpcEvent::Ready));

		// 내부 커맨드 루프: running_ && connected_ 동안 명령 처리
		// Detach 시 connected_=false로 내부 루프만 탈출
		// Shutdown 시 running_=false로 양쪽 루프 모두 탈출
		while (running_ && connected_) {
			IpcHeader hdr;
			if (!AsyncReadExact(&hdr, sizeof(hdr), READ_TIMEOUT_MS)) {
				if (!running_ || !connected_) break;

				// 하트비트 타임아웃 체크
				uint64_t elapsed = GetTickCount64() - lastCommandTime_;
				if (elapsed >= HEARTBEAT_TIMEOUT_MS) {
					LOG_ERROR("Heartbeat timeout: no command for %llu ms", elapsed);
					EmergencyCleanup();
					connected_ = false;
					break;
				}
				// 타임아웃이면 재시도 (정상 — READ_TIMEOUT_MS마다 체크)
				continue;
			}

			lastCommandTime_ = GetTickCount64();

			std::vector<uint8_t> payload;
			if (hdr.payloadSize > 0) {
				if (hdr.payloadSize > 16 * 1024 * 1024) {
					LOG_ERROR("Payload too large: %u", hdr.payloadSize);
					connected_ = false;
					break;
				}
				payload.resize(hdr.payloadSize);
				if (!AsyncReadExact(payload.data(), hdr.payloadSize, 3000)) {
					LOG_ERROR("AsyncReadExact(payload) failed");
					connected_ = false;
					break;
				}
			}

			LOG_DEBUG("IPC cmd=0x%04X size=%u", hdr.command, hdr.payloadSize);
			HandleCommand(hdr.command, payload.data(), hdr.payloadSize);
		}

		// Detach 후: 파이프 연결만 끊고 외부 루프에서 새 클라이언트 대기
		// Shutdown 후: running_=false이므로 외부 루프도 종료
		if (running_) {
			DisconnectNamedPipe(pipe_);
			LOG_INFO("Client disconnected, ready for re-connection");
		}
	}

	connected_ = false;
	LOG_INFO("Server thread exiting");
}

void PipeServer::HandleCommand(uint32_t command, const uint8_t* payload, uint32_t payloadSize) {
	auto cmd = static_cast<IpcCommand>(command);

	switch (cmd) {

	case IpcCommand::Heartbeat: {
		// 하트비트 응답 — HeartbeatAck 이벤트 전송
		SendEvent(static_cast<uint32_t>(IpcEvent::HeartbeatAck));
		break;
	}

	case IpcCommand::SetBreakpoint: {
		if (payloadSize < sizeof(SetBreakpointRequest)) {
			SetBreakpointResponse resp{IpcStatus::InvalidArgs, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetBreakpointRequest*>(payload);
		LOG_INFO("SetBreakpoint: addr=0x%llX", req->address);
		uint32_t id = BreakpointManager::Instance().Add(req->address);

		SetBreakpointResponse resp;
		resp.status = id ? IpcStatus::Ok : IpcStatus::Error;
		resp.id = id;
		SendResponse(command, &resp, sizeof(resp));
		LOG_INFO("SetBreakpoint: addr=0x%llX -> id=%u status=%d", req->address, id, (int)resp.status);
		break;
	}

	case IpcCommand::RemoveBreakpoint: {
		if (payloadSize < sizeof(RemoveBreakpointRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const RemoveBreakpointRequest*>(payload);
		bool ok = BreakpointManager::Instance().Remove(req->id);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::NotFound;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::SetHwBreakpoint: {
		if (payloadSize < sizeof(SetHwBreakpointRequest)) {
			SetHwBreakpointResponse resp{IpcStatus::InvalidArgs, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}
		auto* req = reinterpret_cast<const SetHwBreakpointRequest*>(payload);
		auto type = static_cast<HwBreakType>(req->type);
		HwBreakSize bpSize;
		switch (req->size) {
		case 1: bpSize = HwBreakSize::Byte;  break;
		case 2: bpSize = HwBreakSize::Word;  break;
		case 4: bpSize = HwBreakSize::Dword; break;
		case 8: bpSize = HwBreakSize::Qword; break;
		default:
			SetHwBreakpointResponse resp{IpcStatus::InvalidArgs, 0, 0};
			SendResponse(command, &resp, sizeof(resp));
			return;
		}

		uint32_t id = HwBreakpointManager::Instance().Add(req->address, type, bpSize);
		SetHwBreakpointResponse resp;
		resp.status = id ? IpcStatus::Ok : IpcStatus::Error;
		resp.id = id;
		resp.slot = 0;
		if (id) {
			auto hwbp = HwBreakpointManager::Instance().FindById(id);
			if (hwbp) resp.slot = hwbp->slot;
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::RemoveHwBreakpoint: {
		if (payloadSize < sizeof(RemoveHwBreakpointRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const RemoveHwBreakpointRequest*>(payload);
		bool ok = HwBreakpointManager::Instance().Remove(req->id);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::NotFound;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::Continue: {
		if (payloadSize < sizeof(ContinueRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ContinueRequest*>(payload);
		// VEH 핸들러에서 대기 중인 스레드를 깨운다
		if (req->threadId == 0) {
			VehHandler::Instance().ResumeAllStoppedThreads();
		} else {
			VehHandler::Instance().ResumeStoppedThread(req->threadId);
		}
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::StepOver:
	case IpcCommand::StepInto: {
		if (payloadSize < sizeof(StepRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const StepRequest*>(payload);
		// 싱글스텝 TF 설정: 정지된 컨텍스트에서 직접 설정은 불가
		// VEH 핸들러가 재개 후 다음 명령어에서 TF를 설정하도록 함
		// → 여기서는 단순히 resume하고, VEH 핸들러 쪽에서 처리
		bool ok = ThreadManager::Instance().SetSingleStep(req->threadId);
		VehHandler::Instance().ResumeStoppedThread(req->threadId);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::StepOut: {
		if (payloadSize < sizeof(StepRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const StepRequest*>(payload);
		bool ok = ThreadManager::Instance().SetSingleStep(req->threadId);
		VehHandler::Instance().ResumeStoppedThread(req->threadId);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::TerminateThread: {
		if (payloadSize < sizeof(TerminateThreadRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const TerminateThreadRequest*>(payload);
		HANDLE hThread = ::OpenThread(THREAD_TERMINATE, FALSE, req->threadId);
		IpcStatus status = IpcStatus::Error;
		if (hThread) {
			if (::TerminateThread(hThread, 0)) status = IpcStatus::Ok;
			CloseHandle(hThread);
		}
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::SetInstructionPointer: {
		if (payloadSize < sizeof(SetInstructionPointerRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const SetInstructionPointerRequest*>(payload);
		CONTEXT ctx;
		IpcStatus status = IpcStatus::Error;
		if (ThreadManager::Instance().GetContext(req->threadId, ctx)) {
#ifdef _WIN64
			ctx.Rip = req->address;
#else
			ctx.Eip = static_cast<DWORD>(req->address);
#endif
			if (ThreadManager::Instance().SetContext(req->threadId, ctx)) {
				status = IpcStatus::Ok;
			}
		}
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::Pause: {
		if (payloadSize < sizeof(PauseRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const PauseRequest*>(payload);
		if (req->threadId == 0) {
			ThreadManager::Instance().SuspendAllExcept(GetCurrentThreadId());
		} else {
			ThreadManager::Instance().SuspendThread(req->threadId);
		}
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::GetThreads: {
		auto threads = ThreadManager::Instance().EnumerateThreads();
		GetThreadsResponse resp;
		resp.status = IpcStatus::Ok;
		resp.count = static_cast<uint32_t>(threads.size());

		std::vector<uint8_t> buf(sizeof(resp) + threads.size() * sizeof(ThreadInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		auto* infos = reinterpret_cast<ThreadInfo*>(buf.data() + sizeof(resp));
		for (size_t i = 0; i < threads.size(); ++i) {
			infos[i].id = threads[i].id;
			memset(infos[i].name, 0, sizeof(infos[i].name));
			strncpy_s(infos[i].name, threads[i].name.c_str(), sizeof(infos[i].name) - 1);
		}
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetStackTrace: {
		if (payloadSize < sizeof(GetStackTraceRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const GetStackTraceRequest*>(payload);
		auto frames = StackWalker::Instance().Walk(req->threadId, req->startFrame, req->maxFrames);

		GetStackTraceResponse resp;
		resp.status = IpcStatus::Ok;
		resp.totalFrames = static_cast<uint32_t>(frames.size());
		resp.count = static_cast<uint32_t>(frames.size());

		std::vector<uint8_t> buf(sizeof(resp) + frames.size() * sizeof(StackFrameInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		auto* infos = reinterpret_cast<StackFrameInfo*>(buf.data() + sizeof(resp));
		for (size_t i = 0; i < frames.size(); ++i) {
			infos[i].address       = frames[i].address;
			infos[i].returnAddress = frames[i].returnAddress;
			infos[i].frameBase     = frames[i].frameBase;
			infos[i].line          = frames[i].line;
			memset(infos[i].moduleName, 0, sizeof(infos[i].moduleName));
			strncpy_s(infos[i].moduleName, frames[i].moduleName.c_str(), sizeof(infos[i].moduleName) - 1);
			memset(infos[i].functionName, 0, sizeof(infos[i].functionName));
			strncpy_s(infos[i].functionName, frames[i].functionName.c_str(), sizeof(infos[i].functionName) - 1);
			memset(infos[i].sourceFile, 0, sizeof(infos[i].sourceFile));
			strncpy_s(infos[i].sourceFile, frames[i].sourceFile.c_str(), sizeof(infos[i].sourceFile) - 1);
		}
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::GetRegisters: {
		if (payloadSize < sizeof(GetRegistersRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const GetRegistersRequest*>(payload);
		CONTEXT ctx;
		GetRegistersResponse resp;
		memset(&resp, 0, sizeof(resp));

		// VEH 정지 컨텍스트를 먼저 시도, 실패 시 ThreadManager::GetContext fallback
		bool gotContext = VehHandler::Instance().GetStoppedContext(req->threadId, ctx)
			|| ThreadManager::Instance().GetContext(req->threadId, ctx);
		if (gotContext) {
			resp.status = IpcStatus::Ok;
#ifdef _WIN64
			resp.regs.is32bit = 0;
			resp.regs.rax = ctx.Rax; resp.regs.rbx = ctx.Rbx;
			resp.regs.rcx = ctx.Rcx; resp.regs.rdx = ctx.Rdx;
			resp.regs.rsi = ctx.Rsi; resp.regs.rdi = ctx.Rdi;
			resp.regs.rbp = ctx.Rbp; resp.regs.rsp = ctx.Rsp;
			resp.regs.r8  = ctx.R8;  resp.regs.r9  = ctx.R9;
			resp.regs.r10 = ctx.R10; resp.regs.r11 = ctx.R11;
			resp.regs.r12 = ctx.R12; resp.regs.r13 = ctx.R13;
			resp.regs.r14 = ctx.R14; resp.regs.r15 = ctx.R15;
			resp.regs.rip = ctx.Rip;
			resp.regs.rflags = ctx.EFlags;
			resp.regs.cs = ctx.SegCs; resp.regs.ss = ctx.SegSs;
			resp.regs.ds = ctx.SegDs; resp.regs.es = ctx.SegEs;
			resp.regs.fs = ctx.SegFs; resp.regs.gs = ctx.SegGs;
			// Debug registers
			resp.regs.dr0 = ctx.Dr0; resp.regs.dr1 = ctx.Dr1;
			resp.regs.dr2 = ctx.Dr2; resp.regs.dr3 = ctx.Dr3;
			resp.regs.dr6 = ctx.Dr6; resp.regs.dr7 = ctx.Dr7;
			static_assert(sizeof(ctx.FltSave.XmmRegisters) >= sizeof(resp.regs.xmm),
				"XMM register size mismatch");
			memcpy(resp.regs.xmm, ctx.FltSave.XmmRegisters, sizeof(resp.regs.xmm));
#else
			resp.regs.is32bit = 1;
			resp.regs.rax = ctx.Eax; resp.regs.rbx = ctx.Ebx;
			resp.regs.rcx = ctx.Ecx; resp.regs.rdx = ctx.Edx;
			resp.regs.rsi = ctx.Esi; resp.regs.rdi = ctx.Edi;
			resp.regs.rbp = ctx.Ebp; resp.regs.rsp = ctx.Esp;
			resp.regs.r8 = 0;  resp.regs.r9 = 0;
			resp.regs.r10 = 0; resp.regs.r11 = 0;
			resp.regs.r12 = 0; resp.regs.r13 = 0;
			resp.regs.r14 = 0; resp.regs.r15 = 0;
			resp.regs.rip = ctx.Eip;
			resp.regs.rflags = ctx.EFlags;
			resp.regs.cs = ctx.SegCs; resp.regs.ss = ctx.SegSs;
			resp.regs.ds = ctx.SegDs; resp.regs.es = ctx.SegEs;
			resp.regs.fs = ctx.SegFs; resp.regs.gs = ctx.SegGs;
			// Debug registers (x86도 동일한 CONTEXT 필드)
			resp.regs.dr0 = ctx.Dr0; resp.regs.dr1 = ctx.Dr1;
			resp.regs.dr2 = ctx.Dr2; resp.regs.dr3 = ctx.Dr3;
			resp.regs.dr6 = ctx.Dr6; resp.regs.dr7 = ctx.Dr7;
			// x86에는 XMM이 FloatSave에 포함되지 않음 — 0으로 초기화
			memset(resp.regs.xmm, 0, sizeof(resp.regs.xmm));
#endif
		} else {
			resp.status = IpcStatus::Error;
		}
		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::ReadMemory: {
		if (payloadSize < sizeof(ReadMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ReadMemoryRequest*>(payload);
		if (req->size > 16 * 1024 * 1024) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto data = MemoryManager::Instance().Read(req->address, req->size);

		IpcStatus status = data.empty() ? IpcStatus::Error : IpcStatus::Ok;
		std::vector<uint8_t> buf(sizeof(IpcStatus) + data.size());
		memcpy(buf.data(), &status, sizeof(status));
		if (!data.empty()) memcpy(buf.data() + sizeof(status), data.data(), data.size());
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::WriteMemory: {
		if (payloadSize < sizeof(WriteMemoryRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const WriteMemoryRequest*>(payload);
		const uint8_t* data = payload + sizeof(WriteMemoryRequest);
		uint32_t dataSize = payloadSize - sizeof(WriteMemoryRequest);
		if (dataSize != req->size) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		bool ok = MemoryManager::Instance().Write(req->address, data, dataSize);
		IpcStatus status = ok ? IpcStatus::Ok : IpcStatus::Error;
		SendResponse(command, &status, sizeof(status));
		break;
	}

	case IpcCommand::ResolveSourceLine: {
		if (payloadSize < sizeof(ResolveSourceLineRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ResolveSourceLineRequest*>(payload);

		// 안전한 복사본 생성 — null 종단 강제
		ResolveSourceLineRequest safeReq = *req;
		safeReq.fileName[sizeof(safeReq.fileName) - 1] = '\0';

		ResolveSourceLineResponse resp;
		resp.status = IpcStatus::Error;
		resp.address = 0;

		IMAGEHLP_LINE64 lineInfo = {};
		lineInfo.SizeOfStruct = sizeof(lineInfo);
		LONG displacement = 0;

		// SymGetLineFromName64 대신 전체 모듈 순회
		HANDLE hProcess = GetCurrentProcess();
		if (SymGetLineFromName64(hProcess, NULL, safeReq.fileName, safeReq.line, &displacement, &lineInfo)) {
			resp.status = IpcStatus::Ok;
			resp.address = lineInfo.Address;
			LOG_INFO("ResolveSourceLine: %s:%u -> 0x%llX", safeReq.fileName, safeReq.line, resp.address);
		} else {
			LOG_WARN("ResolveSourceLine failed: %s:%u (error=%lu)", safeReq.fileName, safeReq.line, GetLastError());
		}

		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::ResolveFunction: {
		if (payloadSize < sizeof(ResolveFunctionRequest)) {
			IpcStatus status = IpcStatus::InvalidArgs;
			SendResponse(command, &status, sizeof(status));
			return;
		}
		auto* req = reinterpret_cast<const ResolveFunctionRequest*>(payload);

		// 안전한 복사본 생성 — null 종단 강제
		ResolveFunctionRequest safeReq = *req;
		safeReq.functionName[sizeof(safeReq.functionName) - 1] = '\0';

		ResolveFunctionResponse resp;
		resp.status = IpcStatus::Error;
		resp.address = 0;

		constexpr size_t kSymBufSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME;
		uint8_t symBuf[kSymBufSize];
		auto* symInfo = reinterpret_cast<SYMBOL_INFO*>(symBuf);
		symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		symInfo->MaxNameLen = MAX_SYM_NAME;

		HANDLE hProcess = GetCurrentProcess();
		if (SymFromName(hProcess, safeReq.functionName, symInfo)) {
			resp.status = IpcStatus::Ok;
			resp.address = symInfo->Address;
			LOG_INFO("ResolveFunction: %s -> 0x%llX", safeReq.functionName, resp.address);
		} else {
			LOG_WARN("ResolveFunction failed: %s (error=%lu)", safeReq.functionName, GetLastError());
		}

		SendResponse(command, &resp, sizeof(resp));
		break;
	}

	case IpcCommand::GetModules: {
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid_);
		if (snap == INVALID_HANDLE_VALUE) {
			GetModulesResponse resp{IpcStatus::Error, 0};
			SendResponse(command, &resp, sizeof(resp));
			break;
		}
		std::vector<ModuleInfo> modules;
		MODULEENTRY32W me;
		me.dwSize = sizeof(me);
		if (Module32FirstW(snap, &me)) {
			do {
				ModuleInfo mi = {};
				mi.baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
				mi.size = me.modBaseSize;
				WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, mi.name, sizeof(mi.name), NULL, NULL);
				mi.name[sizeof(mi.name) - 1] = '\0';
				WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, mi.path, sizeof(mi.path), NULL, NULL);
				mi.path[sizeof(mi.path) - 1] = '\0';
				modules.push_back(mi);
			} while (Module32NextW(snap, &me));
		}
		CloseHandle(snap);

		GetModulesResponse resp;
		resp.status = IpcStatus::Ok;
		resp.count = static_cast<uint32_t>(modules.size());
		std::vector<uint8_t> buf(sizeof(resp) + modules.size() * sizeof(ModuleInfo));
		memcpy(buf.data(), &resp, sizeof(resp));
		if (!modules.empty()) memcpy(buf.data() + sizeof(resp), modules.data(), modules.size() * sizeof(ModuleInfo));
		SendResponse(command, buf.data(), static_cast<uint32_t>(buf.size()));
		break;
	}

	case IpcCommand::Detach: {
		// Detach: 디버깅 상태만 정리하고 파이프 서버는 유지한다.
		// connected_=false로 내부 커맨드 루프만 탈출 → 외부 루프에서 새 클라이언트 대기
		// 이를 통해 어댑터가 다시 attach 할 때 DLL 재주입 없이 즉시 연결 가능
		LOG_INFO("Detach requested");
		BreakpointManager::Instance().RemoveAll();
		HwBreakpointManager::Instance().RemoveAll();
		VehHandler::Instance().ResumeAllStoppedThreads();
		VehHandler::Instance().Uninstall();
		ThreadManager::Instance().ResumeAll();
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		connected_ = false;
		break;
	}

	case IpcCommand::Shutdown: {
		// Shutdown: 완전 종료. running_=false로 ServerThread 자체가 종료된다.
		// 프로세스 종료 또는 DLL 언로드 시 사용
		LOG_INFO("Shutdown requested");
		BreakpointManager::Instance().RemoveAll();
		HwBreakpointManager::Instance().RemoveAll();
		VehHandler::Instance().Uninstall();
		IpcStatus status = IpcStatus::Ok;
		SendResponse(command, &status, sizeof(status));
		running_ = false;
		break;
	}

	default:
		LOG_WARN("Unknown command: 0x%04X", command);
		IpcStatus status = IpcStatus::InvalidArgs;
		SendResponse(command, &status, sizeof(status));
		break;
	}
}

bool PipeServer::SendEvent(uint32_t eventId, const void* payload, uint32_t payloadSize) {
	if (!connected_ || pipe_ == INVALID_HANDLE_VALUE) return false;
	auto msg = BuildIpcMessage(eventId, payload, payloadSize);
	std::lock_guard<std::mutex> lock(writeMutex_);
	return AsyncWriteExact(msg.data(), static_cast<DWORD>(msg.size()));
}

bool PipeServer::SendResponse(uint32_t command, const void* payload, uint32_t payloadSize) {
	if (!connected_ || pipe_ == INVALID_HANDLE_VALUE) return false;
	auto msg = BuildIpcMessage(command, payload, payloadSize);
	std::lock_guard<std::mutex> lock(writeMutex_);
	return AsyncWriteExact(msg.data(), static_cast<DWORD>(msg.size()));
}

} // namespace veh
