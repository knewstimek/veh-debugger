#include "pipe_client.h"
#include "logger.h"
#include <chrono>

namespace veh {

// --- Overlapped I/O helpers ---

bool PipeClient::AsyncReadExact(void* buf, DWORD size, DWORD timeoutMs) {
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
			// 즉시 완료
			CloseHandle(ov.hEvent);
			if (bytesRead == 0) return false;
			totalRead += bytesRead;
			continue;
		}

		// 비동기 대기
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
			// CancelIoEx/CloseHandle가 GetLastError()를 덮어쓰므로
			// 호출자가 타임아웃과 실제 오류를 구분할 수 있도록 명시적으로 설정
			SetLastError(wait == WAIT_TIMEOUT ? WAIT_TIMEOUT : ERROR_OPERATION_ABORTED);
			return false;
		}
	}
	return true;
}

bool PipeClient::AsyncWriteExact(const void* buf, DWORD size, DWORD timeoutMs) {
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

// --- Connection ---

bool PipeClient::Connect(uint32_t targetPid, int timeoutMs) {
	std::wstring pipeName = GetPipeName(targetPid);

	stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);

	auto start = std::chrono::steady_clock::now();
	while (true) {
		pipe_ = CreateFileW(
			pipeName.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0, nullptr,
			OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED,  // Overlapped I/O
			nullptr);

		if (pipe_ != INVALID_HANDLE_VALUE) break;

		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - start).count();
		if (elapsed >= timeoutMs) {
			LOG_ERROR("Pipe connect timeout (%dms) for PID %u", timeoutMs, targetPid);
			return false;
		}

		if (GetLastError() == ERROR_PIPE_BUSY) {
			WaitNamedPipeW(pipeName.c_str(), 500);
		} else {
			Sleep(50);
		}
	}

	DWORD mode = PIPE_READMODE_BYTE;
	SetNamedPipeHandleState(pipe_, &mode, nullptr, nullptr);

	connected_ = true;
	lastRecvTime_ = GetTickCount64();
	LOG_INFO("Connected to VEH DLL pipe (PID: %u) [overlapped]", targetPid);
	return true;
}

void PipeClient::Disconnect() {
	StopHeartbeat();
	StopEventListener();

	if (pipe_ != INVALID_HANDLE_VALUE) {
		CancelIoEx(pipe_, nullptr);
		CloseHandle(pipe_);
		pipe_ = INVALID_HANDLE_VALUE;
	}
	if (stopEvent_) {
		CloseHandle(stopEvent_);
		stopEvent_ = nullptr;
	}
	connected_ = false;
}

// --- Send ---

bool PipeClient::SendCommand(IpcCommand cmd, const void* payload, uint32_t payloadSize) {
	if (!connected_) return false;
	std::lock_guard<std::mutex> lock(sendMutex_);

	auto msg = BuildIpcMessage(static_cast<uint32_t>(cmd), payload, payloadSize);
	return AsyncWriteExact(msg.data(), static_cast<DWORD>(msg.size()), 3000);
}

bool PipeClient::SendAndReceive(IpcCommand cmd,
	const void* payload, uint32_t payloadSize,
	std::vector<uint8_t>& response, int timeoutMs)
{
	std::lock_guard<std::mutex> sendLock(sendReceiveMutex_);
	if (!running_) {
		// 리더 스레드 없으면 직접 읽기 (초기 연결 시)
		if (!SendCommand(cmd, payload, payloadSize))
			return false;

		IpcHeader respHdr;
		if (!AsyncReadExact(&respHdr, sizeof(respHdr), timeoutMs))
			return false;

		if (respHdr.payloadSize > 64 * 1024 * 1024) {
			LOG_ERROR("Response payload too large: %u", respHdr.payloadSize);
			return false;
		}
		response.resize(respHdr.payloadSize);
		if (respHdr.payloadSize > 0) {
			if (!AsyncReadExact(response.data(), respHdr.payloadSize, timeoutMs))
				return false;
		}
		lastRecvTime_ = GetTickCount64();
		return true;
	}

	// 리더 스레드 활성 → condvar로 응답 대기
	{
		std::lock_guard<std::mutex> lock(responseMutex_);
		responseReady_ = false;
		waitingForResponse_ = true;
		expectedCommand_ = static_cast<uint32_t>(cmd);
	}

	if (!SendCommand(cmd, payload, payloadSize)) {
		std::lock_guard<std::mutex> lock(responseMutex_);
		waitingForResponse_ = false;
		return false;
	}

	std::unique_lock<std::mutex> lock(responseMutex_);
	bool ok = responseCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
		[this] { return responseReady_; });

	waitingForResponse_ = false;

	if (!ok) {
		LOG_ERROR("SendAndReceive timeout for cmd 0x%04X (%dms)", static_cast<uint32_t>(cmd), timeoutMs);
		return false;
	}

	response = std::move(responseData_);
	return true;
}

// --- Event Listener ---

void PipeClient::StartEventListener(EventCallback cb) {
	eventCallback_ = std::move(cb);
	running_ = true;
	readerThread_ = std::thread(&PipeClient::ReaderThread, this);
}

void PipeClient::StopEventListener() {
	running_ = false;
	if (stopEvent_) SetEvent(stopEvent_);
	if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);
	if (readerThread_.joinable()) {
		// reader thread는 AsyncReadExact(5초 타임아웃)에서 블로킹될 수 있다.
		// CancelIoEx로 I/O를 취소했지만 타이밍상 즉시 종료되지 않을 수 있으므로
		// 최대 2초만 대기하고, 초과 시 detach하여 disconnect 응답 지연을 방지한다.
		// detach된 스레드는 어댑터 프로세스 종료 시 OS가 정리한다.
		auto handle = readerThread_.native_handle();
		if (WaitForSingleObject(handle, 5000) == WAIT_OBJECT_0) {
			readerThread_.join();
		} else {
			// detach 대신 TerminateThread로 강제 종료.
			// detach하면 PipeClient 소멸 후에도 스레드가 멤버에 접근하여
			// use-after-free 위험이 있다. TerminateThread는 최후의 수단이지만
			// 이 시점에서 리더 스레드가 5초 후에도 종료되지 않으면 안전하게 제거해야 한다.
			LOG_WARN("Reader thread did not exit in 5s, terminating");
			TerminateThread(handle, 1);
			readerThread_.join();
		}
	}
}

void PipeClient::ReaderThread() {
	LOG_DEBUG("PipeClient reader thread started [overlapped]");

	while (running_ && connected_) {
		IpcHeader hdr;
		if (!AsyncReadExact(&hdr, sizeof(hdr), 5000)) {
			if (!running_) break;
			// 타임아웃은 정상 (하트비트가 올 때까지 대기)
			// AsyncReadExact는 타임아웃 시 SetLastError(WAIT_TIMEOUT)을 설정함
			DWORD err = GetLastError();
			if (err != ERROR_OPERATION_ABORTED && err != WAIT_TIMEOUT
				&& err != ERROR_IO_PENDING) {
				// ERROR_IO_PENDING(997)은 비동기 I/O 취소 후 잔여 상태일 수 있으므로 무시
				// 실제 파이프 오류(ERROR_BROKEN_PIPE=109 등)만 치명적으로 처리
				LOG_ERROR("Pipe read error: %u", err);
				connected_ = false;
			}
			continue;  // 타임아웃이면 재시도
		}

		lastRecvTime_ = GetTickCount64();

		if (hdr.payloadSize > 64 * 1024 * 1024) {
			LOG_ERROR("Payload too large: %u", hdr.payloadSize);
			connected_ = false;
			break;
		}
		std::vector<uint8_t> payload(hdr.payloadSize);
		if (hdr.payloadSize > 0) {
			if (!AsyncReadExact(payload.data(), hdr.payloadSize, 3000)) {
				LOG_ERROR("Pipe payload read failed");
				connected_ = false;
				break;
			}
		}

		LOG_DEBUG("Pipe recv cmd=0x%04X size=%u", hdr.command, hdr.payloadSize);

		// 이벤트인지 응답인지 구분
		if (hdr.command >= IPC_EVENT_THRESHOLD) {
			if (eventCallback_) {
				eventCallback_(hdr.command, payload.data(), hdr.payloadSize);
			}
		} else {
			std::lock_guard<std::mutex> lock(responseMutex_);
			if (waitingForResponse_) {
				responseData_ = std::move(payload);
				responseCommand_ = hdr.command;
				responseReady_ = true;
				responseCv_.notify_one();
			} else {
				LOG_WARN("Unexpected response for cmd 0x%04X (no waiter)", hdr.command);
			}
		}
	}

	// 종료 시 대기 중인 SendAndReceive 깨우기
	{
		std::lock_guard<std::mutex> lock(responseMutex_);
		if (waitingForResponse_) {
			responseReady_ = true;
			responseCv_.notify_one();
		}
	}

	LOG_DEBUG("PipeClient reader thread exiting");
}

// --- Heartbeat ---

void PipeClient::StartHeartbeat() {
	heartbeatRunning_ = true;
	heartbeatThread_ = std::thread(&PipeClient::HeartbeatThread, this);
}

void PipeClient::StopHeartbeat() {
	heartbeatRunning_ = false;
	if (stopEvent_) SetEvent(stopEvent_);
	if (heartbeatThread_.joinable()) {
		heartbeatThread_.join();
	}
}

void PipeClient::HeartbeatThread() {
	LOG_DEBUG("Heartbeat thread started (interval=10s, timeout=30s)");

	while (heartbeatRunning_ && connected_) {
		// 10초 대기
		for (int i = 0; i < 100 && heartbeatRunning_ && connected_; ++i) {
			Sleep(100);
		}
		if (!heartbeatRunning_ || !connected_) break;

		// Heartbeat 전송
		if (!SendCommand(IpcCommand::Heartbeat)) {
			LOG_WARN("Heartbeat send failed");
			continue;
		}

		// 30초 무응답 체크
		uint64_t elapsed = GetTickCount64() - lastRecvTime_;
		if (elapsed > 30000) {
			LOG_ERROR("Heartbeat timeout: no response for %llu ms", elapsed);
			connected_ = false;
			if (stopEvent_) SetEvent(stopEvent_);
			break;
		}
	}

	LOG_DEBUG("Heartbeat thread exiting");
}

} // namespace veh
