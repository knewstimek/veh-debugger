#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "ipc_protocol.h"

namespace veh {

// 이벤트 ID 경계: 0x1000 이상이면 이벤트, 미만이면 명령 응답
constexpr uint32_t IPC_EVENT_THRESHOLD = 0x1000;

class PipeClient {
public:
	~PipeClient() { Disconnect(); }

	// Connect to VEH DLL's named pipe (overlapped)
	bool Connect(uint32_t targetPid, int timeoutMs = 7000);
	void Disconnect();
	bool IsConnected() const { return connected_; }

	// Send command (fire-and-forget)
	bool SendCommand(IpcCommand cmd, const void* payload = nullptr, uint32_t payloadSize = 0);

	// Send command and receive response (blocks until response or timeout)
	bool SendAndReceive(IpcCommand cmd,
		const void* payload, uint32_t payloadSize,
		std::vector<uint8_t>& response, int timeoutMs = 3000);

	// Start event listener thread (single reader thread)
	using EventCallback = std::function<void(uint32_t eventId, const uint8_t* payload, uint32_t size)>;
	void StartEventListener(EventCallback cb);
	void StopEventListener();

	// Heartbeat: 10초 간격 ping, 30초 무응답 시 연결 끊김 판정
	void StartHeartbeat();
	void StopHeartbeat();

private:
	void ReaderThread();
	void HeartbeatThread();

	// Overlapped I/O helpers
	bool AsyncReadExact(void* buf, DWORD size, DWORD timeoutMs = 3000);
	bool AsyncWriteExact(const void* buf, DWORD size, DWORD timeoutMs = 3000);

	HANDLE pipe_ = INVALID_HANDLE_VALUE;
	HANDLE stopEvent_ = nullptr;
	std::atomic<bool> connected_{false};
	std::mutex sendMutex_;       // write 직렬화
	std::mutex sendReceiveMutex_; // SendAndReceive 직렬화

	// 단일 리더 스레드
	std::thread readerThread_;
	std::atomic<bool> running_{false};
	EventCallback eventCallback_;

	// 하트비트
	std::thread heartbeatThread_;
	std::atomic<bool> heartbeatRunning_{false};
	std::atomic<uint64_t> lastRecvTime_{0};  // GetTickCount64

	// 응답 대기용
	std::mutex responseMutex_;
	std::condition_variable responseCv_;
	bool responseReady_ = false;
	std::vector<uint8_t> responseData_;
	uint32_t responseCommand_ = 0;
	bool waitingForResponse_ = false;
	uint32_t expectedCommand_ = 0;
};

} // namespace veh
