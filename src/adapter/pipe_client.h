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

	// Connect 직후, StartEventListener 전에 호출. DLL이 클라 연결 후 보내는 Ready
	// 이벤트를 동기로 수신해 VEH 핸들러 설치 완료를 보장한다(attach race 방지).
	// 성공 시 true, 타임아웃/오류 시 false (호출 측은 false여도 진행 가능 - 보수적).
	bool WaitForReady(int timeoutMs = 3000);

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

	// 리더 스레드 시작 대기용
	std::mutex readerReadyMutex_;
	std::condition_variable readerReadyCv_;
	bool readerReady_ = false;

	// Ready 핸드셰이크용. reader thread가 Ready(0x1000) 이벤트를 수신하면 signal.
	// WaitForReady는 이 condvar만 대기 -> 동기 부분 읽기로 인한 프레이밍 desync 없음.
	// (WaitForReady는 StartEventListener로 reader가 시작된 후 호출해야 한다.)
	std::mutex readyMutex_;
	std::condition_variable readyCv_;
	bool readyReceived_ = false;

	// 응답 대기용
	std::mutex responseMutex_;
	std::condition_variable responseCv_;
	bool responseReady_ = false;
	std::vector<uint8_t> responseData_;
	uint32_t responseCommand_ = 0;
	bool waitingForResponse_ = false;
	uint32_t expectedCommand_ = 0;
	bool responseAborted_ = false;  // reader thread exit signal
};

} // namespace veh
