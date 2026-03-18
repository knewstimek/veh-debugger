#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include "../common/ipc_protocol.h"

namespace veh {

class PipeServer {
public:
	static PipeServer& Instance();

	bool Start(uint32_t targetPid);
	void Stop();
	bool IsRunning() const { return running_; }

	// 이벤트 전송 (VEH 핸들러 등 다른 스레드에서 호출)
	bool SendEvent(uint32_t eventId, const void* payload = nullptr, uint32_t payloadSize = 0);

	// 응답 전송 (ServerThread에서 호출)
	bool SendResponse(uint32_t command, const void* payload = nullptr, uint32_t payloadSize = 0);

private:
	PipeServer() = default;

	void ServerThread();
	void HandleCommand(uint32_t command, const uint8_t* payload, uint32_t payloadSize);

	// Overlapped I/O helpers
	bool AsyncReadExact(void* buf, DWORD size, DWORD timeoutMs = 5000);
	bool AsyncWriteExact(const void* buf, DWORD size, DWORD timeoutMs = 3000);

	// HW BP를 모든 스레드의 DR 레지스터에 즉시 적용
	void ApplyHwBreakpointsToAllThreads();

	// VEH 핸들러 해제 + BP 제거 + 스레드 복구
	void EmergencyCleanup();

	HANDLE pipe_ = INVALID_HANDLE_VALUE;
	HANDLE stopEvent_ = nullptr;
	std::thread serverThread_;
	std::mutex writeMutex_;
	std::atomic<bool> running_{false};
	std::atomic<bool> connected_{false};
	uint32_t targetPid_ = 0;

	// 하트비트 타임아웃 (30초 무명령 → 어댑터 죽은 것으로 판단)
	static constexpr DWORD HEARTBEAT_TIMEOUT_MS = 30000;
	static constexpr DWORD READ_TIMEOUT_MS = 10000;  // 10초 read 타임아웃
	std::atomic<uint64_t> lastCommandTime_{0};
};

} // namespace veh
