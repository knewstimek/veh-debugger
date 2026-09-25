#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <vector>
#include "ipc_protocol.h"

namespace veh {

constexpr uint32_t IPC_EVENT_THRESHOLD = 0x1000;

enum class PipeExchangeFailure : uint8_t {
	None = 0,
	NotRunning,
	SendFailed,
	HeaderReadFailed,
	PayloadTooLarge,
	PayloadReadFailed,
	WaitTimeout,
	ReaderAborted,
};

struct PipeExchangeDiagnostics {
	PipeExchangeFailure failure = PipeExchangeFailure::None;
	uint32_t advertisedPayloadSize = 0;
	DWORD systemError = ERROR_SUCCESS;
};

class IIpcTransport {
public:
	using EventCallback = std::function<void(uint32_t eventId, const uint8_t* payload, uint32_t size)>;

	virtual ~IIpcTransport() = default;

	virtual bool Connect(uint32_t targetPid, int timeoutMs = 7000) = 0;
	virtual void Disconnect() = 0;
	virtual bool IsConnected() const = 0;
	virtual bool SendCommand(IpcCommand cmd, const void* payload = nullptr, uint32_t payloadSize = 0) = 0;
	virtual bool SendAndReceive(IpcCommand cmd,
		const void* payload, uint32_t payloadSize,
		std::vector<uint8_t>& response, int timeoutMs = 3000,
		PipeExchangeDiagnostics* diagnostics = nullptr) = 0;
	virtual bool WaitForReady(int timeoutMs = 3000) = 0;
	virtual void StartEventListener(EventCallback cb) = 0;
	virtual void StopEventListener() = 0;
	virtual void StartHeartbeat() = 0;
	virtual void StopHeartbeat() = 0;
};

} // namespace veh
