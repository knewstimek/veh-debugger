#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <thread>
#include "common/ipc_protocol.h"

namespace veh {

struct TraceEventArtifactResult {
	bool requested = false;
	bool success = false;
	bool captureComplete = false;
	bool captureTruncated = false;
	std::string path;
	std::string sha256;
	std::string error;
	uint64_t fileSize = 0;
	uint64_t recordBytes = 0;
	uint64_t basicBlockEvents = 0;
	uint64_t memoryEvents = 0;
	uint64_t registerEvents = 0;
	uint64_t waitTimeNs = 0;
	uint32_t chunks = 0;
	uint32_t chunkBytes = 0;
	uint32_t schemaVersion = 0;
	TraceEventTruncationReason truncationReason = TraceEventTruncationReason::None;
};

class TraceEventArtifactReceiver {
public:
	TraceEventArtifactReceiver() = default;
	~TraceEventArtifactReceiver();
	TraceEventArtifactReceiver(const TraceEventArtifactReceiver&) = delete;
	TraceEventArtifactReceiver& operator=(const TraceEventArtifactReceiver&) = delete;

	bool Start(const std::string& requestedPath, uint32_t chunkBytes, uint64_t maxFileBytes);
	TraceEventArtifactResult Finish(bool controlResponseReceived);
	uint64_t Token() const { return token_; }
	uint32_t OwnerPid() const { return GetCurrentProcessId(); }

private:
	void ReaderThread();
	bool ReadExact(void* data, DWORD size);
	bool ValidateRecords(const TraceEventStreamComplete& complete);
	void Fail(const std::string& message);
	void CloseResources();

	HANDLE pipe_ = INVALID_HANDLE_VALUE;
	HANDLE file_ = INVALID_HANDLE_VALUE;
	HANDLE stopEvent_ = nullptr;
	HANDLE doneEvent_ = nullptr;
	std::thread thread_;
	std::wstring finalPath_;
	std::wstring partialPath_;
	uint64_t token_ = 0;
	uint64_t maxRecordBytes_ = 0;
	uint64_t receivedBytes_ = 0;
	uint64_t expectedChunk_ = 0;
	uint32_t chunkBytes_ = 0;
	TraceEventArtifactResult result_;
};

} // namespace veh
