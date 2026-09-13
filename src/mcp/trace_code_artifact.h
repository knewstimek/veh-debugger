#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <thread>
#include "common/ipc_protocol.h"

namespace veh {

struct TraceCodeArtifactResult {
	bool requested = false;
	bool success = false;
	bool captureComplete = false;
	bool captureTruncated = false;
	std::string path;
	std::string sha256;
	std::string error;
	uint64_t fileSize = 0;
	uint64_t codeBytes = 0;
	uint64_t recordBytes = 0;
	uint32_t versions = 0;
	uint32_t chunks = 0;
	uint32_t chunkBytes = 0;
	uint32_t schemaVersion = 0;
};

class TraceCodeArtifactReceiver {
public:
	TraceCodeArtifactReceiver() = default;
	~TraceCodeArtifactReceiver();
	TraceCodeArtifactReceiver(const TraceCodeArtifactReceiver&) = delete;
	TraceCodeArtifactReceiver& operator=(const TraceCodeArtifactReceiver&) = delete;

	bool Start(const std::string& requestedPath, uint32_t chunkBytes, uint64_t maxCodeBytes,
		uint64_t rangeStart, uint64_t rangeEnd);
	TraceCodeArtifactResult Finish(bool controlResponseReceived);
	uint64_t Token() const { return token_; }
	uint32_t OwnerPid() const { return GetCurrentProcessId(); }

private:
	void ReaderThread();
	bool ReadExact(void* data, DWORD size);
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
	uint64_t maxCodeBytes_ = 0;
	uint64_t rangeStart_ = 0;
	uint64_t rangeEnd_ = 0;
	uint64_t receivedBytes_ = 0;
	uint64_t expectedChunk_ = 0;
	uint32_t chunkBytes_ = 0;
	TraceCodeArtifactResult result_;
};

} // namespace veh
