#include "trace_event_artifact.h"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

static std::string EventWideToUtf8(const std::wstring& value) {
	if (value.empty()) return {};
	int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
		nullptr, 0, nullptr, nullptr);
	std::string result(static_cast<size_t>(size), '\0');
	if (size) WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
		result.data(), size, nullptr, nullptr);
	return result;
}

static std::string EventFileSha256(const std::wstring& path) {
	HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) return {};
	HCRYPTPROV provider = 0;
	HCRYPTHASH hash = 0;
	std::string output;
	bool complete = false;
	if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
		CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
		std::vector<uint8_t> buffer(1024 * 1024);
		while (true) {
			DWORD read = 0;
			if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) break;
			if (!read) { complete = true; break; }
			if (!CryptHashData(hash, buffer.data(), read, 0)) break;
		}
		DWORD length = 32;
		uint8_t bytes[32]{};
		if (complete && CryptGetHashParam(hash, HP_HASHVAL, bytes, &length, 0)) {
			std::ostringstream stream;
			stream << std::hex << std::setfill('0');
			for (DWORD i = 0; i < length; ++i)
				stream << std::setw(2) << static_cast<unsigned>(bytes[i]);
			output = stream.str();
		}
	}
	if (hash) CryptDestroyHash(hash);
	if (provider) CryptReleaseContext(provider, 0);
	CloseHandle(file);
	return output;
}

TraceEventArtifactReceiver::~TraceEventArtifactReceiver() {
	if (thread_.joinable()) {
		if (stopEvent_) SetEvent(stopEvent_);
		if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);
		thread_.join();
	}
	CloseResources();
}

bool TraceEventArtifactReceiver::Start(const std::string& requestedPath, uint32_t chunkBytes,
		uint64_t maxFileBytes) {
	result_ = {};
	result_.requested = true;
	result_.chunkBytes = chunkBytes;
	result_.schemaVersion = kTraceEventArtifactSchemaVersion;
	chunkBytes_ = chunkBytes;
	if (maxFileBytes < sizeof(TraceEventArtifactHeader) ||
		maxFileBytes > kTraceEventMaxFileBytes) {
		result_.error = "max_event_file_bytes is outside the supported range";
		return false;
	}
	maxRecordBytes_ = maxFileBytes - sizeof(TraceEventArtifactHeader);
	std::random_device random;
	token_ = (static_cast<uint64_t>(random()) << 32) ^ random() ^ GetTickCount64();
	if (!token_) token_ = 1;

	std::filesystem::path finalPath;
	try {
		if (requestedPath.empty()) {
			std::wostringstream name;
			name << L"veh-events-" << GetCurrentProcessId() << L"-" << std::hex << token_ << L".vte";
			finalPath = std::filesystem::temp_directory_path() / name.str();
		} else {
			finalPath = std::filesystem::absolute(std::filesystem::u8path(requestedPath));
		}
		if (!finalPath.has_parent_path() || !std::filesystem::exists(finalPath.parent_path())) {
			result_.error = "event output directory does not exist";
			return false;
		}
		if (std::filesystem::exists(finalPath)) {
			result_.error = "event output file already exists";
			return false;
		}
	} catch (const std::exception& error) {
		result_.error = std::string("invalid event output path: ") + error.what();
		return false;
	}
	finalPath_ = finalPath.wstring();
	std::wostringstream suffix;
	suffix << L".partial-" << std::hex << token_;
	partialPath_ = finalPath_ + suffix.str();

	file_ = CreateFileW(partialPath_.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
	if (file_ == INVALID_HANDLE_VALUE) {
		result_.error = "cannot create event artifact output file";
		return false;
	}
	TraceEventArtifactHeader placeholder{};
	DWORD written = 0;
	if (!WriteFile(file_, &placeholder, sizeof(placeholder), &written, nullptr) ||
		written != sizeof(placeholder)) {
		result_.error = "cannot initialize event artifact output file";
		CloseResources(); DeleteFileW(partialPath_.c_str());
		return false;
	}

	stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	doneEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	std::wstring pipeName = GetTraceEventPipeName(GetCurrentProcessId(), token_);
	pipe_ = CreateNamedPipeW(pipeName.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 64 * 1024, 64 * 1024, 0, nullptr);
	if (!stopEvent_ || !doneEvent_ || pipe_ == INVALID_HANDLE_VALUE) {
		result_.error = "cannot create event artifact data pipe";
		CloseResources(); DeleteFileW(partialPath_.c_str());
		return false;
	}
	thread_ = std::thread(&TraceEventArtifactReceiver::ReaderThread, this);
	return true;
}

bool TraceEventArtifactReceiver::ReadExact(void* data, DWORD size) {
	DWORD total = 0;
	while (total < size) {
		OVERLAPPED ov{};
		ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!ov.hEvent) return false;
		DWORD read = 0;
		BOOL ok = ReadFile(pipe_, static_cast<uint8_t*>(data) + total, size - total, &read, &ov);
		if (!ok && GetLastError() == ERROR_IO_PENDING) {
			HANDLE waits[] = {ov.hEvent, stopEvent_};
			DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
			if (wait == WAIT_OBJECT_0) ok = GetOverlappedResult(pipe_, &ov, &read, FALSE);
			else { CancelIoEx(pipe_, &ov); ok = FALSE; }
		}
		CloseHandle(ov.hEvent);
		if (!ok || !read) return false;
		total += read;
	}
	return true;
}

bool TraceEventArtifactReceiver::ValidateRecords(const TraceEventStreamComplete& complete) {
	LARGE_INTEGER position{};
	position.QuadPart = sizeof(TraceEventArtifactHeader);
	if (!SetFilePointerEx(file_, position, nullptr, FILE_BEGIN)) return false;
	uint64_t cursor = 0;
	uint64_t counts[3]{};
	while (cursor < complete.committedRecordBytes) {
		TraceEventArtifactRecordHeader record{};
		DWORD read = 0;
		if (complete.committedRecordBytes - cursor < sizeof(record) ||
			!ReadFile(file_, &record, sizeof(record), &read, nullptr) || read != sizeof(record)) return false;
		uint32_t expected = 0;
		if (record.type == static_cast<uint16_t>(TraceEventRecordType::BasicBlock)) {
			expected = sizeof(TraceBasicBlockEventEntry); ++counts[0];
		} else if (record.type == static_cast<uint16_t>(TraceEventRecordType::Memory)) {
			expected = sizeof(TraceBasicBlockMemoryEventEntry); ++counts[1];
		} else if (record.type == static_cast<uint16_t>(TraceEventRecordType::Register)) {
			expected = sizeof(TraceBasicBlockRegisterEventEntry); ++counts[2];
		} else return false;
			if (record.reserved || record.payloadSize != expected ||
			complete.committedRecordBytes - cursor - sizeof(record) < record.payloadSize) return false;
		position.QuadPart = record.payloadSize;
		if (!SetFilePointerEx(file_, position, nullptr, FILE_CURRENT)) return false;
		cursor += sizeof(record) + record.payloadSize;
	}
	return cursor == complete.committedRecordBytes &&
		counts[0] == complete.basicBlockEventCount &&
		counts[1] == complete.memoryEventCount &&
		counts[2] == complete.registerEventCount;
}

void TraceEventArtifactReceiver::Fail(const std::string& message) {
	if (result_.error.empty()) result_.error = message;
}

void TraceEventArtifactReceiver::ReaderThread() {
	OVERLAPPED connect{};
	connect.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	BOOL connected = ConnectNamedPipe(pipe_, &connect);
	DWORD error = connected ? ERROR_SUCCESS : GetLastError();
	if (!connected && error == ERROR_IO_PENDING) {
		HANDLE waits[] = {connect.hEvent, stopEvent_};
		DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
		DWORD transferred = 0;
		if (wait == WAIT_OBJECT_0) connected = GetOverlappedResult(pipe_, &connect, &transferred, FALSE);
		else CancelIoEx(pipe_, &connect);
	} else if (!connected && error == ERROR_PIPE_CONNECTED) {
		connected = TRUE;
	}
	CloseHandle(connect.hEvent);
	if (!connected) {
		if (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0)
			Fail("event artifact data pipe was not connected");
		SetEvent(doneEvent_);
		return;
	}

	std::vector<uint8_t> payload(chunkBytes_);
	while (true) {
		TraceEventStreamFrameHeader frame{};
		if (!ReadExact(&frame, sizeof(frame))) { Fail("event artifact stream ended before completion"); break; }
		if (frame.magic != kTraceEventStreamMagic || frame.reserved ||
			frame.schemaVersion != kTraceEventArtifactSchemaVersion || frame.token != token_) {
			Fail("invalid event artifact stream frame"); break;
		}
		if (frame.type == static_cast<uint16_t>(TraceEventStreamFrameType::Data)) {
			if (!frame.payloadSize || frame.payloadSize > chunkBytes_ ||
				frame.chunkIndex != expectedChunk_ || frame.streamOffset != receivedBytes_ ||
				receivedBytes_ + frame.payloadSize > maxRecordBytes_) {
				Fail("out-of-order or oversized event artifact chunk"); break;
			}
			if (!ReadExact(payload.data(), frame.payloadSize) ||
				TraceEventPayloadHash(payload.data(), frame.payloadSize) != frame.payloadHash) {
				Fail("event artifact chunk checksum mismatch"); break;
			}
			DWORD written = 0;
			if (!WriteFile(file_, payload.data(), frame.payloadSize, &written, nullptr) ||
				written != frame.payloadSize) {
				Fail("event artifact file write failed"); break;
			}
			receivedBytes_ += frame.payloadSize;
			++expectedChunk_;
			continue;
		}
		if (frame.type == static_cast<uint16_t>(TraceEventStreamFrameType::Complete)) {
			TraceEventStreamComplete complete{};
			DWORD written = 0;
			if (frame.payloadSize != sizeof(complete) || !ReadExact(&complete, sizeof(complete)) ||
				TraceEventPayloadHash(&complete, sizeof(complete)) != frame.payloadHash ||
				frame.chunkIndex != expectedChunk_ ||
				frame.streamOffset != complete.committedRecordBytes ||
				complete.chunkCount != expectedChunk_ ||
				complete.committedRecordBytes != receivedBytes_ || complete.truncated > 1 ||
				(complete.truncated == 0 && complete.truncationReason !=
					static_cast<uint32_t>(TraceEventTruncationReason::None)) ||
				(complete.truncationReason >
					static_cast<uint32_t>(TraceEventTruncationReason::TransferFailure)) ||
				complete.committedRecordBytes > maxRecordBytes_) {
				Fail("invalid event artifact completion frame"); break;
			}
			LARGE_INTEGER end{};
			end.QuadPart = sizeof(TraceEventArtifactHeader) + complete.committedRecordBytes;
			if (!SetFilePointerEx(file_, end, nullptr, FILE_BEGIN) || !SetEndOfFile(file_) ||
				!ValidateRecords(complete)) {
				Fail("event artifact records are invalid"); break;
			}
			TraceEventArtifactHeader header{};
			header.magic = kTraceEventArtifactMagic;
			header.schemaVersion = kTraceEventArtifactSchemaVersion;
			header.headerSize = sizeof(header);
			header.flags = kTraceEventArtifactFlagComplete |
				(complete.truncated ? kTraceEventArtifactFlagTruncated : 0);
			header.recordHeaderSize = sizeof(TraceEventArtifactRecordHeader);
			header.basicBlockEntrySize = sizeof(TraceBasicBlockEventEntry);
			header.memoryEntrySize = sizeof(TraceBasicBlockMemoryEventEntry);
			header.registerEntrySize = sizeof(TraceBasicBlockRegisterEventEntry);
			header.recordByteCount = complete.committedRecordBytes;
			header.basicBlockEventCount = complete.basicBlockEventCount;
			header.memoryEventCount = complete.memoryEventCount;
			header.registerEventCount = complete.registerEventCount;
			header.waitTimeNs = complete.waitTimeNs;
			header.truncationReason = complete.truncationReason;
			header.chunkCount = complete.chunkCount;
			LARGE_INTEGER start{};
			if (!SetFilePointerEx(file_, start, nullptr, FILE_BEGIN) ||
				!WriteFile(file_, &header, sizeof(header), &written, nullptr) || written != sizeof(header) ||
				!FlushFileBuffers(file_)) {
				Fail("cannot write event artifact header"); break;
			}
			result_.success = true;
			result_.captureTruncated = complete.truncated != 0;
			result_.captureComplete = !result_.captureTruncated;
			result_.recordBytes = complete.committedRecordBytes;
			result_.basicBlockEvents = complete.basicBlockEventCount;
			result_.memoryEvents = complete.memoryEventCount;
			result_.registerEvents = complete.registerEventCount;
			result_.waitTimeNs = complete.waitTimeNs;
			result_.chunks = complete.chunkCount;
			result_.truncationReason = static_cast<TraceEventTruncationReason>(complete.truncationReason);
			result_.fileSize = sizeof(header) + complete.committedRecordBytes;
			break;
		}
		Fail("unsupported event artifact stream frame type");
		break;
	}
	SetEvent(doneEvent_);
}

TraceEventArtifactResult TraceEventArtifactReceiver::Finish(bool controlResponseReceived) {
	if (thread_.joinable()) {
		if (controlResponseReceived) WaitForSingleObject(doneEvent_, 10000);
		SetEvent(stopEvent_);
		if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);
		thread_.join();
	}
	bool published = false;
	if (file_ != INVALID_HANDLE_VALUE && result_.success && result_.error.empty()) {
		published = CreateHardLinkW(finalPath_.c_str(), partialPath_.c_str(), nullptr) != FALSE;
		if (!published) published = CopyFileW(partialPath_.c_str(), finalPath_.c_str(), TRUE) != FALSE;
		if (!published) {
			result_.success = false;
			result_.error = "cannot publish completed event artifact";
		}
	}
	if (file_ != INVALID_HANDLE_VALUE) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; }
	if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
	if (stopEvent_) { CloseHandle(stopEvent_); stopEvent_ = nullptr; }
	if (doneEvent_) { CloseHandle(doneEvent_); doneEvent_ = nullptr; }
	if (result_.success && result_.error.empty() && published) {
		result_.path = EventWideToUtf8(finalPath_);
		result_.sha256 = EventFileSha256(finalPath_);
		if (result_.sha256.empty()) {
			result_.success = false;
			result_.error = "cannot verify completed event artifact";
			DeleteFileW(finalPath_.c_str());
			result_.path.clear();
		}
	}
	if (!result_.success) DeleteFileW(partialPath_.c_str());
	return result_;
}

void TraceEventArtifactReceiver::CloseResources() {
	if (pipe_ != INVALID_HANDLE_VALUE) { CloseHandle(pipe_); pipe_ = INVALID_HANDLE_VALUE; }
	if (file_ != INVALID_HANDLE_VALUE) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; }
	if (stopEvent_) { CloseHandle(stopEvent_); stopEvent_ = nullptr; }
	if (doneEvent_) { CloseHandle(doneEvent_); doneEvent_ = nullptr; }
}

} // namespace veh
