#include "trace_event_artifact.h"
#include "common/trace_path_compressor.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
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
		uint64_t maxFileBytes, uint32_t schemaVersion) {
	result_ = {};
	result_.requested = true;
	result_.chunkBytes = chunkBytes;
	result_.schemaVersion = schemaVersion;
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

bool TraceEventArtifactReceiver::ValidateRecords(const TraceEventStreamComplete& complete, uint64_t hardwareEvents) {
	LARGE_INTEGER position{};
	position.QuadPart = sizeof(TraceEventArtifactHeader);
	if (!SetFilePointerEx(file_, position, nullptr, FILE_BEGIN)) return false;
	uint64_t cursor = 0;
	uint64_t counts[3]{};
    uint64_t hardwareCount = 0;
    hardwaretrace::EventValidator hardware;
	TracePathValidator validator;
	while (cursor < complete.committedRecordBytes) {
		TraceEventArtifactRecordHeader record{};
		DWORD read = 0;
		if (complete.committedRecordBytes - cursor < sizeof(record) ||
			!ReadFile(file_, &record, sizeof(record), &read, nullptr) || read != sizeof(record)) return false;
		uint32_t expected = 0;
        if (hardware.uncertainRecords && record.type != 4) return false;
		if (record.type == static_cast<uint16_t>(TraceEventRecordType::BasicBlock)) {
			expected = sizeof(TraceBasicBlockEventEntry); ++counts[0];
		} else if (record.type == static_cast<uint16_t>(TraceEventRecordType::Memory)) {
			expected = sizeof(TraceBasicBlockMemoryEventEntry); ++counts[1];
		} else if (record.type == static_cast<uint16_t>(TraceEventRecordType::Register)) {
			expected = sizeof(TraceBasicBlockRegisterEventEntry); ++counts[2];
        } else if (result_.schemaVersion == hardwaretrace::kSchema && record.type == 4) {
            expected = sizeof(hardwaretrace::EventV1); ++hardwareCount;
        } else return false;
			if (record.reserved || record.payloadSize != expected ||
			complete.committedRecordBytes - cursor - sizeof(record) < record.payloadSize) return false;
        if (result_.schemaVersion == hardwaretrace::kSchema && record.type == 4) {
            hardwaretrace::EventV1 event{};
            if (!ReadFile(file_, &event, sizeof(event), &read, nullptr) || read != sizeof(event) ||
                !hardware.Accept(event)) return false;
        } else if (result_.schemaVersion == hardwaretrace::kSchema && record.type == 1) {
            TraceBasicBlockEventEntry event{};
            if (!ReadFile(file_, &event, sizeof(event), &read, nullptr) || read != sizeof(event) ||
                event.type == TraceBasicBlockEventType::Repeat) return false;
        } else if (result_.schemaVersion == 2) {
			if (record.type != static_cast<uint16_t>(TraceEventRecordType::BasicBlock)) return false;
			TraceBasicBlockEventEntry event{};
			if (!ReadFile(file_, &event, sizeof(event), &read, nullptr) || read != sizeof(event) ||
				!validator.Accept(event)) return false;
			result_.threadId = event.threadId;
		} else {
			position.QuadPart = record.payloadSize;
			if (!SetFilePointerEx(file_, position, nullptr, FILE_CURRENT)) return false;
		}
		cursor += sizeof(record) + record.payloadSize;
	}
	result_.expandedEvents = result_.schemaVersion == 2 ? validator.ExpandedCount() : counts[0];
    result_.hardware = hardware;
    result_.hardwareEvents = hardwareCount;
	return cursor == complete.committedRecordBytes &&
		counts[0] == complete.basicBlockEventCount &&
		counts[1] == complete.memoryEventCount &&
		counts[2] == complete.registerEventCount && hardwareCount == hardwareEvents;
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
			frame.schemaVersion != result_.schemaVersion || frame.token != token_) {
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
                if (result_.schemaVersion == hardwaretrace::kSchema) {
                    size_t cursor = 0;
                    bool valid = true;
                    while (cursor < frame.payloadSize) {
                        TraceEventArtifactRecordHeader record{};
                        if (frame.payloadSize - cursor < sizeof(record)) { valid = false; break; }
                        std::memcpy(&record, payload.data() + cursor, sizeof(record));
                        cursor += sizeof(record);
                        const uint32_t expected = record.type == 1 ? sizeof(TraceBasicBlockEventEntry) :
                            record.type == 2 ? sizeof(TraceBasicBlockMemoryEventEntry) :
                            record.type == 3 ? sizeof(TraceBasicBlockRegisterEventEntry) :
                            record.type == 4 ? sizeof(hardwaretrace::EventV1) : 0;
                        if (!expected || record.reserved || record.payloadSize != expected ||
                            record.payloadSize > frame.payloadSize - cursor) { valid = false; break; }
                        cursor += record.payloadSize;
                    }
                    if (!valid) { Fail("event chunk splits or corrupts a record"); break; }
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
                struct HardwareComplete { TraceEventStreamComplete base; uint64_t hardwareEvents; } completion{};
                static_assert(sizeof(HardwareComplete) == 64);
                auto& complete = completion.base;
                const uint32_t completionSize = result_.schemaVersion == hardwaretrace::kSchema ?
                    sizeof(completion) : sizeof(complete);
                DWORD written = 0;
                if (frame.payloadSize != completionSize || !ReadExact(&completion, completionSize) ||
                    TraceEventPayloadHash(&completion, completionSize) != frame.payloadHash ||
                    std::any_of(std::begin(complete.reserved), std::end(complete.reserved), [](uint8_t b) { return b != 0; }) ||
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
				!ValidateRecords(complete, completion.hardwareEvents)) {
				Fail("event artifact records are invalid"); break;
			}
			TraceEventArtifactHeader header{};
			header.magic = kTraceEventArtifactMagic;
			header.schemaVersion = result_.schemaVersion;
			header.headerSize = sizeof(header);
			header.flags = kTraceEventArtifactFlagComplete |
				(complete.truncated ? kTraceEventArtifactFlagTruncated : 0);
                if (result_.schemaVersion == hardwaretrace::kSchema) {
                    if (completion.hardwareEvents > UINT32_MAX) { Fail("hardware event count overflow"); break; }
                    header.flags |= hardwaretrace::kHasHardware;
                    header.reserved = static_cast<uint32_t>(completion.hardwareEvents);
                }
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
                if (result_.schemaVersion == hardwaretrace::kSchema) {
                    uint8_t extra = 0;
                    if (ReadExact(&extra, 1)) { Fail("event stream has data after completion"); break; }
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
    // A rejected frame must wake a peer blocked while draining its writes;
    // otherwise its control response cannot arrive until the capture timeout.
    if (result_.schemaVersion == hardwaretrace::kSchema && !result_.success)
        DisconnectNamedPipe(pipe_);
	SetEvent(doneEvent_);
}

TraceEventArtifactResult TraceEventArtifactReceiver::Finish(bool controlResponseReceived) {
	if (thread_.joinable()) {
		if (controlResponseReceived) WaitForSingleObject(doneEvent_, 10000);
		SetEvent(stopEvent_);
		if (pipe_ != INVALID_HANDLE_VALUE) CancelIoEx(pipe_, nullptr);
		thread_.join();
	}
    // Preserve verified raw chunks when control/stream completion is unavailable.
    // This is explicitly a raw prefix, never a complete .vte artifact.
    if (result_.schemaVersion == hardwaretrace::kSchema && !result_.success &&
        file_ != INVALID_HANDLE_VALUE && receivedBytes_) {
        finalPath_ += L".prefix";
        if (FlushFileBuffers(file_) &&
            (CreateHardLinkW(finalPath_.c_str(), partialPath_.c_str(), nullptr) ||
             CopyFileW(partialPath_.c_str(), finalPath_.c_str(), TRUE))) {
            result_.rawPrefix = true;
            result_.recordBytes = receivedBytes_;
            result_.fileSize = sizeof(TraceEventArtifactHeader) + receivedBytes_;
            result_.path = EventWideToUtf8(finalPath_);
            result_.sha256 = EventFileSha256(finalPath_);
        }
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
    if (result_.rawPrefix) result_.sha256 = EventFileSha256(finalPath_);
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

namespace {
using json = nlohmann::json;
std::string HardwareHex(uint64_t value) {
    char text[24]; snprintf(text, sizeof(text), "0x%llX", value); return text;
}
json HardwareJson(const hardwaretrace::EventV1& e) {
    auto value = [&](uint16_t bit, uint64_t n) -> json {
        return (e.known & bit) ? json(HardwareHex(n)) : json(nullptr);
    };
    const char* kinds[] = {"control_register", "msr", "io_port"};
    return {{"record", "hardware_event"}, {"sequence", (e.known & hardwaretrace::Step) ? json(std::to_string(e.sequence)) : json(nullptr)},
        {"attempt", std::to_string(e.attempt)}, {"instruction", HardwareHex(e.instruction)},
        {"subject", HardwareHex(e.subject)}, {"value", value(hardwaretrace::Value, e.value)},
        {"before", value(hardwaretrace::Before, e.before)}, {"after", value(hardwaretrace::After, e.after)},
        {"event_index", e.eventIndex}, {"cpu", e.cpu},
        {"thread_id", (e.known & hardwaretrace::Thread) ? json(std::to_string(e.threadId)) : json(nullptr)},
        {"kind", kinds[static_cast<unsigned>(e.kind) - 1]},
        {"operation", e.operation == hardwaretrace::Operation::Read ? "read" : "write"},
        {"width", e.width}, {"completion", e.completion == hardwaretrace::Completion::Confirmed ? "confirmed" : "uncertain"},
        {"code_verified", !(e.flags & 1)}, {"cpl_before", e.cplBefore},
        {"cpl_after", (e.known & hardwaretrace::CplAfter) ? json(e.cplAfter) : json(nullptr)}};
}
}
nlohmann::json ReadTraceHardwareArtifact(const nlohmann::json& args) {
    try {
        const auto operation = args.value("operation", std::string{});
        if (operation != "read_events" && operation != "analyze_events")
            return {{"error", "unknown event artifact operation"}};
        if (!args.contains("event_file") || !args["event_file"].is_string())
            return {{"error", "event_file must be a saved .vte path"}};
        if (args.contains("offset") && !args["offset"].is_string())
            return {{"error", "offset must be an exact decimal string"}};
        const std::string offsetText = args.value("offset", "0");
        if (offsetText.empty() || offsetText.size() > 20 ||
            offsetText.find_first_not_of("0123456789") != std::string::npos)
            return {{"error", "offset must be an exact decimal string"}};
        size_t used = 0;
        const uint64_t offset = std::stoull(offsetText, &used, 10);
        if (used != offsetText.size()) return {{"error", "invalid offset"}};
        if (args.contains("limit") && (!args["limit"].is_number_integer() ||
            args["limit"].get<int64_t>() < 1 || args["limit"].get<int64_t>() > 100))
            return {{"error", "limit must be 1-100"}};
        const size_t limit = args.value("limit", 16u);
        const std::string kind = args.value("hardware_kind", "");
        if (!kind.empty() && kind != "control_register" && kind != "msr" && kind != "io_port")
            return {{"error", "hardware_kind must be control_register, msr, or io_port"}};
        const auto path = std::filesystem::u8path(args["event_file"].get<std::string>());
        const auto fileSize = std::filesystem::file_size(path);
        if (fileSize < sizeof(TraceEventArtifactHeader) || fileSize > kTraceEventMaxFileBytes)
            return {{"error", "invalid event artifact size"}};
        std::ifstream file(path, std::ios::binary);
        auto read = [&](void* data, size_t size) {
            return static_cast<bool>(file.read(static_cast<char*>(data), static_cast<std::streamsize>(size)));
        };
        TraceEventArtifactHeader header{};
        if (!read(&header, sizeof(header)) || header.magic != kTraceEventArtifactMagic ||
            header.schemaVersion < 1 || header.schemaVersion > 3 ||
            header.headerSize != sizeof(header) || header.recordHeaderSize != sizeof(TraceEventArtifactRecordHeader) ||
            header.basicBlockEntrySize != sizeof(TraceBasicBlockEventEntry) ||
            header.memoryEntrySize != sizeof(TraceBasicBlockMemoryEventEntry) ||
            header.registerEntrySize != sizeof(TraceBasicBlockRegisterEventEntry) ||
            !(header.flags & kTraceEventArtifactFlagComplete) ||
            (header.flags & ~(header.schemaVersion == 3 ? 7u : 3u)) ||
            (header.schemaVersion == 3 ? !(header.flags & hardwaretrace::kHasHardware) : header.reserved != 0) ||
            header.truncationReason > static_cast<uint32_t>(TraceEventTruncationReason::TransferFailure) ||
            (!(header.flags & kTraceEventArtifactFlagTruncated) && header.truncationReason) ||
            header.recordByteCount != fileSize - sizeof(header))
            return {{"error", "invalid or incomplete event artifact header"}};
        if (args.contains("sha256") && (!args["sha256"].is_string() ||
            args["sha256"].get<std::string>() != EventFileSha256(path.wstring())))
            return {{"error", "event artifact SHA-256 mismatch"}};
        uint64_t remaining = header.recordByteCount, counts[4]{}, matched = 0, next = offset;
        uint64_t reads[3]{}, writes[3]{};
        hardwaretrace::EventValidator validator;
        TracePathValidator paths;
        json events = json::array();
        bool full = false;
        while (remaining) {
            TraceEventArtifactRecordHeader record{};
            if (remaining < sizeof(record) || !read(&record, sizeof(record)))
                return {{"error", "incomplete event record header"}};
            remaining -= sizeof(record);
            const uint32_t expected = record.type == 1 ? sizeof(TraceBasicBlockEventEntry) :
                record.type == 2 ? sizeof(TraceBasicBlockMemoryEventEntry) :
                record.type == 3 ? sizeof(TraceBasicBlockRegisterEventEntry) :
                record.type == 4 && header.schemaVersion == 3 ? sizeof(hardwaretrace::EventV1) : 0;
            if (!expected || record.reserved || record.payloadSize != expected || expected > remaining ||
                (header.schemaVersion == 2 && record.type != 1))
                return {{"error", "invalid event record"}};
            uint8_t payload[sizeof(TraceBasicBlockRegisterEventEntry)]{};
            if (!read(payload, expected)) return {{"error", "incomplete event record"}};
            remaining -= expected;
            ++counts[record.type - 1];
            if (validator.uncertainRecords && record.type != 4)
                return {{"error", "record follows an uncertain hardware tail"}};
            if (record.type == 1) {
                TraceBasicBlockEventEntry event{}; std::memcpy(&event, payload, sizeof(event));
                if (header.schemaVersion == 2 ? !paths.Accept(event) : event.type == TraceBasicBlockEventType::Repeat)
                    return {{"error", "invalid path record"}};
            }
            if (record.type != 4) continue;
            hardwaretrace::EventV1 event{}; std::memcpy(&event, payload, sizeof(event));
            if (!validator.Accept(event)) return {{"error", "invalid hardware event or order"}};
            const unsigned index = static_cast<unsigned>(event.kind) - 1;
            if (event.operation == hardwaretrace::Operation::Read) ++reads[index]; else ++writes[index];
            const char* names[] = {"control_register", "msr", "io_port"};
            if (!kind.empty() && kind != names[index]) continue;
            const uint64_t position = matched++;
            if (operation != "read_events" || position < offset || full) continue;
            json row = HardwareJson(event);
            if (events.size() >= limit || events.dump().size() + row.dump().size() > 5800) {
                full = true; continue;
            }
            events.push_back(std::move(row));
            next = position + 1;
        }
        if (counts[0] != header.basicBlockEventCount || counts[1] != header.memoryEventCount ||
            counts[2] != header.registerEventCount || counts[3] != (header.schemaVersion == 3 ? header.reserved : 0) ||
            file.peek() != std::char_traits<char>::eof())
            return {{"error", "event artifact count or EOF mismatch"}};
        json summary = {{"counts", {{"control_register", std::to_string(validator.counts[0])},
            {"msr", std::to_string(validator.counts[1])}, {"io_port", std::to_string(validator.counts[2])}}},
            {"unknown_value_fields", std::to_string(validator.unknownValueFields)},
            {"uncertain_records", std::to_string(validator.uncertainRecords)},
            {"code_uncertain", validator.codeUncertain}};
        const char* names[] = {"control_register", "msr", "io_port"};
        for (unsigned i = 0; i < 3; ++i) summary["operations"][names[i]] = {
            {"read", std::to_string(reads[i])}, {"write", std::to_string(writes[i])}};
        json result = {{"schema_version", header.schemaVersion}, {"event_file", path.u8string()},
            {"storage_complete", true}, {"stream_truncated", (header.flags & kTraceEventArtifactFlagTruncated) != 0},
            {"hardware", std::move(summary)}};
        // A raw artifact alone cannot establish the control envelope's capture completion.
        result["capture_complete"] = nullptr;
        if (operation == "read_events") {
            result["events"] = std::move(events);
            result["offset"] = std::to_string(offset);
            result["next_offset"] = next < matched ? json(std::to_string(next)) : json(nullptr);
            result["matched_records"] = std::to_string(matched);
        }
        if (result.dump().size() > 8192) return {{"error", "event page metadata exceeds 8KiB"}};
        return result;
    } catch (const std::exception& error) {
        return {{"error", std::string("event artifact: ") + error.what()}};
    }
}
} // namespace veh
