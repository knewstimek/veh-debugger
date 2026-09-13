#include "trace_output_file.h"

#include <windows.h>
#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <vector>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

namespace veh {

static constexpr uint64_t kTraceOutputFileMaxBytes = 1024ULL * 1024 * 1024;

static std::string WideToUtf8(const std::wstring& value) {
	if (value.empty()) return {};
	int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
		nullptr, 0, nullptr, nullptr);
	std::string result(static_cast<size_t>(size), '\0');
	if (size) WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
		result.data(), size, nullptr, nullptr);
	return result;
}

static std::string Sha256(const std::wstring& path) {
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

static std::string SerializeJsonLines(const nlohmann::json& trace) {
	using json = nlohmann::json;
	json metadata = json::object();
	json arrays = json::array();
	for (const auto& [key, value] : trace.items()) {
		if (value.is_array()) arrays.push_back({{"name", key}, {"count", value.size()}});
		else metadata[key] = value;
	}
	std::string output = json{{"record", "manifest"}, {"schema_version", 1},
		{"arrays", arrays}, {"value", metadata}}.dump();
	output.push_back('\n');
	for (const auto& descriptor : arrays) {
		const std::string name = descriptor["name"].get<std::string>();
		const auto& values = trace[name];
		for (size_t index = 0; index < values.size(); ++index) {
			output += json{{"record", "item"}, {"section", name}, {"index", index},
				{"value", values[index]}}.dump();
			output.push_back('\n');
		}
	}
	return output;
}

std::string ValidateTraceOutputFile(const std::string& requestedPath, const std::string& format) {
	if (requestedPath.empty()) return "output_file must not be empty";
	if (format != "json" && format != "jsonl") return "output_format must be json or jsonl";
	try {
		auto path = std::filesystem::absolute(std::filesystem::u8path(requestedPath));
		if (!path.has_parent_path() || !std::filesystem::exists(path.parent_path()))
			return "output_file directory does not exist";
		if (std::filesystem::exists(path)) return "output_file already exists";
	} catch (const std::exception& error) {
		return std::string("invalid output_file: ") + error.what();
	}
	return {};
}

TraceOutputFileResult WriteTraceOutputFile(const std::string& requestedPath,
		const std::string& format, const nlohmann::json& trace) {
	TraceOutputFileResult result;
	result.format = format;
	result.error = ValidateTraceOutputFile(requestedPath, format);
	if (!result.error.empty()) return result;
	std::filesystem::path finalPath;
	try {
		finalPath = std::filesystem::absolute(std::filesystem::u8path(requestedPath));
	} catch (const std::exception& error) {
		result.error = std::string("invalid output_file: ") + error.what(); return result;
	}

	std::string payload;
	try { payload = format == "jsonl" ? SerializeJsonLines(trace) : trace.dump(2) + "\n"; }
	catch (const std::exception& error) {
		result.error = std::string("trace serialization failed: ") + error.what(); return result;
	}
	if (payload.size() > kTraceOutputFileMaxBytes) {
		result.error = "serialized trace exceeds the 1 GiB output_file limit"; return result;
	}

	std::random_device random;
	uint64_t token = (static_cast<uint64_t>(random()) << 32) ^ random() ^ GetTickCount64();
	std::wostringstream suffix;
	suffix << L".partial-" << GetCurrentProcessId() << L"-" << std::hex << token;
	const std::wstring partialPath = finalPath.wstring() + suffix.str();
	HANDLE file = CreateFileW(partialPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		result.error = "cannot create output_file partial"; return result;
	}
	bool writtenAll = true;
	size_t offset = 0;
	while (offset < payload.size()) {
		DWORD written = 0;
		DWORD amount = static_cast<DWORD>(std::min<size_t>(payload.size() - offset, 4 * 1024 * 1024));
		if (!WriteFile(file, payload.data() + offset, amount, &written, nullptr) || written != amount) {
			writtenAll = false; break;
		}
		offset += written;
	}
	if (writtenAll) writtenAll = FlushFileBuffers(file) != FALSE;
	CloseHandle(file);
	if (!writtenAll || !MoveFileExW(partialPath.c_str(), finalPath.wstring().c_str(), MOVEFILE_WRITE_THROUGH)) {
		DeleteFileW(partialPath.c_str());
		result.error = writtenAll ? "cannot publish output_file" : "cannot write output_file";
		return result;
	}
	result.sha256 = Sha256(finalPath.wstring());
	if (result.sha256.empty()) {
		DeleteFileW(finalPath.wstring().c_str());
		result.error = "cannot verify output_file"; return result;
	}
	result.success = true;
	result.path = WideToUtf8(finalPath.wstring());
	result.size = payload.size();
	return result;
}

} // namespace veh
