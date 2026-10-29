#include "analysis_store.h"
#include <windows.h>
#include <bcrypt.h>
#include <limits>
#include <set>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

namespace veh {
namespace {
using Json = nlohmann::json;
constexpr size_t kMaximumBytes = 8 * 1024 * 1024, kMaximumEntries = 4096;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
std::filesystem::path Absolute(const std::string& value) {
    if (value.empty() || value.find('\0') != std::string::npos) throw AnalysisError("analysis_path", "An absolute analysis directory is required");
    auto path = std::filesystem::u8path(value);
    if (!path.is_absolute() || !path.has_root_name()) throw AnalysisError("analysis_path", "Analysis directory must be absolute");
    return path.lexically_normal();
}
void Regular(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
        throw AnalysisError("analysis_file", "Analysis files must be regular files, not directories or reparse points");
}
void Directory(const std::filesystem::path& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw AnalysisError("analysis_path", "Analysis directory is unavailable or is a reparse point");
}
void Lock(const std::filesystem::path& path, Handle& handle) {
    handle.value = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle.value == INVALID_HANDLE_VALUE) throw AnalysisError("analysis_busy", "Analysis file is locked or unavailable; retry without changing revisions");
    Regular(handle.value);
}
Json Read(const std::filesystem::path& path) {
    Handle handle;
    handle.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle.value == INVALID_HANDLE_VALUE) throw AnalysisError("analysis_read", "Cannot open the analysis file");
    Regular(handle.value);
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(handle.value, &length) || length.QuadPart <= 0 || length.QuadPart > kMaximumBytes)
        throw AnalysisError("analysis_size", "Analysis file must be nonempty and at most 8 MiB");
    std::string bytes(static_cast<size_t>(length.QuadPart), '\0'); DWORD count = 0;
    if (!ReadFile(handle.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) || count != bytes.size())
        throw AnalysisError("analysis_read", "Incomplete analysis file read");
    auto result = Json::parse(bytes, [](int depth, Json::parse_event_t, Json&) {
        if (depth > 24) throw AnalysisError("analysis_format", "Analysis JSON nesting limit exceeded");
        return true;
    }, false);
    if (result.is_discarded() || !result.is_object()) throw AnalysisError("analysis_format", "Malformed analysis JSON; the file was not modified");
    return result;
}
void Write(const std::filesystem::path& path, const Json& document) {
    const auto bytes = document.dump(2) + "\n";
    if (bytes.size() > kMaximumBytes) throw AnalysisError("analysis_size", "Analysis document exceeds 8 MiB");
    const auto temporary = path.parent_path() / (L".analysis-" + std::filesystem::u8path(AnalysisStore::Nonce()).wstring() + L".tmp");
    try {
        {
            Handle handle;
            handle.value = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle.value == INVALID_HANDLE_VALUE) throw AnalysisError("analysis_write", "Cannot create an analysis temporary file");
            DWORD count = 0;
            if (!WriteFile(handle.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) ||
                    count != bytes.size() || !FlushFileBuffers(handle.value))
                throw AnalysisError("analysis_write", "Analysis write did not complete; existing data was preserved");
        }
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) throw AnalysisError("analysis_file", "Cannot replace a non-regular analysis file");
            if (!ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr))
                throw AnalysisError("analysis_write", "Analysis replacement failed; existing data was preserved");
        } else if (GetLastError() != ERROR_FILE_NOT_FOUND || !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH))
            throw AnalysisError("analysis_write", "Cannot install the analysis file");
    } catch (...) { DeleteFileW(temporary.c_str()); throw; }
}
uint64_t Revision(const Json& value) {
    if (!value.is_string()) throw AnalysisError("analysis_format", "Revisions must be decimal strings");
    const auto text = value.get<std::string>();
    if (text.empty() || text.size() > 20 || text.find_first_not_of("0123456789") != std::string::npos)
        throw AnalysisError("analysis_format", "Invalid analysis revision");
    try { return std::stoull(text); } catch (...) { throw AnalysisError("analysis_format", "Analysis revision overflow"); }
}
void Validate(const Json& doc) {
    if (doc.value("format", "") != "veh-analysis" || doc.value("version", 0) != 1 || !doc.contains("revision") ||
            !doc.contains("entries") || !doc["entries"].is_object() || doc["entries"].size() > kMaximumEntries)
        throw AnalysisError("analysis_format", "Unknown or oversized analysis document; no migration was attempted");
    Revision(doc["revision"]);
    for (const auto& item : doc["entries"].items()) {
        const auto& entry = item.value();
        if (!entry.is_object()) throw AnalysisError("analysis_format", "Invalid annotation entry");
        for (const char* field : {"id", "build_id", "module", "rva", "original_bytes", "revision", "comment", "label", "status", "author", "position", "context"})
            if (!entry.contains(field) || !entry[field].is_string()) throw AnalysisError("analysis_format", "Invalid annotation fields");
        static const std::set<std::string> allowed = {"id","build_id","module","rva","original_bytes","revision","comment","label","status","author","position","context","evidence","persistent_identity","address_bits","history","history_truncated"};
        for (const auto& field : entry.items()) if (!allowed.count(field.key())) throw AnalysisError("analysis_format", "Unknown annotation field");
        for (const auto& field : std::vector<std::pair<const char*,size_t>>{{"id",300},{"author",64},{"status",32},{"position",16},{"context",512},{"module",256},{"build_id",256},{"rva",18},{"original_bytes",30},{"revision",20},{"comment",4096},{"label",128}}) {
            const auto& text = entry[field.first].get_ref<const std::string&>();
            if (text.size() > field.second || text.find('\0') != std::string::npos) throw AnalysisError("analysis_format", "Oversized annotation field");
        }
        if (!entry.contains("persistent_identity") || !entry["persistent_identity"].is_boolean() || !entry.contains("address_bits") ||
                !entry["address_bits"].is_number_integer() || (entry["address_bits"] != 0 && entry["address_bits"] != 32 && entry["address_bits"] != 64) ||
                (entry["status"] != "hypothesis" && entry["status"] != "observed" && entry["status"] != "refuted") ||
                (entry["position"] != "before" && entry["position"] != "after") ||
                (entry.contains("history_truncated") && !entry["history_truncated"].is_boolean()))
            throw AnalysisError("analysis_format", "Invalid annotation status or identity fields");
        const auto build = entry["build_id"].get<std::string>();
        if (entry["persistent_identity"].get<bool>()) {
            if (build.size() != 74 || build.rfind("sha256:", 0) != 0 ||
                    build.substr(7,64).find_first_not_of("0123456789abcdef") != std::string::npos ||
                    build.substr(71) != ":" + std::to_string(entry["address_bits"].get<int>()))
                throw AnalysisError("analysis_format", "Invalid stable build identity");
        } else if (build.rfind("session:",0) != 0 || build.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:") != std::string::npos)
            throw AnalysisError("analysis_format", "Invalid unbound annotation identity");
        if (entry["id"] != item.key() || !entry.contains("evidence") || !entry["evidence"].is_array() ||
                entry["comment"].get_ref<const std::string&>().size() > 4096 || entry["label"].get_ref<const std::string&>().size() > 128 ||
                entry["build_id"].get_ref<const std::string&>().size() > 256 || entry["module"].get_ref<const std::string&>().size() > 256 ||
                entry["original_bytes"].get_ref<const std::string&>().size() > 30 || entry["rva"].get_ref<const std::string&>().size() > 18 ||
                entry["evidence"].size() > 16)
            throw AnalysisError("analysis_format", "Invalid annotation data");
        const auto& rva = entry["rva"].get_ref<const std::string&>();
        const auto& bytes = entry["original_bytes"].get_ref<const std::string&>();
        if (rva.size() < 3 || rva.rfind("0x", 0) != 0 || rva.find_first_not_of("0123456789abcdefABCDEF", 2) != std::string::npos ||
                bytes.empty() || bytes.size() % 2 || bytes.find_first_not_of("0123456789abcdef") != std::string::npos ||
                entry["id"] != entry["build_id"].get<std::string>() + "@" + rva)
            throw AnalysisError("analysis_format", "Invalid annotation identity or byte anchor");
        for (const auto& ref : entry["evidence"]) if (!ref.is_string() || ref.get_ref<const std::string&>().size() > 512)
            throw AnalysisError("analysis_format", "Invalid annotation evidence");
        if (entry.contains("history") && (!entry["history"].is_array() || entry["history"].size() > 8))
            throw AnalysisError("analysis_format", "Invalid annotation history");
        const auto entryRevision = Revision(entry["revision"]);
        if (!entryRevision || entryRevision > Revision(doc["revision"])) throw AnalysisError("analysis_format", "Annotation revision exceeds document revision");
        if (entry.contains("history")) for (const auto& previous : entry["history"]) {
            if (!previous.is_object() || previous.contains("history") || previous.value("id", "") != item.key() ||
                    !previous.contains("revision") || Revision(previous["revision"]) >= entryRevision)
                throw AnalysisError("analysis_format", "Invalid annotation history record");
            Validate({{"format","veh-analysis"},{"version",1},{"revision",doc["revision"]},
                {"entries",{{item.key(),previous}}}});
        }
    }
}
std::string Environment(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::vector<wchar_t> buffer(size);
    if (!GetEnvironmentVariableW(name, buffer.data(), size)) return {};
    return std::filesystem::path(buffer.data()).u8string();
}
}

std::string AnalysisStore::Nonce() {
    unsigned char bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw AnalysisError("analysis_random", "Cannot create a unique analysis identifier");
    std::string result; const char* hex = "0123456789abcdef";
    for (auto value : bytes) { result += hex[value >> 4]; result += hex[value & 15]; }
    return result;
}

AnalysisStore::AnalysisStore() {
    try {
        auto state = Environment(L"VEH_ANALYSIS_STATE_DIR");
        if (state.empty()) { const auto local = Environment(L"LOCALAPPDATA"); if (!local.empty()) state = (Absolute(local) / L"VEHDebugger").u8string(); }
        if (!state.empty()) settings_ = Absolute(state) / L"analysis-settings.json";
        auto directory = Environment(L"VEH_ANALYSIS_DIR");
        if (directory.empty() && !settings_.empty() && std::filesystem::exists(settings_)) directory = Read(settings_).value("directory", "");
        if (!directory.empty()) Open(directory, false, false);
    } catch (const std::exception& error) { startupError_ = error.what(); }
}

AnalysisStore::Json AnalysisStore::Open(const std::string& directory, bool create, bool remember) {
    std::lock_guard<std::mutex> guard(mutex_);
    const auto path = Absolute(directory);
    if (create) std::filesystem::create_directories(path);
    Directory(path); Handle lock; Lock(path / L"analysis.lock", lock);
    const auto file = path / L"analysis.json";
    if (!std::filesystem::exists(file)) {
        if (!create) throw AnalysisError("analysis_read", "Analysis file does not exist; use create=true explicitly");
        Write(file, {{"format", "veh-analysis"}, {"version", 1}, {"revision", "0"}, {"entries", Json::object()}});
    }
    Validate(Read(file));
    directory_ = path; startupError_.clear();
    bool remembered = false;
    if (remember && !settings_.empty()) {
        try {
            std::filesystem::create_directories(settings_.parent_path()); Directory(settings_.parent_path());
            Handle stateLock; Lock(settings_.parent_path() / L"analysis-settings.lock", stateLock);
            Write(settings_, {{"directory", path.u8string()}}); remembered = true;
        } catch (...) { remembered = false; }
    }
    return {{"success", true}, {"directory", directory_.u8string()}, {"remembered", remembered}};
}

AnalysisStore::Json AnalysisStore::Close() {
    std::lock_guard<std::mutex> guard(mutex_);
    // Keep the current project open if forgetting the pointer fails.
    if (!settings_.empty() && std::filesystem::exists(settings_)) {
        Directory(settings_.parent_path()); Handle lock; Lock(settings_.parent_path() / L"analysis-settings.lock", lock);
        Write(settings_, {{"directory", ""}});
    }
    directory_.clear(); startupError_.clear(); return {{"success", true}, {"enabled", false}};
}

AnalysisStore::Json AnalysisStore::Status() {
    std::lock_guard<std::mutex> guard(mutex_);
    Json out = {{"enabled", !directory_.empty()}, {"directory", directory_.empty() ? Json(nullptr) : Json(directory_.u8string())}};
    if (!startupError_.empty()) out["warning"] = startupError_;
    if (!directory_.empty()) { const auto doc = ReadLocked(); out["revision"] = doc["revision"]; out["count"] = doc["entries"].size(); }
    return out;
}

AnalysisStore::Json AnalysisStore::ReadLocked() {
    if (directory_.empty()) throw AnalysisError("analysis_not_open", "Open an analysis directory first");
    Directory(directory_); auto doc = Read(directory_ / L"analysis.json"); Validate(doc); return doc;
}

AnalysisStore::Json AnalysisStore::Snapshot() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (directory_.empty()) return Json();
    return ReadLocked();
}

AnalysisStore::Json AnalysisStore::Mutate(const std::string& operation, Json entry, const std::string& expectedRevision) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (directory_.empty()) throw AnalysisError("analysis_not_open", "Open an analysis directory first");
    Directory(directory_); Handle lock; Lock(directory_ / L"analysis.lock", lock);
    auto doc = ReadLocked(); auto& entries = doc["entries"]; const auto id = entry.at("id").get<std::string>();
    const auto documentRevision = Revision(doc["revision"]);
    if (documentRevision == UINT64_MAX) throw AnalysisError("analysis_size", "Analysis revision limit reached");
    const auto found = entries.find(id);
    if (found != entries.end()) {
        if (expectedRevision.empty() || (*found)["revision"] != expectedRevision)
            throw AnalysisError("analysis_conflict", "Annotation changed or expected_revision is missing; read it before updating");
    } else if (!expectedRevision.empty() || operation == "delete")
        throw AnalysisError("analysis_conflict", "Annotation no longer exists");
    if (operation == "delete") entries.erase(id);
    else {
        const uint64_t revision = found == entries.end() ? 0 : Revision((*found)["revision"]);
        if (revision == UINT64_MAX || (found == entries.end() && entries.size() >= kMaximumEntries))
            throw AnalysisError("analysis_size", "Annotation capacity or revision limit reached");
        if (found != entries.end()) {
            auto previous = *found; auto history = previous.value("history", Json::array()); previous.erase("history");
            history.push_back(std::move(previous));
            if (history.size() > 8) { history.erase(history.begin()); entry["history_truncated"] = true; }
            entry["history"] = std::move(history);
        }
        // Document-monotonic revisions prevent stale writers from matching an
        // annotation that was deleted and recreated at the same build/RVA.
        entry["revision"] = std::to_string(documentRevision + 1); entries[id] = entry;
    }
    const auto revision = Revision(doc["revision"]);
    if (revision == UINT64_MAX) throw AnalysisError("analysis_size", "Analysis revision limit reached");
    doc["revision"] = std::to_string(revision + 1); Validate(doc); Write(directory_ / L"analysis.json", doc);
    Json out = {{"success", true}, {"revision", doc["revision"]}};
    if (operation != "delete") {
        out["annotation"] = entries[id];
        out["annotation"]["history_count"] = entries[id].value("history", Json::array()).size();
        out["annotation"].erase("history");
    }
    return out;
}
} // namespace veh
