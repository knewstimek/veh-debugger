#pragma once
#include <nlohmann/json.hpp>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>

namespace veh {
struct AnalysisError : std::runtime_error {
    std::string code;
    AnalysisError(std::string value, std::string message) : std::runtime_error(std::move(message)), code(std::move(value)) {}
};
// Frontend-only metadata. Never opens a path reported by a target/backend.
class AnalysisStore {
public:
    using Json = nlohmann::json;
    AnalysisStore();
    Json Open(const std::string& directory, bool create, bool remember = true);
    Json Close();
    Json Status();
    Json Snapshot();
    Json Mutate(const std::string& operation, Json entry, const std::string& expectedRevision);
    static std::string Nonce();
private:
    Json ReadLocked();
    std::mutex mutex_;
    std::filesystem::path directory_, settings_;
    std::string startupError_;
};
} // namespace veh
