#pragma once

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>

namespace veh {

struct TraceOutputFileResult {
	bool success = false;
	std::string path;
	std::string format;
	std::string sha256;
	std::string error;
	uint64_t size = 0;
};

std::string ValidateTraceOutputFile(const std::string& requestedPath,
	const std::string& format);

TraceOutputFileResult WriteTraceOutputFile(const std::string& requestedPath,
	const std::string& format, const nlohmann::json& trace);

// Writes JSON/JSONL to a generated, non-overwriting MCP-host artifact. An empty
// directory selects a dedicated folder under the host temporary directory.
TraceOutputFileResult WriteJsonArtifactInDirectory(const std::string& directory,
	const std::string& stem, const nlohmann::json& value,
	const std::string& format = "json");

} // namespace veh
