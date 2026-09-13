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

} // namespace veh
