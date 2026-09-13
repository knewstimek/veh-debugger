#pragma once

#include "debug_session.h"
#include <functional>
#include <nlohmann/json.hpp>
#include <string>

namespace veh {

using TraceAddressResolver = std::function<bool(const std::string&, uint64_t&)>;

// Shared implementation used by direct MCP calls and veh_batch. Keeping the
// validation and JSON shaping here guarantees that both entry points stay in
// lockstep as the trace result evolves.
nlohmann::json ExecuteTraceBasicBlocksTool(DebugSession& session,
	const nlohmann::json& args, const TraceAddressResolver& resolveAddress,
	const nlohmann::json& artifactMetadata = nlohmann::json::object());

} // namespace veh
