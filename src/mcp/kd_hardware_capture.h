#pragma once
#include "../common/kd_hardware_trace_protocol.h"
#include <nlohmann/json.hpp>
namespace veh {
nlohmann::json ShapeKdHardwareRecords(const kdtrace::Record* records, size_t count,
    const kdtrace::Header& header, const nlohmann::json& args);
nlohmann::json ReadKdHardwareCapture(const nlohmann::json& args);
}
