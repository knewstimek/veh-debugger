#pragma once
#include "mcp_server.h"

namespace veh {

uint32_t JsonUint32(const json& args, const char* key, uint32_t defaultVal = 0);
int JsonInt(const json& args, const char* key, int defaultVal = 0);
bool JsonBool(const json& args, const char* key, bool defaultVal = false);
std::string HexAddr(uint64_t value);
unsigned ProfileMask(const std::string& profile);

} // namespace veh
