#pragma once
#include "mcp_server.h"

namespace veh {

uint32_t JsonUint32(const json& args, const char* key, uint32_t defaultVal = 0);
int JsonInt(const json& args, const char* key, int defaultVal = 0);
bool JsonBool(const json& args, const char* key, bool defaultVal = false);
std::string HexAddr(uint64_t value);
inline json ModuleIdentity(const ModuleEntry& module) {
    return {{"name", module.name}, {"path", module.path}, {"baseAddress", HexAddr(module.baseAddress)},
        {"addressBits", module.addressBits ? json(module.addressBits) : json(nullptr)},
        {"bitness", module.addressBits == 32 ? "32-bit" : module.addressBits == 64 ? "64-bit" : "unknown"}};
}
unsigned ProfileMask(const std::string& profile);

} // namespace veh
