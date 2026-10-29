#pragma once
#include "../common/ipc_protocol.h"
namespace veh {
void PrepareModuleIdentity(); // IPC startup, before clients can install loader stops
void SetModuleIdentityTracking(bool available);
GetModuleIdentityResponse InspectModuleIdentity(uint64_t base);
}
