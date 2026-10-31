#pragma once
#include "kd_capture_store.h"
#include "kernel_debug_client.h"
namespace veh {
struct KdCollected { kdtrace::Header final={}; bool timedOut=false; uint32_t chunks=0; };
bool CollectKdCapture(KernelDebugClient& kd,uint32_t version,uint32_t steps,uint32_t timeout,
    uint32_t flags,uint32_t cpu,uint64_t start,uint64_t end,KdCaptureStore& store,
    KdCollected& result,nlohmann::json& error);
}
