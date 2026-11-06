#pragma once
#include <windows.h>
#include <array>
#include <mutex>
#include <atomic>
#include "../common/ipc_protocol.h"

namespace veh {
// Process-wide page protection; no allocation or callback under this lock.
// PAGE_GUARD is one-shot: other threads can access during the rearm window.
class PageBreakpointManager {
public:
    static PageBreakpointManager& Instance();
    IpcStatus Add(uint64_t address, uint32_t size, uint8_t access, uint32_t& id);
    IpcStatus Remove(uint32_t id);
    bool RemoveAll();
    bool Active();
    struct Fault { bool handled=false; uint32_t id=0; bool originalTF=false; bool failed=false; };
    Fault OnGuard(uint32_t tid, uint64_t address, uint32_t access, CONTEXT& ctx);
    // Returns true only for our pending one-instruction lease.
    bool Complete(uint32_t tid, CONTEXT& ctx, bool& originalTF, bool* failed=nullptr);
    void Cancel(uint32_t tid, CONTEXT& ctx);
    bool Park(uint32_t tid);
    bool OpenForStep(uint32_t tid);
private:
    struct Watch { uint32_t id=0; uint64_t address=0; uint32_t size=0; uint8_t access=0; };
    struct Page { uintptr_t base=0, allocation=0; DWORD original=0; uint32_t refs=0; };
    struct Pending { uint32_t tid=0; uint64_t pages=0; bool originalTF=false; HANDLE thread=nullptr; };
    std::array<Watch,32> watches_{};
    std::array<Page,64> pages_{};
    std::array<Pending,128> pending_{};
    std::mutex mutex_;
    std::atomic<unsigned> pendingCount_{0};
    uint32_t nextId_=20000001;
    DWORD pageSize_=4096;
    bool Protect(Page& page, bool guard);
    bool CompleteLocked(Pending& pending, CONTEXT& ctx, bool& originalTF, bool* failed);
};
}
