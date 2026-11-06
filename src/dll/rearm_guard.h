#pragma once
#include <windows.h>
#include <array>
#include <atomic>
#include <cstdint>

namespace veh {
// One execution lease per process. Own suspend counts/handles are independent
// of user Pause/Freeze. No allocation or debugger locks while peers are held.
class RearmGuard {
public:
    static RearmGuard& Instance();
    struct Page { uintptr_t base=0; DWORD protection=0; };
    static constexpr DWORD kFailure=0xE0564802;
    bool Initialize();
    bool Shutdown();
    bool Ready() const {return ready_.load(std::memory_order_acquire);}
    bool Reserved(uint64_t address,uint64_t size=1) const;
    bool HandleThreadEntry(PEXCEPTION_POINTERS info,uint32_t tid);
    void RegisterInternal(uint32_t tid);
    void UnregisterInternal(uint32_t tid);
    bool Internal(uint32_t tid) const;
    bool EnterCommand();
    void LeaveCommand();
    // Enter before reading manager metadata; pipe mutations cannot race the plan.
    bool Enter(uint32_t tid);
    bool Open(uint64_t softwareAddress,uint8_t original,const Page* pages,size_t count);
    bool Finish(uint32_t tid); // raw restore first; release peers before normal VEH
private:
    static constexpr uint32_t kCommand=UINT32_MAX,kRecover=UINT32_MAX-1;
    static constexpr size_t kMaxThreads=1024,kMaxPages=64;
    std::atomic<uint32_t> owner_{0};
    std::atomic<uintptr_t> entry_{0};
    std::atomic<bool> ready_{false};
    std::array<std::atomic<uint32_t>,128> internal_{};
    HANDLE idle_=nullptr;
    std::atomic<HANDLE> ownerThread_{nullptr};
    std::atomic<uint32_t> commandThread_{0};
    uint32_t commandDepth_=0;
    bool returnCommand_=false;
    std::array<HANDLE,kMaxThreads> peers_{};
    size_t peerCount_=0,pageCount_=0;
    std::array<Page,kMaxPages> pages_{};
    uint64_t software_=0;
    uint8_t originalEntry_=0,entryLength_=0,stackSubtract_=0;
    uintptr_t comparisonAddress_=0;
    bool softwareOpen_=false;
    bool Wait(uint32_t wanted);
    bool RecoverDeadOwner();
    bool RestoreAndRelease();
    static bool Patch(uint64_t address,uint8_t byte);
};
class RearmMutation {
public:
    explicit RearmMutation(bool enabled=true):active_(enabled),ok_(!enabled||RearmGuard::Instance().EnterCommand()){}
    ~RearmMutation(){if(active_&&ok_)RearmGuard::Instance().LeaveCommand();}
    explicit operator bool() const{return ok_;}
private:bool active_,ok_;
};
}
