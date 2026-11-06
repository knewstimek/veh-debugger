#include "rearm_guard.h"
#include "syscall_resolver.h"
#include "hw_breakpoint.h"
#include <intrin.h>

namespace veh {
// This path may precede CRT TLS; a local-static guard would read its TLS epoch.
namespace {RearmGuard processGuard;}
RearmGuard& RearmGuard::Instance(){return processGuard;}
bool RearmGuard::Patch(uint64_t address,uint8_t byte) {
    auto& nt=SyscallResolver::Instance();
    PVOID base=reinterpret_cast<void*>(static_cast<uintptr_t>(address));
    SIZE_T size=1;ULONG old=0;
    if(!NT_SUCCESS(nt.ProtectVirtualMemory(&base,&size,PAGE_EXECUTE_READWRITE,&old)))return false;
    *reinterpret_cast<volatile uint8_t*>(static_cast<uintptr_t>(address))=byte;
    base=reinterpret_cast<void*>(static_cast<uintptr_t>(address));size=1;ULONG unused=0;
    const bool restored=NT_SUCCESS(nt.ProtectVirtualMemory(&base,&size,old,&unused));
    return NT_SUCCESS(nt.FlushInstructionCache(reinterpret_cast<void*>(static_cast<uintptr_t>(address)),1))&&restored;
}
bool RearmGuard::Initialize() {
    if(Ready())return true;
    auto p=reinterpret_cast<uint8_t*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlUserThreadStart"));
    if(!p)return false;
#ifdef _WIN64
    // Emulate only this verified, position-independent prologue instruction.
    if(p[0]!=0x48||p[1]!=0x83||p[2]!=0xEC)return false;
    entryLength_=4;stackSubtract_=p[3];
    if(stackSubtract_&0x80)return false;
#else
    if(p[0]==0x8B&&p[1]==0xFF)entryLength_=2; //mov edi,edi
    else if(p[0]==0x90)entryLength_=1;
    else if(p[0]==0x83&&p[1]==0x3D&&p[6]==0) {
        comparisonAddress_=*reinterpret_cast<const uint32_t*>(p+2);entryLength_=7;
    } else return false;
#endif
    originalEntry_=p[0];
    if(!idle_&&!NT_SUCCESS(SyscallResolver::Instance().CreateEvent(&idle_,true)))return false;
    SyscallResolver::Instance().SetEvent(idle_);
    // Construct published DR state before exposing the private exception path.
    HwBreakpointManager::Instance();
    entry_.store(reinterpret_cast<uintptr_t>(p),std::memory_order_release);
    if(!Patch(reinterpret_cast<uintptr_t>(p),0xCC)) {
        // A restore/flush error after the write must not orphan a live INT3.
        if(Patch(reinterpret_cast<uintptr_t>(p),originalEntry_))entry_.store(0);
        return false;
    }
    ready_.store(true,std::memory_order_release);
    return true;
}
bool RearmGuard::Shutdown() {
    // Lifecycle commands own kCommand; an executing retry cannot be uninstalled.
    const auto owner=owner_.load(std::memory_order_acquire);
    if(owner&&owner!=kCommand)return false;
    const auto address=entry_.load(std::memory_order_acquire);
    if(address) {
        if(*reinterpret_cast<volatile uint8_t*>(address)!=0xCC||!Patch(address,originalEntry_))return false;
        entry_.store(0,std::memory_order_release);
    }
    ready_.store(false,std::memory_order_release);
    // Keep the event alive for callbacks already dispatched before restoration.
    return true;
}
bool RearmGuard::Reserved(uint64_t address,uint64_t size) const {
    const auto entry=entry_.load(std::memory_order_acquire);
    return entry&&size&&address<=UINT64_MAX-size&&address<entry+entryLength_&&entry<address+size;
}
void RearmGuard::RegisterInternal(uint32_t tid) {
    for(auto& value:internal_) {
        if(value.load(std::memory_order_acquire)==tid)return;
        uint32_t empty=0;if(value.compare_exchange_strong(empty,tid))return;
    }
}
void RearmGuard::UnregisterInternal(uint32_t tid) {
    for(auto& value:internal_){uint32_t found=tid;value.compare_exchange_strong(found,0);}
}
bool RearmGuard::Internal(uint32_t tid) const {
    for(const auto& value:internal_)if(value.load(std::memory_order_acquire)==tid)return true;
    return false;
}
bool RearmGuard::RecoverDeadOwner() {
    auto owner=owner_.load(std::memory_order_acquire);
    if(!owner||owner==kCommand||owner==kRecover||!ownerThread_)return false;
    uint32_t tid=0;bool dead=false;
    if(!NT_SUCCESS(SyscallResolver::Instance().ThreadIdentity(ownerThread_,tid,dead))||!dead||tid!=owner)return false;
    if(!owner_.compare_exchange_strong(owner,kRecover))return false;
    returnCommand_=false;commandThread_.store(0);commandDepth_=0;
    RestoreAndRelease();return true;
}
bool RearmGuard::Wait(uint32_t wanted) {
    for(size_t attempt=0;attempt<2000;++attempt) {
        const auto owner=owner_.load(std::memory_order_acquire);
        if(owner==wanted||(!wanted&&owner==kCommand))return true;
        if(RecoverDeadOwner())continue;
        LARGE_INTEGER timeout{};timeout.QuadPart=-10000; //relative monotonic 1 ms
        if(idle_)SyscallResolver::Instance().WaitForSingleObject(idle_,&timeout);
        else YieldProcessor();
    }
    return false;
}
bool RearmGuard::EnterCommand() {
#ifdef _WIN64
    const uint32_t tid=__readgsdword(0x48);
#else
    const uint32_t tid=__readfsdword(0x24);
#endif
    if(owner_.load(std::memory_order_acquire)==kCommand&&commandThread_.load()==tid){++commandDepth_;return true;}
    for(size_t attempt=0;attempt<2000;++attempt) {
        uint32_t empty=0;
        if(owner_.compare_exchange_strong(empty,kCommand)) {
            commandThread_.store(tid);commandDepth_=1;
            if(idle_)SyscallResolver::Instance().ResetEvent(idle_);
            return true;
        }
        RecoverDeadOwner();
        LARGE_INTEGER timeout{};timeout.QuadPart=-10000;
        if(idle_)SyscallResolver::Instance().WaitForSingleObject(idle_,&timeout);
        else YieldProcessor();
    }
    return false;
}
void RearmGuard::LeaveCommand(){if(--commandDepth_)return;commandThread_.store(0);owner_.store(0,std::memory_order_release);if(idle_)SyscallResolver::Instance().SetEvent(idle_);}
bool RearmGuard::Enter(uint32_t tid) {
    if(!Ready())return false;
    for(size_t attempt=0;attempt<2000;++attempt) {
        uint32_t empty=0;
        const bool nested=owner_.load(std::memory_order_acquire)==kCommand&&commandThread_.load()==tid;
        if((empty=0,owner_.compare_exchange_strong(empty,tid))||(nested&&(empty=kCommand,owner_.compare_exchange_strong(empty,tid)))) {
            returnCommand_=nested;
            peerCount_=pageCount_=0;software_=0;softwareOpen_=false;
            HANDLE ownerHandle=nullptr;
            SyscallResolver::Instance().ResetEvent(idle_);
            if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&ownerHandle,0,FALSE,DUPLICATE_SAME_ACCESS)) {
                RestoreAndRelease();return false;
            }
            ownerThread_.store(ownerHandle,std::memory_order_release);
            return true;
        }
        // Do not hold manager locks while waiting for command/retry ownership.
        LARGE_INTEGER timeout{};timeout.QuadPart=-10000;
        SyscallResolver::Instance().WaitForSingleObject(idle_,&timeout);
        RecoverDeadOwner();
    }
    return false;
}
bool RearmGuard::Open(uint64_t softwareAddress,uint8_t original,const Page* pages,size_t count) {
    if(count>pages_.size())return false;
    auto& nt=SyscallResolver::Instance();
    const auto self=owner_.load(std::memory_order_acquire);
    HANDLE previous=nullptr;bool previousKept=false;
    for(size_t n=0;n<kMaxThreads;++n) {
        HANDLE thread=nullptr;
        const auto status=nt.NextThread(previous,THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,&thread);
        if(previous&&!previousKept)nt.Close(previous);
        previousKept=false;
        previous=nullptr;
        if(status==static_cast<NTSTATUS>(0x8000001A))break; //STATUS_NO_MORE_ENTRIES
        if(!NT_SUCCESS(status)){return false;}
        uint32_t tid=0;bool exited=false;
        if(!NT_SUCCESS(nt.ThreadIdentity(thread,tid,exited))){nt.Close(thread);return false;}
        if(!exited&&tid!=self&&!Internal(tid)) {
            if(!NT_SUCCESS(nt.Suspend(thread))){nt.Close(thread);return false;}
            peers_[peerCount_++]=thread;
            previousKept=true;
        }
        previous=thread;
        if(n==kMaxThreads-1){if(!previousKept)nt.Close(previous);return false;}
    }
    software_=softwareAddress;
    if(software_) {
        // A syscall can block until a peer runs. Do not silently freeze peers
        // across a kernel transition that cannot deliver the one-step promptly.
        const auto p=reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(software_));
        if((original==0x0F&&(p[1]==0x05||p[1]==0x34))||(original==0xCD&&p[1]==0x2E))return false;
        softwareOpen_=true;
        if(!Patch(software_,original))return false;
    }
    for(size_t i=0;i<count;++i) {
        pages_[pageCount_++]=pages[i];
        PVOID base=reinterpret_cast<void*>(pages[i].base);SIZE_T size=4096;ULONG old=0;
        if(!NT_SUCCESS(nt.ProtectVirtualMemory(&base,&size,pages[i].protection,&old)))return false;
    }
    return true;
}
bool RearmGuard::RestoreAndRelease() {
    auto& nt=SyscallResolver::Instance();bool ok=true;
    if(softwareOpen_&&!Patch(software_,0xCC))ok=false;
    softwareOpen_=false;software_=0;
    for(size_t i=0;i<pageCount_;++i) {
        PVOID base=reinterpret_cast<void*>(pages_[i].base);SIZE_T size=4096;ULONG old=0;
        if(!NT_SUCCESS(nt.ProtectVirtualMemory(&base,&size,pages_[i].protection|PAGE_GUARD,&old)))ok=false;
    }
    pageCount_=0;
    // Only our own suspend increments are removed. User Freeze/Pause stay intact.
    for(size_t i=0;i<peerCount_;++i){if(!NT_SUCCESS(nt.Resume(peers_[i])))ok=false;nt.Close(peers_[i]);peers_[i]=nullptr;}
    peerCount_=0;
    if(const auto ownerHandle=ownerThread_.exchange(nullptr))nt.Close(ownerHandle);
    const bool command=returnCommand_;
    returnCommand_=false;
    owner_.store(command?kCommand:0,std::memory_order_release);
    if(idle_&&!command)nt.SetEvent(idle_);
    return ok;
}
bool RearmGuard::Finish(uint32_t tid) {
    if(owner_.load(std::memory_order_acquire)!=tid)return true;
    return RestoreAndRelease();
}
bool RearmGuard::HandleThreadEntry(PEXCEPTION_POINTERS info,uint32_t tid) {
    const auto address=entry_.load(std::memory_order_acquire);
    if(!address||info->ExceptionRecord->ExceptionCode!=EXCEPTION_BREAKPOINT||
       reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress)!=address)return false;
    // New starts wait outside loader initialization while an execution lease
    // owns the briefly open code/data page. No CRT, heap, or debugger mutex here.
    if(!Internal(tid)) {
        if(!Wait(0))return false;
    }
    if(!HwBreakpointManager::ApplyAtThreadEntry(*info->ContextRecord,Internal(tid)))return false;
    CONTEXT debug=*info->ContextRecord;debug.ContextFlags=CONTEXT_DEBUG_REGISTERS;
    if(!NT_SUCCESS(SyscallResolver::Instance().SetThreadContext(reinterpret_cast<HANDLE>(-2),&debug)))return false;
    info->ContextRecord->ContextFlags|=CONTEXT_DEBUG_REGISTERS;
#ifdef _WIN64
    const uint64_t before=info->ContextRecord->Rsp,imm=stackSubtract_,after=before-imm;
    unsigned low=static_cast<unsigned>(after)&255;low^=low>>4;low&=15;
    const uint32_t flags=(before<imm?1u:0u)|
        (((0x6996u>>low)&1)?0u:4u)|
        (((before^imm^after)&16)?16u:0u)|(after==0?64u:0u)|
        ((after>>63)?128u:0u)|((((before^imm)&(before^after))>>63)?2048u:0u);
    info->ContextRecord->EFlags=(info->ContextRecord->EFlags&~0x8D5u)|flags;
    info->ContextRecord->Rsp=after;
    info->ContextRecord->Rip=address+entryLength_;
#else
    if(comparisonAddress_) {
        const DWORD value=*reinterpret_cast<volatile DWORD*>(comparisonAddress_);
        unsigned low=value&255;low^=low>>4;low&=15;
        const DWORD flags=(((0x6996u>>low)&1)?0u:4u)|(value==0?64u:0u)|((value>>31)?128u:0u);
        info->ContextRecord->EFlags=(info->ContextRecord->EFlags&~0x8D5u)|flags;
    }
    info->ContextRecord->Eip=static_cast<DWORD>(address+entryLength_);
#endif
    return true;
}
}
