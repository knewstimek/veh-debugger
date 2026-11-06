#include "page_breakpoint.h"
#include "syscall_resolver.h"
#include "veh_handler.h"
#include <algorithm>

namespace veh {
PageBreakpointManager& PageBreakpointManager::Instance() {
    static PageBreakpointManager value;
    return value;
}
bool PageBreakpointManager::Protect(Page& page, bool guard) {
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(reinterpret_cast<void*>(page.base), &region, sizeof(region)))return false;
    if(region.State!=MEM_COMMIT||reinterpret_cast<uintptr_t>(region.AllocationBase)!=page.allocation)
        return !guard; //retire a disappeared/replaced mapping without writing to it
    // Do not overwrite a protection change made by the target. Cleanup can
    // relinquish ownership without restoring an obsolete protection value.
    if (region.Protect != page.original && region.Protect != (page.original|PAGE_GUARD)) return !guard;
    const auto desired=page.original|(guard?PAGE_GUARD:0);
    if (region.Protect==desired) return true;
    PVOID base=reinterpret_cast<void*>(page.base); SIZE_T size=pageSize_; ULONG old=0;
    return NT_SUCCESS(SyscallResolver::Instance().ProtectVirtualMemory(&base,&size,desired,&old));
}
bool PageBreakpointManager::Active() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& watch:watches_) if(watch.id)return true;
    if(pendingCount_.load(std::memory_order_acquire))return true;
    return false;
}
IpcStatus PageBreakpointManager::Add(uint64_t address,uint32_t size,uint8_t access,uint32_t& id) {
    RearmMutation mutation;
    id=0;
    if(!mutation||!RearmGuard::Instance().Ready())return IpcStatus::InvalidState;
    if (!address||!size||size>65536||address>UINTPTR_MAX||
        size-1>UINTPTR_MAX-static_cast<uintptr_t>(address)||(access!=1&&access!=3))return IpcStatus::InvalidArgs;
    SYSTEM_INFO system{};GetSystemInfo(&system);
    std::lock_guard<std::mutex> lock(mutex_);
    pageSize_=system.dwPageSize;
    Watch* free=nullptr;
    for(auto& watch:watches_) {
        if(!watch.id){if(!free)free=&watch;continue;}
        if(address<watch.address+watch.size && watch.address<address+size)return IpcStatus::InvalidArgs;
    }
    if(!free||nextId_==UINT32_MAX)return IpcStatus::LimitReached;
    std::array<size_t,64> indices{};size_t count=0;
    const uintptr_t first=static_cast<uintptr_t>(address)&~(static_cast<uintptr_t>(pageSize_)-1);
    const uintptr_t last=(static_cast<uintptr_t>(address)+size-1)&~(static_cast<uintptr_t>(pageSize_)-1);
    if(first!=last){*free={};return IpcStatus::InvalidArgs;} //v1: one page per watch
    for(uintptr_t base=first;;base+=pageSize_) {
        size_t index=pages_.size();
        for(size_t i=0;i<pages_.size();++i)if(pages_[i].base==base){index=i;break;}
        if(index==pages_.size())
            for(size_t i=0;i<pages_.size();++i) {
                if(pages_[i].refs)continue;
                bool selected=false;for(size_t j=0;j<count;++j)if(indices[j]==i)selected=true;
                // Pending leases keep their slot until completion.
                for(const auto& lease:pending_)if(lease.tid&&(lease.pages&(1ULL<<i)))selected=true;
                if(!selected){index=i;break;}
            }
        if(index==pages_.size())return IpcStatus::LimitReached;
        auto& page=pages_[index];
        if(!page.refs) {
            MEMORY_BASIC_INFORMATION region{};
            if(!VirtualQuery(reinterpret_cast<void*>(base),&region,sizeof(region))||
               region.State!=MEM_COMMIT||region.Type!=MEM_PRIVATE||
               (region.Protect!=PAGE_READWRITE&&region.Protect!=PAGE_READONLY))
                return IpcStatus::InvalidArgs;
            // A stack reservation includes an existing guard; never take ownership
            // of OS stack growth or another component's guard page.
            uintptr_t cursor=reinterpret_cast<uintptr_t>(region.AllocationBase);
            for(size_t n=0;n<4096;++n) {
                MEMORY_BASIC_INFORMATION part{};
                if(!VirtualQuery(reinterpret_cast<void*>(cursor),&part,sizeof(part))||
                   part.AllocationBase!=region.AllocationBase)break;
                if(part.Protect&PAGE_GUARD) {
                    for(uintptr_t p=cursor;p<cursor+part.RegionSize;p+=pageSize_) {
                        bool ours=false;
                        for(const auto& owned:pages_)if(owned.refs&&owned.base==p){ours=true;break;}
                        if(!ours)return IpcStatus::InvalidArgs;
                    }
                }
                if(part.RegionSize>UINTPTR_MAX-cursor)return IpcStatus::InvalidArgs;
                const auto next=cursor+part.RegionSize;if(next<=cursor)return IpcStatus::InvalidArgs;
                cursor=next;
                if(n==4095)return IpcStatus::InvalidArgs;
            }
            page={base,reinterpret_cast<uintptr_t>(region.AllocationBase),region.Protect,0};
        }
        indices[count++]=index;
        if(base==last)break;
    }
    // Publish the watch before arming; a concurrent exception waits for this lock.
    const uint32_t assigned=nextId_++;
    *free={assigned,address,size,access};
    size_t applied=0;
    for(;applied<count;++applied) {
        auto& page=pages_[indices[applied]];
        ++page.refs;
        bool borrowed=false;
        // A parked lease is safe to arm, including remove/recreate at a stop.
        // Only an executing retry must retain its temporarily open page.
        for(const auto& lease:pending_)if(lease.tid&&!lease.parked&&(lease.pages&(1ULL<<indices[applied])))borrowed=true;
        if(!borrowed&&!Protect(page,true)){--page.refs;break;}
    }
    if(applied!=count) {
        for(size_t i=0;i<applied;++i) {
            auto& page=pages_[indices[i]];
            if(!--page.refs)Protect(page,false);
        }
        *free={};return IpcStatus::Error;
    }
    id=assigned;return IpcStatus::Ok;
}
IpcStatus PageBreakpointManager::Remove(uint32_t id) {
    RearmMutation mutation;if(!mutation)return IpcStatus::InvalidState;
    std::lock_guard<std::mutex> lock(mutex_);
    Watch* watch=nullptr;
    for(auto& value:watches_)if(value.id==id){watch=&value;break;}
    if(!watch)return IpcStatus::NotFound;
    // Validate and restore all last-owner pages before retiring the watch.
    for(auto& page:pages_)if(page.refs&&page.base<watch->address+watch->size&&
        watch->address<page.base+pageSize_&&page.refs==1)
        if(!Protect(page,false))return IpcStatus::InvalidState;
    for(auto& page:pages_)if(page.refs&&page.base<watch->address+watch->size&&
        watch->address<page.base+pageSize_)--page.refs;
    *watch={};return IpcStatus::Ok;
}
PageBreakpointManager::Fault PageBreakpointManager::OnGuard(uint32_t tid,uint64_t address,uint32_t access,CONTEXT& ctx) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t index=pages_.size();
    for(size_t i=0;i<pages_.size();++i)
        if(pages_[i].base&&address>=pages_[i].base&&address-pages_[i].base<pageSize_){index=i;break;}
    if(index==pages_.size())return {};
    // Includes a guard exception dispatched just after last-owner removal.
    Fault result{true,0,(ctx.EFlags&0x100)!=0};
    if(!pages_[index].refs)return result;
    Pending* pending=nullptr;
    for(auto& lease:pending_)if(lease.tid==tid){pending=&lease;break;}
    if(!pending)for(auto& lease:pending_)if(!lease.tid) {
        HANDLE thread=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,tid);
        if(!thread)break;
        lease={tid,0,result.originalTF,thread};pending=&lease;
        pendingCount_.fetch_add(1,std::memory_order_release);break;
    }
    if(!pending) {
        // Report an unconfirmed lease; do not re-arm/retry forever on the
        // internal control thread, which must remain able to remove watches.
        Protect(pages_[index],false);result.failed=true;return result;
    }
    pending->parked=false;
    pending->pages|=1ULL<<index;
    result.originalTF=pending->originalTF;
    ctx.EFlags|=0x100;
    for(const auto& watch:watches_)if(watch.id&&address>=watch.address&&address-watch.address<watch.size&&
        (access==1||(access==0&&watch.access==3))) {result.id=watch.id;break;}
    return result;
}
bool PageBreakpointManager::CompleteLocked(Pending& pending,CONTEXT& ctx,bool& originalTF,bool* failed) {
    originalTF=pending.originalTF;
    for(size_t i=0;i<pages_.size();++i)
        if((pending.pages&(1ULL<<i))&&pages_[i].refs) {
            // On failure retain ownership; caller surfaces the real stop rather
            // than asserting complete coverage. Removal reports restoration failure.
            if(!Protect(pages_[i],true)&&failed)*failed=true;
        }
    ctx.EFlags=(ctx.EFlags&~0x100UL)|(originalTF?0x100UL:0);
    if(pending.thread)SyscallResolver::Instance().Close(pending.thread);
    pending={};pendingCount_.fetch_sub(1,std::memory_order_release);return true;
}
bool PageBreakpointManager::Complete(uint32_t tid,CONTEXT& ctx,bool& originalTF,bool* failed) {
    if(failed)*failed=false;
    if(!pendingCount_.load(std::memory_order_acquire))return false;
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto& lease:pending_)if(lease.tid==tid)return CompleteLocked(lease,ctx,originalTF,failed);
    return false;
}
void PageBreakpointManager::Cancel(uint32_t tid,CONTEXT& ctx) {bool original=false;Complete(tid,ctx,original);}
bool PageBreakpointManager::Park(uint32_t tid) {
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto& lease:pending_)if(lease.tid==tid) {
        bool ok=true;
        for(size_t i=0;i<pages_.size();++i)if((lease.pages&(1ULL<<i))&&pages_[i].refs)
            if(!Protect(pages_[i],true))ok=false;
        lease.parked=ok;
        return ok;
    }
    return false;
}
bool PageBreakpointManager::PrepareStep(uint32_t tid,RearmGuard::Page* pages,size_t& count) {
    std::lock_guard<std::mutex> lock(mutex_);
    count=0;
    for(auto& lease:pending_)if(lease.tid==tid) {
        for(size_t i=0;i<pages_.size();++i)if((lease.pages&(1ULL<<i))&&pages_[i].refs) {
            MEMORY_BASIC_INFORMATION region{};
            const auto& page=pages_[i];
            if(!VirtualQuery(reinterpret_cast<void*>(page.base),&region,sizeof(region))||
               region.State!=MEM_COMMIT||reinterpret_cast<uintptr_t>(region.AllocationBase)!=page.allocation||
               (region.Protect!=page.original&&region.Protect!=(page.original|PAGE_GUARD)))return false;
            pages[count++]={page.base,page.original};
        }
        lease.parked=false;
        break;
    }
    return true;
}
bool PageBreakpointManager::RemoveAll() {
    RearmMutation mutation;if(!mutation)return false;
    std::array<Pending,128> leases{};
    struct Handles {
        std::array<HANDLE,128> values{};
        ~Handles(){for(auto h:values)if(h)CloseHandle(h);}
    } handles;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for(auto& page:pages_)if(page.refs&&!Protect(page,false))return false;
        for(auto& page:pages_)page.refs=0;
        for(auto& watch:watches_)watch={};
        leases=pending_;
        for(size_t i=0;i<leases.size();++i)if(leases[i].tid) {
            if(!DuplicateHandle(GetCurrentProcess(),leases[i].thread,GetCurrentProcess(),
                &handles.values[i],0,FALSE,DUPLICATE_SAME_ACCESS))return false;
            leases[i].thread=handles.values[i];
        }
    }
    // Clear only the TF bit borrowed by this feature. Preserve every other
    // register and the caller's original TF; never change user suspend counts.
    for(const auto& lease:leases)if(lease.tid) {
        CONTEXT ctx{};
        if(VehHandler::Instance().GetStoppedContext(lease.tid,ctx)) {
            ctx.EFlags=(ctx.EFlags&~0x100UL)|(lease.originalTF?0x100UL:0);
            if(!VehHandler::Instance().SetStoppedContext(lease.tid,ctx))return false;
            std::lock_guard<std::mutex> lock(mutex_);
            for(auto& pending:pending_)if(pending.tid==lease.tid) {
                if(pending.thread)SyscallResolver::Instance().Close(pending.thread);pending={};pendingCount_.fetch_sub(1,std::memory_order_release);
            }
            continue;
        }
        HANDLE thread=lease.thread;
        DWORD exitCode=STILL_ACTIVE;
        if(GetExitCodeThread(thread,&exitCode)&&exitCode!=STILL_ACTIVE) {
            std::lock_guard<std::mutex> lock(mutex_);
            for(auto& pending:pending_)if(pending.tid==lease.tid) {
                if(pending.thread)SyscallResolver::Instance().Close(pending.thread);pending={};pendingCount_.fetch_sub(1,std::memory_order_release);
            }
            continue;
        }
        if(SuspendThread(thread)==DWORD(-1))return false;
        // A suspended thread may own this lock: never block on it.
        if(!mutex_.try_lock()){ResumeThread(thread);return false;}
        bool ok=true;
        for(auto& pending:pending_)if(pending.tid==lease.tid) {
            ctx.ContextFlags=CONTEXT_CONTROL;
            ok=GetThreadContext(thread,&ctx)!=FALSE;
            if(ok) {
                ctx.EFlags=(ctx.EFlags&~0x100UL)|(pending.originalTF?0x100UL:0);
                ok=SetThreadContext(thread,&ctx)!=FALSE;
            }
            if(ok){if(pending.thread)SyscallResolver::Instance().Close(pending.thread);pending={};pendingCount_.fetch_sub(1,std::memory_order_release);}
            break;
        }
        mutex_.unlock();
        ResumeThread(thread);
        if(!ok)return false;
    }
    return true;
}
}
