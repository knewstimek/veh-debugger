#include "kd_capture_collect.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>
namespace veh {
namespace {
using json=nlohmann::json;
std::string Field(uint64_t n){char b[24];snprintf(b,sizeof(b),"%llx",static_cast<unsigned long long>(n));return b;}
bool Unhex(const std::string& text,void* output,size_t bytes){
    if(text.size()!=bytes*2)return false;
    auto digit=[](char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    auto* p=static_cast<uint8_t*>(output);
    for(size_t i=0;i<bytes;++i){const int a=digit(text[i*2]),b=digit(text[i*2+1]);if(a<0||b<0)return false;p[i]=static_cast<uint8_t>(a*16+b);}return true;
}
}
bool CollectKdCapture(KernelDebugClient& kd,uint32_t version,uint32_t steps,uint32_t timeout,
    uint32_t flags,uint32_t cpu,uint64_t start,uint64_t end,KdCaptureStore& store,
    KdCollected& result,json& error){
    std::string text,stop;
    kdtrace::Header before={};
    if(!kd.Request("qTraceBB:status",&text)||!Unhex(text,&before,sizeof(before))){
        error={{"error","Cannot read initial KD capture status"}};return false;
    }
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout);
    uint64_t generation=0,received=0,previousNext=0;
    const auto fail=[&](const char* message,bool halted=true){
        error={{"error",message},{"halted",halted},{"capture_incomplete",true},
            {"generation",std::to_string(generation)},{"copied_records",std::to_string(received)},
            {"backend_buffer_retained",halted}};
        if(store.size())error["capture_file"]=store.Keep(false);
        return false;
    };
    auto command="vTraceBB:"+Field(version)+","+Field(steps)+","+Field(start)+","+Field(end)+","+Field(flags);
    for(;;){
        if(!kd.Resume(command))return fail("KD link lost before capture acknowledgement; execution state unknown",false);
        const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        const uint32_t wait=static_cast<uint32_t>((std::max)(int64_t{1},left));
        if(!kd.WaitStop(&stop,wait)){
            result.timedOut=std::chrono::steady_clock::now()>=deadline;
            if(!kd.QueryStop(&stop,500)&&!kd.Interrupt(&stop,5000))return fail("Could not confirm KD capture stop",false);
        }
        kdtrace::HeaderV2 stream={};auto& h=stream.base;
        if(version==kdtrace::kStreamVersion){
            const bool statusRead=kd.Request("qTraceBB:status2",&text);
            if(statusRead&&text=="E23"){
                fail("KD backend cannot confirm all-CPU halt or selected final PC",false);
                error["backend_error"]="E23";return false;
            }
            if(!statusRead||!Unhex(text,&stream,sizeof(stream)))return fail("Malformed streamed KD capture status");
        }else{
            if(!kd.Request("qTraceBB:status",&text)||!Unhex(text,&h,sizeof(h)))return fail("Malformed KD capture status");
            stream.recordOffset=0;stream.maxSteps=steps;
        }
        const uint32_t recordSize=version==kdtrace::kVersion||flags&kdtrace::kSnapshots?
            sizeof(kdtrace::Record):sizeof(kdtrace::CompactRecord);
        const bool more=version==kdtrace::kStreamVersion&&h.end==kdtrace::kBufferFull;
        const bool peerPolicy=version==kdtrace::kStreamVersion&&(flags&kdtrace::kRunPeerCpus);
        const bool codeUncertain=h.end==kdtrace::kCodeUncertain;
        const bool completionUncertain=h.end==kdtrace::kCompletionUncertain;
        if(!generation)generation=h.generation;
        if(h.version!=version||h.recordSize!=recordSize||!generation||h.generation!=generation||generation==before.generation||
            h.cpu!=cpu||h.flags!=flags||h.reserved||stream.reserved||stream.recordOffset!=received||
            h.count>kdtrace::kCapacity||h.steps>steps||stream.recordOffset>steps||
            stream.recordOffset+h.count!=h.steps||stream.maxSteps!=steps||
            (version==kdtrace::kStreamVersion&&stream.paused!=(more?1u:0u))||
            (h.end==kdtrace::Budget&&h.steps!=steps)||
            (h.end==kdtrace::Range&&h.finalAddress>=start&&h.finalAddress<end)||
            (more&&(h.count!=kdtrace::kCapacity||h.steps>=steps||h.finalAddress<start||h.finalAddress>=end))||
            ((codeUncertain||completionUncertain)&&!peerPolicy)||(codeUncertain&&!h.count)||
            (completionUncertain&&h.steps>=steps)||
            h.end<kdtrace::Budget||h.end>(version==kdtrace::kStreamVersion?kdtrace::kCompletionUncertain:kdtrace::UnsupportedInstruction))
            return fail("KD capture refused or returned inconsistent terminal/offset/CPU receipt");
        std::vector<kdtrace::Record> chunk(h.count);
        for(uint32_t offset=0;offset<h.count;){
            const uint32_t count=(std::min)(4096u/(2*recordSize),h.count-offset);
            const std::string read=version==kdtrace::kVersion?
                "qTraceBB:read,"+Field(generation)+","+Field(offset)+","+Field(count):
                "qTraceBB:read2,"+Field(generation)+","+Field(received+offset)+","+Field(count);
            if(!kd.Request(read,&text))return fail("KD capture page read failed; current buffer retained");
            if(text=="E23"){
                fail("KD backend cannot confirm all-CPU halt or selected final PC",false);
                error["backend_error"]="E23";return false;
            }
            std::vector<uint8_t> wire(count*recordSize);
            if(!Unhex(text,wire.data(),wire.size()))return fail("Malformed KD capture page; current buffer retained");
            for(uint32_t i=0;i<count;++i){
                auto& r=chunk[offset+i];
                if(version==kdtrace::kVersion)std::memcpy(&r,wire.data()+i*recordSize,sizeof(r));
                else{
                    kdtrace::CompactRecord compact;std::memcpy(&compact,wire.data()+i*recordSize,sizeof(compact));
                    r.address=compact.address;r.nextAddress=compact.nextAddress;r.cr3=compact.cr3;
                    r.cpu=compact.cpu;r.pid=compact.pid;r.tid=compact.tid;r.addressBits=compact.addressBits;
                    r.cpl=compact.cpl;r.codeSize=compact.codeSize;r.reserved=compact.reserved;
                    std::memcpy(r.code,compact.code,sizeof(r.code));
                    if(flags&kdtrace::kSnapshots)std::memcpy(r.registers,wire.data()+i*recordSize+sizeof(compact),sizeof(r.registers));
                }
                const uint64_t index=received+offset+i;
                const bool uncertainRecord=codeUncertain&&offset+i+1==h.count;
                const bool codeValid=uncertainRecord?
                    r.reserved==kdtrace::kCodeUncertainRecord&&r.codeSize==0&&
                        std::all_of(std::begin(r.code),std::end(r.code),[](uint8_t b){return b==0;}):
                    r.reserved==0&&r.codeSize>=1&&r.codeSize<=15;
                if(r.cpu!=cpu||!codeValid||(r.addressBits!=32&&r.addressBits!=64)||r.cpl>3||
                    r.address<start||r.address>=end||
                    (index&&r.address!=previousNext)||
                    ((offset+i+1<h.count||more)&&(r.nextAddress<start||r.nextAddress>=end)))
                    return fail("Inconsistent KD capture record chain");
                previousNext=r.nextAddress;
            }
            offset+=count;
        }
        if(!completionUncertain&&((h.steps&&previousNext!=h.finalAddress)||
           (!h.steps&&(h.finalAddress<start||h.finalAddress>=end))))
            return fail("KD capture final PC disagrees with copied records");
        if(!store.Append(chunk.data(),h.count,generation,cpu))return fail("Capture storage failed; acknowledged prefix and current buffer retained");
        received+=h.count;++result.chunks;result.final=h;
        if(!more)return true;
        // The operation deadline is rechecked after all I/O and before the next
        // execution effect. Draining cannot reset the logical step budget.
        if(std::chrono::steady_clock::now()>=deadline){
            result.timedOut=true;
            if(!kd.Request("qTraceBB:cancel2,"+Field(generation),&text)||text!="OK")return fail("Could not cancel paused KD capture");
            kdtrace::HeaderV2 ended={};
            const bool statusRead=kd.Request("qTraceBB:status2",&text);
            if(statusRead&&text=="E23"){
                fail("KD backend cannot confirm all-CPU halt or selected final PC",false);
                error["backend_error"]="E23";return false;
            }
            if(!statusRead||!Unhex(text,&ended,sizeof(ended))||
                ended.base.generation!=generation||ended.base.steps!=received||ended.base.end!=kdtrace::Interrupted||
                ended.base.finalAddress!=h.finalAddress||ended.paused||ended.reserved||
                ended.base.version!=version||ended.base.recordSize!=recordSize||ended.base.flags!=flags||
                ended.base.cpu!=cpu||ended.base.reserved||ended.base.count!=h.count||
                ended.recordOffset!=stream.recordOffset||ended.maxSteps!=steps)
                return fail("Invalid KD cancellation receipt");
            result.final=ended.base;return true;
        }
        command="vTraceBB:resume2,"+Field(generation)+","+Field(received);
    }
}
}
