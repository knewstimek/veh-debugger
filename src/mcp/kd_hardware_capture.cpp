#include "mcp_server.h"
#include "kernel_debug_client.h"
#include "kd_hardware_capture.h"
#include "kd_capture_store.h"
#include "trace_output_file.h"
#include "trace_event_artifact.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <set>
#include <stdexcept>
#include <vector>

namespace veh {
namespace {
using json = nlohmann::json;
namespace hw = kdhardware;
namespace event = hardwaretrace;
std::atomic<uint64_t> nextRequest{1};
std::string Field(uint64_t n) { char s[24]; snprintf(s,sizeof(s),"%llx",static_cast<unsigned long long>(n)); return s; }
std::string Hex(uint64_t n) { return "0x" + Field(n); }
bool Unhex(const std::string& s, void* data, size_t bytes) {
    if (s.size()!=bytes*2) return false;
    auto digit=[](char c) { return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; };
    auto* out=static_cast<uint8_t*>(data);
    for(size_t i=0;i<bytes;++i) { int a=digit(s[2*i]),b=digit(s[2*i+1]); if(a<0||b<0)return false; out[i]=uint8_t(a*16+b); }
    return true;
}
bool Integer(const json& a,const char* key,uint64_t def,uint64_t lo,uint64_t hi,uint64_t& out,bool text=false) {
    out=def;if(!a.contains(key))return out>=lo&&out<=hi;
    const auto& v=a[key];
    if(v.is_number_unsigned())out=v.get<uint64_t>();
    else if(v.is_number_integer()) { const auto n=v.get<int64_t>(); if(n<0)return false;out=uint64_t(n); }
    else if(text&&v.is_string()) {
        const auto& s=v.get_ref<const std::string&>();const auto r=std::from_chars(s.data(),s.data()+s.size(),out);
        if(s.empty()||r.ec!=std::errc{}||r.ptr!=s.data()+s.size())return false;
    } else return false;
    return out>=lo&&out<=hi;
}
bool Address(const json& a,const char* key,uint64_t& out) {
    if(!a.contains(key)||!a[key].is_string())return false;
    auto s=a[key].get<std::string>();if(s.rfind("0x",0)==0||s.rfind("0X",0)==0)s.erase(0,2);
    const auto r=std::from_chars(s.data(),s.data()+s.size(),out,16);
    return !s.empty()&&r.ec==std::errc{}&&r.ptr==s.data()+s.size();
}
std::wstring Wide(const std::string& s) {
    const auto error=ValidateKdCapturePath(s,1024);if(!error.empty())throw std::runtime_error(error);
    const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
    std::wstring w(n,0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),w.data(),n);return w;
}
std::string Utf8(const std::wstring& w) {
    const int n=WideCharToMultiByte(CP_UTF8,0,w.data(),int(w.size()),nullptr,0,nullptr,nullptr);
    std::string s(n,0);WideCharToMultiByte(CP_UTF8,0,w.data(),int(w.size()),s.data(),n,nullptr,nullptr);return s;
}
bool WriteAt(HANDLE file,uint64_t offset,const void* data,DWORD bytes) {
    if(!bytes)return true;
    LARGE_INTEGER at;at.QuadPart=offset;DWORD wrote=0;
    return SetFilePointerEx(file,at,nullptr,FILE_BEGIN)&&WriteFile(file,data,bytes,&wrote,nullptr)&&wrote==bytes;
}
bool Truncate(HANDLE file,uint64_t bytes) {
    LARGE_INTEGER current{};if(GetFileSizeEx(file,&current)&&uint64_t(current.QuadPart)==bytes)return true;
    LARGE_INTEGER at;at.QuadPart=bytes;return SetFilePointerEx(file,at,nullptr,FILE_BEGIN)&&SetEndOfFile(file);
}
struct HardwareStore {
    HANDLE instructions=INVALID_HANDLE_VALUE,events=INVALID_HANDLE_VALUE,mapping=nullptr;
    const uint8_t* view=nullptr;
    std::wstring instructionPath,eventPath;
    uint64_t steps=0,eventCount=0,budget;
    uint32_t chunks=0;
    bool keep=false,headersOk=false;
    hw::HeaderV1 last;
    HardwareStore(const std::string& output,const std::string& eventOutput,uint64_t limit):budget(limit) {
        try {
            instructions=Open(output.empty()?"":output+".records",instructionPath);
            events=Open(eventOutput.empty()?(output.empty()?"":output+".events.vte"):eventOutput,eventPath);
            if(!WriteHeaders())throw std::runtime_error("Cannot initialize hardware capture artifacts");
        } catch(...) { Close();if(!instructionPath.empty())DeleteFileW(instructionPath.c_str());
            if(!eventPath.empty())DeleteFileW(eventPath.c_str());throw; }
    }
    static HANDLE Open(const std::string& requested,std::wstring& path) {
        HANDLE file;
        if(requested.empty()) {
            wchar_t folder[MAX_PATH+1]{},name[MAX_PATH+1]{};
            const auto n=GetTempPathW(MAX_PATH,folder);ULARGE_INTEGER free{};
            if(!n||n>=MAX_PATH||!GetDiskFreeSpaceExW(folder,&free,nullptr,nullptr)||free.QuadPart<16*1024*1024||
                !GetTempFileNameW(folder,L"vhw",0,name))throw std::runtime_error("Cannot reserve hardware capture storage");
            path=name;file=CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
        } else {
            const auto candidate=Wide(requested);
            file=CreateFileW(candidate.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,0,nullptr);
            if(file!=INVALID_HANDLE_VALUE)path=candidate;
        }
        if(file==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create hardware artifact; existing paths are never overwritten");
        return file;
    }
    void Close() {
        if(view)UnmapViewOfFile(view);view=nullptr;
        if(mapping)CloseHandle(mapping);mapping=nullptr;
        if(instructions!=INVALID_HANDLE_VALUE)CloseHandle(instructions);instructions=INVALID_HANDLE_VALUE;
        if(events!=INVALID_HANDLE_VALUE)CloseHandle(events);events=INVALID_HANDLE_VALUE;
    }
    ~HardwareStore() { Close();if(!keep){DeleteFileW(instructionPath.c_str());DeleteFileW(eventPath.c_str());} }
    uint64_t InstructionBytes() const {return sizeof(hw::CaptureFileV1)+steps*sizeof(kdtrace::Record);}
    uint64_t EventBytes() const {return sizeof(TraceEventArtifactHeader)+eventCount*(sizeof(event::EventV1)+8);}
    bool WriteHeaders() {
        hw::CaptureFileV1 file;file.terminal=last;
        TraceEventArtifactHeader e{};
        e.magic=kTraceEventArtifactMagic;e.schemaVersion=3;e.headerSize=sizeof(e);
        e.flags=event::kHasHardware|kTraceEventArtifactFlagComplete;e.recordHeaderSize=8;
        e.basicBlockEntrySize=48;e.memoryEntrySize=84;e.registerEntrySize=320;
        e.recordByteCount=eventCount*88;e.reserved=static_cast<uint32_t>(eventCount);e.chunkCount=chunks;
        headersOk=WriteAt(instructions,0,&file,sizeof(file))&&WriteAt(events,0,&e,sizeof(e))&&
            FlushFileBuffers(instructions)&&FlushFileBuffers(events);
        return headersOk;
    }
    bool Append(const std::vector<kdtrace::Record>& code,const std::vector<event::EventV1>& hardware,const hw::HeaderV1& h) {
        const uint64_t newBytes=sizeof(hw::CaptureFileV1)+sizeof(TraceEventArtifactHeader)+
            (steps+code.size())*200+(eventCount+hardware.size())*88;
        if(newBytes>budget)return false;
        std::vector<uint8_t> packed(hardware.size()*88);
        for(size_t i=0;i<hardware.size();++i) {
            TraceEventArtifactRecordHeader r{4,0,80};
            std::memcpy(packed.data()+i*88,&r,8);std::memcpy(packed.data()+i*88+8,&hardware[i],80);
        }
        if(!WriteAt(instructions,InstructionBytes(),code.data(),DWORD(code.size()*200))||
            !WriteAt(events,EventBytes(),packed.data(),DWORD(packed.size()))||
            !FlushFileBuffers(instructions)||!FlushFileBuffers(events)) {
            Truncate(instructions,InstructionBytes());Truncate(events,EventBytes());return false;
        }
        steps+=code.size();eventCount+=hardware.size();last=h;++chunks;
        return WriteHeaders();
    }
    const kdtrace::Record* Map() {
        mapping=CreateFileMappingW(instructions,nullptr,PAGE_READONLY,0,0,nullptr);
        if(!mapping)return nullptr;
        view=static_cast<const uint8_t*>(MapViewOfFile(mapping,FILE_MAP_READ,0,0,0));
        return view?reinterpret_cast<const kdtrace::Record*>(view+sizeof(hw::CaptureFileV1)):nullptr;
    }
    json Receipt(HANDLE file,const std::wstring& path,uint64_t bytes,bool complete,bool header) {
        LARGE_INTEGER size{};const bool sized=GetFileSizeEx(file,&size)!=FALSE;
        const bool flushed=FlushFileBuffers(file)!=FALSE;
        const auto hash=flushed?HashKdArtifact(file,bytes):std::string{};
        const bool stored=header&&sized&&uint64_t(size.QuadPart)==bytes&&flushed&&!hash.empty();
        return {{"path",Utf8(path)},{"size",bytes},{"sha256",hash.empty()?json(nullptr):json(hash)},
            {"storage_complete",stored},{"capture_complete",complete},{"complete",stored&&complete}};
    }
    json Keep(bool complete) {
        keep=true;
        const bool resized=Truncate(instructions,InstructionBytes())&&Truncate(events,EventBytes());
        const bool repaired=WriteHeaders()&&resized;
        auto code=Receipt(instructions,instructionPath,InstructionBytes(),complete,repaired&&last.generation!=0);
        code["schema"]="veh.kd.hardware.capture.v1";code["record_size"]=200;code["records"]=std::to_string(steps);
        auto hardware=Receipt(events,eventPath,EventBytes(),complete,repaired);
        hardware["schema_version"]=3;hardware["counts"]={{"hardware_events",std::to_string(eventCount)}};
        if(!repaired) {
            code["recovery"]={{"records",std::to_string(steps)},{"header_bytes",216}};
            hardware["recovery"]={{"hardware_events",std::to_string(eventCount)},{"header_bytes",88}};
        }
        return {{"capture_file",code},{"event_file",hardware}};
    }
};
bool StopCpu(const std::string& stop,uint32_t expected) {
    if(stop.size()<3||stop[0]!='T')return false;
    bool seen=false;
    for(size_t at=3;at<stop.size();) {
        const auto end=stop.find(';',at);const size_t tail=end==std::string::npos?stop.size():end;
        if(stop.compare(at,7,"thread:")==0) {
            if(seen)return false;seen=true;uint32_t id=0;
            const auto r=std::from_chars(stop.data()+at+7,stop.data()+tail,id,16);
            if(r.ec!=std::errc{}||r.ptr!=stop.data()+tail||id!=expected+1)return false;
        }
        at=tail+1;
    }
    return seen;
}
std::string EndReason(const hw::HeaderV1& h) {
    if(h.resultFlags&event::kCountLowerBound)return "completion_uncertain";
    if(h.resultFlags&event::kCodeUncertain)return "code_uncertain";
    if(h.resultFlags&event::kUnsupportedAtPc)return "unsupported_hardware";
    if(h.resultFlags&event::kScopeExit)return "left_scope";
    const char* names[]={"incomplete","max_steps","range_exit","interrupted","exception","code_unavailable",
        "debug_stop","unsupported_instruction","buffer_full","code_uncertain","completion_uncertain","left_scope","size_limit"};
    return names[static_cast<uint32_t>(h.end)];
}
} // namespace

json McpServer::ToolKdTraceHardware(const json& args) {
    if(!kd_)return KdNotConnected();
    if(kd_->running())return {{"error","running: veh_kd_break first"}};
    const std::set<std::string> accepted={"operation","execution_context","cpu","threadId","start","end","max_steps",
        "timeout_ms","stack_bytes","collect_snapshots","collect_code","collect_events","output_file","output_format",
        "output_mode","events_output","events_output_path","max_event_file_bytes","code_output","run_peer_cpus",
        "collect_hardware_events","hardware_kinds","follow_exceptions","compress_paths","collect_memory_writes",
        "collect_memory_reads","collect_memory_events","collect_register_events","stop_on_return"};
    for(const auto& f:args.items())if(!accepted.count(f.key()))return {{"error","KD hardware trace does not support "+f.key().substr(0,100)}};
    for(const char* key:{"collect_snapshots","collect_code","collect_events","run_peer_cpus","follow_exceptions",
        "compress_paths","collect_memory_writes","collect_memory_reads","collect_memory_events","collect_register_events","stop_on_return"})
        if(args.contains(key)&&!args[key].is_boolean())return {{"error",std::string(key)+" must be boolean"}};
    for(const char* key:{"compress_paths","collect_memory_writes","collect_memory_reads","collect_memory_events",
        "collect_register_events","stop_on_return","follow_exceptions"})
        if(args.value(key,false))return {{"error",std::string(key)+" is unsupported for KD hardware capture"}};
    for(const char* key:{"events_output","output_mode"})if(args.contains(key)&&args[key]!="file")
        return {{"error",std::string(key)+" must be file for KD hardware capture"}};
    if(args.contains("code_output")&&args["code_output"]!="inline")return {{"error","KD instruction code is stored in capture_file; code_output must be inline"}};
    uint64_t steps,timeout,budget,unused,start,end;
    if(!Integer(args,"max_steps",100000,1,hw::kMaxSteps,steps)||
        !Integer(args,"timeout_ms",10000,1,hw::kMaxTimeoutMs,timeout)||
        !Integer(args,"max_event_file_bytes",hw::kMaxFileBytes,1912,hw::kMaxFileBytes,budget,true)||
        !Integer(args,"threadId",0,0,0,unused)||!Integer(args,"stack_bytes",0,0,0,unused)||
        !Integer(args,"cpu",0,0,63,unused)||!Address(args,"start",start)||!Address(args,"end",end)||start>=end)
        return {{"error","Invalid KD hardware range/steps/timeout/file budget/CPU; threadId and stack_bytes must be zero"}};
    uint32_t kinds=event::kKinds;
    if(args.contains("hardware_kinds")) {
        const auto& list=args["hardware_kinds"];kinds=0;
        if(!list.is_array()||list.empty()||list.size()>3)return {{"error","hardware_kinds must be a nonempty unique list"}};
        for(const auto& v:list) {
            const uint32_t bit=v=="control_register"?1:v=="msr"?2:v=="io_port"?4:0;
            if(!v.is_string()||!bit||(kinds&bit))return {{"error","hardware_kinds contains an unknown/duplicate kind"}};
            kinds|=bit;
        }
    }
    for(const char* key:{"output_file","events_output_path"})
        if(args.contains(key)&&(!args[key].is_string()||!ValidateKdCapturePath(args[key].get<std::string>(),1024).empty()))
            return {{"error",std::string(key)+" must be a valid nonempty path of at most1024 UTF-8 bytes"}};
    const auto output=args.value("output_file",std::string{}),eventOutput=args.value("events_output_path",std::string{});
    const auto format=args.value("output_format",std::string("json"));
    if(format!="json"&&format!="jsonl")return {{"error","output_format must be json or jsonl"}};
    if(!output.empty()) {const auto e=ValidateTraceOutputFile(output,format);if(!e.empty())return {{"error",e}};}
    json selection;if(!KdSelect(args,selection))return selection;
    std::string text;
    if(!kd_->Request("qC",&text)||text.rfind("QC",0)!=0)return {{"error","Cannot verify selected KD CPU"}};
    uint32_t cpuId=0;const auto selected=std::from_chars(text.data()+2,text.data()+text.size(),cpuId,16);
    if(selected.ec!=std::errc{}||selected.ptr!=text.data()+text.size()||!cpuId||cpuId>64||
        (args.contains("cpu")&&cpuId!=args["cpu"].get<uint64_t>()+1))return {{"error","Invalid selected KD CPU receipt"}};
    const uint32_t cpu=cpuId-1;
    hw::CapabilitiesV1 caps{};
    if(!kd_->Request("qTraceHW:cap1",&text)||!Unhex(text,&caps,sizeof(caps))||!hw::ValidCapabilities(caps))
        return {{"error","KD backend does not support valid TraceHW v1 capabilities"},{"code","unsupported_backend"}};
    const uint32_t flags=(args.value("collect_snapshots",true)?1u:0u)|(args.value("run_peer_cpus",false)?2u:0u);
    if((caps.supportedKinds&kinds)!=kinds||(caps.supportedFlags&flags)!=flags||
        steps>caps.maxSteps||timeout>caps.maxTimeoutMs||budget>caps.maxFileBytes)
        return {{"error","KD backend does not advertise all requested hardware kinds, flags or budgets"},{"code","unsupported_policy"}};
    uint64_t request=nextRequest.load();
    while(request&&request<UINT64_MAX&&!nextRequest.compare_exchange_weak(request,request+1)){}
    if(!request||request==UINT64_MAX)return {{"error","KD hardware request ID exhausted; reconnect with a new MCP process"}};
    std::unique_ptr<HardwareStore> store;
    try {store=std::make_unique<HardwareStore>(output,eventOutput,budget);}
    catch(const std::exception& e){return {{"error",e.what()},{"code","capture_storage"}};}
    if(!output.empty()){const auto e=ValidateTraceOutputFile(output,format);if(!e.empty())return {{"error",e}};}
    // One monotonic logical deadline; I/O does not renew execution time.
    const auto begin=std::chrono::steady_clock::now();
    const auto deadline=begin+std::chrono::milliseconds(timeout);
    uint64_t generation=0,received=0,hardwareReceived=0,chunkIndex=0,previousNext=0;
    bool halted=false,timedOut=false,headerKnown=false;
    hw::HeaderV1 h;
    event::EventValidator validator;
    auto fail=[&](const std::string& message) -> json {
        auto result=store->Keep(false);result["error"]=message;result["capture_incomplete"]=true;
        result["capture_complete"]=false;result["complete"]=false;result["halted"]=halted;
        result["final_address"]=halted&&headerKnown?json(Hex(h.finalAddress)):json(nullptr);
        result["backend_buffer_retained"]=halted&&headerKnown;
        result["generation"]=generation?json(std::to_string(generation)):json(nullptr);
        result["request_id"]=std::to_string(request);
        result["copied_records"]=std::to_string(store->steps);
        result["copied_hardware_events"]=std::to_string(store->eventCount);
        return result;
    };
    auto readStatus=[&](hw::HeaderV1& status) {
        if(!kd_->Request("qTraceHW:status1,"+Field(request),&text))return false;
        if(text=="E23"){halted=false;headerKnown=false;return false;}
        return Unhex(text,&status,sizeof(status))&&hw::ValidHeader(status)&&
            status.requestId==request&&status.cpu==cpu&&status.appliedFlags==flags&&status.appliedKinds==kinds&&
            status.maxSteps==steps&&status.attempts<=status.steps+1&&status.instructionCount<=caps.instructionCapacity&&
            status.hardwareCount<=caps.hardwareCapacity;
    };
    std::string command="vTraceHW:1,"+Field(cpu)+","+Field(steps)+","+Field(start)+","+Field(end)+","+
        Field(flags)+","+Field(kinds)+","+Field(timeout)+","+Field(budget)+","+Field(request);
    for(;;) {
        halted=false;headerKnown=false;
        if(!kd_->Resume(command))return fail("KD link lost before hardware capture acknowledgement; execution state unknown");
        std::string stop;
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if(!kd_->WaitStop(&stop,uint32_t((std::max)(int64_t{1},left)))) {
            timedOut=std::chrono::steady_clock::now()>=deadline;
            if(!kd_->QueryStop(&stop,500)&&!kd_->Interrupt(&stop,5000))return fail("Cannot confirm KD hardware capture stop");
        }
        if(!readStatus(h))return fail(text=="E23"?"E23: selected final PC/all-CPU halt unconfirmed":"Malformed or refused KD hardware status");
        halted=true;headerKnown=true;
        if(!generation)generation=h.generation;
        const bool more=h.end==hw::End::BufferFull;
        if(h.generation!=generation||h.chunkIndex!=chunkIndex||h.instructionOffset!=received||
            h.hardwareOffset!=hardwareReceived||(h.end==hw::End::Budget&&h.steps!=steps)||
            (h.end==hw::End::Range&&h.finalAddress>=start&&h.finalAddress<end)||
            (more&&(h.finalAddress<start||h.finalAddress>=end))||
            (h.end==hw::End::CompletionUncertain&&h.steps>=steps))
            return fail("Inconsistent KD hardware generation/chunk/offset/termination receipt");
        std::vector<kdtrace::Record> code(static_cast<size_t>(h.instructionCount));
        std::vector<event::EventV1> hardware(static_cast<size_t>(h.hardwareCount));
        auto readStream=[&](uint32_t stream,uint64_t offset,uint64_t count,uint32_t recordBytes,std::vector<uint8_t>& data) {
            const uint32_t pageMax=(uint32_t((caps.maxReplyBytes-1)/2)-sizeof(hw::PageV1))/recordBytes;
            if(!pageMax)return false;
            data.resize(static_cast<size_t>(count)*recordBytes);
            for(uint64_t done=0;done<count;) {
                const uint32_t n=uint32_t((std::min)(uint64_t(pageMax),count-done));
                if(!kd_->Request("qTraceHW:read1,"+Field(generation)+","+Field(request)+","+Field(chunkIndex)+","+
                    Field(stream)+","+Field(offset+done)+","+Field(n),&text))return false;
                if(text=="E23"){halted=false;headerKnown=false;return false;}
                std::vector<uint8_t> wire(sizeof(hw::PageV1)+size_t(n)*recordBytes);
                if(!Unhex(text,wire.data(),wire.size()))return false;
                hw::PageV1 page;std::memcpy(&page,wire.data(),sizeof(page));
                if(page.version!=1||page.headerBytes!=sizeof(page)||page.recordBytes!=recordBytes||
                    page.generation!=generation||page.requestId!=request||page.chunkIndex!=chunkIndex||
                    page.offset!=offset+done||page.count!=n||page.stream!=stream||page.reserved||
                    TraceEventPayloadHash(wire.data()+sizeof(page),size_t(n)*recordBytes)!=page.payloadHash)return false;
                std::memcpy(data.data()+size_t(done)*recordBytes,wire.data()+sizeof(page),size_t(n)*recordBytes);done+=n;
            }
            return true;
        };
        std::vector<uint8_t> wire;
        if(!readStream(1,received,h.instructionCount,h.instructionRecordBytes,wire))
            return fail("KD hardware instruction page rejected; current buffer retained");
        for(size_t i=0;i<code.size();++i) {
            kdtrace::CompactRecord r;std::memcpy(&r,wire.data()+i*h.instructionRecordBytes,sizeof(r));
            auto& out=code[i];out.address=r.address;out.nextAddress=r.nextAddress;out.cr3=r.cr3;
            out.cpu=r.cpu;out.pid=r.pid;out.tid=r.tid;out.addressBits=r.addressBits;out.cpl=r.cpl;
            out.codeSize=r.codeSize;out.reserved=r.reserved;std::memcpy(out.code,r.code,16);
            if(flags&1)std::memcpy(out.registers,wire.data()+i*h.instructionRecordBytes+56,sizeof(out.registers));
            const bool unknown=(h.resultFlags&event::kCodeUncertain)&&i+1==code.size();
            const bool codeValid=unknown&&r.reserved==1?r.codeSize==0&&
                std::all_of(std::begin(r.code),std::end(r.code),[](uint8_t b){return b==0;}):
                r.reserved==0&&r.codeSize>=1&&r.codeSize<=15;
            if(!codeValid||r.cpu!=cpu||(r.addressBits!=32&&r.addressBits!=64)||r.cpl>3||
                r.address<start||r.address>=end||((received+i)&&r.address!=previousNext)||
                ((i+1<code.size()||more)&&(r.nextAddress<start||r.nextAddress>=end)))
                return fail("Inconsistent KD hardware instruction chain/code/CPU");
            previousNext=r.nextAddress;
        }
        if(!(h.resultFlags&event::kCountLowerBound)&&
            ((h.steps&&previousNext!=h.finalAddress)||(!h.steps&&(h.finalAddress<start||h.finalAddress>=end))))
            return fail("KD hardware final PC disagrees with completed records");
        if(!readStream(2,hardwareReceived,h.hardwareCount,80,wire))
            return fail("KD hardware event page rejected; current buffer retained");
        if(!hardware.empty())std::memcpy(hardware.data(),wire.data(),hardware.size()*80);
        auto candidate=validator;
        for(const auto& e:hardware) {
            if(!candidate.Accept(e)||!(kinds&(1u<<(static_cast<unsigned>(e.kind)-1)))||
                e.cpu!=cpu||e.eventIndex>=caps.maxPerInstruction||e.attempt>h.attempts||
                (e.completion==event::Completion::Confirmed&&(e.sequence<=received||e.sequence>h.steps)))
                return fail("Invalid KD hardware event/order/negotiated limit");
            if(e.completion==event::Completion::Confirmed) {
                const auto& instruction=code[static_cast<size_t>(e.sequence-received-1)];
                if(e.instruction!=instruction.address||e.cplBefore!=instruction.cpl||
                    ((e.known&event::Thread)&&instruction.tid&&e.threadId!=instruction.tid))
                    return fail("KD hardware event is not associated with its instruction");
            } else if(!(h.resultFlags&event::kCountLowerBound)||e.instruction<start||e.instruction>=end||
                (h.steps&&e.instruction!=previousNext))return fail("Invalid uncertain KD hardware attempt");
        }
        if(candidate.uncertainRecords!=h.uncertainRecords||candidate.unknownValueFields!=h.unknownValueFields||
            (candidate.codeUncertain&&!(h.resultFlags&event::kCodeUncertain)))
            return fail("KD hardware cumulative counts disagree with events");
        if(!store->Append(code,hardware,h))return fail("Cannot persist both KD hardware streams; no continuation acknowledged");
        validator=candidate;received=h.steps;hardwareReceived=h.retainedHardware;
        if(!more)break;
        if(!StopCpu(stop,cpu))return fail("Peer or unverified CPU stop refuses KD hardware continuation");
        if(std::chrono::steady_clock::now()>=deadline) {
            timedOut=true;
            if(!kd_->Request("qTraceHW:cancel1,"+Field(generation)+","+Field(request)+","+Field(chunkIndex),&text)||text!="OK")
                return fail("KD hardware paused cancellation was not acknowledged");
            hw::HeaderV1 ended;halted=false;headerKnown=false;
            if(!readStatus(ended))return fail("KD hardware cancellation halt/status unconfirmed");
            auto expected=h;expected.end=hw::End::Interrupted;expected.paused=0;
            if(std::memcmp(&ended,&expected,sizeof(ended)))return fail("KD hardware cancellation changed the retained buffer");
            h=ended;store->last=h;halted=true;headerKnown=true;break;
        }
        command="vTraceHW:resume1,"+Field(generation)+","+Field(request)+","+Field(chunkIndex)+","+
            Field(received)+","+Field(hardwareReceived);++chunkIndex;
    }
    const bool complete=h.end==hw::End::Range&&!(h.resultFlags&(event::kCountLowerBound|event::kCodeUncertain|
        event::kUnsupportedAtPc|event::kNoTargetInstructionAttempted|event::kScopeExit))&&
        !h.droppedHardware&&!h.uncertainRecords&&!timedOut;
    json files=store->Keep(complete);
    if(!files["capture_file"]["storage_complete"].get<bool>()||!files["event_file"]["storage_complete"].get<bool>())
        return fail("KD hardware artifacts could not be finalized; backend buffer retained");
    kdtrace::Header base{};base.version=2;base.recordSize=200;base.generation=generation;
    base.count=static_cast<uint32_t>(received);base.steps=static_cast<uint32_t>(received);
    base.end=static_cast<uint32_t>(h.end);base.flags=flags;base.finalAddress=h.finalAddress;base.cpu=cpu;
    auto shapeArgs=args;shapeArgs["_range_start"]=start;shapeArgs["_range_end"]=end;
    json full;
    if(const auto* records=store->Map())full=ShapeKdHardwareRecords(records,static_cast<size_t>(received),base,shapeArgs);
    else full={{"blocks",json::array()},{"edges",json::array()},{"events",json::array()},
        {"snapshots",json::array()},{"code_versions",json::array()},{"analysis_incomplete",true},{"decode_incomplete",true}};
    const char* names[]={"control_register","msr","io_port"};json applied=json::array(),counts=json::object();
    for(unsigned i=0;i<3;++i){if(kinds&(1u<<i))applied.push_back(names[i]);counts[names[i]]=std::to_string(validator.counts[i]);}
    const bool lower=(h.resultFlags&event::kCountLowerBound)!=0;
    const char* scopes[]={nullptr,"address_space","cpl","thread","rip_range","identity_unavailable"};
    const json scope=h.scopeExit==event::ScopeExit::None?json(nullptr):json(scopes[static_cast<unsigned>(h.scopeExit)]);
    json collection={{"protocol_version",1},{"transport","kd-rsp-hardware-v1"},{"requested",true},
        {"requested_kinds",applied},{"applied_kinds",applied},{"complete",complete},
        {"events",std::to_string(h.retainedHardware)},{"dropped_records",lower||h.droppedHardware==UINT64_MAX?
            json(nullptr):json(std::to_string(h.droppedHardware))},{"unknown_value_fields",std::to_string(h.unknownValueFields)},
        {"uncertain_records",std::to_string(h.uncertainRecords)},{"scope_exit",scope}};
    full["execution_context"]="kd";full["capture_scope"]="selected_cpu";full["cpu"]=cpu;full["transport_version"]=1;
    full["generation"]=std::to_string(generation);full["request_id"]=std::to_string(request);
    full["steps_executed"]=lower?json(nullptr):json(std::to_string(received));
    if(lower)full["steps_executed_lower_bound"]=std::to_string(received);
    full["execution_count_incomplete"]=lower;full["lost_records"]=collection["dropped_records"];
    full["final_address"]=Hex(h.finalAddress);full["halted"]=true;full["stop_reason"]=EndReason(h);
    full["scope_exit"]=scope;full["hardware_collection"]=collection;full["hardware_counts"]=counts;
    full["capture_file"]=files["capture_file"];full["event_file"]=files["event_file"];
    full["storage_complete"]=true;full["capture_complete"]=complete;full["complete"]=complete;
    full["capture_incomplete"]=!complete;full["timeout_requested"]=timedOut;
    full["decode_incomplete"]=full.value("decode_incomplete",false)||bool(h.resultFlags&event::kCodeUncertain);
    full["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
    full["chunks"]=store->chunks;full["applied_flags"]=flags;full["run_peer_cpus"]=bool(flags&2);
    const auto exported=output.empty()?WriteJsonArtifactInDirectory("","kd-hardware",full,format):WriteTraceOutputFile(output,format,full);
    if(!exported.success) {
        auto error=files;error["error"]=exported.error;error["hardware_collection"]=collection;
        error["storage_complete"]=false;error["capture_complete"]=complete;error["complete"]=false;
        error["halted"]=true;error["final_address"]=Hex(h.finalAddress);error["backend_buffer_retained"]=true;
        error["generation"]=std::to_string(generation);error["request_id"]=std::to_string(request);return error;
    }
    bool released=false;
    json result={{"execution_context","kd"},{"capture_scope","selected_cpu"},{"cpu",cpu},{"generation",std::to_string(generation)},
        {"request_id",std::to_string(request)},{"hardware_collection",collection},{"hardware_counts",counts},
        {"steps_executed",full["steps_executed"]},{"execution_count_incomplete",lower},{"final_address",Hex(h.finalAddress)},
        {"stop_reason",full["stop_reason"]},{"halted",true},{"scope_exit",scope},{"chunks",store->chunks},
        {"storage_complete",true},{"capture_complete",complete},{"complete",complete},{"capture_incomplete",!complete},
        {"decode_incomplete",full["decode_incomplete"]},{"analysis_incomplete",full["analysis_incomplete"]},
        {"capture_file",files["capture_file"]},{"event_file",files["event_file"]},{"backend_buffer_retained",!released},
        {"output_file",{{"path",exported.path},{"format",exported.format},{"size",exported.size},{"sha256",exported.sha256},
            {"storage_complete",true},{"capture_complete",complete},{"complete",complete}}},
        {"read_events",{{"execution_context","kd"},{"operation","read_events"},{"event_file",Utf8(store->eventPath)},
            {"offset","0"},{"limit",16}}},
        {"read_capture",{{"execution_context","kd"},{"operation","read_capture"},{"capture_file",Utf8(store->instructionPath)},
            {"offset","0"},{"limit",16}}}};
    if(lower)result["steps_executed_lower_bound"]=std::to_string(received);
    if(result.dump().size()>7900){result.erase("read_events");result.erase("read_capture");}
    if(result.dump().size()>7900)return fail("KD hardware receipt exceeds8KiB; artifacts retained");
    // Only release after both durable streams and the bounded JSON receipt exist.
    const auto release="qTraceHW:release1,"+Field(generation)+","+Field(request)+","+Field(chunkIndex)+","+
        Field(received)+","+Field(hardwareReceived);
    for(unsigned attempt=0;attempt<2&&!released;++attempt)released=kd_->Request(release,&text)&&text=="OK";
    result["backend_buffer_retained"]=!released;
    if(!released)result["release_error"]="Backend capture retained: terminal release was not acknowledged";
    return result;
}

json ReadKdHardwareCapture(const json& args) {
    const auto path=args.value("capture_file",std::string{});
    if(!ValidateKdCapturePath(path,1024).empty())return nullptr;
    HANDLE file=CreateFileW(Wide(path).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    if(file==INVALID_HANDLE_VALUE)return nullptr;
    struct Close {HANDLE file;~Close(){CloseHandle(file);}} close{file};
    hw::CaptureFileV1 header;DWORD read=0;LARGE_INTEGER size{};
    if(!ReadFile(file,&header,sizeof(header),&read,nullptr)||read<8||std::memcmp(header.magic,"VEHKDHW1",8))return nullptr;
    if(read!=sizeof(header)||!GetFileSizeEx(file,&size)||header.version!=1||header.headerBytes!=216||
        header.recordBytes!=200||header.reserved||!hw::ValidHeader(header.terminal)||
        uint64_t(size.QuadPart)!=216+header.terminal.steps*200)return {{"error","Invalid KD hardware capture artifact"}};
    uint64_t offset,limit;
    if(args.contains("offset")&&!args["offset"].is_string())return {{"error","offset must be an exact decimal string"}};
    if(!Integer(args,"offset",0,0,header.terminal.steps,offset,true)||
        !Integer(args,"limit",16,1,100,limit))return {{"error","Invalid exact offset or limit1..100"}};
    if(args.contains("include_registers")&&!args["include_registers"].is_boolean())return {{"error","include_registers must be boolean"}};
    uint64_t start=0,end=UINT64_MAX;
    if((args.contains("address_start")&&!Address(args,"address_start",start))||
        (args.contains("address_end")&&!Address(args,"address_end",end))||start>=end)return {{"error","Invalid capture address filter"}};
    json rows=json::array();const uint64_t first=offset,stop=(std::min)(header.terminal.steps,offset+65536);
    for(;offset<stop&&rows.size()<limit;++offset) {
        LARGE_INTEGER at;at.QuadPart=216+offset*200;kdtrace::Record r{};
        if(!SetFilePointerEx(file,at,nullptr,FILE_BEGIN)||!ReadFile(file,&r,sizeof(r),&read,nullptr)||read!=sizeof(r))
            return {{"error","KD hardware capture read failed"}};
        if(r.cpu!=header.terminal.cpu||(r.addressBits!=32&&r.addressBits!=64)||r.cpl>3)return {{"error","Invalid instruction identity"}};
        const bool unknown=(header.terminal.resultFlags&event::kCodeUncertain)&&offset+1==header.terminal.steps&&
            r.reserved==1&&!r.codeSize&&std::all_of(std::begin(r.code),std::end(r.code),[](uint8_t b){return b==0;});
        if(!unknown&&(r.reserved||!r.codeSize||r.codeSize>15))return {{"error","Invalid instruction code"}};
        if(r.address<start||r.address>=end)continue;
        json row={{"sequence",std::to_string(offset+1)},{"address",Hex(r.address)},{"next_address",Hex(r.nextAddress)},
            {"cr3",Hex(r.cr3)},{"cpu",r.cpu},{"cpl",r.cpl},{"address_bits",r.addressBits},
            {"thread_id",r.tid?json(std::to_string(r.tid)):json(nullptr)},{"process_id",r.pid?json(std::to_string(r.pid)):json(nullptr)},
            {"execution_code_verified",!unknown}};
        if(!unknown){std::string bytes;const char* digits="0123456789abcdef";
            for(unsigned i=0;i<r.codeSize;++i){if(i)bytes+=' ';bytes+=digits[r.code[i]>>4];bytes+=digits[r.code[i]&15];}row["bytes"]=bytes;}
        if(args.value("include_registers",false)) {
            row["registers_available"]=bool(header.terminal.appliedFlags&1);
            if(header.terminal.appliedFlags&1){row["registers"]=json::array();for(auto n:r.registers)row["registers"].push_back(Hex(n));}
        }
        if(rows.dump().size()+row.dump().size()>5800)break;
        rows.push_back(std::move(row));
    }
    json result={{"capture_file",path},{"records",rows},{"count",rows.size()},{"total_records",std::to_string(header.terminal.steps)},
        {"generation",std::to_string(header.terminal.generation)},{"request_id",std::to_string(header.terminal.requestId)},
        {"next_offset",offset<header.terminal.steps?json(std::to_string(offset)):json(nullptr)},{"examined",offset-first},
        {"scan_limited",offset==stop&&offset<header.terminal.steps},{"integrity","not_checked"}};
    if(result.dump().size()>8192)return {{"error","KD hardware page exceeds8KiB"}};
    return result;
}
} // namespace veh
