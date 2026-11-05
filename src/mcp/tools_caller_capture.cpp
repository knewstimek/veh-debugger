#include "mcp_server.h"
#include "tools_common.h"
#include "common/caller_capture_protocol.h"
#include "common/ipc_response_validation.h"
#include "trace_output_file.h"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <limits>

namespace veh {
namespace {
namespace cc = callercapture;
constexpr const char* kRegisters[] = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
    "r8","r9","r10","r11","r12","r13","r14","r15","rip","rflags"};
bool U32(const json& a, const char* key, uint32_t fallback, uint32_t limit, uint32_t& out) {
    if (!a.contains(key)) { out=fallback; return true; }
    const auto& v=a[key];
    if (!v.is_number_integer() || v<0 || v>limit) return false;
    out=v.get<uint32_t>(); return true;
}
bool Decimal(const json& a, const char* key, uint64_t fallback, uint64_t& out) {
    if (!a.contains(key)) {out=fallback;return true;}
    if (!a[key].is_string()) return false;
    const auto s=a[key].get<std::string>();
    if(s.empty()||(s.size()>1&&s[0]=='0'))return false;
    auto p=std::from_chars(s.data(),s.data()+s.size(),out);
    return p.ec==std::errc{}&&p.ptr==s.data()+s.size();
}
bool Hex(const json& v,uint64_t& out) {
    if(!v.is_string())return false;
    const auto s=v.get<std::string>();
    if(s.size()<3||s.substr(0,2)!="0x")return false;
    auto p=std::from_chars(s.data()+2,s.data()+s.size(),out,16);
    return p.ec==std::errc{}&&p.ptr==s.data()+s.size();
}
template<size_t N> std::string Text(const char (&v)[N]) {
    return {v,std::find(v,v+N,'\0')};
}
bool ConfigValid(const cc::StartRequest& c) {
    if(c.version!=cc::kVersion || !c.address || c.stackBytes>cc::kMaxStackBytes ||
        !c.bufferRecords||c.bufferRecords>cc::kMaxRecords || c.bufferBytes>cc::kMaxBufferBytes ||
        c.bufferBytes<sizeof(cc::Record)+c.stackBytes || c.filterCount>cc::kMaxFilters ||
        c.durationMs>cc::kMaxDurationMs||(!c.durationMs&&!c.maxHits) ||
        c.dataPolicy!=InstrumentationDataPolicy::Original||
        c.transactionPolicy!=InstrumentationTransactionPolicy::Omit)return false;
    for(uint32_t i=0;i<cc::kMaxFilters;++i) {
        const auto& f=c.filters[i];
        if(i<c.filterCount) {
            if(f.reg>=cc::kRegisterCount||f.reserved||(f.expected&~f.mask))return false;
        } else if(f.reg||f.reserved||f.mask||f.expected)return false;
    }
    return true;
}
const char* StopName(cc::StopReason r) {
    switch(r) {
    case cc::StopReason::Active:return "active";
    case cc::StopReason::User:return "user";
    case cc::StopReason::MaxHits:return "max_hits";
    case cc::StopReason::Duration:return "duration";
    case cc::StopReason::Buffer:return "buffer";
    case cc::StopReason::Detached:return "detached";
    default:return "error";
    }
}
const char* ClockName(cc::Clock c) {
    return c==cc::Clock::Tsc?"tsc":c==cc::Clock::MonotonicNs?"monotonic_ns":"none";
}
json Counter(uint64_t v){return v==UINT64_MAX?json(nullptr):json(std::to_string(v));}
std::string BytesHex(const uint8_t* data,size_t size) {
    constexpr char digits[]="0123456789abcdef";
    std::string result(size*2,'0');
    for(size_t i=0;i<size;++i){result[i*2]=digits[data[i]>>4];result[i*2+1]=digits[data[i]&15];}
    return result;
}
}

json McpServer::ToolCallerCapture(const json& args) {
    if(!session_.IsAttached())return {{"error",NotAttachedMessage()}};
    if(!args.is_object())return {{"error","detailed capture arguments must be an object"}};
    const auto opIt=args.find("operation");
    if(opIt!=args.end()&&!opIt->is_string())return {{"error","operation must be a string"}};
    const std::string operation=args.value("operation","status");
    if(operation!="status"&&operation!="start"&&operation!="stop"&&operation!="read"&&operation!="export")
        return {{"error","operation must be status, start, stop, read or export"}};
    for(const auto& [key,value]:args.items()) {
        const bool common=key=="mode"||key=="operation";
        const bool start=operation=="start"&&(key=="address"||key=="stack_bytes"||key=="max_hits"||
            key=="duration_ms"||key=="buffer_records"||key=="buffer_bytes"||key=="filters");
        const bool id=(operation=="read"||operation=="stop"||operation=="export")&&key=="trace_id";
        const bool page=operation=="read"&&(key=="cursor"||key=="max");
        const bool file=(operation=="read"||operation=="export")&&key=="output_file";
        if(!common&&!start&&!id&&!page&&!file)return {{"error",key+" is not valid for detailed "+operation}};
    }
    std::string path,format="json";
    if(args.contains("output_file")) {
        const auto& f=args["output_file"];
        if(!f.is_object()||f.size()>2||!f.contains("path")||!f["path"].is_string()||
            (f.contains("format")&&!f["format"].is_string()))return {{"error","output_file requires {path, format: json|jsonl}"}};
        for(const auto& [key,v]:f.items())if(key!="path"&&key!="format")return {{"error","unknown output_file option"}};
        path=f["path"].get<std::string>();format=f.value("format","json");
        if(path.find('\0')!=std::string::npos||std::any_of(path.begin(),path.end(),[](unsigned char c){return c<32;}))
            return {{"error","output_file path contains a control character"}};
        const auto error=ValidateTraceOutputFile(path,format);
        if(!error.empty())return {{"error",error}};
    }
    uint64_t trace=0,cursor=0;
    uint32_t maximum=0;
    if(operation=="stop"||operation=="read"||operation=="export") {
        if(!Decimal(args,"trace_id",0,trace)||!trace)return {{"error","trace_id must be a nonzero exact decimal string"}};
    }
    if(!Decimal(args,"cursor",0,cursor)||!U32(args,"max",0,256,maximum))
        return {{"error","cursor must be an exact decimal string and max must be 0..256"}};

    // One monotonic operation clock. It never supplies capture timestamps.
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(operation=="export"?60:5);
    const auto& info=session_.GetBackendInfo();
    const auto supports=[&](IpcCommand c){return info.reported&&info.Supports(c);};
    const auto exchange=[&](IpcCommand c,const void* request,uint32_t size,std::vector<uint8_t>& bytes,json& error) {
        if(!supports(c)){error={{"error","Backend does not advertise detailed caller capture"},{"available",false}};return false;}
        const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if(left<=0){error={{"error","Detailed caller capture operation deadline expired; outcome is unconfirmed"}};return false;}
        PipeExchangeDiagnostics d{};
        if(!session_.GetPipeClient().SendAndReceive(c,request,size,bytes,static_cast<int>((std::min)(left,int64_t{3000})),&d)) {
            error={{"error",session_.DescribeIpcFailure(&d)+"; operation outcome is unconfirmed"}};return false;
        }
        if(bytes.size()<sizeof(IpcStatus)){error={{"error","Short caller capture status; outcome is unconfirmed"}};return false;}
        IpcStatus status{};std::memcpy(&status,bytes.data(),sizeof(status));
        if(status!=IpcStatus::Ok){error={{"error","Caller capture: "+BackendStatusText(status)},{"backendStatus",static_cast<uint32_t>(status)}};return false;}
        return true;
    };
    if(!supports(IpcCommand::QueryCallerCapture)) {
        if(operation=="status")return {{"mode","detailed"},{"protocolSupported",false},{"available",false},
            {"reason","Backend does not advertise detailed caller capture v1"}};
        return {{"error","Backend does not advertise detailed caller capture v1"},{"available",false}};
    }
    const cc::QueryRequest request{cc::kVersion};
    std::vector<uint8_t> bytes;
    json error;
    if(!exchange(IpcCommand::QueryCallerCapture,&request,sizeof(request),bytes,error))return error;
    cc::QueryResponse q{};
    if(bytes.size()!=sizeof(q))return {{"error","Malformed caller capture capability receipt"}};
    std::memcpy(&q,bytes.data(),sizeof(q));
    if(q.version!=cc::kVersion||q.reserved||(q.features&~cc::kFeatures)||
        q.maxStackBytes>cc::kMaxStackBytes||q.maxRecords>cc::kMaxRecords||q.maxBufferBytes>cc::kMaxBufferBytes||
        q.maxPageBytes>cc::kMaxPageBytes||q.maxFilters>cc::kMaxFilters||static_cast<uint32_t>(q.clock)>2||
        (!(q.features&cc::Stack)&&q.maxStackBytes)||(!(q.features&cc::Filters)&&q.maxFilters)||
        ((q.features&cc::Timestamp)==0)!=(q.clock==cc::Clock::None)||
        (q.clock==cc::Clock::None&&(q.clockFrequency||(q.features&cc::SynchronizedClock)))||(q.clock==cc::Clock::MonotonicNs&&q.clockFrequency!=1000000000ULL))
        return {{"error","Invalid caller capture version, capabilities, clock or limits"}};
    const auto targetBits=session_.TargetAddressBits();
    const bool contextWidths=session_.GetBackendInfo().reported&&
        (session_.GetBackendInfo().flags&kCapRegisterContextV1);
    const bool targetSupported=(targetBits==32||targetBits==64)&&
        (contextWidths?bool(q.features&(cc::X86|cc::X64)):
         targetBits==32?bool(q.features&cc::X86):bool(q.features&cc::X64));
    const bool available=targetSupported&&(q.features&cc::Available)&&(q.features&cc::Registers)&&
        q.maxRecords&&q.maxBufferBytes>=sizeof(cc::Record)&&q.maxPageBytes>=sizeof(cc::Response)+sizeof(cc::Record)+q.maxStackBytes&&
        supports(IpcCommand::StartCallerCapture)&&supports(IpcCommand::StopCallerCapture)&&supports(IpcCommand::ReadCallerCapture);
    if(operation=="status")return {{"mode","detailed"},{"protocol_version",cc::kVersion},{"protocolSupported",true},{"available",available},
        {"provider",Text(q.provider)},{"reason",targetSupported ? Text(q.reason) :
            (targetBits==32||targetBits==64 ? "Collector does not support the attached target address width" :
                "Detailed capture requires a process target with a known x86/x64 address width")},
        {"trace_id",q.currentTraceId?json(std::to_string(q.currentTraceId)):json(nullptr)},
        {"maxStackBytes",q.maxStackBytes},{"maxBufferRecords",q.maxRecords},{"maxBufferBytes",q.maxBufferBytes},
        {"maxPageBytes",q.maxPageBytes},{"maxFilters",q.maxFilters},{"x86",bool(q.features&cc::X86)},{"x64",bool(q.features&cc::X64)},
        {"clock",{{"kind",ClockName(q.clock)},{"frequency_hz",q.clockFrequency?json(std::to_string(q.clockFrequency)):json(nullptr)},
            {"cross_cpu_synchronized",bool(q.features&cc::SynchronizedClock)}}}};
    if(!available)return {{"error","Detailed caller capture is unavailable"},{"available",false}};
    cc::StartRequest start{};
    IpcCommand command=IpcCommand::ReadCallerCapture;
    if(operation=="start") {
        start.version=cc::kVersion;
        if(!args.contains("address")||!args["address"].is_string()||
            !ParseAddress(args["address"].get<std::string>(),start.address)||!start.address)
            return {{"error","A nonzero function-entry address is required"}};
        auto bits=session_.TargetAddressBits();
        if(bits!=32&&bits!=64)return {{"error","Target address width is unknown"}};
        if(!contextWidths&&bits==32&&(start.address>UINT32_MAX||!(q.features&cc::X86)))return {{"error","Address or capture architecture is unsupported"}};
        if(((!contextWidths&&bits==64)||start.address>UINT32_MAX)&&!(q.features&cc::X64))return {{"error","Backend does not support x64 caller capture"}};
        if(!U32(args,"stack_bytes",(std::min)(256u,q.maxStackBytes),q.maxStackBytes,start.stackBytes)||
            !U32(args,"buffer_records",(std::min)(4096u,q.maxRecords),q.maxRecords,start.bufferRecords)||
            !U32(args,"buffer_bytes",(std::min)(4u*1024*1024,q.maxBufferBytes),q.maxBufferBytes,start.bufferBytes)||
            !U32(args,"duration_ms",5000,cc::kMaxDurationMs,start.durationMs)||
            !Decimal(args,"max_hits",1000,start.maxHits))return {{"error","Invalid detailed capture limits; max_hits must be an exact decimal string"}};
        if(args.contains("filters")) {
            if(!args["filters"].is_array()||args["filters"].size()>q.maxFilters)return {{"error","Too many filters or unsupported register filters"}};
            start.filterCount=static_cast<uint32_t>(args["filters"].size());
            for(uint32_t i=0;i<start.filterCount;++i) {
                const auto& f=args["filters"][i];
                if(!f.is_object()||f.size()!=3||!f.contains("register")||!f["register"].is_string()||
                    !f.contains("mask")||!f.contains("equals"))return {{"error","Each filter requires register, mask, equals"}};
                auto& out=start.filters[i];const auto name=f["register"].get<std::string>();
                const auto found=std::find(std::begin(kRegisters),std::end(kRegisters),name);
                if(found==std::end(kRegisters)||!Hex(f["mask"],out.mask)||!Hex(f["equals"],out.expected))
                    return {{"error","Invalid filter register or exact hexadecimal operand"}};
                out.reg=static_cast<uint32_t>(found-std::begin(kRegisters));
            }
        }
        if(!ConfigValid(start))return {{"error","Capture needs nonzero buffers, at least one stop boundary and canonical filters"}};
        command=IpcCommand::StartCallerCapture;
        if(!exchange(command,&start,sizeof(start),bytes,error))return error;
    } else if(operation=="stop") {
        command=IpcCommand::StopCallerCapture;
        const cc::StopRequest stop{cc::kVersion,0,trace};
        if(!exchange(command,&stop,sizeof(stop),bytes,error))return error;
    } else {
        const cc::ReadRequest read{cc::kVersion,operation=="export"?0:maximum,trace,cursor,q.maxPageBytes,0};
        if(!exchange(command,&read,sizeof(read),bytes,error))return error;
    }

    cc::Response first{};
    bool haveFirst=false;
    uint64_t exportBytes=0,exportWireBytes=0;
    bool exportIncomplete=false;
    json all=json::array(),result;
    for(;;) {
        cc::Response h{};
        if(bytes.size()<sizeof(h)||bytes.size()>q.maxPageBytes)return {{"error","Incomplete or oversized caller capture receipt; outcome is unconfirmed"}};
        std::memcpy(&h,bytes.data(),sizeof(h));
        const bool active=bool(h.flags&cc::Active);
        if(h.version!=cc::kVersion||!h.traceId||(trace&&trace!=h.traceId)||(h.flags&~7u)||h.reserved||
            static_cast<uint32_t>(h.stopReason)>6||active!=(h.stopReason==cc::StopReason::Active)||
            !ConfigValid(h.config)||h.config.stackBytes>q.maxStackBytes||h.config.bufferRecords>q.maxRecords||
            h.config.bufferBytes>q.maxBufferBytes||h.config.filterCount>q.maxFilters||
            h.totalRecords>h.config.bufferRecords||h.totalRecords>h.config.bufferBytes/sizeof(cc::Record)||
            h.matchedHits<h.totalRecords||(h.config.maxHits&&h.matchedHits>h.config.maxHits)||
            h.clock!=q.clock||h.clockFrequency!=q.clockFrequency||
            h.cursor!=cursor||h.cursor>h.totalRecords||h.nextCursor!=h.cursor+h.count||
            h.count>h.totalRecords-h.cursor||h.count>maximum||
            h.payloadBytes!=bytes.size()-sizeof(h)||(h.count&&active)||
            (maximum&&h.cursor<h.totalRecords&&!h.count)||
            (operation=="stop"&&active)||
            (operation=="start"&&(std::memcmp(&h.config,&start,sizeof(start))||h.count||h.cursor||
                (q.currentTraceId&&h.traceId==q.currentTraceId)))||
            (h.stopReason==cc::StopReason::MaxHits&&(!h.config.maxHits||h.matchedHits!=h.config.maxHits))||
            (h.stopReason==cc::StopReason::Duration&&!h.config.durationMs)||
            ((h.flags&cc::Overflow)&&(!(h.flags&cc::Incomplete)||h.stopReason!=cc::StopReason::Buffer))||
            (h.lostRecords!=0&&!(h.flags&cc::Incomplete)))
            return {{"error","Inconsistent caller capture receipt; outcome is unconfirmed"}};
        auto stable=h;stable.cursor=stable.nextCursor=0;stable.count=stable.payloadBytes=0;
        if(haveFirst&&std::memcmp(&stable,&first,sizeof(first)))return {{"error","Stopped capture changed during export"}};
        if(!haveFirst){first=stable;haveFirst=true;}
        json records=json::array();
        size_t offset=sizeof(h);
        bool incomplete=bool(h.flags&(cc::Incomplete|cc::Overflow))||h.lostRecords!=0;
        for(uint32_t i=0;i<h.count;++i) {
            cc::Record r{};
            if(bytes.size()-offset<sizeof(r))return {{"error","Short caller capture record"}};
            std::memcpy(&r,bytes.data()+offset,sizeof(r));
            if(r.recordBytes!=sizeof(r)+r.stackCaptured||r.recordBytes>bytes.size()-offset||
                r.stackRequested!=h.config.stackBytes||r.stackCaptured>r.stackRequested||
                r.sequence!=h.cursor+i+1||r.functionAddress!=h.config.address||
                r.pid!=session_.GetTargetPid()||!r.tid||(r.addressBits!=32&&r.addressBits!=64)||
                (!contextWidths&&r.addressBits!=targetBits)||
                (r.addressBits==32&&(!(q.features&cc::X86)||(contextWidths&&(r.validRegisters&0xFF00u))))||
                (r.addressBits==64&&!(q.features&cc::X64))||
                r.registers[cc::Rip]!=r.functionAddress||
                (r.flags&~3u)||(r.validRegisters&~cc::kRegisterMask)||
                (r.validRegisters&cc::kRequiredRegisters)!=cc::kRequiredRegisters||
                static_cast<uint32_t>(r.stackStatus)>3||
                (r.stackStatus==cc::StackStatus::NotRequested&&(r.stackRequested||r.stackCaptured))||
                (r.stackStatus==cc::StackStatus::Complete&&(!r.stackRequested||r.stackCaptured!=r.stackRequested))||
                (r.stackStatus==cc::StackStatus::Partial&&(!r.stackCaptured||r.stackCaptured>=r.stackRequested))||
                (r.stackStatus==cc::StackStatus::Unreadable&&(!r.stackRequested||r.stackCaptured))||
                ((r.flags&cc::TimestampValid)&&h.clock==cc::Clock::None)||
                (!(r.flags&cc::TimestampValid)&&r.timestamp))
                return {{"error","Malformed caller capture record or stack prefix"}};
            json regs=json::object();
            for(uint32_t j=0;j<cc::kRegisterCount;++j) {
                const bool valid=bool(r.validRegisters&(1u<<j));
                if((!valid&&r.registers[j])||(r.addressBits==32&&r.registers[j]>UINT32_MAX))
                    return {{"error","Invalid register validity mask or x86 register width"}};
                regs[kRegisters[j]]=valid?json(HexAddr(r.registers[j])):json(nullptr);
            }
            for(uint32_t j=0;j<h.config.filterCount;++j) {
                const auto& f=h.config.filters[j];
                if(!(r.validRegisters&(1u<<f.reg))||(r.registers[f.reg]&f.mask)!=f.expected)
                    return {{"error","Caller record does not satisfy the accepted hit-time filters"}};
            }
            if(r.stackCaptured&&(r.registers[cc::Rsp]>UINT64_MAX-(r.stackCaptured-1)||
                (r.addressBits==32&&r.registers[cc::Rsp]+r.stackCaptured-1>UINT32_MAX)))
                return {{"error","Captured stack prefix wraps the target address space"}};
            if(r.addressBits==32&&(r.functionAddress>UINT32_MAX||r.callerAddress>UINT32_MAX))
                return {{"error","Invalid x86 caller address"}};
            if(!(r.flags&cc::CallerValid)&&r.callerAddress)return {{"error","Invalid caller validity flag"}};
            if(r.stackStatus==cc::StackStatus::Partial||r.stackStatus==cc::StackStatus::Unreadable)incomplete=true;
            const char* status=r.stackStatus==cc::StackStatus::Complete?"complete":
                r.stackStatus==cc::StackStatus::Partial?"partial":r.stackStatus==cc::StackStatus::Unreadable?"unreadable":"not_requested";
            records.push_back({{"sequence",std::to_string(r.sequence)},{"pid",r.pid},{"tid",r.tid},{"cpu",r.cpu},
                {"addressBits",r.addressBits},{"execution_mode","user"},{"functionAddress",HexAddr(r.functionAddress)},
                {"callerAddress",(r.flags&cc::CallerValid)?json(HexAddr(r.callerAddress)):json(nullptr)},
                {"timestamp",(r.flags&cc::TimestampValid)?json(std::to_string(r.timestamp)):json(nullptr)},
                {"registers",std::move(regs)},{"stack",{{"address",HexAddr(r.registers[cc::Rsp])},
                    {"requestedBytes",r.stackRequested},{"capturedBytes",r.stackCaptured},{"status",status},
                    {"hex",BytesHex(bytes.data()+offset+sizeof(r),r.stackCaptured)}}}});
            offset+=r.recordBytes;
        }
        if(offset!=bytes.size())return {{"error","Trailing caller capture payload bytes"}};
        result={{"mode","detailed"},{"protocol_version",cc::kVersion},{"trace_id",std::to_string(h.traceId)},
            {"active",active},{"stop_reason",StopName(h.stopReason)},{"totalRecords",std::to_string(h.totalRecords)},
            {"matchedHits",std::to_string(h.matchedHits)},{"filteredHits",Counter(h.filteredHits)},{"lostRecords",Counter(h.lostRecords)},
            {"incomplete",incomplete},{"bufferOverflow",bool(h.flags&cc::Overflow)},
            {"stackBytes",h.config.stackBytes},{"bufferRecords",h.config.bufferRecords},{"bufferBytes",h.config.bufferBytes},
            {"max_hits",std::to_string(h.config.maxHits)},{"duration_ms",h.config.durationMs},
            {"cursor",std::to_string(h.cursor)},{"nextCursor",std::to_string(h.nextCursor)},
            {"hasMore",h.nextCursor<h.totalRecords},{"clock",{{"kind",ClockName(h.clock)},
                {"frequency_hz",h.clockFrequency?json(std::to_string(h.clockFrequency)):json(nullptr)},
                {"cross_cpu_synchronized",bool(q.features&cc::SynchronizedClock)}}},
            {"stackInterpretation","Raw hit-time bytes; complete call-stack unwinding is not guaranteed"}};
        json filters=json::array();
        for(uint32_t i=0;i<h.config.filterCount;++i) {
            const auto& f=h.config.filters[i];
            filters.push_back({{"register",kRegisters[f.reg]},{"mask",HexAddr(f.mask)},{"equals",HexAddr(f.expected)}});
        }
        result["config"]={{"address",HexAddr(h.config.address)},{"stack_bytes",h.config.stackBytes},
            {"max_hits",std::to_string(h.config.maxHits)},{"duration_ms",h.config.durationMs},
            {"buffer_records",h.config.bufferRecords},{"buffer_bytes",h.config.bufferBytes},{"filters",std::move(filters)},
            {"data_policy","original"},{"transaction_policy","omit"}};
        if(operation!="export") {
            if(maximum)result["records"]=std::move(records);
            break;
        }
        if(active)return {{"error","Stop the capture before exporting records"}};
        exportIncomplete=exportIncomplete||incomplete;
        exportWireBytes+=h.payloadBytes;
        if(exportWireBytes>h.config.bufferBytes)return {{"error","Exported records exceed the accepted byte capacity"}};
        if(maximum) {
            for(auto& item:records) {
                exportBytes+=item.dump().size();
                if(exportBytes>256ULL*1024*1024)return {{"error","Caller capture JSON export exceeds 256 MiB"}};
                all.push_back(std::move(item));
            }
        }
        if(h.nextCursor==h.totalRecords) {
            result["cursor"]="0";result["nextCursor"]=std::to_string(h.totalRecords);
            result["records"]=std::move(all);result["hasMore"]=false;result["incomplete"]=exportIncomplete;
            break;
        }
        cursor=h.nextCursor;maximum=256;
        const cc::ReadRequest read{cc::kVersion,maximum,trace,cursor,q.maxPageBytes,0};
        if(!exchange(IpcCommand::ReadCallerCapture,&read,sizeof(read),bytes,error))return error;
    }
    if(std::chrono::steady_clock::now()>=deadline)return {{"error","Caller capture operation deadline expired before artifact creation"}};
    const bool file=operation=="export"||!path.empty()||result.dump().size()>65536;
    if(file) {
        const auto written=path.empty()?WriteJsonArtifactInDirectory("","caller-capture",result,format):
            WriteTraceOutputFile(path,format,result);
        if(!written.success)return {{"error",written.error},{"trace_id",result["trace_id"]},{"storage_completed",false}};
        result.erase("records");
        result["storage_completed"]=true;
        result["output_file"]={{"path",written.path},{"format",written.format},{"size",std::to_string(written.size)},{"sha256",written.sha256}};
    }
    return result;
}
} // namespace veh
