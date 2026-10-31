// KD trace transport and pure decoding of immutable backend observations.
#include "mcp_server.h"
#include "kernel_debug_client.h"
#include "../common/kd_trace_protocol.h"
#include "../adapter/disassembler.h"
#include "trace_output_file.h"
#include "kd_capture_store.h"
#include "kd_capture_collect.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <array>
#include <tuple>
#include <memory>

namespace veh {
namespace {
using json = nlohmann::json;
std::string Hex(uint64_t n) { char b[24]; snprintf(b,sizeof(b),"0x%llX",static_cast<unsigned long long>(n)); return b; }
std::string Field(uint64_t n) { char b[24]; snprintf(b,sizeof(b),"%llx",static_cast<unsigned long long>(n)); return b; }
bool Address(const json& a, const char* key, uint64_t& n) {
    if (!a.contains(key) || !a[key].is_string()) return false;
    const auto s=a[key].get<std::string>();
    if(s.empty() || s[0]=='-' || s[0]=='+') return false;
    try { size_t pos=0; n=std::stoull(s,&pos,16); return pos==s.size(); } catch(...) { return false; }
}
bool Number(const json& a,const char* key,uint32_t def,uint32_t lo,uint32_t hi,uint32_t& n) {
    if(!a.contains(key)) {n=def;return true;}
    if(!a[key].is_number_integer())return false;
    const auto v=a[key].get<int64_t>();
    if(v<lo || v>hi)return false;n=static_cast<uint32_t>(v);return true;
}
bool Unhex(const std::string& s,void* output,size_t bytes) {
    if(s.size()!=bytes*2)return false;
    auto digit=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;};
    auto* p=static_cast<uint8_t*>(output);
    for(size_t i=0;i<bytes;++i){const int h=digit(s[i*2]),l=digit(s[i*2+1]);if(h<0||l<0)return false;p[i]=static_cast<uint8_t>(h*16+l);}
    return true;
}
std::string Kind(const std::string& mnemonic) {
    const auto op=mnemonic.substr(0,mnemonic.find(' '));
    if(op=="call"||op=="syscall"||op=="sysenter")return "call";
    if(op=="ret"||op=="retf"||op=="sysret"||op=="sysretq"||op=="sysexit"||op=="iretq"||op=="iret")return "return";
    if(!op.empty()&&(op[0]=='j'||op.rfind("loop",0)==0))return "branch";
    return "fallthrough";
}
template<class Records>
json Shape(const Records& records,const kdtrace::Header& h,const json& args) {
    struct Decoded { DisasmInstruction ins; std::string kind; };
    using Key=std::tuple<uint64_t,uint8_t,uint8_t,std::array<uint8_t,16>>;
    std::map<Key,Decoded> cache;
    auto dis64=CreateDisassembler(true),dis32=CreateDisassembler(false);
    const auto decode=[&](const kdtrace::Record& r) {
        std::array<uint8_t,16> bytes={};std::copy(r.code,r.code+16,bytes.begin());
        const Key key={r.address,r.addressBits,r.codeSize,bytes};
        const auto found=cache.find(key);if(found!=cache.end())return found->second;
        Decoded out;auto d=(r.addressBits==64?dis64:dis32)->Disassemble(r.code,r.codeSize,r.address,1);
        if(d.size()==1&&d[0].length&&d[0].length<=r.codeSize){out.ins=std::move(d[0]);out.kind=Kind(out.ins.mnemonic);}
        if(cache.size()<4096)cache.emplace(key,out);
        return out;
    };
    // Two passes over the disk mapping: bounded decode cache, no decoded object
    // or retained register snapshot for every occurrence.
    std::set<uint64_t> leaders;size_t decodedCount=0;
    std::string previousKind;bool incomplete=false;
    for(size_t i=0;i<records.size();++i) {
        const auto& r=records[i];const auto d=decode(r);
        if(!d.ins.length){incomplete=true;break;}
        if(i==0)leaders.insert(r.address);
        if(d.kind!="fallthrough"||r.nextAddress!=r.address+d.ins.length)leaders.insert(r.nextAddress);
        if(i&&(previousKind!="fallthrough"||records[i-1].nextAddress!=r.address||
            records[i-1].cpl!=r.cpl||records[i-1].cr3!=r.cr3||records[i-1].addressBits!=r.addressBits))leaders.insert(r.address);
        if(leaders.size()>65536){incomplete=true;break;}
        previousKind=d.kind;++decodedCount;
    }
    json blocks=json::array(),edges=json::array(),snapshots=json::array(),events=json::array(),versions=json::array();
    std::map<std::string,size_t> blockIndex,edgeIndex;
    const bool collectCode=args.value("collect_code",false);
    const bool collectEvents=args.value("collect_events",false)||collectCode;
    const bool collectSnapshots=(h.flags&kdtrace::kSnapshots)!=0;
    constexpr const char* names[]={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip","eflags"};
    constexpr unsigned order[]={0,3,1,2,6,7,5,4,8,9,10,11,12,13,14,15,16,17};
    size_t first=0,keyBytes=0,codeBytes=0;uint64_t eventCount=0;
    while(first<decodedCount) {
        size_t last=first;auto tailDecoded=decode(records[last]);std::string bytes=tailDecoded.ins.bytes;
        while(last+1<decodedCount&&tailDecoded.kind=="fallthrough"&&
              records[last].nextAddress==records[last].address+tailDecoded.ins.length&&
              !leaders.count(records[last+1].address)){
            ++last;tailDecoded=decode(records[last]);bytes+=' ';bytes+=tailDecoded.ins.bytes;
            if(bytes.size()>3*1024*1024){incomplete=true;break;}
        }
        if(bytes.size()>3*1024*1024)break; // raw facts remain in the artifact
        const auto& r=records[first];const auto& tail=records[last];
        const auto key=Hex(r.address)+":"+Hex(r.cr3)+":"+std::to_string(r.addressBits)+":"+bytes;
        auto found=blockIndex.find(key);size_t index;
        if(found==blockIndex.end()){
            if(blocks.size()>=16384||keyBytes+key.size()>24*1024*1024){incomplete=true;break;}
            index=blocks.size();blockIndex.emplace(key,index);keyBytes+=key.size();
            json block={{"start",Hex(r.address)},{"end",Hex(tail.address+tailDecoded.ins.length)},{"hits",1},{"first_record_offset",std::to_string(first)},
                {"cpu",r.cpu},{"cpl",r.cpl},{"address_bits",r.addressBits},{"cr3",Hex(r.cr3)}};
            if(collectSnapshots){
                json regs=json::array();for(auto j:order)regs.push_back(Hex(r.registers[j]));
                block["first_snapshot"]=snapshots.size();
                snapshots.push_back({{"id",snapshots.size()},{"instruction_pointer",Hex(r.address)},
                    {"stack_pointer",Hex(r.registers[4])},{"registers",regs},{"stack",""},{"address_bits",r.addressBits}});
            }
            blocks.push_back(std::move(block));
            if(collectCode&&codeBytes+bytes.size()<=3*1024*1024){
                versions.push_back({{"id",index},{"start",Hex(r.address)},
                    {"end",Hex(tail.address+tailDecoded.ins.length)},{"bytes",bytes},{"address_bits",r.addressBits}});
                codeBytes+=bytes.size();blocks[index]["code_version"]=index;
            }
        }else{index=found->second;blocks[index]["hits"]=blocks[index]["hits"].get<uint32_t>()+1;}
        const bool out=tail.nextAddress<args["_range_start"].get<uint64_t>()||tail.nextAddress>=args["_range_end"].get<uint64_t>();
        const auto kind=out?std::string("range_exit"):tailDecoded.kind;
        const auto edgeKey=std::to_string(index)+":"+Hex(tail.address)+":"+Hex(tail.nextAddress)+":"+kind;
        if(!edgeIndex.count(edgeKey)){
            if(edges.size()>=32768){incomplete=true;break;}
            edgeIndex[edgeKey]=edges.size();edges.push_back({{"source",Hex(r.address)},
                {"source_instruction",Hex(tail.address)},{"target",Hex(tail.nextAddress)},{"kind",kind},{"hits",1}});
        }else{auto& edge=edges[edgeIndex[edgeKey]];edge["hits"]=edge["hits"].get<uint32_t>()+1;}
        if(collectEvents){
            eventCount+=2;
            if(events.size()+2<=8192){
                const auto version=blocks[index].contains("code_version")?blocks[index]["code_version"]:json(nullptr);
                events.push_back({{"sequence",std::to_string(eventCount-1)},{"instruction_sequence",std::to_string(first+1)},{"kind","block"},
                    {"address",Hex(r.address)},{"code_version",version},{"thread_id",r.tid?json(r.tid):json(nullptr)},
                    {"process_id",r.pid?json(r.pid):json(nullptr)},{"cpu",r.cpu}});
                events.push_back({{"sequence",std::to_string(eventCount)},{"instruction_sequence",std::to_string(last+1)},{"kind","edge"},
                    {"source",Hex(r.address)},{"source_instruction",Hex(tail.address)},{"target",Hex(tail.nextAddress)},
                    {"edge_kind",kind},{"cpu",r.cpu},{"thread_id",tail.tid?json(tail.tid):json(nullptr)}});
            }
        }
        first=last+1;
    }
    const char* reason="incomplete";
    switch(h.end){case kdtrace::Budget:reason="max_steps";break;case kdtrace::Range:reason="range_exit";break;
        case kdtrace::Interrupted:reason="interrupted";break;case kdtrace::Exception:reason="exception";break;
        case kdtrace::CodeUnavailable:reason="code_unavailable";break;case kdtrace::UnsupportedInstruction:reason="unsupported_instruction";break;case kdtrace::OtherStop:reason="debug_stop";break;}
    const bool metadataIncomplete=incomplete||first<records.size();
    const bool captureIncomplete=h.end!=kdtrace::Budget&&h.end!=kdtrace::Range;
    json orderJson=json::array();for(auto name:names)orderJson.push_back(name);
    return {{"execution_context","kd"},{"capture_scope","selected_cpu"},{"cpu",h.cpu},
        {"thread_id",nullptr},{"generation",std::to_string(h.generation)},{"steps_executed",h.steps},
        {"final_address",Hex(h.finalAddress)},{"stop_reason",reason},{"halted",true},
        {"truncated",metadataIncomplete||captureIncomplete},{"decode_incomplete",metadataIncomplete||captureIncomplete},
        {"capture_incomplete",captureIncomplete},{"analysis_incomplete",metadataIncomplete},
        {"blocks",blocks},{"edges",edges},{"snapshots",snapshots},{"register_order",orderJson},
        {"events",events},{"code_versions",versions},{"events_dropped",eventCount-events.size()},
        {"events_truncated",eventCount>events.size()||metadataIncomplete},
        {"code_truncated",collectCode&&versions.size()<blocks.size()},
        {"collection",{{"snapshots",collectSnapshots},{"compressed_paths",false},{"stack_bytes",0}}},
        {"backend_records",h.steps},{"lost_records",0},{"decoded_instruction_count",decodedCount},
        {"analysis_steps",first},{"analysis_steps_omitted",records.size()-first}};
}
}
json McpServer::ToolKdTraceBasicBlocks(const json& args) {
    if(args.value("operation",std::string("capture"))=="read_capture")return ReadKdCapture(args);
    if(args.value("operation",std::string("capture"))!="capture")return {{"error","Unknown KD trace operation"}};
    if(!kd_)return KdNotConnected();
    if(kd_->running())return {{"error","running: veh_kd_break first"}};
    const std::set<std::string> accepted={"operation","execution_context","cpu","threadId","start","end","max_steps","timeout_ms",
        "stack_bytes","max_blocks","max_edges","collect_snapshots","collect_code","collect_events","output_file","output_format",
        "compress_paths","collect_memory_writes","collect_memory_reads","collect_memory_events","collect_register_events",
        "stop_on_return","follow_exceptions","code_output","events_output"};
    for(const auto& field:args.items())if(!accepted.count(field.key()))
        return {{"error","KD trace does not support "+field.key().substr(0,128)},{"code","unsupported_policy"}};
    // Whole-machine control never runs inside process breakpoint actions or capture setup.
    for(const char* key:{"compress_paths","collect_memory_writes","collect_memory_reads",
        "collect_memory_events","collect_register_events","stop_on_return"})
        if(args.contains(key)&&(!args[key].is_boolean()||args[key].get<bool>()))
            return {{"error",std::string("KD trace does not support ")+key},{"code","unsupported_policy"}};
    for(const char* key:{"code_output","events_output"})
        if(args.contains(key)&&args[key]!="inline")return {{"error","KD capture supports inline records only"},{"code","unsupported_policy"}};
    uint32_t steps,timeout,stack,blocks,edges,tid;
    uint64_t start,end;
    if(!Address(args,"start",start)||!Address(args,"end",end)||start>=end||
       !Number(args,"max_steps",100000,1,kdtrace::kMaxStreamSteps,steps)||!Number(args,"timeout_ms",10000,1,600000,timeout)||
       !Number(args,"stack_bytes",0,0,0,stack)||!Number(args,"max_blocks",4096,1,16384,blocks)||
       !Number(args,"max_edges",8192,1,32768,edges)||!Number(args,"threadId",0,0,0,tid))
        return {{"error","KD trace requires hex start<end, max_steps1-5000000, timeout_ms1-600000; stack_bytes/threadId must be 0"}};
    if(args.contains("collect_snapshots")&&!args["collect_snapshots"].is_boolean())return {{"error","collect_snapshots must be boolean"}};
    if(args.contains("follow_exceptions")&&args["follow_exceptions"]!=false)
        return {{"error","KD trace stops before exception delivery; follow_exceptions=true is unsupported"},{"code","unsupported_policy"}};
    for(const char* key:{"collect_code","collect_events"})
        if(args.contains(key)&&!args[key].is_boolean())return {{"error",std::string(key)+" must be boolean"}};
    if(args.contains("cpu")&&(!args["cpu"].is_number_integer()||args["cpu"].get<int64_t>()<0||args["cpu"].get<int64_t>()>=64))
        return {{"error","cpu must be 0-63"}};
    if(args.contains("output_file")&&(!args["output_file"].is_string()||args["output_file"].get<std::string>().empty()||args["output_file"].get<std::string>().size()>2048))
        return {{"error","output_file must be a nonempty path"}};
    if(args.contains("output_format")&&args["output_format"]!="json"&&args["output_format"]!="jsonl")
        return {{"error","output_format must be json or jsonl"}};
    if(args.contains("output_file")){
        const auto pathError=ValidateKdCapturePath(args["output_file"].get<std::string>(),2048);
        if(!pathError.empty())return {{"error",pathError}};
        const auto outputError=ValidateTraceOutputFile(args["output_file"].get<std::string>(),args.value("output_format","json"));
        if(!outputError.empty())return {{"error",outputError}};
    }
    json error;if(!KdSelect(args,error))return error;
    std::string reply;
    if(!kd_->Request("qTraceBB:cap",&reply)||reply!="1,1000")
        return {{"error","KD backend does not support bounded TraceBasicBlocks"},{"code","unsupported_backend"}};
    std::string selected;
    if(!kd_->Request("qC",&selected)||selected.rfind("QC",0)!=0)
        return {{"error","Cannot verify selected KD CPU"}};
    uint64_t selectedId=0;
    try{size_t used=0;selectedId=std::stoull(selected.substr(2),&used,16);if(used!=selected.size()-2)selectedId=0;}catch(...){}
    if(!selectedId||selectedId>64||(args.contains("cpu")&&selectedId!=args["cpu"].get<uint64_t>()+1))
        return {{"error","Invalid selected KD CPU receipt"}};
    uint32_t version=kdtrace::kVersion;
    if(kd_->Request("qTraceBB:cap2",&reply)&&reply=="2,1000,4c4b40")version=kdtrace::kStreamVersion;
    if(version==kdtrace::kVersion){
        if(!args.contains("max_steps"))steps=kdtrace::kCapacity;
        if(steps>kdtrace::kCapacity||blocks<steps||edges<steps)
            return {{"error","This legacy KD backend is limited to4096 steps"},{"code","unsupported_backend"}};
    }else if(args.contains("max_blocks")||args.contains("max_edges"))
        return {{"error","Streamed KD capture uses bounded output aggregates; custom block/edge execution stops are unsupported"},{"code","unsupported_policy"}};
    const uint32_t flags=args.value("collect_snapshots",true)?kdtrace::kSnapshots:0;
    const auto begin=std::chrono::steady_clock::now();
    std::unique_ptr<KdCaptureStore> store;
    try{store=std::make_unique<KdCaptureStore>(steps,flags,start,end,args.value("output_file",std::string{}));}
    catch(const std::exception& e){return {{"error",e.what()},{"code","capture_storage"}};}
    KdCollected collected;
    try{
        if(!CollectKdCapture(*kd_,version,steps,timeout,flags,static_cast<uint32_t>(selectedId-1),
                start,end,*store,collected,error))return error;
        if(!store->Map())return {{"error","Cannot map captured records for analysis"},
            {"capture_file",store->Keep(false)},{"halted",true}};
        auto shapeArgs=args;shapeArgs["_range_start"]=start;shapeArgs["_range_end"]=end;
        auto result=Shape(*store,collected.final,shapeArgs);
        result["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
        result["timeout_requested"]=collected.timedOut;result["chunks"]=collected.chunks;
        result["transport_version"]=version;
        const bool exportResult=args.contains("output_file");
        const bool compact=steps>kdtrace::kCapacity||result.dump().size()>8192||exportResult;
        json artifact;
        if(compact){artifact=store->Keep(true);result["capture_file"]=artifact;}
        TraceOutputFileResult written;
        if(exportResult){
            written=WriteTraceOutputFile(args["output_file"].get<std::string>(),args.value("output_format","json"),result);
            if(!written.success)return {{"error",written.error},{"capture_file",artifact},{"halted",true}};
        }
        if(!compact)return result;
        json summary;
        for(const char* name:{"execution_context","capture_scope","cpu","generation","steps_executed","final_address",
            "stop_reason","halted","truncated","decode_incomplete","capture_incomplete","analysis_incomplete",
            "analysis_steps","analysis_steps_omitted","lost_records","events_dropped","events_truncated","code_truncated",
            "elapsed_ms","timeout_requested","chunks","transport_version"})summary[name]=result[name];
        summary["capture_file"]=artifact;
        summary["counts"]={{"blocks",result["blocks"].size()},{"edges",result["edges"].size()},
            {"snapshots",result["snapshots"].size()},{"events",result["events"].size()},{"code_versions",result["code_versions"].size()}};
        auto hot=result["blocks"].get<std::vector<json>>();
        std::sort(hot.begin(),hot.end(),[](const json& a,const json& b){return a["hits"].get<uint32_t>()>b["hits"].get<uint32_t>();});
        summary["hot_blocks"]=json::array();for(size_t i=0;i<(std::min)(hot.size(),size_t{8});++i)summary["hot_blocks"].push_back(hot[i]);
        for(auto& block:summary["hot_blocks"])block.erase("first_snapshot");
        summary["read_capture"]={{"operation","read_capture"},{"offset","0"},{"limit",16}};
        if(exportResult)summary["output_file"]={{"path",written.path},{"format",written.format},
            {"size",written.size},{"sha256",written.sha256}};
        if(summary.dump().size()>8192)summary.erase("hot_blocks");
        if(summary.dump().size()>8192)return {{"error","KD capture receipt exceeds the 8192-byte limit; artifacts retained"},
            {"halted",true},{"capture_retained",true}};
        return summary;
    }catch(const std::exception& e){
        return {{"error",e.what()},{"capture_incomplete",true},{"halted",!kd_->running()},
            {"capture_file",store->Keep(false)}};
    }
}
} // namespace veh
