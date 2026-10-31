// KD trace transport and pure decoding of immutable backend observations.
#include "mcp_server.h"
#include "kernel_debug_client.h"
#include "../common/kd_trace_protocol.h"
#include "../adapter/disassembler.h"
#include "trace_output_file.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

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
json Shape(const std::vector<kdtrace::Record>& records,const kdtrace::Header& h,const json& args) {
    struct Decoded { DisasmInstruction ins; std::string kind; };
    std::vector<Decoded> decoded; std::set<uint64_t> leaders;
    bool incomplete=false;
    for(size_t i=0;i<records.size();++i) {
        const auto& r=records[i]; auto dis=CreateDisassembler(r.addressBits==64);
        auto d=dis->Disassemble(r.code,r.codeSize,r.address,1);
        if(d.size()!=1||!d[0].length||d[0].length>r.codeSize) {incomplete=true;break;}
        auto kind=Kind(d[0].mnemonic);
        if(i==0)leaders.insert(r.address);
        if(kind!="fallthrough" || r.nextAddress!=r.address+d[0].length)leaders.insert(r.nextAddress);
        if(i && (decoded.back().kind!="fallthrough" || records[i-1].nextAddress!=r.address ||
            records[i-1].cpl!=r.cpl || records[i-1].cr3!=r.cr3 || records[i-1].addressBits!=r.addressBits))leaders.insert(r.address);
        decoded.push_back({std::move(d[0]),kind});
    }
    json blocks=json::array(),edges=json::array(),snapshots=json::array(),events=json::array(),versions=json::array();
    std::map<std::string,size_t> blockIndex,edgeIndex;
    const bool collectCode=args.value("collect_code",false);
    const bool collectEvents=args.value("collect_events",false)||collectCode;
    const bool collectSnapshots=(h.flags&kdtrace::kSnapshots)!=0;
    constexpr const char* names[]={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip","eflags"};
    constexpr unsigned order[]={0,3,1,2,6,7,5,4,8,9,10,11,12,13,14,15,16,17};
    size_t first=0;
    while(first<decoded.size()) {
        size_t last=first;
        while(last+1<decoded.size() && decoded[last].kind=="fallthrough" &&
              records[last].nextAddress==records[last].address+decoded[last].ins.length &&
              !leaders.count(records[last+1].address))++last;
        std::string bytes;
        for(size_t k=first;k<=last;++k){if(!bytes.empty())bytes+=' ';bytes+=decoded[k].ins.bytes;}
        const auto& r=records[first]; const auto& tail=records[last];
        const auto key=Hex(r.address)+":"+Hex(r.cr3)+":"+std::to_string(r.addressBits)+":"+bytes;
        auto found=blockIndex.find(key); size_t index;
        if(found==blockIndex.end()){
            index=blocks.size();blockIndex[key]=index;
            json block={{"start",Hex(r.address)},{"end",Hex(tail.address+decoded[last].ins.length)},{"hits",1},
                {"cpu",r.cpu},{"cpl",r.cpl},{"address_bits",r.addressBits},{"cr3",Hex(r.cr3)}};
            if(collectSnapshots){
                json regs=json::array();for(auto j:order)regs.push_back(Hex(r.registers[j]));
                block["first_snapshot"]=snapshots.size();
                snapshots.push_back({{"id",snapshots.size()},{"instruction_pointer",Hex(r.address)},
                    {"stack_pointer",Hex(r.registers[4])},{"registers",regs},{"stack",""},{"address_bits",r.addressBits}});
            }
            blocks.push_back(std::move(block));
            if(collectCode)versions.push_back({{"id",index},{"start",Hex(r.address)},
                {"end",Hex(tail.address+decoded[last].ins.length)},{"bytes",bytes},{"address_bits",r.addressBits}});
        }else{index=found->second;blocks[index]["hits"]=blocks[index]["hits"].get<uint32_t>()+1;}
        const bool out=tail.nextAddress<args["_range_start"].get<uint64_t>()||tail.nextAddress>=args["_range_end"].get<uint64_t>();
        const auto kind=out?std::string("range_exit"):decoded[last].kind;
        const auto edgeKey=std::to_string(index)+":"+Hex(tail.address)+":"+Hex(tail.nextAddress)+":"+kind;
        if(!edgeIndex.count(edgeKey)){edgeIndex[edgeKey]=edges.size();edges.push_back({{"source",Hex(r.address)},
            {"source_instruction",Hex(tail.address)},{"target",Hex(tail.nextAddress)},{"kind",kind},{"hits",1}});}
        else {auto& e=edges[edgeIndex[edgeKey]];e["hits"]=e["hits"].get<uint32_t>()+1;}
        if(collectEvents)events.push_back({{"sequence",std::to_string(events.size()+1)},{"instruction_sequence",std::to_string(first+1)},{"kind","block"},
            {"address",Hex(r.address)},{"code_version",collectCode?json(index):json(nullptr)},
            {"thread_id",r.tid?json(r.tid):json(nullptr)},{"process_id",r.pid?json(r.pid):json(nullptr)},{"cpu",r.cpu}});
        if(collectEvents)events.push_back({{"sequence",std::to_string(events.size()+1)},
            {"instruction_sequence",std::to_string(last+1)},{"kind","edge"},
            {"source",Hex(r.address)},{"source_instruction",Hex(tail.address)},{"target",Hex(tail.nextAddress)},
            {"edge_kind",kind},{"cpu",r.cpu},{"thread_id",tail.tid?json(tail.tid):json(nullptr)}});
        if(collectCode)blocks[index]["code_version"]=index;
        first=last+1;
    }
    const char* reason="incomplete";
    switch(h.end){case kdtrace::Budget:reason="max_steps";break;case kdtrace::Range:reason="range_exit";break;
        case kdtrace::Interrupted:reason="interrupted";break;case kdtrace::Exception:reason="exception";break;
        case kdtrace::CodeUnavailable:reason="code_unavailable";break;case kdtrace::UnsupportedInstruction:reason="unsupported_instruction";break;case kdtrace::OtherStop:reason="debug_stop";break;}
    incomplete|=h.end!=kdtrace::Budget&&h.end!=kdtrace::Range;
    json orderJson=json::array();for(auto name:names)orderJson.push_back(name);
    return {{"execution_context","kd"},{"capture_scope","selected_cpu"},{"cpu",h.cpu},
        {"thread_id",nullptr},{"generation",std::to_string(h.generation)},{"steps_executed",h.steps},
        {"final_address",Hex(h.finalAddress)},{"stop_reason",reason},{"halted",true},
        {"truncated",incomplete},{"decode_incomplete",incomplete},{"blocks",blocks},{"edges",edges},
        {"snapshots",snapshots},{"register_order",orderJson},{"events",events},{"code_versions",versions},
        {"collection",{{"snapshots",collectSnapshots},{"compressed_paths",false},{"stack_bytes",0}}},
        {"backend_records",h.count},{"lost_records",0},{"decoded_instruction_count",decoded.size()}};
}
}
json McpServer::ToolKdTraceBasicBlocks(const json& args) {
    if(!kd_)return KdNotConnected();
    if(kd_->running())return {{"error","running: veh_kd_break first"}};
    const std::set<std::string> accepted={"execution_context","cpu","threadId","start","end","max_steps","timeout_ms",
        "stack_bytes","max_blocks","max_edges","collect_snapshots","collect_code","collect_events","output_file","output_format",
        "compress_paths","collect_memory_writes","collect_memory_reads","collect_memory_events","collect_register_events",
        "stop_on_return","follow_exceptions","code_output","events_output"};
    for(const auto& field:args.items())if(!accepted.count(field.key()))
        return {{"error","KD trace does not support "+field.key()},{"code","unsupported_policy"}};
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
       !Number(args,"max_steps",4096,1,4096,steps)||!Number(args,"timeout_ms",10000,1,60000,timeout)||
       !Number(args,"stack_bytes",0,0,0,stack)||!Number(args,"max_blocks",4096,1,16384,blocks)||
       !Number(args,"max_edges",8192,1,32768,edges)||!Number(args,"threadId",0,0,0,tid))
        return {{"error","KD trace requires hex start<end, max_steps 1-4096, timeout_ms 1-60000; stack_bytes/threadId must be 0"}};
    if(blocks<steps||edges<steps)return {{"error","KD max_blocks/max_edges must cover max_steps"},{"code","unsupported_policy"}};
    if(args.contains("collect_snapshots")&&!args["collect_snapshots"].is_boolean())return {{"error","collect_snapshots must be boolean"}};
    if(args.contains("follow_exceptions")&&args["follow_exceptions"]!=false)
        return {{"error","KD trace stops before exception delivery; follow_exceptions=true is unsupported"},{"code","unsupported_policy"}};
    for(const char* key:{"collect_code","collect_events"})
        if(args.contains(key)&&!args[key].is_boolean())return {{"error",std::string(key)+" must be boolean"}};
    if(args.contains("cpu")&&(!args["cpu"].is_number_integer()||args["cpu"].get<int64_t>()<0||args["cpu"].get<int64_t>()>=64))
        return {{"error","cpu must be 0-63"}};
    if(args.contains("output_file")&&(!args["output_file"].is_string()||args["output_file"].get<std::string>().empty()))
        return {{"error","output_file must be a nonempty path"}};
    if(args.contains("output_format")&&args["output_format"]!="json"&&args["output_format"]!="jsonl")
        return {{"error","output_format must be json or jsonl"}};
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
    kdtrace::Header before{};
    if(!kd_->Request("qTraceBB:status",&reply)||!Unhex(reply,&before,sizeof(before)))
        return {{"error","Invalid KD trace status"}};
    const uint32_t flags=args.value("collect_snapshots",true)?kdtrace::kSnapshots:0;
    const auto begin=std::chrono::steady_clock::now();
    const auto command="vTraceBB:1,"+Field(steps)+","+Field(start)+","+Field(end)+","+Field(flags);
    if(!kd_->Resume(command))return {{"error","KD trace link lost before start; execution state unknown"}};
    std::string stop;bool timedOut=false;
    if(!kd_->WaitStop(&stop,timeout)){
        timedOut=true;
        if(!kd_->QueryStop(&stop,500) && !kd_->Interrupt(&stop,5000))return {{"error","Could not confirm KD trace stop"},{"running",true},{"capture_incomplete",true}};
    }
    kdtrace::Header h{};
    if(!kd_->Request("qTraceBB:status",&reply)||!Unhex(reply,&h,sizeof(h))||
       h.version!=kdtrace::kVersion||h.recordSize!=sizeof(kdtrace::Record)||!h.generation||
       h.generation==before.generation||h.count>steps||h.count!=h.steps||h.flags!=flags||
       h.cpu!=selectedId-1||(h.end==kdtrace::Budget&&h.count!=steps)||
       (h.end==kdtrace::Range&&h.finalAddress>=start&&h.finalAddress<end)||
       h.reserved||h.end<kdtrace::Budget||h.end>kdtrace::UnsupportedInstruction)
        return {{"error","KD trace refused or returned an invalid capture receipt"},{"halted",true}};
    std::vector<kdtrace::Record> records(h.count);
    for(uint32_t offset=0;offset<h.count;){
        const uint32_t count=(std::min)(10u,h.count-offset);
        if(!kd_->Request("qTraceBB:read,"+Field(h.generation)+","+Field(offset)+","+Field(count),&reply)||
            !Unhex(reply,records.data()+offset,count*sizeof(kdtrace::Record)))
            return {{"error","KD trace page read failed; capture retained in backend"},{"halted",true},
                {"generation",std::to_string(h.generation)},{"capture_incomplete",true}};
        offset+=count;
    }
    for(size_t i=0;i<records.size();++i){
        const auto& r=records[i];
        if(r.cpu!=h.cpu || (r.addressBits!=32&&r.addressBits!=64)||r.cpl>3||!r.codeSize||r.codeSize>15||
           r.reserved||r.address<start||r.address>=end||(i&&records[i-1].nextAddress!=r.address)||
           (i+1<records.size()&&(r.nextAddress<start||r.nextAddress>=end))||
           (i+1==records.size()&&r.nextAddress!=h.finalAddress))
            return {{"error","Inconsistent KD trace record receipt"},{"halted",true},{"capture_incomplete",true}};
    }
    auto shapeArgs=args;shapeArgs["_range_start"]=start;shapeArgs["_range_end"]=end;
    auto result=Shape(records,h,shapeArgs);
    result["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-begin).count();
    result["timeout_requested"]=timedOut;
    if(args.contains("output_file")){
        const auto path=args["output_file"].get<std::string>();const auto format=args.value("output_format","json");
        auto written=WriteTraceOutputFile(path,format,result);
        if(!written.success)return {{"error",written.error},{"halted",true},{"capture_retained",true}};
        return {{"output_file",{{"path",path},{"format",format}}},{"steps_executed",h.steps},{"final_address",Hex(h.finalAddress)},{"halted",true}};
    }
    return result;
}
} // namespace veh
