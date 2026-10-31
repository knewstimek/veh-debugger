#include "../src/mcp/kd_capture_store.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
using namespace veh;
namespace {
enum Failure {None,BodyShort,HeaderShort,HeaderPersistent,TruncateOnly};
Failure failure=None;
bool bodyWritten=false,triggered=false;
BOOL Write(HANDLE file,const void* data,DWORD bytes,DWORD* wrote){
    if(failure==BodyShort&&!triggered&&bytes>64){
        triggered=true;const auto ok=WriteFile(file,data,bytes/2,wrote,nullptr);return ok;
    }
    if(failure==HeaderShort||failure==HeaderPersistent){
        if(bytes>64)bodyWritten=true;
        if(bytes==64&&bodyWritten){
            if(!triggered){triggered=true;WriteFile(file,data,32,wrote,nullptr);return FALSE;}
            if(failure==HeaderPersistent){*wrote=0;SetLastError(ERROR_WRITE_FAULT);return FALSE;}
        }
    }
    return WriteFile(file,data,bytes,wrote,nullptr);
}
}
int main(){
    int checks=0;
    auto check=[&](bool ok,const char* label){++checks;if(!ok){std::printf("FAIL %s\n",label);std::exit(1);}};
    kdtrace::Record rows[2]={};
    for(auto& r:rows){r.address=0x1000;r.nextAddress=0x1000;r.cr3=0x2000;r.addressBits=64;r.codeSize=2;r.code[0]=0xEB;r.code[1]=0xFE;}
    for(auto plan:{BodyShort,HeaderShort,HeaderPersistent}){
        nlohmann::json saved;std::string path;
        {
            failure=None;bodyWritten=triggered=false;
            KdCaptureStore store(10000,0,0x1000,0x1002,"",Write);
            check(store.Append(rows,2,123,0),"commit initial prefix");
            failure=plan;
            check(!store.Append(rows,2,123,0),"partial write must fail");
            check(store.size()==2,"only committed prefix counted");
            saved=store.Keep(false);path=store.Path();
            check(!saved["complete"].get<bool>(),"failed artifact never complete");
            check(saved["bytes"]==464&&saved["physical_bytes"]==464,"committed length restored");
            check(saved["header_repaired"].get<bool>()==(plan!=HeaderPersistent),"repair status truthful");
        }
        failure=None;
        auto page=ReadKdCapture({{"capture_file",path},{"offset","0"},{"limit",16}});
        if(plan==HeaderPersistent){
            check(page.contains("error"),"corrupt header cannot masquerade as complete");
            check(saved.contains("recovery"),"repair failure exposes recovery descriptor");
            page=ReadKdCapture({{"capture_file",path},{"offset","0"},{"limit",16},{"recovery",saved["recovery"]}});
            check(page.value("recovery_applied",false),"explicit committed-prefix recovery used");
        }
        check(!page.contains("error")&&page["count"]==2&&page["records"][1]["sequence"]=="2","acknowledged facts readable");
        check(!saved["sha256"].is_null()&&saved["sha256_scope"]=="valid_prefix","hash covers declared prefix");
        check(std::filesystem::remove(std::filesystem::u8path(path)),"owned fixture artifact removed");
    }
    for(uint32_t flags:{0u,kdtrace::kRunPeerCpus}){
        for(unsigned marker:{1u,2u}){
            auto uncertain=rows[1];uncertain.reserved=static_cast<uint8_t>(marker);
            uncertain.codeSize=0;std::memset(uncertain.code,0,sizeof(uncertain.code));
            std::string path;nlohmann::json saved;
            {
                KdCaptureStore store(2,flags,0x1000,0x1002,"");
                check(store.Append(rows,1,124,0)&&store.Append(&uncertain,1,124,0),"write unknown-code fixture");
                saved=store.Keep(false);path=store.Path();
                check(saved["storage_complete"].get<bool>()&&!saved["complete"].get<bool>(),"storage independent from capture completion");
            }
            const auto page=ReadKdCapture({{"capture_file",path},{"offset","1"},{"limit",16}});
            if(flags==kdtrace::kRunPeerCpus&&marker==1)
                check(!page.contains("error")&&page["records"][0]["code_uncertain"]==true&&
                    !page["records"][0].contains("instruction"),"offline unknown code never decoded");
            else check(page.contains("error"),"offline reader enforces policy and exact marker");
            check(std::filesystem::remove(std::filesystem::u8path(path)),"unknown-code artifact removed");
        }
    }
    // A marker is legal only at the final raw record, never in an earlier page.
    {
        auto uncertain=rows[0];uncertain.reserved=kdtrace::kCodeUncertainRecord;
        uncertain.codeSize=0;std::memset(uncertain.code,0,sizeof(uncertain.code));
        std::string path;
        {
            KdCaptureStore store(2,kdtrace::kRunPeerCpus,0x1000,0x1002,"");
            check(store.Append(&uncertain,1,125,0)&&store.Append(rows,1,125,0),"write nonfinal unknown marker");
            store.Keep(false);path=store.Path();
        }
        check(ReadKdCapture({{"capture_file",path},{"limit",16}}).contains("error"),"nonfinal unknown marker rejected");
        check(std::filesystem::remove(std::filesystem::u8path(path)),"nonfinal marker artifact removed");
    }
    std::printf("PASS KD artifact short-body/header recovery and unknown-code boundaries (%d checks)\n",checks);
    return 0;
}
