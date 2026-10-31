#include "kd_capture_store.h"
#include "../adapter/disassembler.h"
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>

namespace veh {
namespace {
using json=nlohmann::json;
std::string Utf8(const std::wstring& s) {
    const int n=WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
    std::string out(n,0);if(n)WideCharToMultiByte(CP_UTF8,0,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr);return out;
}
std::wstring Wide(const std::string& s) {
    const auto error=ValidateKdCapturePath(s);
    if(!error.empty())throw std::runtime_error(error);
    const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!n)throw std::runtime_error("Invalid capture path encoding");
    std::wstring out(n,0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);return out;
}
std::string Hex(uint64_t n){char b[24];snprintf(b,sizeof(b),"0x%llX",static_cast<unsigned long long>(n));return b;}
std::string HashFile(HANDLE file,uint64_t remaining) {
    BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return {};
    DWORD size=0,n=0;std::string result;
    if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&size),sizeof(size),&n,0)>=0){
        std::vector<uint8_t> object(size),buffer(65536);
        if(BCryptCreateHash(alg,&hash,object.data(),size,nullptr,0,0)>=0){
            LARGE_INTEGER at={};
            DWORD read=0;bool ok=SetFilePointerEx(file,at,nullptr,FILE_BEGIN)!=FALSE;
            for(;ok;){if(!ReadFile(file,buffer.data(),static_cast<DWORD>((std::min)(uint64_t{buffer.size()},remaining)),&read,nullptr)){ok=false;break;}
                if(!read)break;remaining-=read;if(BCryptHashData(hash,buffer.data(),read,0)<0){ok=false;break;}}
            uint8_t digest[32];if(ok&&!remaining&&BCryptFinishHash(hash,digest,sizeof(digest),0)>=0){
                const char* digits="0123456789abcdef";for(auto value:digest){result+=digits[value>>4];result+=digits[value&15];}}
            BCryptDestroyHash(hash);
        }
    }
    BCryptCloseAlgorithmProvider(alg,0);return result;
}
bool HeaderValid(const kdtrace::CaptureFileHeader& h,uint64_t bytes) {
    return !std::memcmp(h.magic,"VEHKDTR2",8)&&h.version==1&&h.recordSize==sizeof(kdtrace::Record)&&
        !h.reserved&&!(h.flags&~kdtrace::kSnapshots)&&h.cpu<64&&h.records<=kdtrace::kMaxStreamSteps&&
        h.rangeStart<h.rangeEnd&&bytes>=sizeof(h)+h.records*sizeof(kdtrace::Record);
}
}
std::string ValidateKdCapturePath(const std::string& path,size_t maxBytes) {
    if(path.empty()||path.size()>maxBytes)return "Invalid capture path length";
    for(unsigned char value:path)if(value<32||value==127)
        return "Capture paths must not contain NUL or control characters";
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path.data(),static_cast<int>(path.size()),nullptr,0))
        return "Invalid capture path encoding";
    return {};
}
KdCaptureStore::KdCaptureStore(uint32_t steps,uint32_t flags,uint64_t start,uint64_t end,const std::string& output,KdCaptureWrite write):write_(write) {
    if(output.empty()){
        wchar_t folder[MAX_PATH+1],path[MAX_PATH+1];
        const auto n=GetTempPathW(MAX_PATH,folder);
        if(!n||n>=MAX_PATH)throw std::runtime_error("Cannot resolve capture storage directory");
        ULARGE_INTEGER free={};
        if(!GetDiskFreeSpaceExW(folder,&free,nullptr,nullptr)||
           free.QuadPart<static_cast<uint64_t>(steps)*sizeof(kdtrace::Record)+16*1024*1024)
            throw std::runtime_error("Insufficient capture storage space");
        if(!GetTempFileNameW(folder,L"vkd",0,path))throw std::runtime_error("Cannot create capture spool");
        wide_=path;file_=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_TEMPORARY,nullptr);
    }else{
        wide_=Wide(output+".records");file_=CreateFileW(wide_.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    }
    path_=Utf8(wide_);
    if(file_==INVALID_HANDLE_VALUE){if(output.empty())DeleteFileW(wide_.c_str());throw std::runtime_error("Cannot create capture artifact (an existing file is never overwritten)");}
    std::memcpy(header_.magic,"VEHKDTR2",8);header_.version=1;header_.recordSize=sizeof(kdtrace::Record);
    header_.flags=flags;header_.rangeStart=start;header_.rangeEnd=end;
    if(!WriteHeader()){CloseHandle(file_);file_=INVALID_HANDLE_VALUE;DeleteFileW(wide_.c_str());throw std::runtime_error("Cannot initialize capture artifact");}
}
KdCaptureStore::~KdCaptureStore(){
    if(view_)UnmapViewOfFile(view_);if(mapping_)CloseHandle(mapping_);
    if(file_!=INVALID_HANDLE_VALUE)CloseHandle(file_);
    if(!keep_&&!wide_.empty())DeleteFileW(wide_.c_str());
}
bool KdCaptureStore::WriteBytes(const void* data,DWORD bytes,DWORD* written){
    return write_?write_(file_,data,bytes,written)!=FALSE:WriteFile(file_,data,bytes,written,nullptr)!=FALSE;
}
bool KdCaptureStore::RepairPrefix(){
    const bool header=WriteHeader();
    LARGE_INTEGER end;end.QuadPart=sizeof(header_)+header_.records*sizeof(kdtrace::Record);
    const bool length=SetFilePointerEx(file_,end,nullptr,FILE_BEGIN)&&SetEndOfFile(file_);
    needsRepair_=!header||!length;return !needsRepair_;
}
bool KdCaptureStore::WriteHeader(){
    LARGE_INTEGER at={};DWORD wrote=0;
    return SetFilePointerEx(file_,at,nullptr,FILE_BEGIN)&&WriteBytes(&header_,sizeof(header_),&wrote)&&wrote==sizeof(header_);
}
bool KdCaptureStore::Append(const kdtrace::Record* records,uint32_t count,uint64_t generation,uint32_t cpu){
    if(view_||count>kdtrace::kCapacity||header_.records+count>kdtrace::kMaxStreamSteps||
       (header_.generation&&header_.generation!=generation)||cpu>=64)return false;
    LARGE_INTEGER at;at.QuadPart=sizeof(header_)+header_.records*sizeof(kdtrace::Record);
    DWORD wrote=0;const DWORD bytes=count*sizeof(kdtrace::Record);
    if(!SetFilePointerEx(file_,at,nullptr,FILE_BEGIN)||!WriteBytes(records,bytes,&wrote)||wrote!=bytes){needsRepair_=true;return false;}
    const auto old=header_;header_.records+=count;header_.generation=generation;header_.cpu=cpu;
    if(!WriteHeader()){header_=old;needsRepair_=true;return false;}
    return true;
}
bool KdCaptureStore::Map(){
    if(view_)return true;
    mapping_=CreateFileMappingW(file_,nullptr,PAGE_READONLY,0,0,nullptr);
    if(!mapping_)return false;
    view_=static_cast<const uint8_t*>(MapViewOfFile(mapping_,FILE_MAP_READ,0,0,0));
    return view_!=nullptr;
}
const kdtrace::Record& KdCaptureStore::operator[](size_t index)const{
    if(!view_||index>=size())throw std::out_of_range("Capture record index");
    return reinterpret_cast<const kdtrace::Record*>(view_+sizeof(header_))[index];
}
nlohmann::json KdCaptureStore::Keep(bool complete){
    // Preserve acknowledged chunks even when a later transport/disk operation fails.
    keep_=true;
    const bool repaired=!needsRepair_||RepairPrefix();
    const uint64_t validBytes=sizeof(header_)+header_.records*sizeof(kdtrace::Record);
    const bool flushed=FlushFileBuffers(file_)!=FALSE;
    const auto hash=flushed?HashFile(file_,validBytes):std::string{};
    LARGE_INTEGER physical={};const bool sizeKnown=GetFileSizeEx(file_,&physical)!=FALSE;
    json result={{"path",path_},{"schema","veh.kd.capture.v1"},{"record_size",sizeof(kdtrace::Record)},
        {"records",std::to_string(header_.records)},{"bytes",validBytes},{"valid_bytes",validBytes},
        {"physical_bytes",sizeKnown?json(physical.QuadPart):json(nullptr)},{"header_repaired",repaired},
        {"sha256",hash.empty()?json(nullptr):json(hash)},{"sha256_scope","valid_prefix"},
        {"complete",complete&&repaired&&flushed&&!hash.empty()&&sizeKnown&&uint64_t(physical.QuadPart)==validBytes}};
    if(!repaired)result["recovery"]={{"records",std::to_string(header_.records)},
        {"generation",std::to_string(header_.generation)},{"flags",header_.flags},{"cpu",header_.cpu},
        {"range_start",Hex(header_.rangeStart)},{"range_end",Hex(header_.rangeEnd)}};
    return result;
}
json ReadKdCapture(const json& args){
    const auto path=args.value("capture_file",std::string{});
    const auto pathError=ValidateKdCapturePath(path);
    if(!pathError.empty())return {{"error",pathError}};
    if(args.contains("limit")&&(!args["limit"].is_number_integer()||args["limit"]<1||args["limit"]>100))
        return {{"error","limit must be1-100"}};
    const uint32_t limit=args.value("limit",16u);
    uint64_t offset=0;try{const auto& v=args.contains("offset")?args["offset"]:json("0");
        if(v.is_string()){size_t used=0;const auto s=v.get<std::string>();if(s.empty()||s[0]=='-'||s[0]=='+')throw std::runtime_error("offset");
            offset=std::stoull(s,&used,10);if(used!=s.size())throw std::runtime_error("offset");}
        else if(v.is_number_unsigned())offset=v.get<uint64_t>();else throw std::runtime_error("offset");
    }catch(...){return {{"error","offset must be an exact nonnegative record index"}};}
    HANDLE file=CreateFileW(Wide(path).c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE)return {{"error","Cannot open capture artifact"}};
    struct Close{HANDLE f;~Close(){CloseHandle(f);}}close{file};
    kdtrace::CaptureFileHeader header={};DWORD read=0;LARGE_INTEGER size;
    if(!GetFileSizeEx(file,&size)||!ReadFile(file,&header,sizeof(header),&read,nullptr)||read!=sizeof(header))
        return {{"error","Cannot read capture artifact header"}};
    const bool recovering=args.contains("recovery");
    if(recovering){
        try{
            const auto& d=args["recovery"];
            auto exact=[](const json& v,int base){if(!v.is_string())throw std::runtime_error("exact string required");
                const auto s=v.get<std::string>();size_t used=0;if(s.empty()||s[0]=='-'||s[0]=='+')throw std::runtime_error("unsigned");
                const auto n=std::stoull(s,&used,base);if(used!=s.size())throw std::runtime_error("digits");return n;};
            header={};std::memcpy(header.magic,"VEHKDTR2",8);header.version=1;header.recordSize=sizeof(kdtrace::Record);
            header.records=exact(d.at("records"),10);header.generation=exact(d.at("generation"),10);
            for(const char* key:{"flags","cpu"})if(!d.at(key).is_number_integer()||d.at(key)<0||d.at(key)>UINT32_MAX)
                throw std::runtime_error("uint32 metadata");
            header.flags=d.at("flags").get<uint32_t>();header.cpu=d.at("cpu").get<uint32_t>();
            header.rangeStart=exact(d.at("range_start"),16);header.rangeEnd=exact(d.at("range_end"),16);
        }catch(...){return {{"error","Invalid committed-prefix recovery descriptor"}};}
    }
    if(!HeaderValid(header,size.QuadPart)||offset>header.records)return {{"error","Invalid capture artifact/offset"}};
    uint64_t begin=0,end=~uint64_t{0};
    for(const auto& item:{std::pair<const char*,uint64_t*>{"address_start",&begin},{"address_end",&end}})
        if(args.contains(item.first)){
            if(!args[item.first].is_string())return {{"error","Address filters must be hex strings"}};
            const auto s=args[item.first].get<std::string>();try{size_t used=0;*item.second=std::stoull(s,&used,16);if(used!=s.size()||s.empty()||s[0]=='-'||s[0]=='+')throw 1;}
            catch(...){return {{"error","Invalid capture address filter"}};}
        }
    if(begin>=end)return {{"error","address_start must be below address_end"}};
    const bool regs=args.value("include_registers",false);
    json rows=json::array();uint64_t at=offset;const uint64_t stop=(std::min)(header.records,offset+65536);
    auto dis64=CreateDisassembler(true),dis32=CreateDisassembler(false);
    for(;at<stop&&rows.size()<limit;++at){
        LARGE_INTEGER position;position.QuadPart=sizeof(header)+at*sizeof(kdtrace::Record);
        kdtrace::Record r={};
        if(!SetFilePointerEx(file,position,nullptr,FILE_BEGIN)||!ReadFile(file,&r,sizeof(r),&read,nullptr)||read!=sizeof(r))
            return {{"error","Capture artifact read failed"}};
        if(r.address<begin||r.address>=end)continue;
        if(!r.codeSize||r.codeSize>15||(r.addressBits!=32&&r.addressBits!=64)||r.cpu!=header.cpu||r.cpl>3||r.reserved)
            return {{"error","Malformed capture record"}};
        auto d=(r.addressBits==64?dis64:dis32)->Disassemble(r.code,r.codeSize,r.address,1);
        json row={{"sequence",std::to_string(at+1)},{"address",Hex(r.address)},{"next_address",Hex(r.nextAddress)},
            {"cr3",Hex(r.cr3)},{"cpu",r.cpu},{"cpl",r.cpl},{"address_bits",r.addressBits},
            {"thread_id",r.tid?json(r.tid):json(nullptr)},{"process_id",r.pid?json(r.pid):json(nullptr)}};
        if(!d.empty()){row["bytes"]=d[0].bytes;row["instruction"]=d[0].mnemonic;}
        if(regs){if(!(header.flags&kdtrace::kSnapshots))row["registers_available"]=false;else{
            json values=json::array();for(auto value:r.registers)values.push_back(Hex(value));row["registers"]=std::move(values);}}
        rows.push_back(std::move(row));
        if(rows.dump().size()>6144){rows.erase(rows.size()-1);break;}
    }
    json result={{"capture_file",path},{"records",rows},{"count",rows.size()},{"total_records",std::to_string(header.records)},
        {"examined",at-offset},{"next_offset",at<header.records?json(std::to_string(at)):json(nullptr)},
        {"scan_limited",at==stop&&at<header.records},{"generation",std::to_string(header.generation)},{"recovery_applied",recovering},{"integrity","not_checked"}};
    while(result.dump().size()>8192&&!result["records"].empty()){
        auto& output=result["records"];at=std::stoull(output.back()["sequence"].get<std::string>())-1;
        output.erase(output.size()-1);result["count"]=output.size();result["examined"]=at-offset;
        result["next_offset"]=std::to_string(at);result["scan_limited"]=false;
    }
    if(result.dump().size()>8192)return {{"error","KD capture page metadata exceeds the 8192-byte response limit"}};
    return result;
}
} // namespace veh
