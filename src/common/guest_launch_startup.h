#pragma once
#include <windows.h>
#include <sddl.h>
#include <bcrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

// Local host bootstrap only. Existing VEH IPC messages remain unchanged.
// This file is shared verbatim with the isolated frontend candidate.
namespace hvguest {
inline constexpr uint64_t kMagic=UINT64_C(0x3154524154534C47);
struct Header {
    uint64_t magic=kMagic,nonce=0;
    uint32_t version=1,size=0,flags=0,program_units=0,cwd_units=0,arguments=0,environment=0,reserved=0;
};
struct Result {
    uint64_t magic=kMagic,nonce=0,entry=0;
    uint32_t version=1,status=0,pid=0,tid=0,bits=0,reserved=0;
}; // status1: verified entry stop; 2: no child submitted; 3: outcome retained.
static_assert(sizeof(wchar_t)==2&&sizeof(Header)==48&&sizeof(Result)==48);
struct Request {Header header{};std::wstring program,cwd;std::vector<std::wstring> args,env;};
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle()=default;explicit Handle(HANDLE h):value(h){}
    ~Handle(){if(value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
inline void transfer(HANDLE file,bool write,void* data,DWORD size){
    DWORD done=0;
    const bool okay=write?WriteFile(file,data,size,&done,nullptr)!=FALSE:ReadFile(file,data,size,&done,nullptr)!=FALSE;
    if(!okay||done!=size)throw std::runtime_error("Guest startup file transfer incomplete");
}
struct Security {
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,FALSE};
    Security(){
        Handle token;HANDLE raw=nullptr;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))throw std::runtime_error("Guest startup token unavailable");
        token.value=raw;DWORD needed=0;GetTokenInformation(raw,TokenUser,nullptr,0,&needed);
        if(!needed||needed>65536)throw std::runtime_error("Guest startup user identity unavailable");
        std::vector<uint8_t> bytes(needed);
        if(!GetTokenInformation(raw,TokenUser,bytes.data(),needed,&needed))throw std::runtime_error("Guest startup user identity unavailable");
        LPWSTR sid=nullptr;
        if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid,&sid))
            throw std::runtime_error("Guest startup user SID unavailable");
        const std::wstring acl=L"D:P(A;;GA;;;SY)(A;;GA;;;"+std::wstring(sid)+L")";LocalFree(sid);
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,&descriptor,nullptr))
            throw std::runtime_error("Guest startup ACL unavailable");
        attributes.lpSecurityDescriptor=descriptor;
    }
    ~Security(){if(descriptor)LocalFree(descriptor);}
};
inline uint64_t nonce(){
    uint64_t n=0;
    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(&n),sizeof(n),BCRYPT_USE_SYSTEM_PREFERRED_RNG)||!n)
        throw std::runtime_error("Guest startup nonce unavailable");
    return n;
}
inline std::vector<uint8_t> encode(Request r){
    auto& h=r.header;if(!h.nonce||r.program.empty()||r.args.size()>4096||r.env.size()>4096||h.flags>1)
        throw std::runtime_error("Guest startup request invalid");
    h.program_units=static_cast<uint32_t>(r.program.size());h.cwd_units=static_cast<uint32_t>(r.cwd.size());
    h.arguments=static_cast<uint32_t>(r.args.size());h.environment=static_cast<uint32_t>(r.env.size());
    std::vector<uint8_t> out(sizeof(h));
    const auto text=[&](const std::wstring& value){
        if(value.size()>32766||value.find(L'\0')!=std::wstring::npos)throw std::runtime_error("Guest startup text invalid");
        const auto* p=reinterpret_cast<const uint8_t*>(value.data());out.insert(out.end(),p,p+value.size()*2);
    };
    text(r.program);text(r.cwd);
    for(const auto* list:{&r.args,&r.env})for(const auto& value:*list){
        const auto units=static_cast<uint32_t>(value.size());const auto* p=reinterpret_cast<const uint8_t*>(&units);
        out.insert(out.end(),p,p+4);text(value);
    }
    if(out.size()>256*1024)throw std::runtime_error("Guest startup request exceeds256KiB");
    h.size=static_cast<uint32_t>(out.size());std::memcpy(out.data(),&h,sizeof(h));return out;
}
inline Request decode(const std::vector<uint8_t>& bytes){
    Request r;auto& h=r.header;
    if(bytes.size()<sizeof(h)||bytes.size()>256*1024)throw std::runtime_error("Guest startup request size invalid");
    std::memcpy(&h,bytes.data(),sizeof(h));
    if(h.magic!=kMagic||h.version!=1||!h.nonce||h.size!=bytes.size()||h.flags>1||h.reserved||
       !h.program_units||h.arguments>4096||h.environment>4096)throw std::runtime_error("Guest startup request header invalid");
    size_t offset=sizeof(h);
    const auto text=[&](uint32_t units){
        if(units>32766||offset>bytes.size()||units>(bytes.size()-offset)/2)throw std::runtime_error("Guest startup field truncated");
        std::wstring s(units,L'\0');if(units)std::memcpy(s.data(),bytes.data()+offset,units*2);offset+=units*2;
        if(s.find(L'\0')!=std::wstring::npos)throw std::runtime_error("Guest startup field has NUL");return s;
    };
    r.program=text(h.program_units);r.cwd=text(h.cwd_units);
    for(auto* list:{&r.args,&r.env}){
        const auto count=list==&r.args?h.arguments:h.environment;
        for(uint32_t i=0;i<count;++i){
            uint32_t units=0;if(offset+4>bytes.size())throw std::runtime_error("Guest startup list truncated");
            std::memcpy(&units,bytes.data()+offset,4);offset+=4;list->push_back(text(units));
        }
    }
    if(offset!=bytes.size())throw std::runtime_error("Guest startup trailing bytes");
    return r;
}
inline void write_new(const std::filesystem::path& path,const void* data,DWORD size){
    Security security;
    Handle file(CreateFileW(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&security.attributes,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(file.value==INVALID_HANDLE_VALUE)throw std::runtime_error("Guest startup file creation refused");
    transfer(file.value,true,const_cast<void*>(data),size);
    if(!FlushFileBuffers(file.value))throw std::runtime_error("Guest startup file flush failed");
}
inline std::vector<uint8_t> read(const std::filesystem::path& path,uint32_t max){
    Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    if(file.value==INVALID_HANDLE_VALUE||!GetFileInformationByHandle(file.value,&info)||
       (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
       !GetFileSizeEx(file.value,&size)||size.QuadPart<=0||size.QuadPart>max)
        throw std::runtime_error("Guest startup file shape invalid");
    std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart));transfer(file.value,false,bytes.data(),static_cast<DWORD>(bytes.size()));return bytes;
}
inline std::filesystem::path temporary(){
    std::array<wchar_t,32768> buffer{};const auto count=GetTempPathW(static_cast<DWORD>(buffer.size()),buffer.data());
    if(!count||count>=buffer.size())throw std::runtime_error("Guest startup temporary directory unavailable");
    const auto n=nonce();wchar_t name[64]{};swprintf_s(name,L"hvguest-%016llx.req",static_cast<unsigned long long>(n));
    return std::filesystem::path(buffer.data())/name;
}
inline std::filesystem::path result_path(const std::filesystem::path& request){return std::filesystem::path(request.wstring()+L".result");}
inline Result read_result(const std::filesystem::path& path,uint64_t nonce_value){
    const auto bytes=read(result_path(path),sizeof(Result));Result result{};
    if(bytes.size()!=sizeof(result))throw std::runtime_error("Guest startup result truncated");std::memcpy(&result,bytes.data(),sizeof(result));
    if(result.magic!=kMagic||result.version!=1||result.nonce!=nonce_value||result.reserved||result.status<1||result.status>3||
       (result.status==1&&(!result.pid||!result.tid||(result.bits!=32&&result.bits!=64)||!result.entry))||
       (result.status==2&&(result.pid||result.tid||result.bits||result.entry)))
        throw std::runtime_error("Guest startup result identity invalid");
    return result;
}
}
