// Exercise the actual artifact receivers with data queued before ConnectNamedPipe.
#include <windows.h>
#include <vector>
#include <array>
#include <cstring>
#include <string>
#include <filesystem>
#include <iostream>
#include <stdexcept>

static HANDLE ready = nullptr;
static std::wstring producerName;
static std::vector<uint8_t> producerBytes;
static DWORD connectError = 0, producerError = 0;
static BOOL InterceptConnect(HANDLE pipe, LPOVERLAPPED overlap);
#define ConnectNamedPipe InterceptConnect
#include "../src/mcp/trace_event_artifact.cpp"
#include "../src/mcp/trace_code_artifact.cpp"
#undef ConnectNamedPipe

static void Check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
static BOOL InterceptConnect(HANDLE pipe, LPOVERLAPPED overlap) {
    if (WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0) {
        producerError = ERROR_TIMEOUT; SetLastError(ERROR_TIMEOUT); return FALSE;
    }
    HANDLE writer = CreateFileW(producerName.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (writer == INVALID_HANDLE_VALUE) {
        producerError = GetLastError(); return FALSE;
    }
    DWORD written = 0;
    if (!producerBytes.empty() && (!WriteFile(writer, producerBytes.data(),
        static_cast<DWORD>(producerBytes.size()), &written, nullptr) || written != producerBytes.size()))
        producerError = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
    CloseHandle(writer); // deliberate close before the receiver's real connect
    const BOOL result = ::ConnectNamedPipe(pipe, overlap);
    connectError = result ? ERROR_SUCCESS : GetLastError();
    SetLastError(connectError);
    return result;
}
template<class T> static void Append(std::vector<uint8_t>& bytes, const T& value) {
    const auto* first = reinterpret_cast<const uint8_t*>(&value);
    bytes.insert(bytes.end(), first, first + sizeof(value));
}
template<class Header, class Payload> static void Frame(std::vector<uint8_t>& wire,
        uint32_t magic, uint64_t token, uint16_t type, uint64_t index, uint64_t offset, const Payload& payload) {
    Header header{};header.magic=magic;header.schemaVersion=1;header.token=token;
    header.type=type;header.chunkIndex=index;header.streamOffset=offset;
    header.payloadSize=sizeof(payload);header.payloadHash=veh::TraceCodePayloadHash(&payload,sizeof(payload));
    Append(wire,header);Append(wire,payload);
}
static void EventCase(unsigned mode, const std::filesystem::path& path) {
    veh::TraceEventArtifactReceiver receiver;
    Check(receiver.Start(path.u8string(),4096,65536),"start event receiver");
    producerName=veh::GetTraceEventPipeName(GetCurrentProcessId(),receiver.Token());
    producerBytes.clear();
    if(mode!=1) {
        struct {veh::TraceEventArtifactRecordHeader head;veh::TraceBasicBlockEventEntry event;} data{};
        data.head.type=static_cast<uint16_t>(veh::TraceEventRecordType::BasicBlock);
        data.head.payloadSize=sizeof(data.event);
        data.event.sequence=1;data.event.target=0x1000;data.event.threadId=77;
        data.event.type=veh::TraceBasicBlockEventType::BlockEntry;data.event.codeVersion=UINT32_MAX;
        Frame<veh::TraceEventStreamFrameHeader>(producerBytes,veh::kTraceEventStreamMagic,receiver.Token(),
            static_cast<uint16_t>(veh::TraceEventStreamFrameType::Data),0,0,data);
        veh::TraceEventStreamComplete complete{};
        complete.committedRecordBytes=sizeof(data);complete.basicBlockEventCount=1;complete.chunkCount=1;
        Frame<veh::TraceEventStreamFrameHeader>(producerBytes,veh::kTraceEventStreamMagic,receiver.Token(),
            static_cast<uint16_t>(veh::TraceEventStreamFrameType::Complete),1,sizeof(data),complete);
        if(mode==2)producerBytes.pop_back(); // incomplete completion
        if(mode==3)producerBytes.back()^=1;  // invalid completion hash/reserved byte
    }
    SetEvent(ready);
    auto result=receiver.Finish(true);
    Check(!producerError && connectError==ERROR_NO_DATA,"expected real event ERROR_NO_DATA race");
    Check(result.success==(mode==0),"event completion classification");
    if(mode==0) Check(result.captureComplete && result.sha256.size()==64 &&
        result.basicBlockEvents==1 && result.recordBytes==56 &&
        std::filesystem::file_size(path)==sizeof(veh::TraceEventArtifactHeader)+56,"valid event preserved");
    else Check(!result.captureComplete,"invalid event was published complete");
}
static void CodeCase(unsigned mode, const std::filesystem::path& path) {
    veh::TraceCodeArtifactReceiver receiver;
    Check(receiver.Start(path.u8string(),4096,4096,0x1000,0x1001),"start code receiver");
    producerName=veh::GetTraceCodePipeName(GetCurrentProcessId(),receiver.Token());
    producerBytes.clear();
    if(mode!=1) {
        std::array<uint8_t,sizeof(veh::TraceCodeArtifactRecord)+1> data{};
        data.back()=0xc3;
        veh::TraceCodeArtifactRecord record{};
        record.blockStart=0x1000;record.blockEnd=0x1001;record.id=1;record.size=1;
        record.firstSequence=1;record.dataOffset=sizeof(record);
        record.hash=veh::TraceCodePayloadHash(&data.back(),1);
        std::memcpy(data.data(),&record,sizeof(record));
        Frame<veh::TraceCodeStreamFrameHeader>(producerBytes,veh::kTraceCodeStreamMagic,receiver.Token(),
            static_cast<uint16_t>(veh::TraceCodeStreamFrameType::Data),0,0,data);
        veh::TraceCodeStreamComplete complete{};
        complete.committedRecordBytes=data.size();complete.codeByteCount=1;complete.versionCount=1;complete.chunkCount=1;
        Frame<veh::TraceCodeStreamFrameHeader>(producerBytes,veh::kTraceCodeStreamMagic,receiver.Token(),
            static_cast<uint16_t>(veh::TraceCodeStreamFrameType::Complete),1,data.size(),complete);
        if(mode==2)producerBytes.pop_back();
        if(mode==3)producerBytes.back()^=1;
    }
    SetEvent(ready);
    auto result=receiver.Finish(true);
    Check(!producerError && connectError==ERROR_NO_DATA,"expected real code ERROR_NO_DATA race");
    Check(result.success==(mode==0),"code completion classification");
    if(mode==0) Check(result.captureComplete && result.sha256.size()==64 &&
        result.codeBytes==1 && result.recordBytes==49 &&
        std::filesystem::file_size(path)==sizeof(veh::TraceCodeArtifactHeader)+49,"valid code preserved");
    else Check(!result.captureComplete && !std::filesystem::exists(path),"invalid code was published complete");
}
int main() {
    auto directory=std::filesystem::temp_directory_path()/
        ("veh-early-close-"+std::to_string(GetCurrentProcessId()));
    bool ownsDirectory=false;
    try {
        ownsDirectory=std::filesystem::create_directory(directory);
        Check(ownsDirectory,"unique test directory");
        for(unsigned mode=0;mode!=4;++mode) {
            ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);Check(ready!=nullptr,"test gate");
            connectError=producerError=0;
            EventCase(mode,directory/("event-"+std::to_string(mode)+".vte"));
            CloseHandle(ready);ready=nullptr;
            ready=CreateEventW(nullptr,TRUE,FALSE,nullptr);Check(ready!=nullptr,"test gate");
            connectError=producerError=0;
            CodeCase(mode,directory/("code-"+std::to_string(mode)+".vtc"));
            CloseHandle(ready);ready=nullptr;
        }
        std::filesystem::remove_all(directory);
        std::cout<<"PASS early-close artifact receivers: real ERROR_NO_DATA; valid completions preserved, empty/truncated/corrupt streams rejected\n";
        return 0;
    } catch(const std::exception& error) {
        if(ready)CloseHandle(ready);
        if(ownsDirectory)std::filesystem::remove_all(directory);
        std::cerr<<error.what()<<'\n';return 1;
    }
}
