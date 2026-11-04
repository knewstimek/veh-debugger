#pragma once
// Host-only synthetic provider; does not qualify real hit-time collection.
#include "caller_capture_protocol.h"
#include <algorithm>
namespace callerfixture {
namespace cc=veh::callercapture;
class Capture {
    std::wstring mode;
    bool active=false;
    uint64_t id=0, nextId=9007199254740993ULL;
    cc::StartRequest config{};
public:
    explicit Capture(const std::wstring& value):mode(value){}
    bool enabled()const{return mode.rfind(L"cc-",0)==0||mode==L"ops-action-callers";}
    bool handles(veh::IpcCommand op)const {
        return enabled()&&op>=veh::IpcCommand::QueryCallerCapture&&op<=veh::IpcCommand::ReadCallerCapture;
    }
    bool handle(HANDLE pipe,uint32_t command,const std::vector<unsigned char>& bytes) {
        const auto op=static_cast<veh::IpcCommand>(command);
        if(op==veh::IpcCommand::QueryCallerCapture) {
            cc::QueryRequest request{};
            if(bytes.size()!=sizeof(request))return reply(pipe,command,veh::IpcStatus::InvalidArgs);
            std::memcpy(&request,bytes.data(),sizeof(request));
            if(request.version!=cc::kVersion)return reply(pipe,command,veh::IpcStatus::Unsupported);
            cc::QueryResponse q{};q.status=veh::IpcStatus::Ok;q.version=1;
            q.features=cc::kFeatures;q.maxStackBytes=4096;q.maxRecords=65536;
            q.maxBufferBytes=cc::kMaxBufferBytes;q.maxPageBytes=65536;q.maxFilters=8;
            q.clock=cc::Clock::Tsc;q.clockFrequency=0;q.currentTraceId=id;
            strcpy_s(q.provider,"synthetic-entry");strcpy_s(q.reason,"host fixture only");
            if(mode==L"cc-query-version")q.version=2;
            if(mode==L"cc-query-limits")q.maxPageBytes=65537;
            if(mode==L"cc-query-clock")q.clock=cc::Clock::None;
            if(mode==L"cc-no-filters"){q.features&=~cc::Filters;q.maxFilters=0;}
            if(mode==L"cc-no-x64")q.features&=~cc::X64;
            if(mode==L"cc-low-limit"){q.maxStackBytes=16;q.maxRecords=2;q.maxBufferBytes=1024;}
            if(mode==L"cc-change-export"){q.maxStackBytes=256;q.maxPageBytes=808;}
            return send(pipe,command,&q,mode==L"cc-query-short"?4:sizeof(q));
        }
        uint64_t trace=0,cursor=0;uint32_t maximum=0,maxBytes=65536;
        if(op==veh::IpcCommand::StartCallerCapture) {
            cc::StartRequest r{};
            if(bytes.size()!=sizeof(r))return reply(pipe,command,veh::IpcStatus::InvalidArgs);
            std::memcpy(&r,bytes.data(),sizeof(r));
            if(r.version!=1)return reply(pipe,command,veh::IpcStatus::Unsupported);
            if(active)return reply(pipe,command,veh::IpcStatus::InvalidState);
            config=r;if(mode!=L"cc-reused-id"||!id)id=++nextId;active=true;
            if(mode==L"cc-auto-stop")active=false;
            trace=id;
        } else if(op==veh::IpcCommand::StopCallerCapture) {
            cc::StopRequest r{};
            if(bytes.size()!=sizeof(r))return reply(pipe,command,veh::IpcStatus::InvalidArgs);
            std::memcpy(&r,bytes.data(),sizeof(r));trace=r.traceId;
            if(trace==id)active=false;
        } else {
            cc::ReadRequest r{};
            if(bytes.size()!=sizeof(r))return reply(pipe,command,veh::IpcStatus::InvalidArgs);
            std::memcpy(&r,bytes.data(),sizeof(r));trace=r.traceId;cursor=r.cursor;
            maximum=r.maxRecords;maxBytes=r.maxBytes;
            if(active&&maximum)return reply(pipe,command,veh::IpcStatus::InvalidState);
        }
        if(!id||id!=trace)return reply(pipe,command,veh::IpcStatus::NotFound);
        cc::Response h{};h.status=veh::IpcStatus::Ok;h.version=1;h.traceId=id;h.config=config;
        h.flags=active?cc::Active:0;h.stopReason=active?cc::StopReason::Active:cc::StopReason::User;
        const uint64_t limit=mode==L"cc-large"?32:3;
        h.totalRecords=(std::min)(uint64_t(config.bufferRecords),limit);
        h.totalRecords=(std::min)(h.totalRecords,uint64_t(config.bufferBytes)/(sizeof(cc::Record)+config.stackBytes));
        if(config.maxHits)h.totalRecords=(std::min)(h.totalRecords,config.maxHits);
        h.matchedHits=h.totalRecords;h.filteredHits=config.filterCount?7:0;
        h.clock=cc::Clock::Tsc;
        if(mode==L"cc-auto-stop"){h.stopReason=cc::StopReason::MaxHits;h.matchedHits=config.maxHits;}
        if(mode==L"cc-partial"||mode==L"cc-unreadable")h.flags|=cc::Incomplete;
        if((mode==L"cc-loss"||mode==L"cc-unknown-loss")&&!active) {
            h.flags|=cc::Incomplete|cc::Overflow;h.stopReason=cc::StopReason::Buffer;
            h.lostRecords=mode==L"cc-unknown-loss"?UINT64_MAX:1;h.matchedHits+=1;
        }
        if(mode==L"cc-unknown-filtered")h.filteredHits=UINT64_MAX;
        if(cursor>h.totalRecords)return reply(pipe,command,veh::IpcStatus::InvalidArgs);
        h.cursor=cursor;
        std::vector<unsigned char> payload;
        while(h.count<maximum&&cursor+h.count<h.totalRecords) {
            cc::Record r{};r.flags=cc::CallerValid|cc::TimestampValid;
            r.sequence=cursor+h.count+1;r.timestamp=9007199254741000ULL+r.sequence;
            r.pid=424242;r.tid=77;r.cpu=static_cast<uint32_t>(r.sequence%2);
            r.addressBits=mode==L"cc-x86"?32:64;r.validRegisters=cc::kRegisterMask;
            r.functionAddress=config.address;r.callerAddress=0x2000;
            r.registers[cc::Rip]=config.address;r.registers[cc::Rsp]=0x3000;
            r.registers[cc::Rbp]=0x3080;r.registers[cc::Rcx]=0x1234;r.registers[cc::Rflags]=0x202;
            r.stackRequested=r.stackCaptured=config.stackBytes;
            r.stackStatus=config.stackBytes?cc::StackStatus::Complete:cc::StackStatus::NotRequested;
            if(mode==L"cc-partial"&&r.sequence==2&&config.stackBytes>16){r.stackCaptured=16;r.stackStatus=cc::StackStatus::Partial;}
            if(mode==L"cc-unreadable"&&config.stackBytes){r.stackCaptured=0;r.stackStatus=cc::StackStatus::Unreadable;}
            r.recordBytes=sizeof(r)+r.stackCaptured;
            if(sizeof(h)+payload.size()+r.recordBytes>maxBytes)break;
            if(mode==L"cc-filter-mismatch")r.registers[cc::Rcx]=0x9999;
            if(mode==L"cc-bad-sequence")++r.sequence;
            if(mode==L"cc-bad-registers")r.validRegisters&=~(1u<<cc::Rsp);
            if(mode==L"cc-bad-width"){r.addressBits=32;r.registers[cc::Rcx]=UINT64_MAX;}
            if(mode==L"cc-stack-wrap")r.registers[cc::Rsp]=UINT64_MAX-8;
            if(mode==L"cc-bad-stack")++r.stackCaptured;
            if(mode==L"cc-no-timestamp"){r.flags&=~cc::TimestampValid;r.timestamp=0;}
            const auto offset=payload.size();payload.resize(offset+sizeof(r)+r.stackCaptured);
            std::memcpy(payload.data()+offset,&r,sizeof(r));
            for(uint32_t i=0;i<r.stackCaptured;++i)payload[offset+sizeof(r)+i]=static_cast<unsigned char>(i);
            ++h.count;
        }
        h.nextCursor=cursor+h.count;h.payloadBytes=static_cast<uint32_t>(payload.size());
        if(mode==L"cc-bad-config")++h.config.durationMs;
        if(mode==L"cc-change-export"&&cursor)++h.config.durationMs;
        if(mode==L"cc-bad-cursor")++h.nextCursor;
        if(mode==L"cc-bad-count")++h.count;
        std::vector<unsigned char> result(sizeof(h)+payload.size());
        std::memcpy(result.data(),&h,sizeof(h));
        if(!payload.empty())std::memcpy(result.data()+sizeof(h),payload.data(),payload.size());
        return send(pipe,command,result.data(),mode==L"cc-reply-short"?4:static_cast<uint32_t>(result.size()));
    }
};
}
