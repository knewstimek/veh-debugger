// Host-only protocol fixture. Never injected into or installed in a guest.
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include "ipc_protocol.h"
#include "startup_diagnostics.h"

bool transfer(HANDLE pipe, bool writing, void* bytes, DWORD size) {
    auto* next = static_cast<unsigned char*>(bytes);
    while (size) {
        DWORD done = 0;
        const BOOL ok = writing ? WriteFile(pipe, next, size, &done, nullptr) : ReadFile(pipe, next, size, &done, nullptr);
        if (!ok || !done) return false;
        next += done; size -= done;
    }
    return true;
}
bool send(HANDLE pipe, uint32_t command, const void* bytes, uint32_t size) {
    veh::IpcHeader header{command, size};
    return transfer(pipe, true, &header, sizeof(header)) &&
        (!size || transfer(pipe, true, const_cast<void*>(bytes), size));
}
template<class T> bool reply(HANDLE pipe, uint32_t command, const T& value) { return send(pipe, command, &value, sizeof(value)); }

int wmain(int argc, wchar_t** argv) {
    std::wstring name, mode, readyEvent;
    uint32_t pid = 0;bool pidProvided=false;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring option = argv[i];
        if (option == L"--pid"){pid = std::stoul(argv[i + 1]);pidProvided=true;}
        else if (option == L"--pipe") name = argv[i + 1];
        else if (option == L"--metadata") mode = argv[i + 1];
        else if (option == L"--ready-event") readyEvent = argv[i + 1];
    }
    if (mode == L"diagnostic-driver" || mode == L"diagnostic-abi") {
        const bool driver = mode == L"diagnostic-driver";
        veh::ReportStartupFailure(driver ? veh::StartupError::BackendUnavailable : veh::StartupError::VersionMismatch,
            driver ? veh::StartupDetail::DriverOpenFailed : veh::StartupDetail::AbiMismatch, driver ? ERROR_ACCESS_DENIED : 0);
        return 10; // deliberately identical exit codes: classification comes from the record
    }
    if (mode == L"diagnostic-invalid") {
        wchar_t value[32]{};
        if (GetEnvironmentVariableW(veh::kStartupDiagnosticHandle, value, 32)) {
            HANDLE diagnostic = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(_wcstoui64(value, nullptr, 10)));
            veh::StartupDiagnostic record; record.version = 99;
            DWORD written = 0; WriteFile(diagnostic, &record, sizeof(record), &written, nullptr);
            CloseHandle(diagnostic);
        }
        return 10;
    }
    if (mode == L"early-exit") return 37;
    const bool machineMode=mode.rfind(L"machine",0)==0;
    const bool vmMode=mode.rfind(L"vm",0)==0||machineMode;uint32_t vmState=2,detachFailures=0;
    uint32_t continueRequests = 0, pauseRequests = 0, resolveRequests = 0;
    uint32_t fixtureBreakpointId = 0, shellcodeRequests=0, localThreadQueries=0;
    const bool deferredMode=mode.rfind(L"deferred-",0)==0;
    bool deferredGuard=false,moduleHeld=false,exceptionHeld=false;
    uint32_t moduleHeldTid=77,deferredStopQueries=0;
    uint32_t deferredResolves=0,deferredSets=0,deferredResumes=0,deferredRemoves=0,deferredId=0,deferredContinueCalls=0;
    if ((!pid&&!machineMode)||name.empty()||(machineMode&&pidProvided)) return 2;
    HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 3;
    if (!readyEvent.empty()) {
        HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyEvent.c_str());
        if (!event) { CloseHandle(pipe); return 5; }
        const BOOL signaled = SetEvent(event); CloseHandle(event);
        if (!signaled) { CloseHandle(pipe); return 5; }
    }
    if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(pipe); return 4; }
    if (mode == L"ready-exit") { Sleep(100); CloseHandle(pipe); return 0; }
    auto emitDeferredLoad=[&](bool force=false){
        const bool initialOnly=mode==L"deferred-queued-release"||mode==L"deferred-queued-new"||
            mode==L"deferred-terminate-old"||mode==L"deferred-exit-old";
        if(!force&&(mode==L"deferred-user-stop"||initialOnly)){
            exceptionHeld=true;
            veh::ExceptionEvent e{};e.threadId=88;e.exceptionCode=0xc0000005;e.address=0x3000;
            if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ExceptionOccurred),e))return false;
        }
        if(!force&&initialOnly)return true;
        if(deferredGuard){
            moduleHeld=true;
            moduleHeldTid=(mode==L"deferred-terminate-old"||mode==L"deferred-exit-old")?88u:77u;
            if(force&&(mode==L"deferred-terminate-old"||mode==L"deferred-exit-old")){
                const veh::ThreadEvent created{88};
                if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ThreadCreated),created))return false;
            }
            veh::ModuleLoadStopEvent e{0x1000,0x1000,moduleHeldTid};
            strcpy_s(e.name,mode==L"deferred-external"?"other.dll":mode==L"deferred-prefix"?"prefix-sample.dll":"sample.dll");
            return reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ModuleLoadStopped),e);
        }
        veh::ModuleEvent e{};e.module.baseAddress=0x1000;strcpy_s(e.module.name,"sample.dll");
        return reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ModuleLoaded),e);
    };
    send(pipe, static_cast<uint32_t>(veh::IpcEvent::Ready), nullptr, 0);
    for (;;) {
        veh::IpcHeader header{};
        if (!transfer(pipe, false, &header, sizeof(header)) || header.payloadSize > 65536) break;
        std::vector<unsigned char> bytes(header.payloadSize);
        if (!bytes.empty() && !transfer(pipe, false, bytes.data(), header.payloadSize)) break;
        const auto command = static_cast<veh::IpcCommand>(header.command);
        if (command == veh::IpcCommand::GetCapabilities) {
            if (mode == L"cap-exit") ExitProcess(0xC0000135U);
            veh::GetCapabilitiesResponse caps{};
            caps.status = veh::IpcStatus::Ok; caps.backend = veh::IpcBackend::Hypervisor;
            caps.flags = veh::kCapNoTargetFootprint | (mode == L"host-cap" ? 0 : machineMode ? veh::kCapVirtualMachineTarget : veh::kCapGuestTarget);
            if(mode==L"machine-guest-cap")caps.flags=veh::kCapNoTargetFootprint|veh::kCapGuestTarget;
            for (auto op : {veh::IpcCommand::GetCapabilities, veh::IpcCommand::GetTargetInfo, veh::IpcCommand::GetThreads,
                            veh::IpcCommand::ReadMemory, veh::IpcCommand::Heartbeat, veh::IpcCommand::Detach})
                veh::SetCommandSupported(caps.commands, op);
            if(mode.rfind(L"modules-",0)==0||mode.rfind(L"reply-",0)==0) // modes that serve GetModules advertise it
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::GetModules);
            if(vmMode) {
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::GetProcesses);
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::ControlVirtualMachine);
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::TraceVirtualCpu);
            }
            if(deferredMode){
                for(auto op:{veh::IpcCommand::ResolveFunction,veh::IpcCommand::SetBreakpoint,
                    veh::IpcCommand::RemoveBreakpoint,veh::IpcCommand::Continue,veh::IpcCommand::TerminateThread})veh::SetCommandSupported(caps.commands,op);
                if(mode!=L"deferred-no-query")veh::SetCommandSupported(caps.commands,veh::IpcCommand::IsThreadStopped);
                if(mode!=L"deferred-unsupported")veh::SetCommandSupported(caps.commands,veh::IpcCommand::SetModuleLoadStop);
            }
            if(mode.rfind(L"shellcode-",0)==0)veh::SetCommandSupported(caps.commands,veh::IpcCommand::ExecuteShellcode);
            if(mode==L"shellcode-action")for(auto op:{veh::IpcCommand::SetBreakpoint,veh::IpcCommand::RemoveBreakpoint,veh::IpcCommand::Continue})veh::SetCommandSupported(caps.commands,op);
            if(mode.rfind(L"control-",0)==0) {
                for(auto op:{veh::IpcCommand::Continue,veh::IpcCommand::Pause,veh::IpcCommand::StepInto,
                    veh::IpcCommand::StepOver,veh::IpcCommand::StepOut,veh::IpcCommand::WriteMemory,veh::IpcCommand::TerminateThread})
                    veh::SetCommandSupported(caps.commands,op);
            }
            if(mode.rfind(L"stack-",0)==0 || mode.rfind(L"control-",0)==0) {
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::GetStackTrace);
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::GetRegisters);
            }
            if(mode==L"address-delay")veh::SetCommandSupported(caps.commands,veh::IpcCommand::ResolveAddressSpace);
            if (mode == L"trace") {
                for (auto op : {veh::IpcCommand::Continue, veh::IpcCommand::Pause, veh::IpcCommand::TraceCallers})
                    veh::SetCommandSupported(caps.commands, op);
            }
            if (mode == L"bp-kinds") {
                for (auto op : {veh::IpcCommand::SetBreakpoint, veh::IpcCommand::RemoveBreakpoint,
                               veh::IpcCommand::SetHwBreakpoint, veh::IpcCommand::RemoveHwBreakpoint,
                               veh::IpcCommand::Continue})
                    veh::SetCommandSupported(caps.commands, op);
            }
            if (mode == L"delayed-trace") veh::SetCommandSupported(caps.commands, veh::IpcCommand::TraceCallers);
            strcpy_s(caps.name, "synthetic-guest");
            if (!reply(pipe, header.command, caps)) break;
        } else if (command == veh::IpcCommand::GetTargetInfo) {
            veh::GetTargetInfoResponse info{veh::IpcStatus::Ok, veh::IpcTargetScope::Guest, pid, 32};
            if(machineMode){info.scope=veh::IpcTargetScope::VirtualMachine;info.pid=0;info.addressBits=0;}
            if(mode==L"machine-wrong-pid")info.pid=1;
            if(mode==L"machine-bad-width")info.addressBits=64;
            if(mode==L"machine-wrong-scope")info.scope=veh::IpcTargetScope::Guest;
            if (mode == L"wrong-pid") ++info.pid;
            if (mode == L"bad-width") info.addressBits = 16;
            if (mode == L"wrong-scope") info.scope = veh::IpcTargetScope::Host;
            if (mode == L"not-found") { info = {}; info.status = veh::IpcStatus::NotFound; }
            if (!send(pipe, header.command, &info, (mode == L"truncated"||mode==L"machine-truncated") ? 8 : sizeof(info))) break;
        } else if(deferredMode && command==veh::IpcCommand::IsThreadStopped){
            ++deferredStopQueries;
            if(mode==L"deferred-query-error"){if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
            if(mode==L"deferred-query-short"){if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;continue;}
            veh::IsThreadStoppedRequest request{};
            if(bytes.size()!=sizeof(request))break;
            std::memcpy(&request,bytes.data(),sizeof(request));
            veh::IsThreadStoppedResponse response{veh::IpcStatus::Ok,
                static_cast<uint8_t>((moduleHeld&&request.threadId==moduleHeldTid)||(exceptionHeld&&request.threadId==88))};
            if(!reply(pipe,header.command,response))break;
            if(!response.stopped&&mode==L"deferred-queued-release"){
                veh::ModuleEvent unloaded{};unloaded.module.baseAddress=0x1000;
                strcpy_s(unloaded.module.name,"sample.dll");
                if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ModuleUnloaded),unloaded))break;
            }
        } else if(deferredMode && command==veh::IpcCommand::TerminateThread){
            exceptionHeld=false;
            if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
            if(mode==L"deferred-terminate-old"&&!emitDeferredLoad(true))break;
        } else if (deferredMode && command==veh::IpcCommand::SetModuleLoadStop) {
            veh::SetModuleLoadStopRequest request{};
            if(bytes.size()!=sizeof(request)){if(!reply(pipe,header.command,veh::IpcStatus::InvalidArgs))break;continue;}
            std::memcpy(&request,bytes.data(),sizeof(request));
            const std::string pattern(request.name,strnlen(request.name,sizeof(request.name)));
            if(request.action==0&&pattern=="sample.dll")deferredGuard=true;
            else if(request.action==1&&pattern=="sample.dll")deferredGuard=false;
            else {if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
            if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
        } else if(deferredMode && command==veh::IpcCommand::ResolveFunction) {
            ++deferredResolves;
            const bool stale=mode==L"deferred-stale"&&deferredResolves==1;
            const bool resident=(moduleHeld&&mode!=L"deferred-prefix")||stale;
            veh::ResolveFunctionResponse response{resident?veh::IpcStatus::Ok:veh::IpcStatus::NotFound,
                resident?0x1100ull:0ull};
            if(!reply(pipe,header.command,response))break;
            if(deferredResolves==1&&!stale&&!emitDeferredLoad())break;
        } else if(deferredMode && command==veh::IpcCommand::SetBreakpoint) {
            ++deferredSets;
            if(!moduleHeld||(mode==L"deferred-reject"&&deferredSets==1)){
                if(!reply(pipe,header.command,veh::IpcStatus::Error))break;
                if(!moduleHeld&&mode==L"deferred-stale"&&!emitDeferredLoad())break;
                continue;
            }
            if((mode==L"deferred-during"||mode==L"deferred-same-tid")&&deferredSets==1){
                exceptionHeld=true;
                veh::ExceptionEvent e{};e.threadId=mode==L"deferred-same-tid"?77:88;e.exceptionCode=0xc0000005;e.address=0x3000;
                if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ExceptionOccurred),e))break;
            }
            deferredId=9000;
            if(!reply(pipe,header.command,veh::SetBreakpointResponse{veh::IpcStatus::Ok,deferredId}))break;
        } else if(deferredMode && command==veh::IpcCommand::RemoveBreakpoint) {
            ++deferredRemoves;deferredId=0;
            if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
        } else if(deferredMode && command==veh::IpcCommand::Continue){
            ++deferredContinueCalls;
            veh::ContinueRequest request{};
            if(bytes.size()!=sizeof(request))break;
            std::memcpy(&request,bytes.data(),sizeof(request));
            if(!request.wantDetails){if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
            if(mode==L"deferred-retained"&&deferredContinueCalls==1){
                struct {veh::ContinueResponse head;uint32_t tid;} held{{veh::IpcStatus::Ok,0,1},77};
                if(!reply(pipe,header.command,held))break;
                continue;
            }
            const bool released=mode==L"deferred-queued-release";
            const bool newer=mode==L"deferred-queued-new";
            if(released&&!emitDeferredLoad(true))break; // old hold delivered inside foreground exchange
            std::vector<uint32_t> resumed,remaining;
            if(moduleHeld&&(request.threadId==0||request.threadId==moduleHeldTid)){
                resumed.push_back(moduleHeldTid);moduleHeld=false;deferredId=0;
            }else if(moduleHeld)remaining.push_back(moduleHeldTid);
            if(exceptionHeld&&(request.threadId==0||request.threadId==88)){resumed.push_back(88);exceptionHeld=false;}
            else if(exceptionHeld)remaining.push_back(88);
            if(newer){
                if(!emitDeferredLoad(true))break; // genuine new hold before the reply
                remaining.push_back(moduleHeldTid);
            }
            ++deferredResumes;
            veh::ContinueResponse head{veh::IpcStatus::Ok,static_cast<uint32_t>(resumed.size()),static_cast<uint32_t>(remaining.size())};
            std::vector<uint8_t> wire(sizeof(head)+(resumed.size()+remaining.size())*sizeof(uint32_t));
            std::memcpy(wire.data(),&head,sizeof(head));
            size_t offset=sizeof(head);
            for(auto tid:resumed){std::memcpy(wire.data()+offset,&tid,sizeof(tid));offset+=sizeof(tid);}
            for(auto tid:remaining){std::memcpy(wire.data()+offset,&tid,sizeof(tid));offset+=sizeof(tid);}
            if(!send(pipe,header.command,wire.data(),static_cast<uint32_t>(wire.size())))break;
        } else if (mode.rfind(L"control-",0)==0 &&
            (command==veh::IpcCommand::Continue || command==veh::IpcCommand::Pause ||
             command==veh::IpcCommand::StepInto || command==veh::IpcCommand::StepOver ||
             command==veh::IpcCommand::StepOut || command==veh::IpcCommand::WriteMemory ||
             command==veh::IpcCommand::TerminateThread)) {
            if(mode==L"control-exit")break; // no reply: transport failure
            if(mode==L"control-error"){if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
            if(mode==L"control-short"){const uint8_t shortReply=0;if(!reply(pipe,header.command,shortReply))break;continue;}
            if(mode==L"control-long"){const uint64_t longReply=0;if(!reply(pipe,header.command,longReply))break;continue;}
            if(command==veh::IpcCommand::Continue){
                veh::ContinueRequest request{};
                if(bytes.size()!=sizeof(request)){if(!reply(pipe,header.command,veh::IpcStatus::InvalidArgs))break;continue;}
                std::memcpy(&request,bytes.data(),sizeof(request));
                if(!request.wantDetails){if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
                struct {veh::ContinueResponse head;uint32_t ids[2];} response{};
                response.head={veh::IpcStatus::Ok,mode==L"control-retained"?0u:1u,
                    (mode==L"control-partial"||mode==L"control-retained")?1u:0u};
                response.ids[0]=77;response.ids[1]=88;
                if(!send(pipe,header.command,&response,sizeof(response.head)+4*(response.head.resumedCount+response.head.stillStoppedCount)))break;
            }else{
                if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
                if(command==veh::IpcCommand::Pause){
                    const uint32_t actualThread=88;
                    if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::Paused),actualThread))break;
                }else if(command==veh::IpcCommand::StepInto||command==veh::IpcCommand::StepOver||command==veh::IpcCommand::StepOut){
                    const veh::StepCompletedEvent stopped{77,0x1234};
                    if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::StepCompleted),stopped))break;
                }
            }
        } else if ((mode.rfind(L"stack-",0)==0 || mode.rfind(L"control-",0)==0) &&
                   command==veh::IpcCommand::GetStackTrace) {
            if(mode==L"stack-exit")break;
            if(mode==L"stack-error"){if(!reply(pipe,header.command,veh::IpcStatus::Error))break;continue;}
            if(mode==L"stack-status-ok"){if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;continue;}
            struct {veh::GetStackTraceResponse head;veh::StackFrameInfo frame;} response{};
            response.head.status=veh::IpcStatus::Ok;
            response.head.count=mode==L"stack-empty"?0u:mode==L"stack-short"?2u:1u;
            response.head.totalFrames=response.head.count;
            response.frame.address=0x1234;response.frame.frameBase=0x8000;
            strcpy_s(response.frame.moduleName,"sample.dll");
            strcpy_s(response.frame.functionName,"SampleFunction");
            strcpy_s(response.frame.sourceFile,"sample.cpp");
            if(mode==L"stack-name")std::memset(response.frame.functionName,'A',sizeof(response.frame.functionName));
            if(!send(pipe,header.command,&response,mode==L"stack-empty"?sizeof(response.head):sizeof(response)))break;
        } else if ((mode.rfind(L"stack-",0)==0 || mode.rfind(L"control-",0)==0) &&
                   command==veh::IpcCommand::GetRegisters) {
            veh::GetRegistersResponse response{};
            response.status=veh::IpcStatus::Ok;response.regs.rip=0x1234;response.regs.is32bit=1;
            if(!reply(pipe,header.command,response))break;
        } else if(mode==L"address-delay" && command==veh::IpcCommand::ResolveAddressSpace){
            if(resolveRequests++==0)Sleep(31000); // longer than the old 30s guest-pipe floor
            struct {veh::ResolveAddressSpaceResponse head;veh::AddressSpaceCandidate candidate;} response{};
            response.head.status=veh::IpcStatus::Ok;response.head.count=1;response.head.chosen=0;
            response.head.inUse=0x22000;response.candidate={0x22000,veh::AddressSpaceMethod::Scan,1};
            if(!reply(pipe,header.command,response))break;
        } else if(mode.rfind(L"shellcode-",0)==0 && command==veh::IpcCommand::ExecuteShellcode){
            ++shellcodeRequests;
            if(mode==L"shellcode-drop")break;
            if(mode==L"shellcode-state"||mode==L"shellcode-action"){
                if(!reply(pipe,header.command,veh::IpcStatus::InvalidState))break;
            }else if(mode==L"shellcode-error"){
                if(!reply(pipe,header.command,veh::IpcStatus::Error))break;
            }else if(mode==L"shellcode-unknown"){
                if(!reply(pipe,header.command,static_cast<veh::IpcStatus>(99)))break;
            }else if(mode==L"shellcode-short"){
                if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
            }else{
                veh::ExecuteShellcodeResponse response{};
                response.status=mode==L"shellcode-state-full"?veh::IpcStatus::InvalidState:veh::IpcStatus::Ok;
                response.exitCode=7;
                if(!reply(pipe,header.command,response))break;
            }
        } else if(mode==L"shellcode-action"&&command==veh::IpcCommand::SetBreakpoint){
            fixtureBreakpointId=9001;
            if(!reply(pipe,header.command,veh::SetBreakpointResponse{veh::IpcStatus::Ok,fixtureBreakpointId}))break;
        } else if(mode==L"shellcode-action"&&command==veh::IpcCommand::RemoveBreakpoint){
            if(!reply(pipe,header.command,veh::IpcStatus::Ok))break;
        } else if(mode==L"shellcode-action"&&command==veh::IpcCommand::Continue){
            veh::ContinueRequest request{};
            if(bytes.size()!=sizeof(request))break;
            std::memcpy(&request,bytes.data(),sizeof(request));
            if(request.wantDetails&&!reply(pipe,header.command,veh::ContinueResponse{veh::IpcStatus::Ok,0,0}))break;
            const veh::BreakpointHitEvent hit{77,++continueRequests==1?fixtureBreakpointId:7u,0x1000,{}};
            if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::BreakpointHit),hit))break;
        } else if (mode == L"bp-kinds" && command == veh::IpcCommand::SetHwBreakpoint) {
            fixtureBreakpointId = 1; // external backends need not reserve the DLL ID range
            const veh::SetHwBreakpointResponse response{veh::IpcStatus::Ok, fixtureBreakpointId, 0};
            if (!reply(pipe, header.command, response)) break;
        } else if (mode == L"bp-kinds" && command == veh::IpcCommand::SetBreakpoint) {
            fixtureBreakpointId = 20001; // a high software ID is equally valid
            const veh::SetBreakpointResponse response{veh::IpcStatus::Ok, fixtureBreakpointId};
            if (!reply(pipe, header.command, response)) break;
        } else if (mode == L"bp-kinds" && (command == veh::IpcCommand::RemoveHwBreakpoint ||
                                          command == veh::IpcCommand::RemoveBreakpoint)) {
            fixtureBreakpointId = 0;
            if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
        } else if (mode == L"bp-kinds" && command == veh::IpcCommand::Continue) {
            const veh::ContinueResponse response{veh::IpcStatus::Ok, 0, 0};
            if (!reply(pipe, header.command, response)) break;
            veh::BreakpointHitEvent event{};
            event.threadId = 77; event.address = 0x1000;
            event.breakpointId = fixtureBreakpointId ? fixtureBreakpointId : 7;
            if (!send(pipe, static_cast<uint32_t>(veh::IpcEvent::BreakpointHit), &event, sizeof(event))) break;
        } else if (mode == L"reply-errors" &&
                   (command == veh::IpcCommand::GetThreads || command == veh::IpcCommand::GetModules)) {
            if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break;
        } else if ((mode == L"reply-empty" || mode == L"reply-truncated") &&
                   (command == veh::IpcCommand::GetThreads || command == veh::IpcCommand::GetModules)) {
            // Both list headers are status/count; no entries follow.
            veh::GetThreadsResponse response{veh::IpcStatus::Ok, mode == L"reply-empty" ? 0U : 1U};
            if (!reply(pipe, header.command, response)) break;
        } else if (mode == L"reply-errors" && command == veh::IpcCommand::TraceRegister) {
            veh::TraceRegisterRequest request{}; memcpy(&request, bytes.data(), sizeof(request));
            if (request.maxSteps <= 5) {
                if (!reply(pipe, header.command, static_cast<veh::IpcStatus>(request.maxSteps))) break;
            } else if (request.maxSteps == 6) {
                veh::TraceRegisterResponse response{}; response.status = veh::IpcStatus::Ok;
                if (!reply(pipe, header.command, response)) break;
            } else if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
        } else if (command == veh::IpcCommand::GetProcesses) {
            if(!vmMode){if(!reply(pipe,header.command,veh::IpcStatus::Unsupported))break;continue;}
            if(!bytes.empty()){if(!reply(pipe,header.command,veh::IpcStatus::InvalidArgs))break;continue;}
            if(mode==L"machine-process-error"){
                if(!reply(pipe,header.command,veh::IpcStatus::Unsupported))break;
                continue;
            }
            struct {veh::GetProcessesResponse header;veh::GuestProcessInfo entries[2];} processes{};
            processes.header.status=veh::IpcStatus::Ok;processes.header.count=2;
            processes.entries[0].pid=4;processes.entries[0].addressBits=64;
            strcpy_s(processes.entries[0].name,"System");
            processes.entries[1].pid=4242;processes.entries[1].addressBits=
                mode==L"machine-process-invalid"?16:32;
            strcpy_s(processes.entries[1].name,"sample32.exe");
            const auto length=mode==L"machine-process-short"
                ?sizeof(processes.header)+sizeof(processes.entries[0]):sizeof(processes);
            if(!send(pipe,header.command,&processes,static_cast<uint32_t>(length)))break;
        } else if (command == veh::IpcCommand::GetThreads) {
            if(mode==L"machine-thread-error") {
                if(!reply(pipe,header.command,veh::IpcStatus::Unsupported))break;
                continue;
            }
            struct { veh::GetThreadsResponse header; veh::ThreadInfo thread; } threads{};
            threads.header.status = veh::IpcStatus::Ok;
            threads.header.count = mode==L"machine-thread-short"?2:1;
            threads.thread.id = 77;
            if(mode==L"local-drop-live"&&++localThreadQueries==2){
                CloseHandle(pipe);
                HANDLE exitEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
                if(exitEvent){WaitForSingleObject(exitEvent,10000);CloseHandle(exitEvent);}
                return 0; // deliberately alive after losing its IPC endpoint
            }
            if(mode.rfind(L"local-",0)==0)sprintf_s(threads.thread.name,"fixture-agent:%lu",GetCurrentProcessId());
            if(mode==L"shellcode-action")sprintf_s(threads.thread.name,"shellcode-calls:%u",shellcodeRequests);
            if(deferredMode)std::snprintf(threads.thread.name,sizeof(threads.thread.name),
                "g=%u,set=%u,res=%u,held=%u,rm=%u,c=%u,q=%u",deferredGuard?1u:0u,deferredSets,deferredResumes,moduleHeld?1u:0u,deferredRemoves,deferredContinueCalls,deferredStopQueries);
            if (mode == L"silent-detach" || mode == L"late-detach" || mode == L"host-cap")
                sprintf_s(threads.thread.name, "fixture-agent:%lu", GetCurrentProcessId());
            if (mode == L"trace") strcpy_s(threads.thread.name,
                continueRequests || pauseRequests ? "unexpected-resume-or-pause" : "untouched");
            if(mode==L"machine-thread-name")std::memset(threads.thread.name,'A',sizeof(threads.thread.name));
            if (!reply(pipe, header.command, threads)) break;
        } else if (command == veh::IpcCommand::GetModules) {
            if(mode==L"modules-error") {
                veh::GetModulesResponse response{veh::IpcStatus::Unsupported,0};
                if(!reply(pipe,header.command,response))break;
                continue;
            }
            if(mode==L"modules-empty") {
                veh::GetModulesResponse response{veh::IpcStatus::Ok,0};
                if(!reply(pipe,header.command,response))break;
                continue;
            }
            struct {veh::GetModulesResponse header;veh::ModuleInfo module;} modules{};
            modules.header.status=veh::IpcStatus::Ok;
            modules.header.count=mode==L"modules-short"?2:1;
            modules.module.baseAddress=0x1000;modules.module.size=0x1000;
            strcpy_s(modules.module.name,"sample.dll");
            strcpy_s(modules.module.path,"C:\\sample.dll");
            if(mode==L"modules-name")
                std::memset(modules.module.name,'A',sizeof(modules.module.name));
            if(!reply(pipe,header.command,modules))break;
        } else if (command == veh::IpcCommand::ReadMemory && bytes.size() == sizeof(veh::ReadMemoryRequest)) {
            veh::ReadMemoryRequest request{}; memcpy(&request, bytes.data(), sizeof(request));
            if (request.size > 4096) { reply(pipe, header.command, veh::IpcStatus::InvalidArgs); continue; }
            std::vector<unsigned char> response(sizeof(veh::IpcStatus) + request.size, 0x90);
            const auto status = veh::IpcStatus::Ok; memcpy(response.data(), &status, sizeof(status));
            // x86 INC EDX; RET, versus the x64 REX prefix. Tests metadata bitness.
            if (request.size) response[sizeof(status)] = 0x42;
            if (request.size > 1) response[sizeof(status) + 1] = 0xc3;
            if (!send(pipe, header.command, response.data(), static_cast<uint32_t>(response.size()))) break;
            if(deferredMode&&request.address==0x3000&&mode==L"deferred-exit-old"){
                exceptionHeld=false;const veh::ThreadEvent exited{88};
                if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ThreadExited),exited)||!emitDeferredLoad(true))break;
            }
            if(deferredMode&&request.address==0x2000&&!emitDeferredLoad(true))break;
        } else if(vmMode&&command==veh::IpcCommand::ControlVirtualMachine&&bytes.size()==sizeof(veh::ControlVirtualMachineRequest)) {
            veh::ControlVirtualMachineRequest request{};memcpy(&request,bytes.data(),sizeof(request));
            veh::ControlVirtualMachineResponse response{veh::IpcStatus::Ok,veh::VirtualMachineState::Paused};
            if(request.reserved||static_cast<uint32_t>(request.action)>2)response.status=veh::IpcStatus::InvalidArgs;
            else if(request.action==veh::VirtualMachineAction::Pause)vmState=2;
            else if(request.action==veh::VirtualMachineAction::Resume)vmState=1;
            response.state=static_cast<veh::VirtualMachineState>(vmState);
            if(!reply(pipe,header.command,response))break;
        } else if(vmMode&&command==veh::IpcCommand::TraceVirtualCpu&&bytes.size()==sizeof(veh::TraceVirtualCpuRequest)) {
            veh::TraceVirtualCpuRequest request{};memcpy(&request,bytes.data(),sizeof(request));
            const uint32_t count=request.maxInstructions<64?request.maxInstructions:64;
            veh::TraceVirtualCpuResponse response{veh::IpcStatus::Ok,1,request.maxInstructions,
                request.maxInstructions-count,123456,count,1,1,0};
            if(mode==L"vm-failure"){response.status=veh::IpcStatus::Error;response.completed=2;response.count=2;response.lost=0;response.stopReason=4;response.executionStatus=23;}
            if(mode==L"vm-bad-trace")response.completed=0;
            std::vector<unsigned char> data(sizeof(response)+response.count*sizeof(veh::VirtualCpuInstructionRecord));
            memcpy(data.data(),&response,sizeof(response));
            for(uint32_t i=0;i<response.count;++i) {
                const veh::VirtualCpuInstructionRecord record{static_cast<uint64_t>(i)+1,UINT64_C(9007199254740993)+i,
                    UINT64_C(0x1000),UINT64_C(0x900f),UINT64_C(0x900f),UINT64_C(0x11223345),UINT64_C(0x11223345),
                    0,0,UINT64_C(0x8000),2,request.cpu,0};
                memcpy(data.data()+sizeof(response)+static_cast<size_t>(i)*sizeof(record),&record,sizeof(record));
            }
            if(!send(pipe,header.command,data.data(),mode==L"vm-truncated"?8:static_cast<uint32_t>(data.size())))break;
        } else if ((mode == L"trace" || mode == L"delayed-trace") && command == veh::IpcCommand::TraceCallers && bytes.size() == sizeof(veh::TraceCallersRequest)) {
            veh::TraceCallersRequest request{}; memcpy(&request, bytes.data(), sizeof(request));
            if (mode == L"delayed-trace") Sleep(request.durationMs > 20000 ? 20000 : request.durationMs);
            const veh::TraceCallersResponse response{request.address == 0x2000 ? veh::IpcStatus::Unsupported : veh::IpcStatus::Ok, 0, 0};
            if (!reply(pipe, header.command, response)) break;
        } else if (mode == L"trace" && (command == veh::IpcCommand::Continue || command == veh::IpcCommand::Pause)) {
            if (command == veh::IpcCommand::Continue) ++continueRequests; else ++pauseRequests;
            if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
        } else if (command == veh::IpcCommand::Heartbeat) {
            if (!send(pipe, static_cast<uint32_t>(veh::IpcEvent::HeartbeatAck), nullptr, 0)) break;
        } else if (command == veh::IpcCommand::Shutdown && mode == L"silent-detach") {
            Sleep(5000); break;
        } else if (command == veh::IpcCommand::Detach) {
            if(mode==L"local-die-detach")break;
            if (mode == L"silent-detach") continue;
            if (mode == L"late-detach") Sleep(4500);
            if(mode==L"detach-three-errors"&&detachFailures++<3) {
                if(!reply(pipe,header.command,veh::IpcStatus::Error))break;
                continue;
            }
            reply(pipe, header.command, veh::IpcStatus::Ok); break;
        } else if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break;
    }
    CloseHandle(pipe);
    return 0;
}
