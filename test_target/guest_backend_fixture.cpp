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
    const bool scanMode=mode.rfind(L"scan-",0)==0;
    uint32_t symbolLookupRequests = 0;
    const bool symbolsMode = mode.rfind(L"symbols-", 0) == 0 || mode == L"ops-action-symbols";
    const bool instrumentationMode = mode.rfind(L"inst-", 0) == 0 || mode == L"ops-action-inst";
    bool captureActive[3]{}, captureCreated[3]{};
    uint64_t captureIds[3]{}, nextCaptureId = 9007199254740993ULL;
    veh::InstrumentationDataPolicy captureData[3]{};
    veh::InstrumentationTransactionPolicy captureTransaction[3]{};
    uint32_t captureBuffer[3]{};
    const bool operationsMode = mode.rfind(L"ops-", 0) == 0;
    const bool receiptMode = mode.rfind(L"receipt-", 0) == 0;
    const bool systemReceiptMode = mode.rfind(L"system-receipts-", 0) == 0;
    bool operationsStopped = true, operationsExitSent = false;
    uint64_t operationsRip = 0x1000, operationsBreakpointAddress = 0x1000;
    uint32_t operationsCreated = 0, operationsRemoved = 0, operationsResumed = 0, operationsWrites = 0;
    unsigned char operationsMemory[64]; std::memset(operationsMemory, 0x11, sizeof(operationsMemory));
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
            if(scanMode){veh::SetCommandSupported(caps.commands,veh::IpcCommand::ValueScan);if(mode!=L"scan-legacy")caps.flags|=veh::kCapValueScanV2;}
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
            if (symbolsMode) {
                for (auto op : {veh::IpcCommand::GetModules, veh::IpcCommand::ResolveFunction})
                    veh::SetCommandSupported(caps.commands, op);
                if (mode != L"symbols-no-caps") veh::SetCommandSupported(caps.commands, veh::IpcCommand::FindSymbols);
            }
            if (instrumentationMode)
                for (auto op : {veh::IpcCommand::QueryBranchTrace, veh::IpcCommand::StartBranchTrace,
                                veh::IpcCommand::StopBranchTrace, veh::IpcCommand::ReadBranchTrace})
                    veh::SetCommandSupported(caps.commands, op);
            if (instrumentationMode && mode != L"inst-no-caps")
                for (auto op : {veh::IpcCommand::QueryInstrumentation, veh::IpcCommand::StartInstrumentation,
                                veh::IpcCommand::StopInstrumentation, veh::IpcCommand::ReadInstrumentation})
                    if (mode != L"inst-partial" || op == veh::IpcCommand::QueryInstrumentation)
                        veh::SetCommandSupported(caps.commands, op);
            if (systemReceiptMode)
                for (auto op : {veh::IpcCommand::ListSystemEvents, veh::IpcCommand::RemoveSystemEvent,
                                veh::IpcCommand::AddHiddenHook, veh::IpcCommand::AddSystemEvent})
                    veh::SetCommandSupported(caps.commands, op);
            if (receiptMode && mode != L"receipt-unsupported")
                for (auto op : {veh::IpcCommand::RemoveBreakpoint, veh::IpcCommand::RemoveHwBreakpoint,
                                veh::IpcCommand::IsThreadStopped})
                    veh::SetCommandSupported(caps.commands, op);
            if (operationsMode) {
                for (auto op : {veh::IpcCommand::SetBreakpoint, veh::IpcCommand::RemoveBreakpoint,
                                veh::IpcCommand::Continue, veh::IpcCommand::IsThreadStopped,
                                veh::IpcCommand::GetRegisters, veh::IpcCommand::FreezeThread,
                                veh::IpcCommand::StepInto, veh::IpcCommand::StepOver, veh::IpcCommand::Pause})
                    veh::SetCommandSupported(caps.commands, op);
                if (mode == L"ops-no-read") {
                    const auto index = static_cast<uint32_t>(veh::IpcCommand::ReadMemory);
                    caps.commands[index / 8] &= static_cast<uint8_t>(~(1u << (index % 8)));
                }
                if (mode != L"ops-no-write") veh::SetCommandSupported(caps.commands, veh::IpcCommand::WriteMemory);
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
            if (mode.rfind(L"path-", 0) == 0) {
                caps.flags |= veh::kCapBasicTracePolicies;
                veh::SetCommandSupported(caps.commands, veh::IpcCommand::TraceBasicBlocks);
            }
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
        } else if (mode.rfind(L"path-", 0) == 0 && command == veh::IpcCommand::TraceBasicBlocks) {
            veh::TraceBasicBlocksRequest request{};
            if (bytes.size() != sizeof(request)) {
                if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break;
                continue;
            }
            std::memcpy(&request, bytes.data(), sizeof(request));
            veh::TraceBasicBlocksResponse response{};
            response.status = veh::IpcStatus::Ok;
            response.headerSize = sizeof(response);
            response.threadId = request.threadId;
            response.appliedCollectionFlags = request.collectionFlags;
            response.eventSchemaVersion = 3;
            response.eventCollectionEnabled = 1;
            response.eventCount = 2;
            response.expandedEventCount = 3;
            response.returnSnapshot = UINT32_MAX;
            veh::TraceBasicBlockEventEntry events[2]{};
            events[0].sequence = 1; events[0].source = 0x1000;
            events[0].sourceInstruction = 0x1001; events[0].target = 0x1000;
            events[0].threadId = request.threadId; events[0].codeVersion = 0;
            events[0].type = veh::TraceBasicBlockEventType::Edge;
            events[0].edgeKind = veh::TraceBasicBlockEdgeKind::Branch;
            events[1].sequence = 2; events[1].source = 1;
            events[1].sourceInstruction = 2; events[1].target = 1;
            events[1].threadId = request.threadId; events[1].codeVersion = UINT32_MAX;
            events[1].type = veh::TraceBasicBlockEventType::Repeat;
            if (mode == L"path-bad-repeat") events[1].source = 2;
            if (mode == L"path-bad-count") response.expandedEventCount = 99;
            if (mode == L"path-bad-thread") events[1].threadId++;
            if (mode == L"path-bad-policy") response.appliedCollectionFlags = 0;
            if (mode == L"path-refused") {
                response.status = veh::IpcStatus::Error;
                response.startFailureReason = static_cast<uint8_t>(veh::TraceBasicBlocksStartFailure::HardwareBreakpointConflict);
                response.eventCount = 0; response.expandedEventCount = 0;
                response.appliedCollectionFlags = 0;
            }
            std::vector<unsigned char> result(sizeof(response) + response.eventCount * sizeof(events[0]));
            std::memcpy(result.data(), &response, sizeof(response));
            if (response.eventCount) std::memcpy(result.data() + sizeof(response), events, sizeof(events));
            if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
        } else if (symbolsMode && command == veh::IpcCommand::FindSymbols) {
            ++symbolLookupRequests;
            veh::FindSymbolsRequest request{};
            if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
            std::memcpy(&request, bytes.data(), sizeof(request));
            const std::string query(request.name, strnlen(request.name, sizeof(request.name)));
            const bool many = query == "ManyProbe*";
            const bool ambiguous = query == "SharedProbe";
            const bool forwarder = query == "ForwardedProbe";
            const bool single = query == "UniqueProbe" || query == "probe_a.dll!SharedProbe" || query == "probe_b.dll!SharedProbe";
            veh::FindSymbolsResponse response{mode == L"symbols-error" ? veh::IpcStatus::Error : veh::IpcStatus::Ok,
                (ambiguous || many) ? (request.maxResults < 2 ? request.maxResults : many ? request.maxResults : 2) : single || forwarder ? 1u : 0u, 0};
            if (many || (ambiguous && request.maxResults == 1)) response.flags |= veh::kFindSymbolsTruncated;
            if (mode == L"symbols-incomplete") response.flags |= veh::kFindSymbolsIncomplete;
            if (mode == L"symbols-flags") response.flags |= 4;
            if (mode == L"symbols-count") response.count = 11;
            std::vector<unsigned char> result(sizeof(response) + response.count * sizeof(veh::FindSymbolEntry));
            std::memcpy(result.data(), &response, sizeof(response));
            for (uint32_t i = 0; i < response.count; ++i) {
                veh::FindSymbolEntry entry{};
                const bool second = query == "probe_b.dll!SharedProbe" || (ambiguous && i == 1);
                entry.moduleBase = second ? 0x2000 : 0x1000;
                entry.address = forwarder ? 0 : entry.moduleBase + 0x100 + i * 16;
                entry.flags = veh::kFindSymbolExport | (forwarder ? veh::kFindSymbolForwarder : 0);
                strcpy_s(entry.moduleName, second ? "probe_b.dll" : "probe_a.dll");
                strcpy_s(entry.functionName, query == "UniqueProbe" ? "UniqueProbe" : forwarder ? "ForwardedProbe" : "SharedProbe");
                if (mode == L"symbols-name") std::memset(entry.functionName, 'X', sizeof(entry.functionName));
                if (mode == L"symbols-address") entry.address = 1;
                std::memcpy(result.data() + sizeof(response) + i * sizeof(entry), &entry, sizeof(entry));
            }
            if (mode == L"symbols-short") result.resize(4);
            if (mode == L"symbols-long") result.push_back(0);
            if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
        } else if (symbolsMode && command == veh::IpcCommand::ResolveFunction) {
            if (!reply(pipe, header.command, veh::ResolveFunctionResponse{veh::IpcStatus::Ok, 0x1100})) break;
        } else if (symbolsMode && command == veh::IpcCommand::GetModules) {
            struct { veh::GetModulesResponse head; veh::ModuleInfo module; } response{};
            response.head = {veh::IpcStatus::Ok, 1};
            response.module.baseAddress = 0x1000; response.module.size = 0x10000;
            strcpy_s(response.module.name, "probe_a.dll");
            if (!reply(pipe, header.command, response)) break;
        } else if (instrumentationMode && command == veh::IpcCommand::QueryBranchTrace) {
            veh::QueryBranchTraceResponse response{};
            response.status = veh::IpcStatus::Ok; response.lastBranches = 1; response.fullPath = 1;
            strcpy_s(response.provider, "synthetic-branches");
            if (!reply(pipe, header.command, response)) break;
        } else if (instrumentationMode && (command == veh::IpcCommand::StartBranchTrace ||
            command == veh::IpcCommand::StopBranchTrace)) {
            if (!reply(pipe, header.command, bytes.size() == sizeof(veh::StartBranchTraceRequest) ?
                veh::IpcStatus::Ok : veh::IpcStatus::InvalidArgs)) break;
        } else if (instrumentationMode && command == veh::IpcCommand::ReadBranchTrace) {
            veh::ReadBranchTraceRequest request{};
            if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
            std::memcpy(&request, bytes.data(), sizeof(request));
            const struct { veh::ReadBranchTraceResponse head; veh::BranchRecord branch; } response{
                {veh::IpcStatus::Ok, request.kind, 1, 0}, {0x1000, 0x2000}};
            if (!reply(pipe, header.command, response)) break;
        } else if(scanMode && command==veh::IpcCommand::ValueScan) {
            if(mode==L"scan-legacy") {
                if(bytes.size()!=sizeof(veh::ValueScanRequest))break;
                veh::ValueScanResponse response{};response.status=veh::IpcStatus::Ok;
                response.mode=veh::ValueScanMode::List;response.valueType=veh::ValueScanType::I32;
                response.candidates=100; // No entries: tests exercise suppression and capability gating.
                if(!reply(pipe,header.command,response))break;
                continue;
            }
            veh::ValueScanRequestV2 request{};
            if(bytes.size()!=sizeof(request))break;
            memcpy(&request,bytes.data(),sizeof(request));
            veh::ValueScanResponseV2 response{};response.version=2;response.headerSize=sizeof(response);
            response.scan.status=veh::IpcStatus::Ok;response.sessionId=9007199254740993ull;
            response.jobId=request.jobId?request.jobId:9007199254740995ull;
            response.generationId=9007199254740997ull;response.sequence=1;
            response.state=veh::ValueScanJobState::Completed;response.phase=veh::ValueScanPhase::Finished;
            response.scan.valueType=veh::ValueScanType::I32;response.scan.mode=veh::ValueScanMode::Disk;
            response.storage=veh::ValueScanStorage::File;response.scan.candidates=100;
            if(mode==L"scan-short"){if(!send(pipe,header.command,&response,sizeof(response)-1))break;continue;}
            if(mode==L"scan-version")response.version=3;
            if(mode==L"scan-count")response.scan.count=1001;
            if(mode==L"scan-job")++response.jobId;
            if(mode==L"scan-progress"){response.processed=2;response.total=1;}
            if(mode==L"scan-state")response.state=static_cast<veh::ValueScanJobState>(99);
            if(mode==L"scan-reserved")response.scan.reserved=1;
            if(mode==L"scan-notify-error"||mode==L"scan-notify-count") {
                auto event=response;event.sequence=2;
                if(mode==L"scan-notify-error")event.scan.status=veh::IpcStatus::Error;
                else event.scan.count=101;
                if(!reply(pipe,static_cast<uint32_t>(veh::IpcEvent::ValueScanProgress),event))break;
            }
            if(!reply(pipe,header.command,response))break;
        } else if (instrumentationMode && command == veh::IpcCommand::QueryInstrumentation) {
            veh::QueryInstrumentationRequest request{};
            if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
            std::memcpy(&request, bytes.data(), sizeof(request));
            veh::QueryInstrumentationResponse response{};
            response.status = mode == L"inst-error" ? veh::IpcStatus::Error : veh::IpcStatus::Ok;
            response.version = mode == L"inst-version" ? 2 : 1; response.kind = request.kind;
            response.features = 511;
            if (mode == L"inst-cpu-off") response.features &= ~(veh::kInstrumentationIntelPt |
                veh::kInstrumentationPtWrite | veh::kInstrumentationPtWriteAvailable);
            if (mode == L"inst-no-original") response.features &= ~veh::kInstrumentationOriginal;
            if (mode == L"inst-no-rollback") response.features &= ~veh::kInstrumentationRollback;
            response.maxBufferRecords = mode == L"inst-low-limit" ? 16 : 65536;
            response.maxPageRecords = 256;
            strcpy_s(response.provider, "synthetic-instrumentation");
            strcpy_s(response.ptWriteReason, mode == L"inst-cpu-off" ? "PTWRITE unavailable" : "");
            if (mode == L"inst-query-long") {
                std::vector<unsigned char> result(sizeof(response) + 1);
                std::memcpy(result.data(), &response, sizeof(response));
                if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
            } else if (!send(pipe, header.command, &response, mode == L"inst-query-short" ? 4 : sizeof(response))) break;
        } else if (instrumentationMode && (command == veh::IpcCommand::StartInstrumentation ||
            command == veh::IpcCommand::StopInstrumentation || command == veh::IpcCommand::ReadInstrumentation)) {
            veh::InstrumentationKind kind{};
            uint64_t requestedId = 0, cursor = 0;
            uint32_t maximum = 0;
            veh::StartInstrumentationRequest start{};
            bool valid = true;
            if (command == veh::IpcCommand::StartInstrumentation && bytes.size() == sizeof(start)) {
                std::memcpy(&start, bytes.data(), sizeof(start));
                kind = start.kind;
                valid = start.version == 1 && start.bufferRecords > 0 && start.bufferRecords <= 65536 &&
                    start.includeIp <= 1 && static_cast<uint32_t>(start.dataPolicy) <= 1 &&
                    static_cast<uint32_t>(start.transactionPolicy) <= 1;
            } else if (command == veh::IpcCommand::StopInstrumentation && bytes.size() == sizeof(veh::StopInstrumentationRequest)) {
                veh::StopInstrumentationRequest request{}; std::memcpy(&request, bytes.data(), sizeof(request));
                kind = request.kind; requestedId = request.traceId; valid = request.version == 1;
            } else if (command == veh::IpcCommand::ReadInstrumentation && bytes.size() == sizeof(veh::ReadInstrumentationRequest)) {
                veh::ReadInstrumentationRequest request{}; std::memcpy(&request, bytes.data(), sizeof(request));
                kind = request.kind; requestedId = request.traceId; cursor = request.cursor; maximum = request.maxRecords;
                valid = request.version == 1 && maximum <= 256;
            } else valid = false;
            const auto index = static_cast<uint32_t>(kind);
            if (!valid || index < 1 || index > 2) {
                if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue;
            }
            if (command == veh::IpcCommand::StartInstrumentation && !captureActive[index]) captureIds[index] = ++nextCaptureId;
            const uint64_t id = captureIds[index];
            if (command == veh::IpcCommand::StartInstrumentation) {
                if (captureActive[index]) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidState)) break; continue; }
                captureActive[index] = true; captureCreated[index] = true;
                captureData[index] = start.dataPolicy; captureTransaction[index] = start.transactionPolicy;
                captureBuffer[index] = start.bufferRecords;
            } else if (!captureCreated[index] || id != requestedId) {
                if (!reply(pipe, header.command, veh::IpcStatus::NotFound)) break; continue;
            } else if (command == veh::IpcCommand::StopInstrumentation) captureActive[index] = false;
            else if (maximum && captureActive[index]) {
                if (!reply(pipe, header.command, veh::IpcStatus::InvalidState)) break; continue;
            }
            veh::InstrumentationResponse response{};
            response.status = veh::IpcStatus::Ok; response.version = 1; response.kind = kind;
            response.traceId = id; response.flags = captureActive[index] ? veh::kInstrumentationActive : 0;
            response.dataPolicy = captureData[index]; response.transactionPolicy = captureTransaction[index];
            response.bufferRecords = captureBuffer[index];
            response.totalRecords = command == veh::IpcCommand::StartInstrumentation ? 0 : (captureBuffer[index] < 3 ? captureBuffer[index] : 3);
            response.omittedTransactionalRecords = 2; response.abortedTransactions = 1;
            if (cursor > response.totalRecords) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
            response.cursor = cursor;
            response.count = static_cast<uint32_t>(response.totalRecords - cursor);
            if (response.count > maximum) response.count = maximum;
            response.nextCursor = cursor + response.count;
            if (mode == L"inst-loss" || mode == L"inst-unknown-loss") {
                response.flags |= veh::kInstrumentationOverflow | veh::kInstrumentationIncomplete;
                response.lostRecords = mode == L"inst-loss" ? 9 : UINT64_MAX;
            }
            if (mode == L"inst-ip-missing") response.flags |= veh::kInstrumentationIncomplete;
            if (mode == L"inst-policy-mismatch") response.dataPolicy = veh::InstrumentationDataPolicy::Patched;
            if (mode == L"inst-kind-mismatch") response.kind = index == 1 ? veh::InstrumentationKind::PtWrite : veh::InstrumentationKind::DetourCalls;
            if (mode == L"inst-id-mismatch") ++response.traceId;
            if (mode == L"inst-bad-cursor") ++response.nextCursor;
            if (mode == L"inst-count") response.count = 257;
            std::vector<unsigned char> result(sizeof(response) + response.count * sizeof(veh::InstrumentationRecord));
            std::memcpy(result.data(), &response, sizeof(response));
            for (uint32_t i = 0; i < response.count; ++i) {
                veh::InstrumentationRecord record{};
                record.value = index == 2 ? 0xfedcba9876543210ULL + cursor + i : 0x1000;
                record.instructionAddress = 0x1000 + (cursor + i) * 5;
                record.callerAddress = 0x2000 + (cursor + i) * 5;
                record.threadId = 77;
                record.flags = veh::kInstrumentationIpValid | (index == 1 ? veh::kInstrumentationCallerValid : 0);
                if (mode == L"inst-ip-missing" && cursor + i == 1) record.flags &= ~veh::kInstrumentationIpValid;
                if (mode == L"inst-record-flags") record.flags |= 4;
                std::memcpy(result.data() + sizeof(response) + i * sizeof(record), &record, sizeof(record));
            }
            if (mode == L"inst-reply-short") result.resize(4);
            if (mode == L"inst-reply-long") result.push_back(0);
            if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
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
        } else if (systemReceiptMode && command == veh::IpcCommand::ListSystemEvents) {
            struct {veh::ListSystemEventsResponse head; veh::SystemEventInfo entry;} response{};
            response.head.status = mode == L"system-receipts-error" ? veh::IpcStatus::Error : veh::IpcStatus::Ok;
            response.head.count = mode == L"system-receipts-empty" || mode == L"system-receipts-error" ? 0 :
                mode == L"system-receipts-short" ? 2 : mode == L"system-receipts-count" ? 257 : 1;
            response.entry.id = 7;
            response.entry.type = static_cast<uint32_t>(veh::SystemEventType::MemoryExecute);
            response.entry.action = 2; response.entry.pid = 424242;
            response.entry.low = response.entry.high = 0x1000; response.entry.hits = 3;
            const bool noEntries = response.head.count == 0 || mode == L"system-receipts-count";
            const auto length = noEntries ? sizeof(response.head) : sizeof(response);
            std::vector<unsigned char> result(length + (mode == L"system-receipts-long" ? 1 : 0), 0);
            std::memcpy(result.data(), &response, length);
            if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
        } else if (systemReceiptMode && command == veh::IpcCommand::RemoveSystemEvent) {
            if (mode == L"system-receipts-short") {
                const uint8_t shortReply = 0; if (!reply(pipe, header.command, shortReply)) break;
            } else if (mode == L"system-receipts-long") {
                const uint64_t longReply = 0; if (!reply(pipe, header.command, longReply)) break;
            } else if (!reply(pipe, header.command, mode == L"system-receipts-error" ?
                veh::IpcStatus::Error : veh::IpcStatus::Ok)) break;
        } else if (systemReceiptMode &&
            (command == veh::IpcCommand::AddHiddenHook || command == veh::IpcCommand::AddSystemEvent)) {
            if (mode == L"system-receipts-short") {
                if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
            } else {
                // These two receipts have the same fixed status/id layout.
                veh::AddHiddenHookResponse response{mode == L"system-receipts-error" ?
                    veh::IpcStatus::Error : veh::IpcStatus::Ok, 7};
                std::vector<unsigned char> result(sizeof(response) +
                    (mode == L"system-receipts-long" ? 1 : 0), 0);
                std::memcpy(result.data(), &response, sizeof(response));
                if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
            }
        } else if (receiptMode &&
            (command == veh::IpcCommand::RemoveBreakpoint || command == veh::IpcCommand::RemoveHwBreakpoint)) {
            if (mode == L"receipt-short") {
                const uint8_t shortReply = 0; if (!reply(pipe, header.command, shortReply)) break;
            } else if (mode == L"receipt-long") {
                const uint64_t longReply = 0; if (!reply(pipe, header.command, longReply)) break;
            } else {
                const auto status = mode == L"receipt-error" ? veh::IpcStatus::Error :
                    mode == L"receipt-invalid" ? static_cast<veh::IpcStatus>(99) :
                    mode == L"receipt-unsupported" ? veh::IpcStatus::Unsupported :
                    mode == L"receipt-not-found" ? veh::IpcStatus::NotFound : veh::IpcStatus::Ok;
                if (!reply(pipe, header.command, status)) break;
            }
        } else if (receiptMode && command == veh::IpcCommand::IsThreadStopped) {
            if (mode == L"receipt-short") {
                const uint8_t shortReply = 0; if (!reply(pipe, header.command, shortReply)) break;
            } else {
                veh::IsThreadStoppedResponse response{mode == L"receipt-error" ? veh::IpcStatus::Error :
                    mode == L"receipt-unsupported" ? veh::IpcStatus::Unsupported : veh::IpcStatus::Ok,
                    static_cast<uint8_t>(mode == L"receipt-invalid" ? 2 : 1)};
                std::vector<unsigned char> result(sizeof(response) + (mode == L"receipt-long" ? 1 : 0), 0);
                std::memcpy(result.data(), &response, sizeof(response));
                if (!send(pipe, header.command, result.data(), static_cast<uint32_t>(result.size()))) break;
            }
        } else if (operationsMode && command != veh::IpcCommand::Heartbeat && command != veh::IpcCommand::Detach) {
            if (command == veh::IpcCommand::SetBreakpoint) {
                veh::SetBreakpointRequest request{};
                if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                std::memcpy(&request, bytes.data(), sizeof(request));
                operationsBreakpointAddress = request.address;
                if (mode == L"ops-no-create-short") {
                    if (!reply(pipe, header.command, veh::IpcStatus::LimitReached)) break;
                    continue;
                }
                if (mode == L"ops-no-create") {
                    if (!reply(pipe, header.command, veh::SetBreakpointResponse{veh::IpcStatus::LimitReached, 0})) break;
                    continue;
                }
                ++operationsCreated;
                if (mode == L"ops-create-ambiguous") {
                    if (!reply(pipe, header.command, veh::IpcStatus::Error)) break;
                    continue;
                }
                if (mode == L"ops-stale") {
                    const veh::BreakpointHitEvent event{77, 100, operationsBreakpointAddress, {}};
                    if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::BreakpointHit), event)) break;
                }
                if (!reply(pipe, header.command, veh::SetBreakpointResponse{veh::IpcStatus::Ok, 100})) break;
            } else if (command == veh::IpcCommand::RemoveBreakpoint) {
                ++operationsRemoved;
                if (!reply(pipe, header.command, mode == L"ops-remove-error" ? veh::IpcStatus::Error : veh::IpcStatus::Ok)) break;
            } else if (command == veh::IpcCommand::IsThreadStopped) {
                if (!reply(pipe, header.command, veh::IsThreadStoppedResponse{veh::IpcStatus::Ok,
                    static_cast<uint8_t>(operationsStopped)})) break;
            } else if (command == veh::IpcCommand::GetRegisters) {
                veh::GetRegistersResponse response{};
                response.status = veh::IpcStatus::Ok; response.regs.is32bit = 1; response.regs.rip = operationsRip;
                if (!reply(pipe, header.command, response)) break;
            } else if (command == veh::IpcCommand::GetThreads) {
                if (mode == L"ops-exit-on-threads" && !operationsExitSent) {
                    operationsExitSent = true; operationsStopped = false;
                    const veh::ProcessExitEvent event{0};
                    if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::ProcessExited), event)) break;
                }
                struct {veh::GetThreadsResponse head; veh::ThreadInfo thread;} response{};
                response.head = {veh::IpcStatus::Ok, 1}; response.thread.id = 77;
                std::snprintf(response.thread.name, sizeof(response.thread.name),
                    "created:%u removed:%u resumed:%u writes:%u",
                    operationsCreated, operationsRemoved, operationsResumed, operationsWrites);
                if (mode == L"ops-action-symbols") sprintf_s(response.thread.name, "symbols:%u", symbolLookupRequests);
                if (!reply(pipe, header.command, response)) break;
            } else if (command == veh::IpcCommand::FreezeThread) {
                struct {veh::FreezeThreadResponse head; uint32_t thread;} response{};
                response.head = {veh::IpcStatus::Ok, mode == L"ops-frozen" ? 1u : 0u}; response.thread = 77;
                if (!send(pipe, header.command, &response, static_cast<uint32_t>(sizeof(response.head) +
                    response.head.count * sizeof(response.thread)))) break;
            } else if (command == veh::IpcCommand::Continue) {
                veh::ContinueRequest request{};
                if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                std::memcpy(&request, bytes.data(), sizeof(request));
                if (request.threadId != 77) {
                    if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break;
                    continue;
                }
                ++operationsResumed; operationsStopped = false;
                if (mode == L"ops-drop") break;
                const bool hit = mode == L"ops-normal" || mode == L"ops-fast" ||
                    ((mode.rfind(L"ops-action", 0) == 0) && operationsResumed <= 2);
                const auto emitHit = [&] {
                    const bool ordinaryActionStop = (mode.rfind(L"ops-action", 0) == 0) && operationsResumed == 2;
                    const uint64_t address = ordinaryActionStop ? 0x1010 : operationsBreakpointAddress;
                    operationsStopped = true; operationsRip = address;
                    const veh::BreakpointHitEvent event{77, ordinaryActionStop ? 7u : 100u, address, {}};
                    return reply(pipe, static_cast<uint32_t>(veh::IpcEvent::BreakpointHit), event);
                };
                const bool earlyAction = mode == L"ops-action-fast" && operationsResumed == 1;
                const bool beforeReply = mode == L"ops-fast" || earlyAction;
                if (beforeReply && !emitHit()) break;
                if (earlyAction) {
                    // Hold the reply briefly after the stop to exercise command-gate wakeups.
                    HANDLE delay = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                    if (!delay) break;
                    WaitForSingleObject(delay, 100); CloseHandle(delay);
                }
                if (request.wantDetails) {
                    struct {veh::ContinueResponse head; uint32_t thread;} response{};
                    response.head = {veh::IpcStatus::Ok, mode == L"ops-fast" ? 0u : 1u, 0};
                    response.thread = 77;
                    if (!send(pipe, header.command, &response, static_cast<uint32_t>(sizeof(response.head) +
                        response.head.resumedCount * sizeof(response.thread)))) break;
                }
                if (hit && !beforeReply && !emitHit()) break;
                if (mode == L"ops-other-thread") {
                    const veh::BreakpointHitEvent event{88, 100, operationsBreakpointAddress, {}};
                    if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::BreakpointHit), event)) break;
                }
                if (mode == L"ops-exit") {
                    const veh::ProcessExitEvent event{0};
                    if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::ProcessExited), event)) break;
                }
            } else if (command == veh::IpcCommand::StepInto || command == veh::IpcCommand::StepOver) {
                ++operationsRip; operationsStopped = true;
                if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
                const veh::StepCompletedEvent event{77, operationsRip};
                if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::StepCompleted), event)) break;
            } else if (command == veh::IpcCommand::Pause) {
                operationsStopped = true;
                if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
                const uint32_t thread = 77;
                if (!reply(pipe, static_cast<uint32_t>(veh::IpcEvent::Paused), thread)) break;
            } else if (command == veh::IpcCommand::ReadMemory) {
                veh::ReadMemoryRequest request{};
                if (bytes.size() != sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                std::memcpy(&request, bytes.data(), sizeof(request));
                if (mode == L"ops-no-read") { if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break; continue; }
                static constexpr unsigned char callCode[] = {0xe8, 0xfb, 0x0f, 0x00, 0x00, 0x90, 0xc3};
                const bool memoryRange = request.address >= 0x2000 && request.address - 0x2000 <= sizeof(operationsMemory) &&
                    request.size <= sizeof(operationsMemory) - static_cast<size_t>(request.address - 0x2000);
                const bool codeRange = request.address >= 0x1000 && request.address - 0x1000 < 4096 && request.size <= 4096 &&
                    request.size <= 4096 - (request.address - 0x1000);
                if (!memoryRange && !codeRange) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                std::vector<unsigned char> response(sizeof(veh::IpcStatus) + request.size, 0x90);
                const auto status = veh::IpcStatus::Ok; std::memcpy(response.data(), &status, sizeof(status));
                if (memoryRange) std::memcpy(response.data() + sizeof(status),
                    operationsMemory + static_cast<size_t>(request.address - 0x2000), request.size);
                else for (uint32_t i = 0; i < request.size; ++i) {
                    const auto index = request.address - 0x1000 + i;
                    if (index < sizeof(callCode)) response[sizeof(status) + i] = callCode[index];
                }
                if (!send(pipe, header.command, response.data(), static_cast<uint32_t>(response.size()))) break;
            } else if (command == veh::IpcCommand::WriteMemory) {
                veh::WriteMemoryRequest request{};
                if (bytes.size() < sizeof(request)) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                std::memcpy(&request, bytes.data(), sizeof(request));
                if (mode == L"ops-no-write") { if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break; continue; }
                const bool valid = request.size && request.size <= sizeof(operationsMemory) &&
                    bytes.size() - sizeof(request) == request.size && request.address >= 0x2000 &&
                    request.address - 0x2000 <= sizeof(operationsMemory) &&
                    request.size <= sizeof(operationsMemory) - static_cast<size_t>(request.address - 0x2000);
                if (!valid) { if (!reply(pipe, header.command, veh::IpcStatus::InvalidArgs)) break; continue; }
                if (++operationsWrites == 1 && mode == L"ops-lease-delay") {
                    HANDLE delay = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                    if (!delay) break;
                    WaitForSingleObject(delay, 1100); CloseHandle(delay);
                }
                if (mode == L"ops-write-error") { if (!reply(pipe, header.command, veh::IpcStatus::Error)) break; continue; }
                if (mode != L"ops-write-mismatch") std::memcpy(
                    operationsMemory + static_cast<size_t>(request.address - 0x2000),
                    bytes.data() + sizeof(request), request.size);
                if (!reply(pipe, header.command, veh::IpcStatus::Ok)) break;
            } else if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break;
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
