#include <windows.h>
#include "ipc_protocol.h"
#include "adapter/ipc_transport.h"
#include <cstdio>
#include <cstdlib>
static void Check(bool value,const char* message){if(!value){std::fprintf(stderr,"FAIL %s\n",message);std::exit(1);}}
class ProbeTransport final:public veh::IIpcTransport {
public:
    bool modern=false;unsigned calls=0,fail_at=0;
    bool Connect(uint32_t,int)override{return true;}
    void Disconnect()override{}
    bool IsConnected()const override{return true;}
    bool SendCommand(veh::IpcCommand,const void*,uint32_t)override{return true;}
    bool SendAndReceive(veh::IpcCommand command,const void* payload,uint32_t size,
        std::vector<uint8_t>& response,int,veh::PipeExchangeDiagnostics*)override {
        ++calls;if(calls==fail_at)return false;
        Check(command==veh::IpcCommand::GetCapabilities,"capability command");
        if(calls==1)Check(size==0&&!payload,"legacy discovery stays empty");
        else {
            Check(modern&&size==8&&payload,"only advertised extension is sent");
            veh::GetCapabilitiesRequestV1 request{};std::memcpy(&request,payload,sizeof(request));
            Check(request.version==1&&request.flags==veh::kCapRegisterContextV1,"version1 exact request");
        }
        veh::GetCapabilitiesResponse caps{};caps.status=veh::IpcStatus::Ok;
        caps.flags=veh::kCapValueScanV2|(modern?veh::kCapRegisterContextV1:0);
        const auto* bytes=reinterpret_cast<const uint8_t*>(&caps);response.assign(bytes,bytes+sizeof(caps));return true;
    }
    bool WaitForReady(int)override{return true;}
    void StartEventListener(EventCallback)override{}
    void StopEventListener()override{}
    void StartHeartbeat()override{}
    void StopHeartbeat()override{}
};
int main(){
    using namespace veh;
    static_assert(sizeof(RegisterSet)==497 && sizeof(GetRegistersRequest)==4 && sizeof(GetRegistersResponse)==501);
    uint32_t selected=0;
    Check(SelectRegisterContext(nullptr,0,0,&selected)&&selected==0,"empty discovery enables nothing");
    Check(SelectRegisterContext(nullptr,0,kCapRegisterContextV1,&selected)&&selected==kCapRegisterContextV1,"discovery retains selected mode");
    for(GetCapabilitiesRequestV1 invalid: {GetCapabilitiesRequestV1{2,kCapRegisterContextV1},GetCapabilitiesRequestV1{1,1u<<31}}){
        selected=kCapRegisterContextV1;
        Check(!SelectRegisterContext(&invalid,sizeof(invalid),0,&selected)&&selected==kCapRegisterContextV1,"invalid request changes no state");
    }
    const GetCapabilitiesRequestV1 on{1,kCapRegisterContextV1},off{1,0};
    selected=0;
    Check(!SelectRegisterContext(&on,4,0,&selected)&&selected==0,"short versioned request rejected");
    Check(SelectRegisterContext(&on,sizeof(on),0,&selected)&&selected==kCapRegisterContextV1,"explicit version1 enables context registers");
    Check(SelectRegisterContext(&off,sizeof(off),selected,&selected)&&selected==0,"explicit version1 can select legacy");
    std::vector<uint8_t> response;
    ProbeTransport legacy;
    Check(legacy.QueryContextCapabilities(response)&&legacy.calls==1,"legacy peer receives no versioned request");
    GetCapabilitiesResponse caps{};std::memcpy(&caps,response.data(),sizeof(caps));
    Check(caps.flags==kCapValueScanV2,"legacy capabilities preserved");
    ProbeTransport modern;modern.modern=true;
    Check(modern.QueryContextCapabilities(response)&&modern.calls==2,"modern peer explicitly negotiated");
    ProbeTransport failed;failed.modern=true;failed.fail_at=2;
    Check(!failed.QueryContextCapabilities(response)&&failed.calls==2,"failed exchange is never retried");
    std::puts("PASS register-context v1 legacy discovery, invalid requests, explicit selection and unchanged layouts");
}
