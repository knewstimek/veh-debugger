#pragma once
#include "pipe_client.h"
#include "common/remote_channel.h"
#include <string>

namespace veh {
struct RemoteEndpoint {
    std::string address;
    uint16_t port = 0;
    std::string certificateSha256;
    std::wstring tokenFile;
    std::string backend;
    int timeoutMs = 20000;
};
struct RemoteWorkInfo {
    std::string id;
    std::string scope;
    uint32_t pid = 0;
    uint32_t addressBits = 0;
    uint32_t mainThreadId = 0; // optional creation metadata; never a local thread handle
    bool outcomeUnknown = false;
};
enum class RemoteOpenOutcome { NotSent, Rejected, Unknown, Opened };
// Reuses the existing single-reader IPC/event/heartbeat engine.
class TcpIpcTransport final : public PipeClient {
public:
    TcpIpcTransport(RemoteEndpoint endpoint, std::string openRequest);
    ~TcpIpcTransport() override { Disconnect(); }
    bool Connect(uint32_t ignoredPid, int timeoutMs = 7000) override;
    void Disconnect() override;
    bool IsRemote() const override { return true; }
    uint32_t PeerProcessId() const override { return 0; }
    const RemoteWorkInfo& Work() const { return work_; }
    const std::string& Error() const { return error_; }
    RemoteOpenOutcome OpenOutcome() const { return openOutcome_; }
    bool MatchesWork(const RemoteEndpoint&, const std::string& scope, uint32_t pid) const;
    // Reader stopped; bounded drain of pending frames until the resident closes the work.
    // acknowledgement: the relayed status of finalCommand, Error when none arrived.
    bool WaitForWorkClose(int timeoutMs, IpcCommand finalCommand, IpcStatus* acknowledgement);
protected:
    bool AsyncReadExact(void* data, DWORD size, DWORD timeoutMs) override;
    bool AsyncWriteExact(const void* data, DWORD size, DWORD timeoutMs) override;
    void CancelPendingIo() override;
private:
    RemoteEndpoint endpoint_;
    std::string openRequest_, error_;
    remote::Channel channel_;
    RemoteWorkInfo work_;
    RemoteOpenOutcome openOutcome_ = RemoteOpenOutcome::NotSent;
};
} // namespace veh
