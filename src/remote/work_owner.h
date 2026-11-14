#pragma once
#include "common/remote_channel.h"
#include "startup_diagnostic_channel.h"
#include "adapter/pipe_client.h"
#include <nlohmann/json.hpp>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace veh::remote {
using Json = nlohmann::json;
struct BackendProfile {
    std::wstring executable;
    std::vector<std::wstring> args;
    std::string scope;
    bool allowLaunch = false;
    std::wstring stderrFile; // optional local log for agent stderr (appended)
};
class WorkOwner : public std::enable_shared_from_this<WorkOwner> {
public:
    static std::shared_ptr<WorkOwner> Open(const BackendProfile&, const Json& request, std::string& code, Json& diagnostics);
    ~WorkOwner();
    bool Reserve(const std::shared_ptr<Channel>&);
    bool Activate(const std::shared_ptr<Channel>&);
    void Unbind(const std::shared_ptr<Channel>&);
    bool Submit(const std::shared_ptr<Channel>&, uint32_t command, std::vector<uint8_t> payload);
    Json Describe() const;
    bool Matches(const std::string& backend, const std::string& scope, uint32_t pid) const;
    bool MatchesRequest(const std::string& backend, const std::string& requestId) const;
    std::string LaunchKey() const;
    Json StartupFailure() const;
    ULONGLONG Expiry() const;
    bool Closing() const;
    bool CleanupReady() const;
    bool HasPendingWork(const std::shared_ptr<Channel>&) const;
    void Stop();
    void Notify(std::function<void()> notify);
private:
    struct Request { uint32_t command; std::vector<uint8_t> payload; uint64_t epoch; };
    struct Frame { uint32_t command; std::vector<uint8_t> payload; };
    bool Initialize(const BackendProfile&, const Json&, std::string& code);
    void CaptureStartupFailure(Json&) const;
    bool StartupError(DWORD error) { startupError_ = error; return false; }
    static void CALLBACK AgentExited(void*, BOOLEAN);
    bool BackendUnavailable() const; // mutex_ held
    void OnEvent(uint32_t, const uint8_t*, uint32_t);
    bool Send(const std::shared_ptr<Channel>&, uint32_t, const void*, uint32_t);
    bool FlushEvents();
    void Worker();
    std::vector<uint8_t> Execute(const Request&, bool& response);
    bool FinalRequestPending() const; // mutex_ held: Detach/Shutdown queued or running, reply owed
    bool ResumeLaunchThread(uint32_t requestedThread);
    mutable std::mutex mutex_;
    std::mutex sendMutex_, launchMutex_;
    std::condition_variable cv_;
    std::unique_ptr<PipeClient> backend_;
    std::shared_ptr<Channel> peer_;
    std::thread worker_;
    std::deque<Request> requests_;
    std::deque<Frame> events_;
    size_t eventBytes_ = 0, requestBytes_ = 0;
    uint64_t epoch_ = 0;
    bool active_ = false, inFlight_ = false, closing_ = false, stopped_ = false;
    bool outcomeUnknown_ = false, releaseTarget_ = false, ending_ = false, published_ = false;
    ULONGLONG disconnectedAt_ = 0;
    std::function<void()> notify_;
    std::string id_, backendName_, scope_, requestId_;
    const char* startupStage_ = "validation";
    DWORD startupError_ = 0;
    StartupDiagnosticChannel startupDiagnostics_;
    uint32_t pid_ = 0, addressBits_ = 0, mainThreadId_ = 0;
    HANDLE agentWait_ = nullptr;
    HANDLE agentProcess_ = nullptr, targetProcess_ = nullptr, primaryThread_ = nullptr, job_ = nullptr;
};
} // namespace veh::remote
