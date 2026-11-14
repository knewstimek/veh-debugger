#include "work_owner.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <algorithm>

namespace {
using namespace veh;
using namespace veh::remote;
constexpr uintptr_t invalidSocket = ~uintptr_t(0);
std::atomic<uintptr_t> listener{invalidSocket};
HANDLE shutdownEvent = nullptr;
BOOL WINAPI Interrupt(DWORD signal) {
    if (signal != CTRL_C_EVENT && signal != CTRL_BREAK_EVENT && signal != CTRL_CLOSE_EVENT &&
        signal != CTRL_SHUTDOWN_EVENT) return FALSE;
    if (shutdownEvent) SetEvent(shutdownEvent);
    CloseSocket(listener.exchange(invalidSocket));
    return TRUE;
}
std::wstring Wide(const std::string& text) {
    if (text.find('\0') != std::string::npos) throw std::invalid_argument("string");
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!text.empty() && !n) throw std::invalid_argument("utf8");
    std::wstring result(n, L'\0');
    if (n) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), n);
    return result;
}
bool HexId(const std::string& id) {
    return id.size() == 64 && std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}
uint32_t Unsigned(const Json& value) {
    if (!value.is_number_unsigned() || value.get<uint64_t>() > UINT32_MAX) throw std::invalid_argument("number");
    return value.get<uint32_t>();
}
struct Configuration {
    std::string address, certificate;
    std::wstring tokenFile;
    uint16_t port = 0;
    std::map<std::string, BackendProfile> backends;
};
Configuration Load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input || std::filesystem::file_size(path) > 65536) throw std::invalid_argument("profile");
    auto json = Json::parse(input);
    Configuration config;
    config.address = json.at("listen").at("address").get<std::string>();
    auto port = Unsigned(json.at("listen").at("port"));
    if (!port || port > 65535) throw std::invalid_argument("port");
    config.port = static_cast<uint16_t>(port);
    config.certificate = json.at("certificate_sha256").get<std::string>();
    if (!HexId(config.certificate) || json.contains("token") || json.contains("password")) throw std::invalid_argument("profile");
    auto resolve = [&](const std::string& value) {
        std::filesystem::path p(Wide(value));
        if (p.empty()) throw std::invalid_argument("path");
        return (p.is_absolute() ? p : path.parent_path() / p).lexically_normal().wstring();
    };
    config.tokenFile = resolve(json.at("token_file").get<std::string>());
    const auto& profiles = json.at("backends");
    if (!profiles.is_object() || profiles.empty() || profiles.size() > 32) throw std::invalid_argument("backends");
    for (auto it = profiles.begin(); it != profiles.end(); ++it) {
        if (it.key().empty() || it.key().size() > 64 ||
            !std::all_of(it.key().begin(), it.key().end(), [](unsigned char c) { return isalnum(c) || c == '_' || c == '-'; }))
            throw std::invalid_argument("alias");
        BackendProfile profile;
        profile.executable = resolve(it.value().at("path").get<std::string>());
        profile.scope = it.value().at("target_scope").get<std::string>();
        profile.allowLaunch = it.value().value("allow_launch", false);
        if ((profile.scope != "host" && profile.scope != "guest" && profile.scope != "vm") ||
            (profile.scope != "host" && profile.allowLaunch)) throw std::invalid_argument("scope");
        const auto args = it.value().value("args", Json::array());
        if (!args.is_array() || args.size() > 128) throw std::invalid_argument("args");
        for (const auto& arg : args) profile.args.push_back(Wide(arg.get<std::string>()));
        if (it.value().contains("stderr_file"))
            profile.stderrFile = resolve(it.value().at("stderr_file").get<std::string>());
        config.backends.emplace(it.key(), std::move(profile));
    }
    return config;
}
class Registry {
public:
    explicit Registry(const Configuration& config) : config_(config), reaper_([this] { Reap(); }) {}
    ~Registry() {
        std::vector<std::shared_ptr<WorkOwner>> owners;
        { std::lock_guard<std::mutex> lock(mutex_); stopping_ = true; owners.swap(owners_); cv_.notify_all(); }
        for (auto& owner : owners) owner->Stop();
        reaper_.join();
    }
    std::shared_ptr<WorkOwner> Open(const Json& request, const std::shared_ptr<Channel>& peer, std::string& code, bool& outcomeUnknown, Json& diagnostics) {
        diagnostics = Json::object();
        outcomeUnknown = false;
        code = "invalid";
        const auto name = request.at("backend").get<std::string>();
        const auto scope = request.at("target_scope").get<std::string>();
        const auto operation = request.at("operation").get<std::string>();
        const auto pid = Unsigned(request.at("pid"));
        auto profile = config_.backends.find(name);
        if (profile == config_.backends.end() || profile->second.scope != scope ||
            (operation != "attach" && operation != "launch") ||
            (operation == "attach" && (scope == "vm" ? pid != 0 : pid == 0))) return {};
        if (operation == "launch" && (scope != "host" || !profile->second.allowLaunch)) { code = "unsupported"; return {}; }
        std::string requestId;
        if (operation == "launch") {
            requestId = request.at("request_id").get<std::string>();
            if (pid || !HexId(requestId)) return {};
        }
        // Serialize creation without blocking other clients behind backend startup.
        std::unique_lock<std::mutex> creation(createMutex_, std::try_to_lock);
        if (!creation.owns_lock()) { code = "busy"; outcomeUnknown = true; return {}; }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) { code = "unavailable"; return {}; }
            PruneLaunches();
            if (operation == "launch" && retiredLaunches_.count(name + ":" + requestId)) {
                code = "expired"; outcomeUnknown = true; return {};
            }
            for (const auto& owner : owners_) {
                if (owner->Closing()) {
                    // Attach needs a fresh agent, not a retiring/dead transport.
                    // A launch retry must still not create a duplicate request.
                    if (operation == "launch" && owner->MatchesRequest(name, requestId)) {
                        code = "expired"; outcomeUnknown = true; return {};
                    }
                    continue;
                }
                if ((operation == "launch" && owner->MatchesRequest(name, requestId)) ||
                    (operation == "attach" && owner->Matches(name, scope, pid))) {
                    if (!owner->Reserve(peer)) { code = owner->Closing() ? "expired" : "busy"; outcomeUnknown = true; return {}; }
                    return owner;
                }
            }
            if (owners_.size() >= 32) { code = "busy"; return {}; }
            const auto launchCount = std::count_if(owners_.begin(), owners_.end(),
                [](const auto& owner) { return !owner->LaunchKey().empty(); });
            if (operation == "launch" && retiredLaunches_.size() + launchCount >= 128) { code = "busy"; return {}; }
        }
        auto owner = WorkOwner::Open(profile->second, request, code, diagnostics);
        if (!owner) return {};
        owner->Notify([this] { cv_.notify_all(); });
        if (!owner->Reserve(peer)) { diagnostics = owner->StartupFailure(); owner->Stop(); code = "expired"; return {}; }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            owners_.push_back(owner); cv_.notify_all();
        }
        return owner;
    }
private:
    void PruneLaunches() {
        const auto now = GetTickCount64();
        for (auto it = retiredLaunches_.begin(); it != retiredLaunches_.end();) {
            if (it->second <= now) it = retiredLaunches_.erase(it); else ++it;
        }
    }
    void Reap() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stopping_) {
            auto next = GetTickCount64() + 60000;
            std::vector<std::shared_ptr<WorkOwner>> expired;
            for (auto it = owners_.begin(); it != owners_.end();) {
                const auto expiry = (*it)->Expiry();
                if ((*it)->CleanupReady() || (expiry && expiry <= GetTickCount64())) {
                    const auto key = (*it)->LaunchKey();
                    // Longer than the frontend's 60-second uncertain retry window.
                    // Preserve deduplication after the old agent's work is removed.
                    if (!key.empty()) retiredLaunches_[key] = GetTickCount64() + 120000;
                    expired.push_back(*it); it = owners_.erase(it);
                } else { if (expiry) next = std::min(next, expiry); ++it; }
            }
            if (!expired.empty()) {
                lock.unlock();
                for (auto& owner : expired) owner->Stop();
                lock.lock(); continue;
            }
            const auto now = GetTickCount64();
            cv_.wait_for(lock, std::chrono::milliseconds(next > now ? next - now : 1));
        }
    }
    const Configuration& config_;
    std::mutex mutex_, createMutex_;
    std::condition_variable cv_;
    bool stopping_ = false;
    std::vector<std::shared_ptr<WorkOwner>> owners_;
    std::map<std::string, ULONGLONG> retiredLaunches_;
    std::thread reaper_;
};
struct Attempts {
    ULONGLONG start = 0;
    unsigned failures = 0;
};
void Serve(const std::shared_ptr<Channel>& channel, uintptr_t socket, const Configuration& config,
    Registry& registry, std::atomic<bool>& authenticated) {
    std::shared_ptr<WorkOwner> owner;
    try {
        const auto deadline = GetTickCount64() + 8000;
        auto remaining = [&] { const auto now = GetTickCount64(); return now < deadline ? static_cast<int>(deadline - now) : 0; };
        if (!channel->Accept(socket, config.certificate, remaining()) ||
            !AuthenticateServer(*channel, config.tokenFile, remaining())) { channel->Cancel(); return; }
        authenticated = true;
        std::vector<uint8_t> bytes;
        if (!ReadControl(*channel, Control::OpenWork, bytes, remaining())) { channel->Cancel(); return; }
        auto request = Json::parse(bytes, nullptr, true, false);
        if (!request.is_object()) throw std::invalid_argument("request");
        std::string code; bool outcomeUnknown = true; Json diagnostics;
        owner = registry.Open(request, channel, code, outcomeUnknown, diagnostics);
        Json reply = owner ? owner->Describe() : Json{{"success", false}, {"code", code}, {"outcome_unknown", outcomeUnknown}};
        if (!owner && diagnostics.is_object() && !diagnostics.empty()) reply["diagnostics"] = std::move(diagnostics);
        auto text = reply.dump();
        if (!WriteControl(*channel, Control::Work, text.data(), static_cast<uint32_t>(text.size()), 5000) || !owner) {
            if (owner) owner->Unbind(channel);
            channel->Cancel(); return;
        }
        IpcHeader ready{static_cast<uint32_t>(IpcEvent::Ready), 0};
        if (!channel->Write(&ready, sizeof(ready), 5000) || !owner->Activate(channel)) {
            owner->Unbind(channel); channel->Cancel(); return;
        }
        for (;;) {
            IpcHeader header{};
            if (!channel->Read(&header, sizeof(header), 15000)) {
                // Synchronous commands suppress frontend heartbeats. An empty
                // input timeout is not disconnection while bounded work owns it.
                // Partial frames and socket errors still terminate the connection.
                if (GetLastError() == WAIT_TIMEOUT && owner->HasPendingWork(channel)) continue;
                break;
            }
            if (header.command >= 0x1000 || header.payloadSize > 64 * 1024 * 1024) break;
            std::vector<uint8_t> payload(header.payloadSize);
            if (header.payloadSize && !channel->Read(payload.data(), payload.size(), 15000)) break;
            if (!owner->Submit(channel, header.command, std::move(payload))) break;
        }
    } catch (...) {
        // Fixed status only: parsed requests, exception messages and credentials never enter logs.
    }
    if (owner) owner->Unbind(channel);
    channel->Cancel();
}
struct Client {
    std::shared_ptr<Channel> channel;
    std::shared_ptr<std::atomic<bool>> done, authenticated;
    std::string address;
    std::thread thread;
};
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 3 || std::wstring(argv[1]) != L"--profile") {
        std::cerr << "Usage: veh-remote-runner --profile <private-profile.json>\n"; return 2;
    }
    shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!shutdownEvent) return 1;
    SetConsoleCtrlHandler(Interrupt, TRUE);
    int result = 0;
    try {
        const auto config = Load(std::filesystem::absolute(argv[2]));
        Registry registry(config);
        std::vector<Client> clients;
        std::map<std::string, Attempts> attempts;
        listener = Listen(config.address, config.port);
        if (listener == invalidSocket) throw std::runtime_error("listen");
        std::cerr << "Remote runner listening; guest process launch unsupported.\n";
        while (WaitForSingleObject(shutdownEvent, 0) == WAIT_TIMEOUT) {
            std::string address;
            const auto socket = AcceptSocket(listener, address);
            if (socket == invalidSocket) break;
            const auto now = GetTickCount64();
            for (auto it = clients.begin(); it != clients.end();) {
                if (*it->done) {
                    it->thread.join();
                    if (!*it->authenticated) {
                        auto& budget = attempts[it->address];
                        if (!budget.start || now - budget.start >= 60000) { budget.start = now; budget.failures = 0; }
                        ++budget.failures;
                    }
                    it = clients.erase(it);
                } else ++it;
            }
            for (auto it = attempts.begin(); it != attempts.end();) {
                const bool pending = std::any_of(clients.begin(), clients.end(), [&](const auto& client) {
                    return client.address == it->first && !*client.authenticated;
                });
                if (now - it->second.start >= 60000) { it->second.start = now; it->second.failures = 0; }
                // Successful authentication consumes no retry budget. Preserve
                // failure history across successes and entries for pending auth.
                if (!pending && !it->second.failures) it = attempts.erase(it); else ++it;
            }
            if (clients.size() >= 8 || (attempts.find(address) == attempts.end() && attempts.size() >= 128)) {
                CloseSocket(socket); continue;
            }
            auto& budget = attempts[address];
            if (!budget.start) budget.start = now;
            const auto pending = std::count_if(clients.begin(), clients.end(), [&](const auto& client) {
                return client.address == address && !*client.authenticated;
            });
            if (budget.failures + pending >= 5) { CloseSocket(socket); continue; }
            auto channel = std::make_shared<Channel>();
            auto done = std::make_shared<std::atomic<bool>>(false);
            auto authenticated = std::make_shared<std::atomic<bool>>(false);
            clients.push_back({channel, done, authenticated, address, std::thread([&, channel, done, authenticated, socket] {
                Serve(channel, socket, config, registry, *authenticated); *done = true;
            })});
        }
        CloseSocket(listener.exchange(invalidSocket));
        for (auto& client : clients) client.channel->Cancel();
        for (auto& client : clients) client.thread.join();
    } catch (...) { std::cerr << "Remote runner could not start with this profile.\n"; result = 1; }
    CloseSocket(listener.exchange(invalidSocket));
    SetConsoleCtrlHandler(Interrupt, FALSE);
    CloseHandle(shutdownEvent); shutdownEvent = nullptr;
    return result;
}
