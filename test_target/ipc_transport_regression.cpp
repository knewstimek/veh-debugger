#include "adapter/pipe_client.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <deque>
#include <future>
#include <chrono>

namespace {
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }

// The peer has accepted the entire frame, but completion races with cancellation.
// A following request would see the peer's stale success if this pipe is reused.
class CompletionRace : public veh::PipeClient {
public:
    explicit CompletionRace(bool reader) {
        connected_ = true;
        running_ = reader;
    }
    int writes = 0, reads = 0;
protected:
    bool AsyncWriteExact(const void*, DWORD, DWORD) override {
        ++writes;
        if (writes == 1) { SetLastError(WAIT_TIMEOUT); return false; }
        return true;
    }
    bool AsyncReadExact(void* data, DWORD size, DWORD) override {
        ++reads;
        std::memset(data, 0, size);
        if (size == sizeof(veh::IpcHeader)) {
            const veh::IpcHeader stale{static_cast<uint32_t>(veh::IpcCommand::GetThreads), sizeof(veh::IpcStatus)};
            std::memcpy(data, &stale, sizeof(stale));
        }
        return true;
    }
};
class RoutedPeer : public veh::PipeClient {
public:
    RoutedPeer() { connected_ = true; StartEventListener({}); }
    ~RoutedPeer() { StopEventListener(); }
    bool waitSent(veh::IpcCommand command, size_t count = 1, int ms = 500) {
        std::unique_lock<std::mutex> lock(mutex);
        return changed.wait_for(lock, std::chrono::milliseconds(ms),
            [&] { return sent[static_cast<uint32_t>(command)] >= count; });
    }
    void respond(veh::IpcCommand command, uint8_t value) {
        auto frame = veh::BuildIpcMessage(static_cast<uint32_t>(command), &value, 1);
        std::lock_guard<std::mutex> lock(mutex);
        incoming.insert(incoming.end(), frame.begin(), frame.end()); changed.notify_all();
    }
    void breakPeer() { CancelPendingIo(); }
protected:
    bool AsyncWriteExact(const void* data, DWORD size, DWORD) override {
        if (size < sizeof(veh::IpcHeader)) return false;
        veh::IpcHeader header{}; std::memcpy(&header, data, sizeof(header));
        std::lock_guard<std::mutex> lock(mutex);
        ++sent[header.command]; changed.notify_all(); return true;
    }
    bool AsyncReadExact(void* data, DWORD size, DWORD timeout) override {
        std::unique_lock<std::mutex> lock(mutex);
        if (!changed.wait_for(lock, std::chrono::milliseconds(timeout),
            [&] { return closed || incoming.size() >= size; })) {
            SetLastError(WAIT_TIMEOUT); return false;
        }
        if (closed) { SetLastError(ERROR_BROKEN_PIPE); return false; }
        auto* bytes = static_cast<uint8_t*>(data);
        for (DWORD i = 0; i < size; ++i) { bytes[i] = incoming.front(); incoming.pop_front(); }
        return true;
    }
    void CancelPendingIo() override {
        std::lock_guard<std::mutex> lock(mutex); closed = true; changed.notify_all();
    }
private:
    std::mutex mutex;
    std::condition_variable changed;
    std::map<uint32_t, size_t> sent;
    std::deque<uint8_t> incoming;
    bool closed = false;
};

auto request(RoutedPeer& pipe, veh::IpcCommand command, int timeout = 2000) {
    return std::async(std::launch::async, [&pipe, command, timeout] {
        std::vector<uint8_t> bytes;
        const bool ok = pipe.SendAndReceive(command, nullptr, 0, bytes, timeout);
        return std::make_pair(ok, bytes);
    });
}

void routedReplies() {
    using C = veh::IpcCommand;
    for (auto trace : {C::TraceCallers, C::TraceCalls}) {
        RoutedPeer pipe;
        auto collection = request(pipe, trace);
        check(pipe.waitSent(trace), "Trace request not sent");
        auto inspection = request(pipe, C::GetThreads);
        check(pipe.waitSent(C::GetThreads), "Inspection blocked behind collection");
        pipe.respond(C::GetThreads, 0x22);
        check(inspection.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready,
            "Inspection did not finish during collection");
        const auto inspected = inspection.get();
        check(inspected.first && inspected.second == std::vector<uint8_t>{0x22}, "Inspection reply misrouted");
        check(collection.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready,
            "Inspection incorrectly completed trace");
        auto second = request(pipe, trace);
        check(!pipe.waitSent(trace, 2, 40), "Same trace command overlapped");
        auto memory = request(pipe, C::ReadMemory);
        check(pipe.waitSent(C::ReadMemory), "Second inspection blocked");
        // Reverse reply order this time.
        pipe.respond(trace, 0x11);
        pipe.respond(C::ReadMemory, 0x33);
        check(collection.get().second == std::vector<uint8_t>{0x11}, "Trace reply lost");
        check(memory.get().second == std::vector<uint8_t>{0x33}, "Memory reply misrouted");
        check(pipe.waitSent(trace, 2), "Queued trace did not start");
        pipe.respond(trace, 0x44);
        check(second.get().second == std::vector<uint8_t>{0x44}, "Queued trace got old reply");
    }
    {
        // A timeout is one request's failure: the session survives it.
        RoutedPeer pipe;
        auto trace = request(pipe, C::TraceCallers, 100);
        check(pipe.waitSent(C::TraceCallers), "Timeout test trace missing");
        auto inspection = request(pipe, C::GetThreads);
        check(pipe.waitSent(C::GetThreads), "Timeout test inspection blocked");
        check(!trace.get().first, "Timed-out request reported success");
        pipe.respond(C::GetThreads, 0x22);
        check(inspection.get().second == std::vector<uint8_t>{0x22}, "Timeout aborted an unrelated request");
        std::vector<uint8_t> bytes;
        veh::PipeExchangeDiagnostics diagnostics{};
        check(!pipe.SendAndReceive(C::TraceCallers, nullptr, 0, bytes, 2000, &diagnostics) &&
            diagnostics.failure == veh::PipeExchangeFailure::EarlierReplyPending,
            "Same command was sent while its late reply could answer it");
        check(!pipe.waitSent(C::TraceCallers, 2, 40), "Refused request reached the peer");
        pipe.respond(C::TraceCallers, 0x11); // the late reply
        // The reader handles frames in order: once this later reply is delivered,
        // the late trace reply has been consumed.
        auto fence = request(pipe, C::GetThreads);
        check(pipe.waitSent(C::GetThreads, 2), "Fence request missing");
        pipe.respond(C::GetThreads, 0x55);
        check(fence.get().second == std::vector<uint8_t>{0x55}, "Late reply was delivered to another command");
        auto retry = request(pipe, C::TraceCallers);
        check(pipe.waitSent(C::TraceCallers, 2), "Command stayed refused after its late reply");
        pipe.respond(C::TraceCallers, 0x44);
        check(retry.get().second == std::vector<uint8_t>{0x44}, "Late reply answered the next request");
    }
    {
        RoutedPeer pipe;
        auto trace = request(pipe, C::TraceCallers);
        check(pipe.waitSent(C::TraceCallers), "Failure test trace missing");
        auto inspection = request(pipe, C::GetThreads);
        check(pipe.waitSent(C::GetThreads), "Failure test inspection blocked");
        pipe.breakPeer();
        check(!trace.get().first && !inspection.get().first, "Pending requests survived loss");
        std::vector<uint8_t> bytes;
        check(!pipe.SendAndReceive(C::GetThreads, nullptr, 0, bytes, 10), "Failed channel reused");
    }
    std::puts("PASS standard trace routing, concurrent inspection, same-command serialization, "
        "timeout recovery and failure wakeup");
}

}

int main() {
    try {
        for (bool reader : {false, true}) {
            CompletionRace pipe(reader);
            std::vector<uint8_t> response;
            veh::PipeExchangeDiagnostics diagnostics{};
            check(!pipe.SendAndReceive(veh::IpcCommand::GetThreads, nullptr, 0, response, 10, &diagnostics),
                "Canceled write reported success");
            check(diagnostics.failure == veh::PipeExchangeFailure::SendFailed &&
                diagnostics.systemError == WAIT_TIMEOUT, "Write failure reason lost");
            check(!pipe.SendAndReceive(veh::IpcCommand::GetThreads, nullptr, 0, response, 10),
                "Late success answered the next same-command request");
            check(!pipe.SendCommand(veh::IpcCommand::Continue), "Poisoned fire-and-forget request accepted");
            check(pipe.writes == 1 && pipe.reads == 0, "Poisoned stream was reused");
            check(pipe.SendCommand(veh::IpcCommand::Detach), "Poisoned stream could not detach");
            check(pipe.SendCommand(veh::IpcCommand::Shutdown), "Poisoned stream could not shut down");
        }
        routedReplies();
        std::puts("PASS pipe write-completion race poisons both request paths and preserves cleanup");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
