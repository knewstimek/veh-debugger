#include "adapter/pipe_client.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>

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
        std::puts("PASS pipe write-completion race poisons both request paths and preserves cleanup");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
