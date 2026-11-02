// Deterministic read boundaries for the production RSP client, without a VM.
#include "../src/mcp/kernel_debug_client.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace {
void Check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }

class FragmentTransport : public veh::KdTransport {
public:
    FragmentTransport(size_t fragment, bool no_ack) : fragment_(fragment), no_ack_(no_ack) {
        Queue("T05thread:01;"); Queue("T05thread:01;"); // unsolicited, coalesced before negotiation
    }
    bool Write(const void* data, size_t size) override {
        const std::string frame(static_cast<const char*>(data), size);
        if (frame == "+") return true;
        Check(frame.size() >= 4 && frame[0] == '$', "unexpected client frame");
        const auto command = frame.substr(1, frame.find('#') - 1);
        if (command.find("qSupported:") == 0) {
            Queue(no_ack_ ? "PacketSize=4000;QStartNoAckMode+" : "qXfer:features:read+;vContSupported+");
        } else if (command == "QStartNoAckMode") {
            Check(no_ack_, "unadvertised QStartNoAckMode must not be sent");
            Queue("OK");
        }
        else if (command == "?") { Queue("T05thread:01;"); Queue("T05thread:01;"); }
        else if (command == "qRcmd,7220") {
            Queue("O7269703d"); Queue("S05"); Queue("O307831303030"); Queue("OK");
        } else if (command == "qRcmd,7720") {
            if (!no_ack_ && rejected_frame_.empty()) {
                rejected_frame_ = frame;
                incoming_ += "-"; // reject once, then accept only the identical frame
            } else {
                Check(no_ack_ || frame == rejected_frame_, "NAK retry changed command bytes");
                Queue("OK");
            }
        }
        else if (command == "p0") Queue("8877665544332211");
        else if (command == "c") {
            Queue("T05thread:01;");
            Queue("O0a64626766206576656e743a20427265616b706f696e7420");
            Queue("O30"); Queue("O212028"); Queue("O726177"); Queue("O290a");
            Queue("O7269703d3078313030300a"); Queue("O25"); Queue("O636320696e74330a");
            Queue("T05thread:01;");
        } else if (command == "z0,1000,1") Queue("OK");
        else throw std::runtime_error("unexpected command: " + command);
        return true;
    }
    int Read(uint8_t* buffer, size_t max, uint32_t) override {
        Check(!incoming_.empty(), "unexpected wait with no reply");
        const size_t count = std::min({max, fragment_, incoming_.size()});
        std::memcpy(buffer, incoming_.data(), count);
        incoming_.erase(0, count);
        return static_cast<int>(count);
    }
private:
    void Queue(std::string payload) {
        payload += '\0'; // VirtualBox includes a NUL within the checksum.
        uint8_t sum = 0;
        for (unsigned char c : payload) sum = static_cast<uint8_t>(sum + c);
        static const char hex[] = "0123456789abcdef";
        incoming_ += "+$" + payload + "#" + hex[sum >> 4] + hex[sum & 15];
    }
    size_t fragment_;
    bool no_ack_;
    std::string incoming_;
    std::string rejected_frame_;
};

class RejectTransport : public veh::KdTransport {
public:
    explicit RejectTransport(bool acknowledged) : acknowledged_(acknowledged) {}
    bool Write(const void* data, size_t size) override {
        const std::string frame(static_cast<const char*>(data), size);
        if (frame == "+") return true;
        if (!writes.empty()) Check(frame == writes.front(), "retry changed frame bytes");
        writes.push_back(frame);
        pending_ += acknowledged_ ? "+-" : "-";
        return true;
    }
    int Read(uint8_t* buffer, size_t, uint32_t) override {
        if (pending_.empty()) return 0;
        *buffer = static_cast<uint8_t>(pending_[0]);
        pending_.erase(0, 1);
        return 1;
    }
    std::vector<std::string> writes;
private:
    bool acknowledged_;
    std::string pending_;
};

void RunRejected(bool acknowledged) {
    auto transport = std::make_unique<RejectTransport>(acknowledged);
    auto* peer = transport.get();
    veh::KernelDebugClient client(std::move(transport));
    std::string reply;
    Check(!client.Request("M1000,1:90", &reply, 20), "rejected request succeeded");
    Check(peer->writes.size() == (acknowledged ? 1 : 4), "NAK retry bound or accepted-frame guard");
    if (!acknowledged)
        Check(client.wait_diagnostic().find("NAK retry limit") != std::string::npos, "retry-limit diagnostic");
    const auto before = peer->writes.size();
    Check(!client.Request("m2000,1", &reply, 20) && peer->writes.size() == before,
          "new request submitted while prior response incomplete or link failed");
}

void Run(size_t fragment, bool no_ack) {
    veh::KernelDebugClient client(std::make_unique<FragmentTransport>(fragment, no_ack));
    std::string stop, error, reply;
    Check(client.Handshake(&stop, &error), "handshake");
    Check(client.Monitor("7220", &reply) && reply == "7269703d307831303030", "initial monitor");
    Check(client.Monitor("7720", &reply) && reply.empty(), "silent write command");
    Check(client.Request("p0", &reply) && reply == "8877665544332211", "write verification");
    Check(client.Resume("c") && client.WaitStop(&stop, 1000), "breakpoint stop");
    Check(client.Request("z0,1000,1", &reply) && reply == "OK", "remove drains console and second stop");
    Check(client.Monitor("7220", &reply) && reply == "7269703d307831303030", "post-breakpoint monitor");
}
}
int main() {
    try {
        for (bool no_ack : {false, true})
            for (size_t fragment : {size_t(1), size_t(2), size_t(3), size_t(7), size_t(64), size_t(4096)})
                Run(fragment, no_ack);
        RunRejected(false);
        RunRejected(true);
        std::cout << "PASS KD read fragmentation: 12 ACK/no-ACK scenarios, NAK retries/limits, accepted-frame guard and duplicate stops\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
