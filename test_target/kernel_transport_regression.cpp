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
        } else if (command == "qRcmd,7720") Queue("OK"); // successful silent command
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
};

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
        std::cout << "PASS KD read fragmentation: 12 ACK/no-ACK scenarios, silent write verification and duplicate breakpoint stops\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
