"""A peer's unsupported no-ACK negotiation must never precede its stop query."""
from mcp_test_client import McpClient
from test_kernel_debug_protocol import Stub


class AckOnlyStub(Stub):
    def packet(self, text):
        if text.startswith("qSupported"):
            self.commands.append(text)
            payload = b"T05thread:01;"
            frame = b"$" + payload + b"#07"
            self.peer.sendall(frame + frame)  # two complete stops in one write
            self.send("qXfer:features:read+;vContSupported+")
        elif text == "QStartNoAckMode":
            self.commands.append(text)
            # No reply to an unadvertised command: do not create that exchange.
        else:
            super().packet(text)


def run():
    stub = AckOnlyStub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        connected = client.tool("veh_kd_connect", {
            "transport": "tcp", "address": f"127.0.0.1:{stub.port}",
        }, timeout=15)
        assert connected.get("halted"), connected
        assert "QStartNoAckMode" not in stub.commands, stub.commands
        assert "?" in stub.commands
        assert client.tool("veh_kd_registers").get("rip") == "0x1000"
        assert client.tool("veh_kd_monitor", {"command": "r"}).get("output") == "rip=0x1000"
        assert client.tool("veh_kd_disconnect").get("detached")
        print("PASS ACK-only handshake: coalesced duplicate stops; no unadvertised negotiation; subsequent commands aligned")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


if __name__ == "__main__":
    run()
