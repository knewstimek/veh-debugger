"""Explicit RSP NAKs retry the rejected write without replaying accepted work."""
from mcp_test_client import McpClient
from test_kernel_reply_failures import FaultStub


class NakStub(FaultStub):
    def __init__(self):
        self.write_attempts = []
        self.executions = 0
        self.reject_forever = False
        super().__init__()

    def packet(self, text):
        if text.startswith("qRcmd,"):
            command = bytes.fromhex(text[6:]).decode()
            if command.startswith("r rax ="):
                self.commands.append(text)
                self.write_attempts.append(text)
                if len(self.write_attempts) == 1 or self.reject_forever:
                    self.peer.sendall(b"-")
                    return
                assert text == self.write_attempts[0], self.write_attempts
                self.peer.sendall(b"+")
                self.executions += 1
                self.send("OK")
                return
        self.peer.sendall(b"+")
        if text == "g":
            self.commands.append(text)
            registers = bytearray(17 * 8 + 4)
            registers[:8] = (1).to_bytes(8, "little")
            registers[16 * 8:17 * 8] = (0x1000).to_bytes(8, "little")
            self.send(registers.hex())
        elif text.startswith("qSupported"):
            self.commands.append(text)
            self.send("qXfer:features:read+;vContSupported+")
        else:
            super().packet(text)


def check(reject_forever):
    stub = NakStub()
    stub.reject_forever = reject_forever
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {
            "transport": "tcp", "address": f"127.0.0.1:{stub.port}",
        }).get("halted")
        registers = client.tool("veh_kd_registers", {"cpu": 0})
        assert registers.get("rip") == "0x1000", registers
        assert not any(command == "qRcmd," + b"regs ".hex() for command in stub.commands)
        assert registers.get("rax") == "0x1", registers
        result = client.tool("veh_kd_set_register", {"cpu": 0, "name": "rax", "value": registers["rax"]}, timeout=17)
        if reject_forever:
            assert "error" in result and "NAK retry limit" in result.get("monitor_diagnostic", ""), result
            assert len(stub.write_attempts) == 4 and stub.executions == 0, stub.write_attempts
            before = len(stub.commands)
            failed = client.tool("veh_kd_memory", {"address": "0x2000", "size": 1})
            assert "error" in failed and len(stub.commands) == before, failed
        else:
            assert result.get("success"), result
            assert len(stub.write_attempts) == 2 and stub.executions == 1, stub.write_attempts
            assert client.tool("veh_kd_monitor", {"command": "r"}).get("output") == "rip=0x1000"
            assert client.tool("veh_kd_disconnect").get("detached")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def run():
    check(False)
    check(True)
    print("PASS KD ACK-mode NAK recovery: identical retry, single execution, bounded rejection and no unsupported DBGC regs probe")


if __name__ == "__main__":
    run()
