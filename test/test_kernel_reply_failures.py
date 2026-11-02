"""Malformed KD replies must not fabricate values or hide command failures."""
import socket
from mcp_test_client import McpClient
from test_kernel_debug_protocol import Stub


class FaultStub(Stub):
    def __init__(self):
        self.mode = "normal"
        self.memory_reads = []
        self.memory_writes = []
        super().__init__()

    def packet(self, text):
        if text.startswith("m"):
            self.commands.append(text)
            address, count = (int(part, 16) for part in text[1:].split(","))
            self.memory_reads.append((address, count))
            if self.mode == "invalid-memory":
                self.send("zz" * count)
            elif self.mode == "odd-memory":
                self.send("123")
            elif self.mode == "oversized-memory":
                self.send("90" * (count + 1))
            elif self.mode == "short-memory":
                self.send("90c3")
            else:
                self.send("90" * count)
        elif text.startswith("M"):
            self.commands.append(text)
            self.memory_writes.append(text)
            self.send("OK")
        elif text == "g" and self.mode == "invalid-registers":
            self.commands.append(text)
            self.send("z" * (2 * (17 * 8 + 4)))
        elif text == "g" and self.mode.startswith("unavailable-"):
            self.commands.append(text)
            registers = bytearray(17 * 8 + 4)
            registers[8:16] = (0x1234).to_bytes(8, "little")
            registers[16 * 8:17 * 8] = (0x1000).to_bytes(8, "little")
            encoded = registers.hex()
            if self.mode == "unavailable-rax":
                encoded = "x" * 16 + encoded[16:] + "x" * 8  # optional CS unavailable too
            elif self.mode == "unavailable-rip":
                encoded = encoded[:16 * 16] + "x" * 16 + encoded[17 * 16:]
            else:
                encoded = "x" * len(encoded)
            self.send(encoded)
        elif text.startswith("qRcmd,"):
            command = bytes.fromhex(text.split(",", 1)[1]).decode()
            if command.startswith("probe"):
                self.commands.append(text)
                if self.mode == "monitor-error":
                    self.send("E01")
                elif self.mode == "monitor-invalid":
                    self.send("Ozz")
                    self.send("OK")
                elif self.mode == "monitor-drop":
                    self.stop.set()
                    self.peer.shutdown(socket.SHUT_RDWR)
                else:
                    self.send("O" + b"probe-ok".hex())
                    self.send("OK")
            elif command.startswith("r rax ="):
                self.commands.append(text)
                self.send("OK")
            else:
                super().packet(text)
        elif text == "p0":
            self.commands.append(text)
            if self.mode == "write-verify-error":
                self.send("E01")
            elif self.mode == "write-unavailable":
                self.send("x" * 16)
            else:
                self.send((1).to_bytes(8, "little").hex())
        elif text.startswith("vCont;s"):
            self.commands.append(text)
            self.send("T05thread:0a;")
        else:
            super().packet(text)


def run():
    stub = FaultStub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        for mode in ("monitor-error", "monitor-invalid"):
            stub.mode = mode
            result = client.tool("veh_kd_monitor", {"command": "probe"})
            assert "error" in result and "output" not in result, (mode, result)
            assert ("E01" if mode == "monitor-error" else "Invalid monitor console hex") in result.get("diagnostic", ""), result
            stub.mode = "normal"
            assert client.tool("veh_kd_monitor", {"command": "probe"}).get("output") == "probe-ok"
            assert client.tool("veh_kd_registers").get("rip") == "0x1000"

        for mode in ("invalid-memory", "odd-memory", "oversized-memory"):
            stub.mode = mode
            result = client.tool("veh_kd_memory", {"address": "0x1000", "size": 4})
            assert "error" in result and "hex" not in result, (mode, result)
        stub.mode = "invalid-registers"
        result = client.tool("veh_kd_registers")
        assert "error" in result and "rip" not in result, result
        stub.mode = "unavailable-rax"
        result = client.tool("veh_kd_registers")
        assert "error" not in result and "rax" not in result and "cs" not in result, result
        assert result.get("rbx") == "0x1234" and result.get("rip") == "0x1000", result
        assert result.get("unavailable_registers") == ["rax", "cs"], result
        stub.mode = "unavailable-all"
        result = client.tool("veh_kd_registers")
        assert "error" not in result and "rip" not in result, result
        assert len(result.get("unavailable_registers", [])) == 18, result
        stub.mode = "unavailable-rip"
        before = sum(command.startswith("vCont;s") for command in stub.commands)
        result = client.tool("veh_kd_step", {"timeout_ms": 200})
        assert "error" in result and sum(command.startswith("vCont;s") for command in stub.commands) == before, result

        stub.mode = "short-memory"
        before = len(stub.memory_reads)
        result = client.tool("veh_kd_memory", {"address": "0x1000", "size": 0x7F4})
        assert result.get("size") == 2 and result.get("hex") == "90c3", result
        assert stub.memory_reads[before:] == [(0x1000, 0x7F0)], stub.memory_reads[before:]
        before = len(stub.memory_reads)
        result = client.tool("veh_kd_memory", {"operation": "disassemble", "address": "0x1000", "count": 286331154})
        assert len(result.get("instructions", [])) == 2, result
        assert stub.memory_reads[before:] == [(0x1000, 0x7F0)], stub.memory_reads[before:]

        stub.mode = "normal"
        for invalid in ("90xx90", "9", "90:90"):
            before = len(stub.memory_writes)
            result = client.tool("veh_kd_memory", {"operation": "write", "address": "0x1000", "data": invalid})
            assert "error" in result and len(stub.memory_writes) == before, (invalid, result)
        result = client.tool("veh_kd_memory", {"operation": "write", "address": "0x1000", "data": "90 c3\n90"})
        assert result.get("success") and result["size"] == 3, result
        for address in ("0x1000zz", "-1", "0x10000000000000000", "0x"):
            before = len(stub.memory_writes)
            refused = client.tool("veh_kd_memory", {"operation": "write", "address": address, "data": "90"})
            assert "error" in refused and len(stub.memory_writes) == before, refused
        for args in ({"size": 2}, {"operation": "write", "data": "90c3"}):
            before = len(stub.memory_reads) + len(stub.memory_writes)
            refused = client.tool("veh_kd_memory", dict(args, address="0xffffffffffffffff"))
            assert "error" in refused and len(stub.memory_reads) + len(stub.memory_writes) == before, refused
        for value in ("0x1zz", "-1", "0x10000000000000000"):
            before = len(stub.commands)
            refused = client.tool("veh_kd_set_register", {"name": "rax", "value": value})
            assert "error" in refused and len(stub.commands) == before, refused
        for tool, args in (("veh_kd_memory", {"operation": "write", "data": "90"}),
                           ("veh_kd_set_register", {"name": "rax"})):
            before = len(stub.commands)
            refused = client.tool(tool, args)
            assert "error" in refused and len(stub.commands) == before, refused

        # Silent DBGC assignment is valid; only the independent readback proves its value.
        same = client.tool("veh_kd_set_register", {"cpu": 0, "name": "rax", "value": "0x1"})
        assert same.get("success"), same
        for mode, value, expected in (("write-verify-error", "0x1", "E01"),
                                      ("write-unavailable", "0x1", "x" * 16),
                                      ("normal", "0x2", "0100000000000000")):
            stub.mode = mode
            failed = client.tool("veh_kd_set_register", {"cpu": 0, "name": "rax", "value": value})
            assert "error" in failed and failed.get("console") == "", (mode, failed)
            assert failed.get("monitor_completed") and failed.get("verification_completed"), failed
            assert failed.get("verification_reply") == expected, failed
            assert "p0" in failed.get("protocol_trace", "") and len(failed["protocol_trace"]) <= 400, failed
        stub.mode = "normal"

        stepped = client.tool("veh_kd_step", {"cpu": 9, "timeout_ms": 200})
        assert stepped.get("steps") == 1, stepped
        assert "Hga" in stub.commands and "vCont;s:a" in stub.commands and "vCont;s:10" not in stub.commands, stub.commands
        for cpu in (-1, 64, 2147483647):
            before = len(stub.commands)
            refused = client.tool("veh_kd_step", {"cpu": cpu, "timeout_ms": 200})
            assert "error" in refused and len(stub.commands) == before, refused
        assert client.tool("veh_kd_continue").get("running")
        before = len(stub.commands)
        refused = client.tool("veh_kd_set_register", {"name": "rax", "value": "0x1"})
        assert "running" in refused.get("error", "") and len(stub.commands) == before, refused
        assert client.tool("veh_kd_break", {"timeout_ms": 1500}).get("running") is False
        assert client.tool("veh_kd_disconnect").get("detached")
        print("PASS KD monitor errors/alignment, strict hex, contiguous prefixes, write admission, CPU routing and running-register refusal")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def check_lost_monitor():
    stub = FaultStub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        stub.mode = "monitor-drop"
        failed = client.tool("veh_kd_monitor", {"command": "probe"})
        assert "error" in failed and "output" not in failed, failed
        failed = client.tool("veh_kd_registers")
        assert "error" in failed and "rip" not in failed, failed
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


if __name__ == "__main__":
    run()
    check_lost_monitor()
