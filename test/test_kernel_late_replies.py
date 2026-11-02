"""Valid late RSP replies must never become another command's result."""
import socket
import threading

from mcp_test_client import McpClient
from test_kernel_reply_failures import FaultStub


class DelayedStub(FaultStub):
    def __init__(self, delayed):
        self.delayed = delayed
        self.delivered = False
        self.waiting = threading.Event()
        self.release = threading.Event()
        super().__init__()

    def packet(self, text):
        if text == self.delayed and not self.delivered:
            self.commands.append(text)
            self.delivered = True
            if text.startswith("qRcmd,"):
                self.send("O" + b"old-".hex())
            self.waiting.set()
            if not self.release.wait(timeout=25):
                raise AssertionError("Delayed fixture response was never released")
            if text.startswith("qRcmd,"):
                self.send("O" + b"tail".hex())
                self.send("OK")
            else:
                self.send("11")
        elif text == "m2000,1":
            self.commands.append(text)
            self.send("22")
        else:
            super().packet(text)


def check_delay(kind, blocked_write=False):
    delayed = "qRcmd," + b"delayed ".hex() if kind == "monitor" else "m1000,1"
    stub = DelayedStub(delayed)
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        if kind == "monitor":
            failed = client.tool("veh_kd_monitor", {"command": "delayed"}, timeout=15)
        else:
            failed = client.tool("veh_kd_memory", {"address": "0x1000", "size": 1}, timeout=8)
        assert "error" in failed and stub.waiting.is_set(), failed
        if blocked_write:
            failed = client.tool("veh_kd_memory", {"operation": "write", "address": "0x2000", "data": "22"}, timeout=8)
            assert "error" in failed, failed
            # The peer is waiting at the old response. Peek, without consuming,
            # proves no later mutating command was transmitted during that wait.
            try:
                queued = stub.peer.recv(4096, socket.MSG_PEEK)
            except socket.timeout:
                queued = b""
            assert not queued, ("new command sent before old reply completed", queued)
        stub.release.set()
        result = client.tool("veh_kd_memory", {"address": "0x2000", "size": 1}, timeout=8)
        assert result.get("hex") == "22", (kind, result)
        assert not stub.memory_writes, stub.memory_writes
        assert client.tool("veh_kd_disconnect").get("detached")
    finally:
        stub.release.set()
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def run():
    check_delay("request")
    check_delay("request", blocked_write=True)
    check_delay("monitor")
    check_pending_stop_query()
    check_breakpoint_console_sequence()
    print("PASS valid delayed request/monitor replies drained before new commands; uncertain exchanges submit no new writes")


def check_pending_stop_query():
    class RunningStub(FaultStub):
        defer_query = False

        def packet(self, text):
            if self.defer_query and (text == "?" or text.startswith("vCont;s")):
                self.commands.append(text)  # no reply until the out-of-band interrupt
            else:
                super().packet(text)

    stub = RunningStub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        stub.defer_query = True
        failed = client.tool("veh_kd_step", {"timeout_ms": 1}, timeout=6)
        assert "error" in failed, failed
        stopped = client.tool("veh_kd_break", {"timeout_ms": 1000}, timeout=3)
        assert stopped.get("stop", {}).get("raw") == "T02thread:01;", stopped
        assert "interrupt" in stub.commands, stub.commands
        assert client.tool("veh_kd_registers").get("rip") == "0x1000"
        assert client.tool("veh_kd_disconnect").get("detached")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def check_breakpoint_console_sequence():
    class BreakpointStub(FaultStub):
        def packet(self, text):
            if text == "c":
                self.commands.append(text)
                self.send("T05thread:01;")
                for chunk in (b"\ndbgf event: Breakpoint ", b"0", b"! (", b"raw", b")\n",
                              b"rip=0000000000001000\n", b"%", b"0000000000001000",
                              b" ", b"cc              int3", b"\n"):
                    self.send("O" + chunk.hex())
                self.send("T05thread:01;")
            elif text.startswith("qRcmd,") and bytes.fromhex(text[6:]).decode().strip() in ("r", "r rip"):
                self.commands.append(text)
                self.send("O" + b"rip=0x1000".hex())
                self.send("OK")
            else:
                super().packet(text)

    stub = BreakpointStub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        assert client.tool("veh_kd_breakpoint", {"action": "add", "address": "0x1000"}).get("success")
        stopped = client.tool("veh_kd_continue", {"wait": True, "timeout_ms": 1000})
        assert stopped.get("stop", {}).get("raw") == "T05thread:01;", stopped
        assert client.tool("veh_kd_breakpoint", {"action": "remove", "address": "0x1000"}).get("success")
        for command in ("r", "r rip"):
            result = client.tool("veh_kd_monitor", {"command": command})
            assert result.get("output") == "rip=0x1000", (command, result)
        assert client.tool("veh_kd_disconnect").get("detached")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


if __name__ == "__main__":
    run()
