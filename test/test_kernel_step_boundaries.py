"""Step success needs a stop notification and valid post-stop register data."""
from mcp_test_client import McpClient
from test_kernel_reply_failures import FaultStub


class StepStub(FaultStub):
    def __init__(self, missing=False, read_error=False):
        self.missing = missing
        self.read_error = read_error
        self.stepped = False
        super().__init__()

    def packet(self, text):
        if text.startswith("vCont;s"):
            self.commands.append(text)
            self.stepped = True
            if not self.missing:
                self.send("T05thread:01;")
        elif text == "?" and self.stepped:
            self.commands.append(text)
            self.send("T05thread:01;")  # stock stub query is not a completion notification
        elif text == "g" and self.stepped:
            if self.missing:
                self.commands.append(text)  # false stop query does not make register access safe
            elif self.read_error:
                self.commands.append(text)
                self.send("E01")
            else:
                super().packet(text)
        elif text == "vCont;t":
            self.commands.append(text)
            self.missing = False
            self.send("T02thread:01;")
        else:
            super().packet(text)


def check(missing):
    stub = StepStub(missing=missing, read_error=not missing)
    client = None
    try:
        client = McpClient()
        client.initialize()
        assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
        result = client.tool("veh_kd_step", {"timeout_ms": 1 if missing else 500}, timeout=14)
        assert "error" in result and "rip" not in result, result
        if missing:
            assert result.get("steps") == 0, result
            index = next(i for i, command in enumerate(stub.commands) if command.startswith("vCont;s"))
            assert not any(command in ("?", "g") for command in stub.commands[index + 1:]), stub.commands
            stopped = client.tool("veh_kd_break", {"timeout_ms": 1000})
            assert stopped.get("running") is False, stopped
        else:
            assert result.get("steps") == 1 and result.get("stop", {}).get("raw") == "T05thread:01;", result
            assert result.get("register_error", {}).get("reply") == "E01", result
            assert "protocol_trace" in result, result
        stub.read_error = False
        assert client.tool("veh_kd_registers").get("rip") == "0x1000"
        assert client.tool("veh_kd_disconnect").get("detached")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def run():
    check(True)
    check(False)
    print("PASS KD missing stop never triggers speculative query/read; register failure cannot become empty-RIP success")


if __name__ == "__main__":
    run()
