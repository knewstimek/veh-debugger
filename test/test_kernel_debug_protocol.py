"""Exercise kernel-stub framing, true stops and safe detach through MCP."""
import socket
import threading

from mcp_test_client import McpClient


class Stub:
    def __init__(self, initial_stop_reply="T05thread:01;"):
        self.initial_stop_reply = initial_stop_reply
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.commands = []
        self.error = None
        self.peer = None
        self.reject_remove = True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def send(self, text):
        # Include the VirtualBox trailing NUL inside the checksummed payload.
        payload = text.encode() + b"\0"
        self.peer.sendall(b"$" + payload + b"#" + f"{sum(payload) & 255:02x}".encode())

    def packet(self, text):
        self.commands.append(text)
        if text.startswith("qSupported"):
            self.send("T05thread:01;")  # unsolicited halt before negotiation
            self.send("T05thread:01;")  # one notification per vCPU
            self.send("PacketSize=4000;QStartNoAckMode+;vContSupported+")
        elif text == "QStartNoAckMode":
            self.send("OK")
        elif text == "?":
            self.send(self.initial_stop_reply)
            if self.initial_stop_reply == "T05thread:01;":
                self.send("T05thread:01;")  # queued behind the requested stop
        elif text.startswith("qRcmd,"):
            command = bytes.fromhex(text.split(",", 1)[1]).decode()
            assert command.endswith(" "), "DBGC drops the final decoded byte"
            assert command[:-1] in ("r", "regs"), command
            self.send("O" + b"rip=".hex())
            self.send("S05")  # a late signal stop between console chunks
            self.send("O" + b"0x1000".hex())
            self.send("T05thread:02;")  # retain the most recent stop, drain to OK
            self.send("OK")
        elif text == "qfThreadInfo":
            self.send("m1,2")
        elif text == "qsThreadInfo":
            self.send("l")
        elif text == "g":
            registers = bytearray(17 * 8 + 4)
            registers[16 * 8:17 * 8] = (0x1000).to_bytes(8, "little")
            self.send(registers.hex())  # no segment registers
        elif text.startswith("H") or text.startswith("Z"):
            self.send("OK")
        elif text.startswith("z"):
            if text == "z2,2000,4" and self.reject_remove:
                self.reject_remove = False
                self.send("E01")
            else:
                self.send("OK")
        elif text == "vCont;t":
            self.send("")  # unsupported is not a stop; client must use 0x03
        elif text == "interrupt":
            self.send("O" + b"halted".hex())
            self.send("T02thread:01;")
        elif text == "D":
            self.send("OK")
        elif text != "c":
            self.send("")

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    self.peer, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if self.peer is None:
                return
            self.peer.settimeout(0.2)
            pending = b""
            while not self.stop.is_set():
                try:
                    chunk = self.peer.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                pending += chunk
                while pending:
                    if pending[0] in (ord("+"), ord("-")):
                        pending = pending[1:]
                    elif pending[0] == 3:
                        pending = pending[1:]
                        self.packet("interrupt")
                    elif pending[0] == ord("$"):
                        end = pending.find(b"#")
                        if end < 0 or len(pending) < end + 3:
                            break
                        command = pending[1:end].decode()
                        pending = pending[end + 3:]
                        self.packet(command)
                    else:
                        raise AssertionError("Unexpected RSP framing")
        except ConnectionResetError:
            pass  # the owned MCP may close its peer while unwinding a failed assertion
        except OSError as error:
            if not self.stop.is_set():
                self.error = error
        except Exception as error:
            self.error = error
        finally:
            if self.peer is not None:
                self.peer.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        if self.peer is not None:
            try:
                self.peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "Stub thread did not exit"
        assert self.error is None, self.error


def check_initial_stop(reply, valid=False):
    stub = Stub(reply)
    client = None
    try:
        client = McpClient()
        client.initialize()
        result = client.tool("veh_kd_connect", {
            "transport": "tcp", "address": f"127.0.0.1:{stub.port}",
        })
        if valid:
            assert result.get("halted") and result["stop"]["raw"] == reply, result
            assert client.tool("veh_kd_disconnect").get("detached")
        else:
            assert "error" in result and not result.get("halted"), (reply, result)
            assert not any(command.startswith("qRcmd,") for command in stub.commands), stub.commands
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


def run():
    for reply in ("OK", "", "E01", "Tzz", "Sx5", "T0", "W00", "X09"):
        check_initial_stop(reply)
    check_initial_stop("S05", valid=True)
    stub = Stub()
    client = None
    try:
        client = McpClient()
        client.initialize()
        connected = client.tool("veh_kd_connect", {
            "transport": "tcp", "address": f"127.0.0.1:{stub.port}",
        })
        assert connected.get("halted"), connected
        assert connected.get("cpus") == [0, 1], connected
        for _ in range(2):
            monitored = client.tool("veh_kd_monitor", {"command": "r"})
            assert monitored.get("output") == "rip=0x1000", monitored
            cached = client.tool("veh_kd_wait")
            assert cached.get("stop", {}).get("raw") == "T05thread:02;", cached
        registers = client.tool("veh_kd_registers")
        assert registers.get("rip") == "0x1000", registers
        for kind, size in (("execute", 1), ("write", 4), ("access", 8)):
            added = client.tool("veh_kd_breakpoint", {
                "action": "add", "address": "0x1000" if kind == "execute" else "0x2000",
                "kind": kind, "size": size,
            })
            assert added.get("success"), added
        assert client.tool("veh_kd_breakpoint")["breakpoints"] == ["0x1000", "0x2000"]
        assert client.tool("veh_kd_continue").get("running")
        stopped = client.tool("veh_kd_break", {"timeout_ms": 1500})
        assert stopped.get("stop", {}).get("raw") == "T02thread:01;", stopped
        assert "interrupt" in stub.commands, stub.commands
        first = client.tool("veh_kd_disconnect")
        assert "error" in first and "retained" in first["error"], first
        assert "D" not in stub.commands, stub.commands
        assert client.tool("veh_kd_registers").get("rip") == "0x1000"
        second = client.tool("veh_kd_disconnect")
        assert second.get("detached"), second
        removals = [p for p in stub.commands if p.startswith("z")]
        assert removals == ["z0,1000,1", "z2,2000,4", "z2,2000,4", "z4,2000,8"], removals
        assert stub.commands[-1] == "D", stub.commands
        print("PASS two-CPU duplicate/late T/S stops, DBGC trailing space, aligned console/register replies and typed detach cleanup")
    finally:
        try:
            if client is not None:
                client.close(terminate_target=False)
        finally:
            stub.close()


if __name__ == "__main__":
    run()
