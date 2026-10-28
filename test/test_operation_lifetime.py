"""Action parity and controller-loss boundaries without a VM or private adapter."""
import json
import ctypes
from ctypes import wintypes
import msvcrt
from pathlib import Path
import tempfile
import threading
import time

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient
from test_remote_transport import KERNEL, owned_handle

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def attach(client, mode):
    result = client.tool("veh_attach", {"pid": 424242, "agent": AGENT,
        "target_scope": "guest", "agent_args": ["--metadata", "ops-" + mode]})
    assert result.get("success"), result


class ThreeReplyClient(OwnedMcpClient):
    # Stop reading after initialize, attach and admission. Closing the read endpoint
    # is then deterministic and does not race a Python thread blocked in readline.
    def _read_responses(self):
        replies = 0
        while replies < 3:
            line = self.proc.stdout.readline()
            if not line:
                self.responses.put(None)
                return
            message = json.loads(line)
            self.responses.put(message)
            replies += "id" in message


def wait_for_full_output(client):
    KERNEL.PeekNamedPipe.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
    pipe = msvcrt.get_osfhandle(client.proc.stdout.fileno())
    deadline = time.monotonic() + 3
    while True:
        available = wintypes.DWORD()
        assert KERNEL.PeekNamedPipe(pipe, None, 0, None, ctypes.byref(available), None)
        if available.value >= 4096:
            assert client.proc.poll() is None, "server exited before EOF"
            return
        assert time.monotonic() < deadline, "output pipe did not fill"
        threading.Event().wait(0.01)


def run(directory):
    log = directory / "actions.log"
    with OwnedMcpClient(args=["--log=" + str(log)]) as client:
        client.initialize()
        for mode in ("action", "action-fast"):
            attach(client, mode)
            installed = client.tool("veh_set_breakpoint", {"address": "0x1800", "action": [{
                "tool": "veh_value_freeze", "args": {"operation": "add", "address": "0x2000",
                    "data": "AA", "interval_ms": 250, "lease_seconds": 1}}]})
            assert installed.get("success"), installed
            stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
            assert stop.get("breakpointId") == 7, stop
            deadline = time.monotonic() + 2
            while True:
                jobs = client.tool("veh_value_freeze")["jobs"]
                if len(jobs) == 1 and int(jobs[0]["writes"]) >= 1:
                    break
                assert time.monotonic() < deadline, jobs
                threading.Event().wait(0.03)
            assert client.tool("veh_value_freeze", {"operation": "clear"}).get("success")

        attach(client, "action")
        installed = client.tool("veh_set_breakpoint", {"address": "0x1800", "action": [{
            "tool": "veh_execution", "args": {"operation": "run_to", "address": "0x1900", "threadId": 77}}]})
        assert installed.get("success"), installed
        stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
        assert stop.get("breakpointId") == 7, stop
        state = client.tool("veh_execution", {"threadId": 77})
        assert not state["runUntil"]["active"], state
        stats = client.tool("veh_threads")["threads"][0]["name"]
        assert "created:1" in stats and "resumed:2" in stats, stats
        assert client.tool("veh_detach").get("success")
    errors = [line for line in log.read_text(encoding="utf-8").splitlines()
              if "Breakpoint action completed with an error:" in line]
    assert len(errors) == 1 and "cannot start inside breakpoint actions" in errors[0], errors

    # A host target exit and immediate replacement must not retag the old
    # monitor's callback as an exit of the new session.
    with OwnedMcpClient() as client:
        client.initialize()
        assert client.tool("veh_execution", {"operation": "notifications", "enabled": True}).get("success")
        program = str(Path(RELEASE) / "test_target.exe")
        previous = client.tool("veh_launch", {"program": program, "stopOnEntry": True})
        assert previous.get("success"), previous
        handle = owned_handle(previous["pid"], program, client.proc.pid, directory)
        try:
            assert KERNEL.TerminateProcess(handle, 0)
            assert KERNEL.WaitForSingleObject(handle, 5000) == 0
            replacement = client.tool("veh_launch", {"program": program, "stopOnEntry": True})
            assert replacement.get("success"), replacement
            snapshot = client.tool("veh_execution")
            assert snapshot["pid"] == replacement["pid"] and snapshot["attached"] and not snapshot["targetExited"], snapshot
        finally:
            KERNEL.CloseHandle(handle)

    # Closing stdout while stdin and the parent remain live must stop the lease.
    # No heartbeat/control notifications are needed to discover the broken output.
    with ThreeReplyClient() as client:
        client.initialize()
        attach(client, "running")
        result = client.tool("veh_value_freeze", {"operation": "add", "address": "0x2000",
            "data": "AA", "interval_ms": 250, "lease_seconds": 10})
        assert result.get("success"), result
        client.reader.join(timeout=1)
        assert not client.reader.is_alive()
        assert not client.proc.stdin.closed and client.proc.poll() is None
        client.proc.stdout.close()
        client.proc.wait(timeout=4)

    # Several workers can queue behind a sender blocked on a full output pipe.
    # Every owned worker must be cancellable even if an earlier one waits on its mutex.
    with ThreeReplyClient() as client:
        client.initialize()
        attach(client, "running")
        client.tool("veh_execution")
        client.reader.join(timeout=1)
        assert not client.reader.is_alive()
        names = ["veh_trace_basic_blocks", "veh_batch", "veh_assemble", "veh_execution",
                 "veh_value_freeze", "veh_read_memory", "veh_write_memory"]
        for identity in range(10000, 10008):
            request = {"jsonrpc": "2.0", "id": identity, "method": "tools/call",
                "params": {"name": "veh_toolbox", "arguments": {
                    "operation": "manifest", "tools": names, "compact": False}}}
            client.proc.stdin.write((json.dumps(request) + "\n").encode())
        client.proc.stdin.flush()
        wait_for_full_output(client)
        client.proc.stdin.close()
        client.proc.wait(timeout=4)

    # Neither protocol-reader replies nor main-loop log notifications may block
    # the thread that has to detect EOF and begin shutdown.
    for producer in ("protocol", "notification"):
        with ThreeReplyClient() as client:
            client.initialize()
            attach(client, "action")
            if producer == "notification":
                result = client.tool("veh_set_breakpoint", {
                    "address": "0x1800", "logMessage": "L" * 16384})
                assert result.get("success"), result
                request = {"jsonrpc": "2.0", "id": 20001, "method": "tools/call",
                    "params": {"name": "veh_continue", "arguments": {"threadId": 77}}}
            else:
                client.tool("veh_execution")
                request = {"jsonrpc": "2.0", "id": 20000, "method": "tools/list"}
            client.reader.join(timeout=1)
            assert not client.reader.is_alive()
            client.proc.stdin.write((json.dumps(request) + "\n").encode())
            client.proc.stdin.flush()
            wait_for_full_output(client)
            client.proc.stdin.close()
            client.proc.wait(timeout=4)

    # A 300-second stop waiter cannot retain the server after input EOF.
    with ThreeReplyClient() as client:
        client.initialize()
        attach(client, "running")
        result = client.tool("veh_execution", {"operation": "run_to", "address": "0x1800", "threadId": 77})
        assert result.get("success") and result.get("pending"), result
        client.reader.join(timeout=1)
        assert not client.reader.is_alive()
        request = {"jsonrpc": "2.0", "id": 9999, "method": "tools/call",
            "params": {"name": "veh_continue", "arguments": {"threadId": 77, "wait": True, "timeout": 300}}}
        client.proc.stdin.write((json.dumps(request) + "\n").encode())
        client.proc.stdin.flush()
        threading.Event().wait(0.05)
        client.proc.stdin.close()
        client.proc.wait(timeout=4)
    print("PASS value-freeze action parity, run-until action exclusion and input/output controller loss")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="veh-operation-lifetime-") as directory:
        run(Path(directory))
