"""Bounded native fault injection against the production PipeClient."""
import subprocess
import ctypes
from ctypes import wintypes
import json
import time
import uuid
import tempfile

from owned_mcp_client import OwnedMcpClient
from pathlib import Path

from build_paths import RELEASE


def test_write_completion_race():
    result = subprocess.run([str(Path(RELEASE) / "ipc_transport_regression.exe")],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS pipe write-completion race" in result.stdout
    assert "PASS standard trace routing" in result.stdout


def test_standard_trace_allows_mcp_inspection():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.ResetEvent.argtypes = (wintypes.HANDLE,)
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    name = "Local\\veh-trace-ready-" + uuid.uuid4().hex
    event = kernel.CreateEventW(None, True, False, name)
    assert event
    try:
        with tempfile.TemporaryDirectory(prefix="veh-pipe-boundary-") as directory, OwnedMcpClient(
            args=["--log=" + str(Path(directory) / "mcp.log")]) as client:
            client.initialize()
            attached = client.tool("veh_attach", {"pid": 424242,
                "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"), "target_scope": "guest",
                "agent_args": ["--metadata", "concurrent-trace", "--ready-event", name]})
            assert attached.get("success"), attached

            def send(tool, args):
                client.seq += 1
                request = {"jsonrpc": "2.0", "id": client.seq, "method": "tools/call",
                    "params": {"name": tool, "arguments": args}}
                client.proc.stdin.write((json.dumps(request) + "\n").encode())
                client.proc.stdin.flush()
                return client.seq

            for tool, args in (
                ("veh_trace_callers", {"address": "0x1000", "duration_ms": 1000}),
                ("veh_trace_calls", {"addresses": ["0x1000"], "duration_ms": 1000}),
            ):
                for batch in (False, True):
                    assert kernel.ResetEvent(event)
                    trace_id = send("veh_batch", {"steps": [{"tool": tool, "args": args}]}) if batch else send(tool, args)
                    assert kernel.WaitForSingleObject(event, 2000) == 0, "fixture did not receive trace"
                    for lifecycle, options in (("veh_attach", {"pid": 424243}),
                        ("veh_launch", {"program": "missing-synthetic-target.exe"}),
                        ("veh_detach", {}), ("veh_terminate", {})):
                        rejected = client.tool(lifecycle, options, timeout=2)
                        assert "standard trace" in rejected.get("error", ""), (lifecycle, rejected)
                    inspect_id = send("veh_threads", {})
                    responses = {}
                    deadline = time.monotonic() + 3
                    while len(responses) < 2:
                        message = client.responses.get(timeout=max(0.01, deadline - time.monotonic()))
                        assert message is not None, client.stderr_tail()
                        if "id" in message:
                            responses[message["id"]] = message
                    def unpack(identity):
                        return json.loads(responses[identity]["result"]["content"][0]["text"])
                    assert unpack(inspect_id)["count"] == 1, responses
                    trace = unpack(trace_id)
                    if batch:
                        assert trace["failed"] == 0, trace
                        trace = trace["results"][0]["result"]
                    assert "error" not in trace and trace["totalHits" if tool == "veh_trace_callers" else "total_hits"] == 0, trace
            # Breakpoint actions use the same suspended admission and pipe lanes.
            for tool, args in (
                ("veh_trace_callers", {"address": "0x1000", "duration_ms": 1000}),
                ("veh_trace_calls", {"addresses": ["0x1000"], "duration_ms": 1000}),
            ):
                attached = client.tool("veh_attach", {"pid": 424242,
                    "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"), "target_scope": "guest",
                    "agent_args": ["--metadata", "ops-action-concurrent", "--ready-event", name]})
                assert attached.get("success"), attached
                assert client.tool("veh_set_breakpoint", {"address": "0x1800",
                    "action": [{"tool": tool, "args": args}]}).get("success")
                assert kernel.ResetEvent(event)
                continue_id = send("veh_continue", {"threadId": 77, "wait": True, "timeout": 3})
                assert kernel.WaitForSingleObject(event, 2000) == 0, "\n".join(
                    (Path(directory) / "mcp.log").read_text(encoding="utf-8").splitlines()[-35:])
                inspect_id = send("veh_threads", {})
                responses = {}
                deadline = time.monotonic() + 4
                while len(responses) < 2:
                    message = client.responses.get(timeout=max(0.01, deadline - time.monotonic()))
                    assert message is not None, client.stderr_tail()
                    if "id" in message:
                        responses[message["id"]] = message
                assert unpack(inspect_id)["count"] == 1, responses
                assert unpack(continue_id).get("breakpointId") == 7, responses
    finally:
        kernel.CloseHandle(event)
