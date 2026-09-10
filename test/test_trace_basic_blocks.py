"""Integration smoke test for veh_trace_basic_blocks."""
import json
import os
import subprocess
import time


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
MCP_EXE = os.path.join(BUILD_DIR, "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe")


class Client:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.seq = 0

    def call(self, method, params=None, timeout=20):
        self.seq += 1
        request = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write((json.dumps(request) + "\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                continue
            message = json.loads(line)
            if message.get("id") == self.seq:
                return message
        raise TimeoutError(method)

    def tool(self, name, arguments=None, timeout=20):
        response = self.call("tools/call", {"name": name, "arguments": arguments or {}}, timeout)
        content = response["result"]["content"][0]["text"]
        return json.loads(content)

    def close(self):
        try:
            self.tool("veh_terminate", timeout=5)
        except Exception:
            pass
        self.proc.terminate()
        self.proc.wait(timeout=5)


def main():
    client = Client()
    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "trace-basic-blocks-test", "version": "1"},
            "capabilities": {},
        })
        listed = client.call("tools/list")["result"]["tools"]
        assert any(tool.get("name") == "veh_trace_basic_blocks" for tool in listed), listed
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch

        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert bp.get("success") and bp.get("address"), bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        thread_id = stop["threadId"]
        start = int(bp["address"], 0)

        trace = client.tool("veh_trace_basic_blocks", {
            "threadId": thread_id,
            "start": hex(start),
            "end": hex(start + 0x100),
            "max_steps": 1000,
            "timeout_ms": 5000,
            "stack_bytes": 32,
        }, timeout=15)
        assert "error" not in trace, trace
        assert len(trace["blocks"]) >= 2, trace
        assert len(trace["edges"]) >= 1, trace
        assert trace["snapshots"], trace
        assert sum(block["hits"] for block in trace["blocks"]) > 0, trace

        # Batch dispatch must use the same implementation and result shape as a
        # direct call. The continue result also verifies $N.threadId expansion.
        batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_blocks": 4096, "max_edges": 8192, "max_steps": 1000,
                "timeout_ms": 5000, "stack_bytes": 32,
            }},
        ]}, timeout=20)
        assert batch.get("totalSteps") == 2, batch
        batch_stop = batch["results"][0]["result"]
        assert batch_stop.get("reason") == "breakpoint", batch_stop
        batch_trace = batch["results"][1]["result"]
        assert "error" not in batch_trace, batch_trace
        assert set(batch_trace) == set(trace), (batch_trace, trace)
        assert batch_trace["register_order"] == trace["register_order"], batch_trace
        assert len(batch_trace["blocks"]) >= 2, batch_trace
        assert len(batch_trace["edges"]) >= 1, batch_trace

        # The independent instruction limit must stop and park the thread without
        # waiting for range exit.
        limited_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 3, "timeout_ms": 5000, "stack_bytes": 0,
            }},
        ]}, timeout=20)
        assert limited_batch.get("totalSteps") == 2, limited_batch
        limited = limited_batch["results"][1]["result"]
        assert limited.get("stop_reason") == "max_steps", limited
        assert limited.get("truncated") is True, limited

        terminated = client.tool("veh_terminate")
        assert terminated.get("success"), terminated
        launch = client.tool("veh_launch", {
            "program": TARGET, "args": ["--trace-exception"], "stopOnEntry": True,
        })
        assert launch.get("success"), launch
        exception_bp = client.tool("veh_set_function_breakpoint", {"name": "TraceExceptionCoverageTarget"})
        assert exception_bp.get("success") and exception_bp.get("address"), exception_bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        exception_start = int(exception_bp["address"], 0)
        exception_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": stop["threadId"], "start": hex(exception_start),
            "end": hex(exception_start + 0x100), "max_steps": 1000,
            "timeout_ms": 5000, "stack_bytes": 16, "follow_exceptions": True,
        }, timeout=15)
        assert exception_trace.get("exceptions_followed", 0) >= 1, exception_trace
        assert any(edge.get("kind") == "exception" for edge in exception_trace["edges"]), exception_trace
        print(json.dumps({
            "stop_reason": trace["stop_reason"],
            "blocks": len(trace["blocks"]),
            "edges": len(trace["edges"]),
            "steps": trace["steps_executed"],
            "batch_blocks": len(batch_trace["blocks"]),
            "batch_edges": len(batch_trace["edges"]),
            "exception_edges": sum(edge.get("kind") == "exception" for edge in exception_trace["edges"]),
        }))
    finally:
        client.close()


if __name__ == "__main__":
    main()
