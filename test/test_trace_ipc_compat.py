"""Mixed-version smoke test for veh_trace_basic_blocks IPC compatibility."""
import json
import os

from test_trace_basic_blocks import Client


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGET = os.environ.get(
    "VEH_TEST_TARGET",
    os.path.join(ROOT, "build", "bin", "Release", "test_target.exe"),
)


def main():
    client = Client()
    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "trace-ipc-compat-test", "version": "1"},
            "capabilities": {},
        })
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch
        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert bp.get("success") and bp.get("address"), bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        start = int(bp["address"], 0)
        trace = client.tool("veh_trace_basic_blocks", {
            "threadId": stop["threadId"],
            "start": hex(start),
            "end": hex(start + 0x100),
            "max_steps": 1000,
            "timeout_ms": 5000,
            "stack_bytes": 0,
            "collect_events": True,
            "max_events": 256,
            "collect_memory_events": True,
            "max_memory_events": 256,
        }, timeout=15)
        assert "error" not in trace, trace
        assert trace.get("schema_version") in {3, 4}, trace
        assert trace.get("blocks") and trace.get("edges"), trace
        assert trace.get("events") and trace.get("memory_events"), trace
        print(json.dumps({
            "mcp": os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build")),
            "target": TARGET,
            "schema": trace["schema_version"],
            "steps": trace["steps_executed"],
        }))
    finally:
        client.close()


if __name__ == "__main__":
    main()
