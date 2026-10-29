"""Mixed-version smoke test for veh_trace_basic_blocks IPC compatibility."""
import json
from build_paths import RELEASE
import os

from mcp_test_client import McpClient


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGET = os.environ.get(
    "VEH_TEST_TARGET",
    os.path.join(RELEASE, "test_target.exe"),
)


def scan_compat(client, launch):
    v2=launch.get("backend",{}).get("valueScan",{}).get("protocol")=="veh-value-scan/2"
    allocated=client.tool("veh_allocate_memory",{"size":4096})
    assert allocated.get("success"),allocated
    address=int(allocated["address"],16)
    def scan(args):
        result=client.tool("veh_value_scan",args)
        if result.get("state")=="running":
            result=client.wait_notification("notifications/veh/value_scan",
                lambda p:p.get("jobId")==result["jobId"] and p.get("state") in ("completed","failed"),timeout=10)
        assert "error" not in result,result
        return result
    first=scan({"operation":"first","start":hex(address),"end":hex(address+4096),"compare":"unknown"})
    assert first["candidates"]==1024,first
    page=scan({"operation":"results","offset":1023,"max_results":1})
    assert len(page["results"])==1 and int(page["results"][0]["address"],16)==address+4092,page
    assert client.tool("veh_write_memory",{"address":hex(address),"data":"01 00 00 00"}).get("success")
    next_result=scan({"operation":"next","compare":"increased"})
    assert next_result["candidates"]==1,next_result
    if v2:
        assert scan({"operation":"undo"})["candidates"]==1024
    assert scan({"operation":"reset"})["candidates"]==0
    assert client.tool("veh_free_memory",{"address":hex(address)}).get("success")
    print(json.dumps({"suite":"scan","v2":v2,"candidates":first["candidates"]}))


def main():
    client = McpClient()
    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "trace-ipc-compat-test", "version": "1"},
            "capabilities": {},
        })
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch
        if os.environ.get("VEH_TEST_SCAN_COMPAT")=="1":
            scan_compat(client,launch)
            return
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
        def stop_at_start():
            next_stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
            assert next_stop.get("reason") == "breakpoint", next_stop
            assert int(next_stop.get("address", "0"), 0) == start, next_stop
            return next_stop
        if os.environ.get("VEH_TEST_EXPECT_POLICIES_UNSUPPORTED") == "1":
            policy_stop = stop_at_start()
            before = client.tool("veh_registers", {"threadId": policy_stop["threadId"]})
            refused = client.tool("veh_trace_basic_blocks", {
                "threadId": policy_stop["threadId"], "start": hex(start), "end": hex(start + 0x100),
                "collect_snapshots": False,
            })
            assert "backend_does_not_support_trace_collection_policies" in str(refused), refused
            after = client.tool("veh_registers", {"threadId": policy_stop["threadId"]})
            assert before == after, (before, after)
        if os.environ.get("VEH_TEST_EXPECT_FILE_UNSUPPORTED") == "1":
            extension_stop = stop_at_start()
            file_trace = client.tool("veh_trace_basic_blocks", {
                "threadId": extension_stop["threadId"], "start": hex(start), "end": hex(start + 0x100),
                "collect_code": True, "code_output": "file",
                "max_code_bytes": 400 * 1024 * 1024,
            }, timeout=15)
            assert file_trace == {
                "error": "injected DLL does not support code_output=file",
            }, file_trace
        if os.environ.get("VEH_TEST_EXPECT_OCCURRENCE_UNSUPPORTED") == "1":
            extension_stop = stop_at_start()
            occurrence_trace = client.tool("veh_trace_basic_blocks", {
                "threadId": extension_stop["threadId"], "start": hex(start), "end": hex(start + 0x100),
                "occurrence_window": {"address": hex(start), "from": 1, "to": 1},
            }, timeout=15)
            assert occurrence_trace == {
                "error": "injected DLL does not support occurrence_window",
            }, occurrence_trace
        if os.environ.get("VEH_TEST_EXPECT_FUNCTION_SCOPE_UNSUPPORTED") == "1":
            extension_stop = stop_at_start()
            function_trace = client.tool("veh_trace_basic_blocks", {
                "threadId": extension_stop["threadId"], "start": hex(start),
                "end": hex(start + 0x100), "stop_on_return": True,
            }, timeout=15)
            assert function_trace == {
                "error": "injected DLL does not support stop_on_return",
            }, function_trace
        if os.environ.get("VEH_TEST_EXPECT_TARGET_WINDOW_UNSUPPORTED") == "1":
            extension_stop = stop_at_start()
            target_trace = client.tool("veh_trace_basic_blocks", {
                "threadId": extension_stop["threadId"], "start": hex(start),
                "end": hex(start + 0x100),
                "target_window": {"address": hex(start), "occurrence": 1,
                                  "before_steps": 0, "after_steps": 1},
            }, timeout=15)
            assert target_trace == {
                "error": "injected DLL does not support target_window",
            }, target_trace
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
