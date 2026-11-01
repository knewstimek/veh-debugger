"""Native lazy-decode budgets, large ranges/steps and file failure parity."""
import json
import os
import tempfile

from build_paths import RELEASE
from mcp_test_client import McpClient, inline_trace_args
from owned_mcp_client import OwnedMcpClient


def main():
    with tempfile.TemporaryDirectory(prefix="veh-lazy-") as temp, McpClient(args=["--profile=full"]) as client:
        client.initialize("lazy-decode-regression")
        launch = client.tool("veh_launch", {"program": os.path.join(RELEASE, "test_target.exe"), "stopOnEntry": True})
        assert launch.get("success"), launch
        assert launch["backend"]["basicTrace"]["protocol"] == "veh-trace/12", launch
        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("stopped"), stop
        tid = stop["threadId"]
        assert client.tool("veh_remove_breakpoint", {"id": bp["id"]}).get("success")
        regs = client.tool("veh_registers", {"threadId": tid})["registers"]
        ip_name = "eip" if regs["is32bit"] else "rip"
        allocation = client.tool("veh_allocate_memory", {"size": 8 * 1024 * 1024, "protection": "rwx"})
        assert allocation.get("success"), allocation
        code = int(allocation["address"], 16)

        def reset(data="90 eb fd"):
            assert client.tool("veh_write_memory", {"address": hex(code), "data": data}).get("success")
            assert client.tool("veh_set_register", {"threadId": tid, "name": ip_name, "value": hex(code)}).get("success")

        def trace(args):
            return client.tool("veh_trace_basic_blocks", inline_trace_args(dict(
                threadId=tid, start=hex(code), end=hex(code + 8 * 1024 * 1024),
                timeout_ms=5000, stack_bytes=0, **args)), timeout=15)

        # Old sweep decoded >1M instructions from this mostly zero-filled range.
        reset()
        default = trace({"max_steps": 16})
        assert default.get("stop_reason") == "max_steps", default
        assert default["steps_executed"] == 16
        assert default["resource_limits"]["max_decoded_instructions"] == 1000000

        args = inline_trace_args({
            "threadId": tid, "start": hex(code + 1), "end": hex(code + 3),
            "max_steps": "10000000000", "max_decoded_instructions": 64,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_events": True,
        })
        reset("90 90 90 eb fe")
        assert client.tool("veh_set_register", {"threadId": tid, "name": ip_name, "value": hex(code + 1)}).get("success")
        direct = client.tool("veh_trace_basic_blocks", args, timeout=15)
        assert direct.get("stop_reason") == "left_range", direct
        assert direct["resource_limits"]["max_steps"] == "10000000000"
        assert direct["steps_executed"] < 10
        reset("90 90 90 eb fe")
        assert client.tool("veh_set_register", {"threadId": tid, "name": ip_name, "value": hex(code + 1)}).get("success")
        batch = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_basic_blocks", "args": args}]}, timeout=15)
        batched = batch["results"][0]["result"]
        assert batched["resource_limits"] == direct["resource_limits"], batch
        assert batched["steps_executed"] == direct["steps_executed"], batch

        reset("90 90 90 eb fe")
        action_path = os.path.join(temp, "action.json")
        action_args = {key: value for key, value in args.items() if key != "output_mode"}
        action_args["output_file"] = action_path
        action_bp = client.tool("veh_set_breakpoint", {"address": hex(code + 1), "action": [
            {"tool": "veh_trace_basic_blocks", "args": action_args},
            {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
        ]})
        assert action_bp.get("hasAction"), action_bp
        action_stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=20)
        assert action_stop.get("stopped"), action_stop
        with open(action_path, encoding="utf-8") as source:
            action = json.load(source)
        assert action["resource_limits"] == direct["resource_limits"], action
        assert action["steps_executed"] == direct["steps_executed"], action
        for identifier in {action_bp["id"], action_stop.get("breakpointId")} - {None}:
            assert client.tool("veh_remove_breakpoint", {"id": identifier}).get("success")

        # A one-entry cache can execute the first NOP only; it must stop before
        # executing the branch, and distinguish resource exhaustion from decoding.
        reset()
        limited = trace({"max_steps": 16, "max_decoded_instructions": 1})
        assert limited.get("stop_reason") == "decode_budget", limited
        assert limited["steps_executed"] == 1, limited
        assert limited["decode_incomplete"] is True, limited
        assert int(limited["final_address"], 16) == code + 1, limited

        # File output cannot replace the backend's precise start failure.
        # Fifteen prefixes are an invalid x86/x64 instruction at the entry.
        reset("66 " * 15)
        failed_args = inline_trace_args({
            "threadId": tid, "start": hex(code), "end": hex(code + 15),
            "events_output": "file", "collect_events": True,
            "events_output_path": os.path.join(temp, "failed.vte"),
            "max_steps": 16, "timeout_ms": 1000,
        })
        failed = client.tool("veh_trace_basic_blocks", failed_args, timeout=10)
        assert failed.get("failure", {}).get("reason") == "decode_failed", failed
        assert "does not support" not in failed["error"], failed
        failed_args["events_output_path"] = os.path.join(temp, "failed-batch.vte")
        batch_failed = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_basic_blocks", "args": failed_args}]})
        assert batch_failed["results"][0]["result"]["failure"]["reason"] == "decode_failed", batch_failed

        # Reject invalid numeric values before any target effects.
        for value in (-1, 1.5, "18446744073709551616", "12junk", True):
            rejected = trace({"max_steps": value})
            assert "max_steps" in rejected.get("error", ""), rejected
        if regs["is32bit"]:
            reset()
            allocation_failure = trace({"max_steps": 16, "max_decoded_instructions": 4294967294})
            assert allocation_failure.get("failure", {}).get("reason") == "allocation_failed", allocation_failure
            assert int(client.tool("veh_registers", {"threadId": tid})["registers"][ip_name], 16) == code

    # Synthetic responses cross UINT32_MAX without executing billions of steps.
    with OwnedMcpClient() as client:
        client.initialize("wide-trace-counter-boundary")
        attached = client.tool("veh_attach", {
            "pid": 4242, "target_scope": "guest",
            "agent": os.path.join(RELEASE, "guest_backend_fixture.exe"),
            "agent_args": ["--metadata", "path-wide-limits"],
        })
        assert attached.get("success"), attached
        args = inline_trace_args({"threadId": 77, "start": "0x1000", "end": "0x1100",
                                  "max_steps": "10000000000", "max_decoded_instructions": 64})
        wide = client.tool("veh_trace_basic_blocks", args)
        assert wide.get("steps_executed") == 10000000000, wide
        assert wide["filtered_steps"] == 4294967297, wide
        assert wide["unsupported_memory_writes"] == 4294967298, wide
        assert wide["unsupported_memory_reads"] == 4294967299, wide
        assert wide["resource_limits"]["max_steps"] == "10000000000", wide
    print("PASS: lazy decode large range, 64-bit steps, cache budget, direct/batch/action and file errors")


if __name__ == "__main__":
    main()
