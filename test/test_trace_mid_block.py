"""Branch targets inside a linearly swept block are reported as the concrete address.

test_target's TraceMidBlockTarget runs a buffer whose indirect jmp lands in the
middle of the block that the linear sweep starts right after the jmp. The nops
between that sweep block start and the target never execute, so neither the
edge target nor any block may claim them.
"""
import os

import pytest

from build_paths import RELEASE, IS_X86
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")
JMP, SWEEP_START, JUMP_TARGET, END = (9, 11, 16, 18) if IS_X86 else (7, 9, 14, 16)


@pytest.fixture(scope="module")
def entry():
    with McpClient() as client:
        client.initialize("trace-mid-block-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
        module = next(m for m in client.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        base, size = int(module["baseAddress"], 16), int(module["size"], 16)
        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceMidBlockTarget"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        client.tool("veh_remove_breakpoint", {"id": bp["id"]})
        tid = stop["threadId"]
        ip = int(stop["address"], 16)
        for _ in range(40):
            if not base <= ip < base + size:
                break
            ip = int(client.tool("veh_step_in", {"threadId": tid})["instructionPointer"], 16)
        assert not base <= ip < base + size, "did not reach the mid-block buffer"
        yield client, tid, ip


def test_indirect_jump_target_is_not_normalized(entry):
    client, tid, code = entry
    trace = client.tool("veh_trace_basic_blocks", {
        "threadId": tid, "start": hex(code), "end": hex(code + END),
        "stop_on_return": True, "max_steps": 1000, "timeout_ms": 5000,
        "collect_events": True, "collect_code": True,
    }, timeout=20)
    assert trace.get("stop_reason") == "function_return", trace

    jumps = [e for e in trace["events"] if e["type"] == "edge"
             and int(e["source_instruction"], 16) == code + JMP]
    assert jumps, trace["events"]
    # Before the fix the target was the sweep block start (code + SWEEP_START).
    assert all(int(e["target"], 16) == code + JUMP_TARGET for e in jumps), jumps

    executed = {int(b["start"], 16) for b in trace["blocks"] if b["hits"] > 0}
    assert code + JUMP_TARGET in executed, trace["blocks"]
    assert not any(code + SWEEP_START <= start < code + JUMP_TARGET for start in executed), trace["blocks"]
    edges = [e for e in trace["edges"] if int(e["source_instruction"], 16) == code + JMP]
    assert edges and all(int(e["target"], 16) == code + JUMP_TARGET for e in edges), edges
