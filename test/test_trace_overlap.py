"""Basic-block trace keeps metadata for instructions executed off the linear sweep.

test_target's TraceOverlapTarget runs `EB 01 | B8 31 C0 90 90 | C3`: the sweep of
the range decodes +2 as one `mov eax, imm32`, while execution jumps to +3 and runs
xor/nop/nop/ret. Those executed addresses must still get hit counts, block extents
and captured code (obfuscated/virtualized code relies on this).
"""
import os

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")


@pytest.fixture(scope="module")
def entry():
    with McpClient() as client:
        client.initialize("trace-overlap-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
        module = next(m for m in client.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        base, size = int(module["baseAddress"], 16), int(module["size"], 16)
        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceOverlapTarget"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        client.tool("veh_remove_breakpoint", {"id": bp["id"]})
        tid = stop["threadId"]
        # Step into the call to the runtime buffer (outside the module image).
        ip = int(stop["address"], 16)
        for _ in range(40):
            if not base <= ip < base + size:
                break
            ip = int(client.tool("veh_step_in", {"threadId": tid})["instructionPointer"], 16)
        assert not base <= ip < base + size, "did not reach the overlap buffer"
        yield client, tid, ip


def test_off_sweep_instructions_are_traced(entry):
    client, tid, code = entry
    trace = client.tool("veh_trace_basic_blocks", {
        "threadId": tid, "start": hex(code), "end": hex(code + 8),
        "stop_on_return": True, "max_steps": 1000, "timeout_ms": 5000,
        "collect_code": True, "max_code_bytes": 4096, "max_code_versions": 64,
    }, timeout=20)
    assert trace.get("stop_reason") == "function_return", trace

    blocks = {int(block["start"], 16): block for block in trace["blocks"]}
    landed = blocks.get(code + 3)
    assert landed, f"no block at the jump target: {sorted(hex(b) for b in blocks)}"
    # Before on-execution decoding this block had hits=0 and end==start.
    # xor/nop/nop run straight into the swept ret at +7, so the block is [+3, +8).
    assert landed["hits"] >= 1, landed
    assert int(landed["end"], 16) == code + 8, landed

    versions = {int(version["block"], 16): version for version in trace["code_versions"]}
    assert code + 3 in versions, trace["code_versions"]
    # Captured bytes cover every executed instruction of the block, including the ret.
    assert versions[code + 3]["bytes"].replace(" ", "").lower() == "31c09090c3", versions[code + 3]
    assert trace["code_capture"]["complete"] is True, trace["code_capture"]
    assert trace["code_truncated"] is False, trace["code_capture"]


def test_call_writes_return_address_below_stack_pointer(entry):
    """CALL stores its return address at SP - pointer size, like PUSH."""
    client, tid, _ = entry
    saved = client.tool("veh_registers", {"threadId": tid})["registers"]
    is_32bit = saved["is32bit"]
    ip_name, sp_name = ("eip", "esp") if is_32bit else ("rip", "rsp")
    pointer_size = 4 if is_32bit else 8
    stack_pointer, resume = int(saved[sp_name], 16), int(saved[ip_name], 16)

    alloc = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
    start = int(alloc["address"], 16)
    # call +0 (pushes start+5) / pop eax|rax / jmp [abs] back to the saved IP
    if is_32bit:
        code = bytes.fromhex("E8 00 00 00 00 58 FF 25") + (start + 12).to_bytes(4, "little") + \
            resume.to_bytes(4, "little")
    else:
        code = bytes.fromhex("E8 00 00 00 00 58 FF 25 00 00 00 00") + resume.to_bytes(8, "little")
    assert client.tool("veh_write_memory", {"address": hex(start), "data": code.hex(" ")}).get("success")
    assert client.tool("veh_set_register", {"threadId": tid, "name": ip_name, "value": hex(start)}).get("success")

    trace = client.tool("veh_trace_basic_blocks", {
        "threadId": tid, "start": hex(start), "end": hex(start + len(code)), "max_steps": 8,
        "timeout_ms": 5000, "stack_bytes": 0,
        "collect_memory_writes": True, "max_memory_writes": 8,
        "collect_memory_events": True, "max_memory_events": 8,
    }, timeout=15)
    call_write = next(event for event in trace["memory_events"]
                      if event["kind"] == "write" and int(event["instruction"], 16) == start)
    assert int(call_write["address"], 16) == stack_pointer - pointer_size, call_write
    assert call_write["after"] == (start + 5).to_bytes(pointer_size, "little").hex(" "), call_write
    assert call_write["before"] != call_write["after"], call_write
    client.tool("veh_free_memory", {"address": hex(start)})
