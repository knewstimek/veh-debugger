"""A function-scoped trace follows execution that leaves the range without a call.

test_target's TraceExternalExitTarget runs a buffer whose thunk returns into an API
(a protected import call); the API returns to the instruction after the thunk call.
TraceExternalTailTarget runs a buffer that ends in a tail jump to the API, which
returns on the function's behalf.
"""
import json
import os

import pytest

from build_paths import RELEASE, IS_X86
from mcp_test_client import McpClient, inline_trace_args

TARGET = os.path.join(RELEASE, "test_target.exe")
# (thunk ret, instruction after the thunk call, function ret, size) and (tail jmp, size)
THUNK_RET, RESUME, FUNCTION_RET, THUNK_END = (11, 5, 5, 12) if IS_X86 else (25, 9, 13, 26)
TAIL_JMP, TAIL_END = (5, 7) if IS_X86 else (10, 12)


@pytest.fixture(scope="module")
def session():
    with McpClient() as client:
        client.initialize("trace-external-exit-test")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
        module = next(m for m in client.tool("veh_modules")["modules"] if "test_target" in m["name"].lower())
        yield client, int(module["baseAddress"], 16), int(module["size"], 16)


def enter_buffer(client, base, size, function):
    """(thread id, first address) of the buffer `function` calls."""
    bp = client.tool("veh_set_function_breakpoint", {"name": function})
    assert bp.get("success"), bp
    stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
    assert stop.get("stopped"), stop
    client.tool("veh_remove_breakpoint", {"id": bp["id"]})
    tid, ip = stop["threadId"], int(stop["address"], 16)
    for _ in range(40):
        if not base <= ip < base + size:
            break
        ip = int(client.tool("veh_step_in", {"threadId": tid})["instructionPointer"], 16)
    assert not base <= ip < base + size, "did not reach the buffer"
    return tid, ip


def function_trace(client, tid, code, end):
    trace = client.tool("veh_trace_basic_blocks", inline_trace_args({
        "threadId": tid, "start": hex(code), "end": hex(code + end),
        "stop_on_return": True, "max_steps": 200000, "timeout_ms": 20000,
        "collect_events": True, "collect_register_events": True, "collect_memory_events": True,
        "collect_code": True,
    }), timeout=40)
    assert trace.get("stop_reason") == "function_return", trace
    scope = trace["function_scope"]
    assert scope["returned"] is True and scope["external_steps"] > 0, trace
    assert int(scope["return_address"], 16) == int(trace["final_address"], 16), trace
    assert scope["return_snapshot"]["instruction_pointer"] == scope["return_address"], trace
    assert all(code <= int(event["instruction"], 16) < code + end
               for event in trace["register_events"] + trace["memory_events"]), trace
    return trace


def test_return_into_an_api_is_followed_back_into_the_range(session):
    client, base, size = session
    tid, code = enter_buffer(client, base, size, "TraceExternalExitTarget")
    trace = function_trace(client, tid, code, THUNK_END)

    exits = [e for e in trace["events"] if e["type"] == "edge" and e["kind"] == "range_exit"]
    assert [int(e["source_instruction"], 16) for e in exits] == [code + THUNK_RET], trace["events"]
    after = trace["events"][trace["events"].index(exits[0]) + 1]
    # Collection resumes where the API returned, and runs on to the function's own ret.
    assert after["type"] == "block_entry" and int(after["block"], 16) == code + RESUME, trace["events"]
    # The entry names the snapshot of the state the API left: its return value is the thread id.
    snapshot = next(s for s in trace["snapshots"] if s["id"] == after["snapshot"])
    assert int(snapshot["instruction_pointer"], 16) == code + RESUME, snapshot
    assert int(snapshot["registers"][0], 16) & 0xFFFFFFFF == tid, snapshot
    returns = [e for e in trace["events"] if e["type"] == "edge" and e["kind"] == "return"]
    assert int(returns[-1]["source_instruction"], 16) == code + FUNCTION_RET, trace["events"]
    assert returns[-1]["target"] == trace["function_scope"]["return_address"], trace["events"]


def test_entry_block_code_is_not_the_breakpoint_that_stopped_there(session):
    """A whole-module trace decodes on execution, from live memory: the INT3 of the function
    breakpoint the thread stopped at must be gone before the entry block is read."""
    client, base, size = session
    bp = client.tool("veh_set_function_breakpoint", {"name": "TraceFunctionScopeTarget"})
    assert bp.get("success"), bp
    stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
    assert stop.get("stopped") and int(stop["address"], 16) == int(bp["address"], 16), stop
    trace = client.tool("veh_trace_basic_blocks", inline_trace_args({
        "threadId": stop["threadId"], "start": hex(base), "end": hex(base + size),
        "stop_on_return": True, "max_steps": 200000, "timeout_ms": 20000,
        "collect_events": True, "collect_code": True,
    }), timeout=40)
    client.tool("veh_remove_breakpoint", {"id": bp["id"]})
    assert trace.get("stop_reason") == "function_return", trace
    entry = trace["events"][0]
    assert entry["type"] == "block_entry" and int(entry["block"], 16) == int(bp["address"], 16), entry
    version = trace["code_versions"][entry["code_version"]]
    assert version["size"] > 1 and not version["bytes"].lower().startswith("cc"), version


def test_tail_jump_returns_on_behalf_of_the_function(session):
    client, base, size = session
    tid, code = enter_buffer(client, base, size, "TraceExternalTailTarget")
    trace = function_trace(client, tid, code, TAIL_END)

    edges = [e for e in trace["events"] if e["type"] == "edge"]
    assert [(int(e["source_instruction"], 16), e["kind"]) for e in edges] == \
        [(code + TAIL_JMP, "range_exit")], trace["events"]


@pytest.mark.parametrize("path", ["direct", "batch", "action"])
def test_tail_jump_stops_before_external_execution_at_step_budget(session, path, tmp_path):
    client, base, size = session
    tid, code = enter_buffer(client, base, size, "TraceExternalTailTarget")
    args = inline_trace_args({
        "threadId": tid, "start": hex(code), "end": hex(code + TAIL_END),
        "stop_on_return": True, "max_steps": 2, "timeout_ms": 5000,
        "collect_events": True, "collect_code": True,
    })
    if path == "batch":
        batch = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_basic_blocks", "args": args}]})
        trace = batch["results"][0]["result"]
    elif path == "action":
        # Reach the action breakpoint from a separate instruction. Installing it
        # at the current stopped IP would exercise breakpoint retry/skip instead.
        hop = code + 128
        jump = b"\xe9" + (-133).to_bytes(4, "little", signed=True)
        assert client.tool("veh_write_memory", {"address": hex(hop), "data": jump.hex(" ")}).get("success")
        assert client.tool("veh_set_register", {"threadId": tid, "name": "eip" if IS_X86 else "rip",
            "value": hex(hop)}).get("success")
        output = tmp_path / "external-budget.json"
        bp = client.tool("veh_set_breakpoint", {"address": hex(code), "action": [
            {"tool": "veh_trace_basic_blocks", "args": dict(args, output_file=str(output), output_mode="file")},
            {"tool": "veh_set_breakpoint", "args": {"address": "$0.function_scope.return_address"}},
        ]})
        assert bp.get("success"), bp
        stopped = None
        try:
            stopped = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=20)
            assert stopped.get("reason") == "breakpoint", (stopped, output.exists(), client.stderr_tail()[-1500:])
            with output.open(encoding="utf-8") as source:
                trace = json.load(source)
        finally:
            if stopped and stopped.get("breakpointId") and stopped["breakpointId"] != bp["id"]:
                client.tool("veh_remove_breakpoint", {"id": stopped["breakpointId"]})
            client.tool("veh_remove_breakpoint", {"id": bp["id"]})
    else:
        trace = client.tool("veh_trace_basic_blocks", args)
    assert trace.get("stop_reason") == "max_steps", trace
    assert trace["steps_executed"] == 2, trace
    assert trace["function_scope"]["external_steps"] == 0, trace
