"""veh_batch runs the direct MCP tool implementations (single dispatch path)."""
import os


import pytest
import time

from mcp_test_client import McpClient, ROOT


def _build_dir():
    return os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))


@pytest.fixture(scope="module")
def session():
    target = os.path.join(_build_dir(), "bin", "Release", "test_target.exe")
    with McpClient() as client:
        client.initialize("batch-unified-test")
        launched = client.tool("veh_launch", {"program": target, "stopOnEntry": True})
        assert launched.get("success"), launched
        bp = client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        client.tool("veh_remove_breakpoint", {"id": bp["id"]})
        yield client, stop["threadId"]


def _steps(client, steps):
    report = client.tool("veh_batch", {"steps": steps}, timeout=60)
    return [entry["result"] for entry in report["results"]]


def test_step_waits_for_completion(session):
    client, tid = session
    ip_key = None
    for _ in range(5):
        step, regs = _steps(client, [
            {"tool": "veh_step_in", "args": {"threadId": tid}},
            {"tool": "veh_registers", "args": {"threadId": tid}},
        ])
        assert step.get("success"), step
        ip_key = ip_key or ("rip" if "rip" in regs["registers"] else "eip")
        # Direct step semantics: the step reports the landed IP and registers agree.
        assert int(step["instructionPointer"], 16) == int(regs["registers"][ip_key], 16)


def test_register_fields_filter(session):
    client, tid = session
    is32 = client.tool("veh_registers", {"threadId": tid})["registers"]["is32bit"]
    fields = ["esp", "eip"] if is32 else ["rsp", "rip"]
    direct = client.tool("veh_registers", {"threadId": tid, "fields": fields})
    (batched,) = _steps(client, [
        {"tool": "veh_registers", "args": {"threadId": tid, "fields": fields}},
    ])
    assert set(direct["registers"]) == set(batched["registers"]) == {*fields, "is32bit"}


def test_previously_missing_tools_are_callable(session):
    client, tid = session
    exception_info, stack, chain = _steps(client, [
        {"tool": "veh_exception_info", "args": {}},
        {"tool": "veh_stack_trace", "args": {"threadId": tid}},
        {"tool": "veh_read_pointer_chain", "args": {"base": "$1.frames.0.address", "offsets": ["0"]}},
    ])
    assert "not available" not in str(exception_info.get("error", ""))
    assert stack["count"] == stack["totalFrames"] > 0
    assert "error" not in chain, chain


def test_direct_address_parser_in_batch(session):
    client, _ = session
    modules = client.tool("veh_modules")["modules"]
    base = int(modules[0]["baseAddress"], 16)
    direct, literal = _steps(client, [
        {"tool": "veh_read_memory", "args": {"address": hex(base), "size": 2}},
        {"tool": "veh_read_memory", "args": {"address": f"{hex(base)}+0x0", "size": 2}},
    ])
    assert direct["hex"] == literal["hex"] == "4d 5a"


@pytest.mark.parametrize("tool", [
    "veh_attach", "veh_launch", "veh_detach", "veh_terminate",
    "veh_batch", "veh_targeted_capture", "veh_toolbox",
])
def test_lifecycle_and_reentrant_tools_are_blocked(session, tool):
    client, _ = session
    (result,) = _steps(client, [{"tool": tool, "args": {}}])
    assert "not available in batch steps" in result["error"]
