"""A single step runs one instruction: from a software breakpoint, and over CPUID where a hypervisor raises the
trap one instruction late."""
import ctypes
import os
from ctypes import wintypes

import pytest

from build_paths import RELEASE, IS_X86
from owned_mcp_client import OwnedMcpClient

PREFIX = "e" if IS_X86 else "r"


def check(result):
    assert "error" not in result and result.get("success", True), result
    return result


@pytest.fixture(scope="module")
def session():
    client = OwnedMcpClient(args=["--profile=full"])
    target = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        client.initialize("cpuid-step-test")
        launch = check(client.tool("veh_launch", {
            "program": os.path.join(RELEASE, "test_target.exe"), "stopOnEntry": True,
        }))
        # Keep the original process handle so cleanup cannot adopt a reused PID.
        target = kernel.OpenProcess(0x00100000, False, launch["pid"])
        assert target, ctypes.get_last_error()
        bp = check(client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"}))
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))
        tid = stop["threadId"]
        # the registers the tests change, put back so the target leaves TraceCoverageTarget and exits
        saved = registers(client, tid)
        page = check(client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"}))
        try:
            yield client, tid, int(page["address"], 0)
        finally:
            check(client.tool("veh_batch", {"steps": [
                {"tool": "veh_set_register", "args": {"threadId": tid, "name": PREFIX + reg, "value": hex(saved[PREFIX + reg])}}
                for reg in ("ax", "bx", "cx", "dx", "si", "di", "ip")]}))
    finally:
        client.close()
        if target:
            try:
                assert kernel.WaitForSingleObject(target, 5000) == 0, "test target did not exit"
            finally:
                kernel.CloseHandle(target)


def place(client, tid, page, code):
    """Write `code` at `page` and point the stopped thread at it with EAX = ECX = 0 and ESI = 2."""
    steps = [{"tool": "veh_write_memory", "args": {"address": hex(page), "data": code}}]
    for reg, value in [("ax", 0), ("cx", 0), ("si", 2), ("ip", page)]:
        steps.append({"tool": "veh_set_register", "args": {"threadId": tid, "name": PREFIX + reg, "value": hex(value)}})
    result = check(client.tool("veh_batch", {"steps": steps}))
    assert all("error" not in item["result"] for item in result["results"]), result


def registers(client, tid):
    return {name: int(value, 0) for name, value in check(client.tool("veh_registers", {"threadId": tid}))["registers"].items()
            if isinstance(value, str) and value.startswith("0x")}


def step(client, tid):
    result = check(client.tool("veh_step_in", {"threadId": tid}, timeout=15))
    assert result.get("stepCompleted"), result
    return registers(client, tid)


def test_step_over_nop(session):
    client, tid, page = session
    place(client, tid, page, "90 90 90 90")
    assert step(client, tid)[PREFIX + "ip"] == page + 1
    assert step(client, tid)[PREFIX + "ip"] == page + 2


def test_step_from_breakpoint(session):
    """A step from a software breakpoint runs the instruction under it only."""
    client, tid, page = session
    place(client, tid, page, "90 90 90 90 90 90")
    bp = check(client.tool("veh_set_breakpoint", {"address": hex(page + 3)}))
    try:
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint" and int(stop["address"], 0) == page + 3, stop
        assert step(client, tid)[PREFIX + "ip"] == page + 4
        assert step(client, tid)[PREFIX + "ip"] == page + 5
    finally:
        check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))


def test_step_over_cpuid(session):
    client, tid, page = session
    place(client, tid, page, "0F A2 89 DE 89 D7 90 90")  # CPUID; MOV ESI, EBX; MOV EDI, EDX; NOP; NOP
    after = step(client, tid)
    assert after[PREFIX + "ip"] == page + 2, hex(after[PREFIX + "ip"])
    assert after[PREFIX + "si"] == 2, after  # the MOV after CPUID has not run
    after = step(client, tid)
    assert after[PREFIX + "ip"] == page + 4 and after[PREFIX + "si"] == after[PREFIX + "bx"], after


def test_step_from_breakpoint_on_cpuid(session):
    client, tid, page = session
    place(client, tid, page, "90 3E 0F A2 89 DE 90 90")  # NOP; prefixed CPUID; MOV ESI, EBX
    bp = check(client.tool("veh_set_breakpoint", {"address": hex(page + 1)}))
    try:
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint" and int(stop["address"], 0) == page + 1, stop
        after = step(client, tid)
        assert after[PREFIX + "ip"] == page + 4 and after[PREFIX + "si"] == 2, after
    finally:
        check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))
