"""Synthetic read/modify/write and conditional-access trace regressions."""
import ctypes
import json
import os
import subprocess
import sys
from ctypes import wintypes

import pytest

from build_paths import RELEASE, IS_X86, ROOT
from mcp_test_client import McpClient


def check(result):
    assert "error" not in result and result.get("success", True), result
    return result


@pytest.fixture(scope="module")
def session():
    client = McpClient(args=["--profile=full"])
    target = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        client.initialize("trace-memory-access-test")
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
        page = check(client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"}))
        yield client, stop["threadId"], int(page["address"], 0)
    finally:
        client.close()
        if target:
            try:
                assert kernel.WaitForSingleObject(target, 5000) == 0, "test target did not exit"
            finally:
                kernel.CloseHandle(target)


class Program:
    def __init__(self, start, data):
        self.start, self.data = start, data
        self.code = bytearray()
        self.steps = 0
        self.accesses = []
        self.flags = []
        self.unsupported_writes = 0
        self.initial = bytes(64)

    def emit(self, code, before=None, after=None, size=4, address=None, zf=None):
        instruction = self.start + len(self.code)
        self.code.extend(bytes.fromhex(code))
        self.steps += 1
        if before is not None:
            self.accesses.append(("read", instruction, self.steps, address or self.data,
                                  size, before, None))
        if after is not None:
            self.accesses.append(("write", instruction, self.steps, address or self.data,
                                  size, before, after))
        if zf is not None:
            self.flags.append((self.steps, zf))
        return instruction

    def immediate(self, opcode, value, size=4):
        self.emit(opcode + " " + value.to_bytes(size, "little").hex(" "))


def rmw_program(start, data):
    p = Program(start, data)
    # Exact indexed-memory encoding, with both successful and failed comparisons.
    p.emit("F0 0F B1 0C 2B", 0, 1, zf=True)
    p.emit("F0 0F B1 0C 2B", 1, 1, zf=False)
    p.emit("F0 0F B1 0C 2B", 1, 1, zf=True)  # successful same-value store
    p.immediate("B9", 3)
    p.emit("F0 0F C1 0C 2B", 1, 4)  # LOCK XADD
    p.immediate("B9", 9)
    p.emit("87 0C 2B", 4, 9)  # XCHG is implicitly locked
    p.emit("F0 01 0C 2B", 9, 13)  # LOCK ADD with ECX=4
    p.immediate("B8", 13)
    p.immediate("B9", 17)
    p.emit("0F B1 0C 2B", 13, 17, zf=True)  # no LOCK prefix
    p.emit("0F B1 0C 2B", 17, 17, zf=False)
    # Sub-register widths and unchanged failed writebacks.
    for prefix, opcode, width, old, new in [
        ("", "B0", 1, 17, 18),
        ("66 ", "B1", 2, 18, 19),
    ]:
        p.immediate("B8", old)
        p.immediate("B9", new)
        p.emit(prefix + "F0 0F " + opcode + " 0C 2B", old, new, size=width, zf=True)
        p.emit(prefix + "F0 0F " + opcode + " 0C 2B", new, new, size=width, zf=False)
    if not IS_X86:
        p.immediate("48 B8", 19, 8)
        p.immediate("48 B9", 20, 8)
        p.emit("F0 48 0F B1 0C 2B", 19, 20, size=8, zf=True)
        p.emit("F0 48 0F B1 0C 2B", 20, 20, size=8, zf=False)
    # CMPXCHG8B/16B use EBX:ECX/RBX:RCX as the new value, so address via DI.
    for width, rex, offset in [(8, "", 32)] + ([] if IS_X86 else [(16, "48 ", 48)]):
        p.immediate("BF" if IS_X86 else "48 BF", data + offset, 4 if IS_X86 else 8)
        p.immediate("BB", 1)
        p.immediate("B9", 0)
        p.immediate("B8", 0)
        p.immediate("BA", 0)
        p.emit("F0 " + rex + "0F C7 0F", 0, 1, size=width, address=data + offset, zf=True)
        p.immediate("B8", 0)
        p.emit("F0 " + rex + "0F C7 0F", 1, 1, size=width, address=data + offset, zf=False)
    return p


def conditional_program(start, data):
    p = Program(start, data)
    p.emit("31 D2")  # ZF=1
    p.emit("0F 44 C6")  # CMOVZ EAX,ESI executes (ESI=2)
    p.emit("89 04 2B", after=2)
    p.immediate("BA", 1)
    p.emit("85 D2")  # ZF=0, flags independent of configured source registers
    p.emit("0F 44 C7")  # CMOVZ EAX,EDI skips (EDI=4), retains ESI origin
    p.emit("89 04 2B", after=2)
    p.emit("0F 44 04 2B", before=2)  # memory source is loaded even when ZF=0
    p.emit("31 D2")
    p.emit("0F 44 04 2B", before=2)  # loaded and assigned, same value
    return p


def masked_program(start, data):
    p = Program(start, data)
    p.immediate("BF" if IS_X86 else "48 BF", data, 4 if IS_X86 else 8)
    p.emit("66 0F EF C0")  # PXOR XMM0,XMM0
    p.emit("66 0F EF C9")  # PXOR XMM1,XMM1: every mask bit is zero
    p.emit("66 0F F7 C1")  # MASKMOVDQU skips every destination byte
    p.unsupported_writes = 1
    p.initial = bytes([0xA5] * 64)
    return p


def capture(client, tid, program, output, caller, mode):
    prefix = "e" if IS_X86 else "r"
    steps = [
        {"tool": "veh_write_memory", "args": {"address": hex(program.start),
         "data": (program.code + b"\x90").hex(" ")}},
        {"tool": "veh_write_memory", "args": {"address": hex(program.data), "data": program.initial.hex(" ")}},
    ]
    for reg, value in [("ax", 0), ("cx", 1), ("bx", program.data), ("bp", 0),
                       ("si", 2), ("di", 4), ("ip", program.start)]:
        steps.append({"tool": "veh_set_register", "args": {
            "threadId": tid, "name": prefix + reg, "value": hex(value)}})
    steps.append({"tool": "veh_set_register", "args": {
        "threadId": tid, "name": "eflags", "value": "0x202"}})
    setup = check(client.tool("veh_batch", {"steps": steps}))
    assert all("error" not in item["result"] for item in setup["results"]), setup
    args = {
        "threadId": tid, "start": hex(program.start), "end": hex(program.start + len(program.code)),
        "max_steps": program.steps + 4, "timeout_ms": 5000, "stack_bytes": 0,
        "collect_memory_reads": True, "collect_memory_writes": True,
        "collect_memory_events": True, "collect_register_events": True,
        "max_memory_events": 256, "max_register_events": 256,
        "dependency_sources": [prefix + "si", prefix + "di"],
        "output_file": output,
    }
    if mode == "file":
        args.update(events_output="file", events_output_path=output + ".vte")
    if caller == "direct":
        check(client.tool("veh_trace_basic_blocks", args, timeout=15))
    elif caller == "batch":
        result = check(client.tool("veh_batch", {"steps": [
            {"tool": "veh_trace_basic_blocks", "args": args}]}))
        check(result["results"][0]["result"])
    else:
        bp = check(client.tool("veh_set_breakpoint", {
            "address": hex(program.start), "action": [
                {"tool": "veh_trace_basic_blocks", "args": args},
                {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
            ]}))
        sentinel = None
        try:
            stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
            sentinel = stop.get("breakpointId")
            assert stop.get("reason") == "breakpoint" and sentinel != bp["id"], stop
            assert int(stop["address"], 0) == program.start + len(program.code), stop
        finally:
            if sentinel and sentinel != bp["id"]:
                check(client.tool("veh_remove_breakpoint", {"id": sentinel}))
            check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))
    with open(output, encoding="utf-8") as stream:
        result = json.load(stream)
    assert result["stop_reason"] == "left_range", result
    assert result["steps_executed"] == program.steps, result
    assert result["unsupported_memory_reads"] == 0, result
    assert result["unsupported_memory_writes"] == program.unsupported_writes, result
    assert result["dependency_incomplete"] == bool(program.unsupported_writes), result
    if mode == "inline":
        return result, result["memory_events"], result["register_events"]
    converted = output + ".jsonl"
    completed = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "read_trace_event_stream.py"),
                                output + ".vte", "--output", converted],
                               capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr
    with open(converted, encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream]
    assert records[0]["truncated"] is False, records[0]
    return (result, [r for r in records if r.get("record") == "memory_event"],
            [r for r in records if r.get("record") == "register_event"])


@pytest.mark.parametrize("caller", ["direct", "batch", "action"])
@pytest.mark.parametrize("mode", ["inline", "file"])
@pytest.mark.parametrize("kind", ["rmw", "conditional", "masked"])
def test_memory_accesses(session, tmp_path, caller, mode, kind):
    client, tid, page = session
    builder = {"rmw": rmw_program, "conditional": conditional_program, "masked": masked_program}[kind]
    program = builder(page, page + 2048)
    result, memory, registers = capture(client, tid, program, str(tmp_path / "trace.json"), caller, mode)
    actual = [(e["kind"], int(e["instruction"], 0), e["sequence"], int(e["address"], 0), e["size"])
              for e in memory]
    assert actual == [e[:5] for e in program.accesses], (actual, program.accesses)
    final_bytes = bytes.fromhex(check(client.tool("veh_read_memory", {
        "address": hex(program.data), "size": 64}))["hex"])
    final = bytearray(program.initial)
    for expected in program.accesses:
        if expected[0] == "write":
            offset, size, value = expected[3] - program.data, expected[4], expected[6]
            final[offset:offset + size] = value.to_bytes(size, "little")
    assert final_bytes == final, (final_bytes.hex(), final.hex())
    for event, expected in zip(memory, program.accesses):
        before, after = expected[5:]
        if event["kind"] == "read":
            assert event["value"] == before.to_bytes(event["size"], "little").hex(" "), event
        else:
            if before is not None:
                assert event["before"] == before.to_bytes(event["size"], "little").hex(" "), event
            assert event["after"] == after.to_bytes(event["size"], "little").hex(" "), event
            aggregate = next(w for w in result["memory_writes"]
                             if int(w["instruction"], 0) == int(event["instruction"], 0))
            assert (aggregate["address"], aggregate["before"], aggregate["after"]) == (
                event["address"], event["before"], event["after"]), aggregate
    expected_flags = dict(program.flags)
    flags = 0x202
    for event in registers:
        if "eflags" in event["changes"]:
            flags = int(event["changes"]["eflags"]["after"], 0)
        if event["sequence"] in expected_flags:
            assert bool(flags & 0x40) == expected_flags[event["sequence"]], event
    if kind == "conditional":
        source = "esi" if IS_X86 else "rsi"
        accumulator = "eax" if IS_X86 else "rax"
        assert source in result["final_dependencies"][accumulator], result["final_dependencies"]
        assert all(source in w.get("dependencies", []) for w in result["memory_writes"]), result["memory_writes"]
