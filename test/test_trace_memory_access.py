"""Synthetic read/modify/write and conditional-access trace regressions."""
from mcp_test_client import inline_trace_args
import ctypes
import json
import os
import subprocess
import sys
from ctypes import wintypes

import pytest

from build_paths import RELEASE, IS_X86, ROOT
from owned_mcp_client import OwnedMcpClient


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
    p.unsupported_writes = 0
    p.initial = bytes([0xA5] * 64)
    return p


def string_program(start, data):
    p = Program(start, data)
    p.initial = bytes(range(64))
    ptr = 4 if IS_X86 else 8
    def setup(count, source=0, dest=32):
        p.immediate("BE" if IS_X86 else "48 BE", data + source, ptr)
        p.immediate("BF" if IS_X86 else "48 BF", data + dest, ptr)
        p.immediate("B9", count)
    def string(code, reads, writes=()):
        pc = p.start + len(p.code)
        p.code.extend(bytes.fromhex(code))
        # TF yields once for every REP iteration (and once for a zero count).
        for read, write in zip(reads, writes or [None] * len(reads)):
            p.steps += 1
            for offset, size, value in read:
                p.accesses.append(("read", pc, p.steps, data + offset, size, value, None))
            if write:
                offset, size, before, after = write
                p.accesses.append(("write", pc, p.steps, data + offset, size, before, after))
        if not reads:
            p.steps += 1
    p.emit("FC")
    setup(3)
    string("F3 A4", [[(i, 1, i)] for i in range(3)],
           [(32 + i, 1, 32 + i, i) for i in range(3)])
    # Zero count must not read invalid pointers or publish a write/dependency.
    p.immediate("BE" if IS_X86 else "48 BE", 0, ptr)
    p.immediate("BF" if IS_X86 else "48 BF", 0, ptr)
    p.immediate("B9", 0)
    string("F3 A4", [])
    p.immediate("B9" if IS_X86 else "48 B9", 1 << (16 if IS_X86 else 32), ptr)
    string("67 F3 A4", [])  # CX/ECX zero despite nonzero enclosing register
    # DF=1, word-sized stores and loads.
    p.emit("FD")
    setup(2, 6, 38)
    p.immediate("B8", 0xBEEF)
    string("F3 66 AB", [[], []], [(38, 2, 0x2726, 0xBEEF), (36, 2, 0x2524, 0xBEEF)])
    string("66 AD", [[(6, 2, 0x0706)]])
    p.immediate("B9", 2)
    string("F3 66 AD", [[(4, 2, 0x0504)], [(2, 2, 0x0302)]])
    p.emit("FC")
    # REPE CMPS continues over equal bytes, then stops on a mismatch.
    setup(4, 0, 0)
    string("A6", [[(0, 1, 0), (0, 1, 0)]])
    setup(5, 0, 32)
    string("F3 A6", [[(i, 1, i), (32 + i, 1, i if i < 3 else 35)] for i in range(4)])
    # REPNE SCAS stops at the matching byte; the remaining count is nonzero.
    setup(4, 0, 0)
    p.immediate("B8", 1)
    string("F2 AE", [[(0, 1, 0)], [(1, 1, 1)]])
    # Unprefixed MOVS/STOS/SCAS and a repeated dword copy.
    setup(1, 8, 40)
    string("A4", [[(8, 1, 8)]], [(40, 1, 40, 8)])
    string("AA", [[]], [(41, 1, 41, 1)])
    string("AE", [[(42, 1, 42)]])
    setup(2, 8, 48)
    string("F3 A5", [[(8 + i * 4, 4, int.from_bytes(p.initial[8+i*4:12+i*4], "little"))]
                     for i in range(2)],
           [(48+i*4, 4, int.from_bytes(p.initial[48+i*4:52+i*4], "little"),
             int.from_bytes(p.initial[8+i*4:12+i*4], "little")) for i in range(2)])
    if not IS_X86:
        setup(1, 16, 56)
        string("F3 48 A5", [[(16, 8, int.from_bytes(p.initial[16:24], "little"))]],
               [(56, 8, int.from_bytes(p.initial[56:64], "little"),
                 int.from_bytes(p.initial[16:24], "little"))])
    return p


def sparse_mask_program(start, data, mmx=False):
    p = Program(start, data)
    mask = bytes(0x80 if i % 3 != 1 else 0x7f for i in range(16))
    p.initial = bytes(range(16)) + mask + bytes([0xA5] * 32)
    p.immediate("BF" if IS_X86 else "48 BF", data + 32, 4 if IS_X86 else 8)
    width = 8 if mmx else 16
    prefix = "" if mmx else "66 "
    for code, offset in [(prefix + "0F 6F 03", 0), (prefix + "0F 6F 4B 10", 16)]:
        p.emit(code, before=int.from_bytes(p.initial[offset:offset + width], "little"),
               size=width, address=data + offset)
    pc = p.emit(prefix + "0F F7 C1")
    for lane in range(width):
        if mask[lane] & 0x80:
            p.accesses.append(("write", pc, p.steps, data + 32 + lane, 1, 0xA5, lane))
    if mmx:
        p.emit("0F 77")
    return p


def indexed_program(start, data):
    p = Program(start, data)
    p.immediate("B9", 33)
    p.emit("0F AB 0B", 0, 2, address=data + 4)  # BTS [BX], bit33
    p.immediate("B9", 0xffffffff)
    p.emit("0F AB 4B 08", 2, 0x80000002, address=data + 4)  # Negative bit index
    p.immediate("B9", 64)
    p.emit("0F BB 0B", 0, 1, address=data + 8)  # BTC bit64
    p.immediate("B8" if IS_X86 else "48 B8", 0xDEAD0003, 4 if IS_X86 else 8)
    p.emit("D7", before=0, size=1, address=data + 3)  # XLAT uses AL only
    return p


def wide_vector_program(start, data):
    if not ctypes.windll.kernel32.IsProcessorFeaturePresent(39):
        pytest.skip("AVX execution requires enabled CPU/OS state")
    p = Program(start, data)
    p.initial = bytes(range(64))
    pc = p.emit("C5 FE 6F 03")  # VMOVDQU YMM0,[BX]
    for offset in (0, 16):
        p.accesses.append(("read", pc, p.steps, data + offset, 16,
                           int.from_bytes(p.initial[offset:offset + 16], "little"), None))
    pc = p.emit("C5 FE 7F 43 20")  # VMOVDQU [BX+32],YMM0
    for offset in (0, 16):
        p.accesses.append(("write", pc, p.steps, data + 32 + offset, 16,
                           int.from_bytes(p.initial[32+offset:48+offset], "little"),
                           int.from_bytes(p.initial[offset:offset+16], "little")))
    p.emit("C5 F8 77")
    return p


def avx_mask_program(start, data, client):
    if not ctypes.windll.kernel32.IsProcessorFeaturePresent(40):
        pytest.skip("AVX2 execution requires enabled CPU/OS state")
    p = Program(start, data)
    p.initial = bytes(range(32)) + b"".join((0x80000000 if i % 2 == 0 else 0x7fffffff).to_bytes(4, "little")
                                           for i in range(8)) + bytes([0xA5] * 32)
    bx = "ebx" if IS_X86 else "rbx"
    def instruction(code):
        assembled = check(client.tool("veh_assemble", {"code": code, "address": hex(p.start + len(p.code))}))
        return p.emit(assembled["bytes"])
    pc = instruction(f"vmovdqu ymm1, [{bx}+32]")
    for offset in (32, 48):
        p.accesses.append(("read", pc, p.steps, data + offset, 16,
                           int.from_bytes(p.initial[offset:offset+16], "little"), None))
    pc = instruction(f"vpmaskmovd ymm0, ymm1, [{bx}]")
    for lane in range(0, 8, 2):
        p.accesses.append(("read", pc, p.steps, data + lane * 4, 4,
                           int.from_bytes(p.initial[lane*4:lane*4+4], "little"), None))
    pc = instruction(f"vpmaskmovd [{bx}+64], ymm1, ymm0")
    for lane in range(0, 8, 2):
        p.accesses.append(("write", pc, p.steps, data + 64 + lane * 4, 4, 0xA5A5A5A5,
                           int.from_bytes(p.initial[lane*4:lane*4+4], "little")))
    p.emit("C5 F8 77")
    return p


def gather_program(start, data, client):
    if not ctypes.windll.kernel32.IsProcessorFeaturePresent(40):
        pytest.skip("AVX2 execution requires enabled CPU/OS state")
    p = Program(start, data)
    indices = [0, 0x40000000, 2, 0x40000000, 4, 0x40000000, 6, 0x40000000]
    masks = [0x80000000 if i % 2 == 0 else 0 for i in range(8)]
    p.initial = bytes(range(32)) + b"".join(v.to_bytes(4, "little") for v in indices + masks)
    bx = "ebx" if IS_X86 else "rbx"
    for reg, offset in [("ymm1", 32), ("ymm2", 64)]:
        pc = p.emit(check(client.tool("veh_assemble", {"code": f"vmovdqu {reg}, [{bx}+{offset}]"}))["bytes"])
        for at in (offset, offset + 16):
            p.accesses.append(("read", pc, p.steps, data + at, 16,
                               int.from_bytes(p.initial[at:at+16], "little"), None))
    pc = p.emit(check(client.tool("veh_assemble", {"code": f"vpgatherdd ymm0, [{bx}+ymm1*4], ymm2"}))["bytes"])
    for lane in range(0, 8, 2):
        offset = indices[lane] * 4
        p.accesses.append(("read", pc, p.steps, data + offset, 4,
                           int.from_bytes(p.initial[offset:offset+4], "little"), None))
    p.emit("C5 F8 77")
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
        receipt = check(client.tool("veh_trace_basic_blocks", inline_trace_args(args), timeout=15))
        assert receipt["capture_complete"] == (not bool(program.unsupported_writes)), receipt
        assert receipt["unsupported_memory_writes"] == program.unsupported_writes, receipt
        assert receipt["output_file"]["capture_complete"] == receipt["capture_complete"], receipt
    elif caller == "batch":
        result = check(client.tool("veh_batch", {"steps": [
            {"tool": "veh_trace_basic_blocks", "args": inline_trace_args(args)}]}))
        receipt = check(result["results"][0]["result"])
        assert receipt["capture_complete"] == (not bool(program.unsupported_writes)), receipt
        assert receipt["output_file"]["capture_complete"] == receipt["capture_complete"], receipt
    else:
        bp = check(client.tool("veh_set_breakpoint", {
            "address": hex(program.start), "action": [
                {"tool": "veh_trace_basic_blocks", "args": inline_trace_args(args)},
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
    assert result["capture_complete"] == (not bool(program.unsupported_writes)), result
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
@pytest.mark.parametrize("kind", ["rmw", "conditional", "masked", "string", "sparse_mask", "mmx_mask", "indexed", "wide_vector", "avx_mask", "gather"])
def test_memory_accesses(session, tmp_path, caller, mode, kind):
    client, tid, page = session
    builder = {"rmw": rmw_program, "conditional": conditional_program, "masked": masked_program, "string": string_program,
               "sparse_mask": sparse_mask_program, "mmx_mask": lambda s, d: sparse_mask_program(s, d, True),
               "indexed": indexed_program, "wide_vector": wide_vector_program,
               "avx_mask": lambda s, d: avx_mask_program(s, d, client),
               "gather": lambda s, d: gather_program(s, d, client)}[kind]
    program = builder(page, page + 2048)
    result, memory, registers = capture(client, tid, program, str(tmp_path / "trace.json"), caller, mode)
    actual = [(e["kind"], int(e["instruction"], 0), e["sequence"], int(e["address"], 0), e["size"])
              for e in memory]
    assert actual == [e[:5] for e in program.accesses], (actual, program.accesses)
    final_bytes = bytes.fromhex(check(client.tool("veh_read_memory", {
        "address": hex(program.data), "size": len(program.initial)}))["hex"])
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
                             if int(w["instruction"], 0) == int(event["instruction"], 0)
                             and w["address"] == event["address"])
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


@pytest.mark.parametrize("caller", ["direct", "batch", "action"])
@pytest.mark.parametrize("mode", ["inline", "file"])
def test_segment_first_access(session, tmp_path, caller, mode):
    client, tid, page = session
    offset, segment = (0x18, "fs") if IS_X86 else (0x30, "gs")
    expected = check(client.tool("veh_evaluate", {"expression": f"{segment}:[{hex(offset)}]",
                                                  "threadId": tid}))
    teb = int(expected["tebAddress"], 0)
    p = Program(page, page + 2048)
    p.emit("64 A1 18 00 00 00" if IS_X86 else "65 48 8B 04 25 30 00 00 00",
           before=teb, size=4 if IS_X86 else 8, address=teb + offset)
    result, memory, _ = capture(client, tid, p, str(tmp_path / "segment.json"), caller, mode)
    assert len(memory) == 1 and int(memory[0]["address"], 0) == teb + offset, memory
    assert int.from_bytes(bytes.fromhex(memory[0]["value"]), "little") == teb, memory
    assert result["unsupported_memory_reads"] == 0, result


@pytest.mark.parametrize("mode", ["inline", "file"])
def test_fxsave_large_operand(session, tmp_path, mode):
    client, tid, page = session
    p = Program(page, page + 2048)
    p.initial = bytes(512)
    p.emit(("48 " if not IS_X86 else "") + "0F AE 03")
    p.emit(("48 " if not IS_X86 else "") + "0F AE 0B")
    result, memory, _ = capture(client, tid, p, str(tmp_path / "fxsave.json"), "direct", mode)
    writes = [e for e in memory if e["kind"] == "write"]
    reads = [e for e in memory if e["kind"] == "read"]
    assert len(writes) == len(reads) == 32, (len(writes), len(reads))
    assert [int(e["address"], 0) for e in writes] == list(range(p.data, p.data + 512, 16))
    assert [e["after"] for e in writes] == [e["value"] for e in reads]
    assert all(e["before"] == bytes(16).hex(" ") for e in writes), writes
    actual = check(client.tool("veh_read_memory", {"address": hex(p.data), "size": 512}))["hex"]
    assert bytes.fromhex(actual) == b"".join(bytes.fromhex(e["after"]) for e in writes), result


@pytest.mark.parametrize("mode", ["inline", "file"])
def test_xsave_dynamic_operand(session, tmp_path, mode):
    if not ctypes.windll.kernel32.IsProcessorFeaturePresent(39):
        pytest.skip("XSAVE execution requires enabled CPU/OS state")
    client, tid, page = session
    p = Program(page, page + 2048)
    p.initial = bytes(576)
    p.immediate("B8", 3)
    p.immediate("BA", 0)
    p.emit("0F AE 23")  # XSAVE [BX], requested x87/SSE only
    p.emit("0F AE 2B")  # XRSTOR from the captured architectural area
    result, memory, _ = capture(client, tid, p, str(tmp_path / "xsave.json"), "direct", mode)
    writes = [e for e in memory if e["kind"] == "write"]
    reads = [e for e in memory if e["kind"] == "read"]
    assert len(writes) == 36 and len(reads) == 37, (len(writes), len(reads))
    assert int(reads[0]["address"], 0) == p.data + 512 and reads[0]["size"] == 8
    assert [int(e["address"], 0) for e in writes] == list(range(p.data, p.data + 576, 16))
    assert [e["after"] for e in writes] == [e["value"] for e in reads[1:]], result


@pytest.mark.parametrize("caller", ["direct", "batch", "action"])
@pytest.mark.parametrize("mode", ["inline", "file"])
def test_vector_mask_first_access(session, tmp_path, caller, mode):
    if not ctypes.windll.kernel32.IsProcessorFeaturePresent(40):
        pytest.skip("AVX2 execution requires enabled CPU/OS state")
    client, tid, page = session
    bx = "ebx" if IS_X86 else "rbx"
    initial = bytes(range(32)) + b"".join(
        (0x80000000 if i % 2 == 0 else 0).to_bytes(4, "little") for i in range(8))
    setup = Program(page, page + 2048)
    setup.initial = initial
    setup.emit(check(client.tool("veh_assemble", {"code": f"vmovdqu ymm1, [{bx}+32]"}))["bytes"])
    capture(client, tid, setup, str(tmp_path / "setup.json"), "direct", "inline")
    p = Program(page, page + 2048)
    p.initial = initial
    p.emit(check(client.tool("veh_assemble", {"code": f"vpmaskmovd ymm0, ymm1, [{bx}]"}))["bytes"])
    p.emit("C5 F8 77")
    _, memory, _ = capture(client, tid, p, str(tmp_path / "first-mask.json"), caller, mode)
    assert [int(e["address"], 0) for e in memory] == [p.data + lane * 4 for lane in range(0, 8, 2)], memory
    assert [bytes.fromhex(e["value"]) for e in memory] == [initial[lane*4:lane*4+4] for lane in range(0, 8, 2)]


@pytest.mark.parametrize("level", [0, 1, 3])
def test_enter_frame_chain(session, tmp_path, level):
    client, tid, page = session
    regs = check(client.tool("veh_registers", {"threadId": tid}))["registers"]
    sp = int(regs["esp" if IS_X86 else "rsp"], 0)
    width = 4 if IS_X86 else 8
    p = Program(page, page + 2048)
    p.initial = bytes(range(128))
    p.immediate("BD" if IS_X86 else "48 BD", p.data + 64, width)
    enter = p.emit("C8 10 00 " + f"{level:02x}")
    leave = p.emit("C9")
    result, memory, _ = capture(client, tid, p, str(tmp_path / "enter.json"), "direct", "file")
    frame_reads = [e for e in memory if int(e["instruction"], 0) == enter and e["kind"] == "read"]
    assert [int(e["address"], 0) for e in frame_reads] == [p.data + 64 - i * width for i in range(1, level)]
    frame_writes = [e for e in memory if int(e["instruction"], 0) == enter and e["kind"] == "write"]
    captured = b"".join(bytes.fromhex(e["after"]) for e in frame_writes)
    expected = (p.data + 64).to_bytes(width, "little")
    if level:
        expected = (sp - width).to_bytes(width, "little") + b"".join(
            p.initial[64-i*width:64-(i-1)*width] for i in range(level - 1, 0, -1)) + expected
    assert captured == expected, (captured.hex(), expected.hex(), result)
    restored = next(e for e in memory if int(e["instruction"], 0) == leave)
    assert int(restored["address"], 0) == sp - width and bytes.fromhex(restored["value"]) == expected[-width:]
    after = check(client.tool("veh_registers", {"threadId": tid}))["registers"]
    assert int(after["esp" if IS_X86 else "rsp"], 0) == sp, after


def test_zero_mask_inline_completeness(session):
    client, tid, page = session
    # Legacy MASKMOV may still fault on an invalid destination; keep it mapped.
    code = "66 0F EF C0 66 0F EF C9 66 0F F7 C1"
    check(client.tool("veh_write_memory", {"address": hex(page), "data": code}))
    for name, value in [("eip" if IS_X86 else "rip", page),
                        ("edi" if IS_X86 else "rdi", page + 2048), ("eflags", 0x202)]:
        check(client.tool("veh_set_register", {"threadId": tid, "name": name, "value": hex(value)}))
    result = check(client.tool("veh_trace_basic_blocks", {
        "threadId": tid, "start": hex(page), "end": hex(page + 12),
        "max_steps": 8, "timeout_ms": 1000, "stack_bytes": 0,
        "collect_memory_events": True, "output_mode": "inline", "events_output": "inline",
    }))
    assert result["steps_executed"] == 3, result
    assert result["unsupported_memory_writes"] == 0, result
    assert result["capture_complete"] is True and result["truncated"] is False, result
