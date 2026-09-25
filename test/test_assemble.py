"""veh_assemble: asmjit/asmtk text assembler, checked against the Zydis disassembler.

The round trip disassembles real code (test_target and ntdll), reassembles every
instruction at its own address, and requires identical bytes or an encoding
that decodes back to the same text.
"""
import os

import pytest

from build_paths import RELEASE, IS_X86
from mcp_test_client import McpClient

TARGET = os.path.join(RELEASE, "test_target.exe")
# Rare legacy forms asmtk does not parse, and far pointers (data decoded as code).
UNSUPPORTED = ("salc", "insb", "insw", "insd", "outsb", "outsw", "outsd", "xlat", "fcmovu", "fcmovnu")


def test_standalone_encodings():
    with McpClient() as client:
        client.initialize("assemble-standalone")
        mov = client.tool("veh_assemble", {"code": "mov esi, eax"})
        assert mov["bytes"] == "89 C6" and mov["arch"] == "x64", mov
        jmp = client.tool("veh_assemble", {"code": "jmp 0x140001010", "address": "0x140001000"})
        assert jmp["bytes"] == "EB 0E", jmp
        call = client.tool("veh_assemble", {"code": "call 0x140002000", "address": "0x140001000"})
        assert call["bytes"] == "E8 FB 0F 00 00", call
        block = client.tool("veh_assemble", {"code": "push ebp; mov ebp, esp\njne 0x401080", "address": "0x401000", "arch": "x86"})
        assert block["bytes"] == "55 89 E5 75 7B", block
        assert [line["text"] for line in block["listing"]] == ["push ebp", "mov ebp, esp", "jnz 0x00401080"], block
        loop = client.tool("veh_assemble", {"code": "top: dec ecx; jnz top", "address": "0x1000"})
        assert loop["bytes"] == "FF C9 75 FC", loop
        rip = client.tool("veh_assemble", {"code": "mov rax, qword ptr [rip+0x10]", "address": "0x140001000"})
        assert rip["bytes"] == "48 8B 05 10 00 00 00", rip

        bad = client.tool("veh_assemble", {"code": "nop; bogus eax"})
        assert "error" in bad and bad["line"] == 2, bad
        assert "error" in client.tool("veh_assemble", {"code": "jmp missing_label"})
        assert "error" in client.tool("veh_assemble", {"code": "nop", "write": True})


def _equivalent(original, listing):
    if len(listing) != 1:
        return False
    normalize = lambda text: text.replace("ds:", "").replace("ret 0x00", "ret")
    return normalize(listing[0]["text"]) == normalize(original)


def test_round_trip_against_zydis_and_write():
    with McpClient() as client:
        client.initialize("assemble-roundtrip")
        assert client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}).get("success")
        modules = {m["name"].lower(): int(m["baseAddress"], 16) for m in client.tool("veh_modules")["modules"]}
        instructions = []
        for name in ("test_target.exe", "ntdll.dll"):
            address = modules[name] + 0x1000
            for _ in range(2):
                chunk = client.tool("veh_disassemble", {"address": hex(address), "count": 500})["instructions"]
                instructions += chunk
                address = int(chunk[-1]["address"], 16) + len(chunk[-1]["bytes"].split())

        checked, failures = 0, []
        for insn in instructions:
            text = insn["mnemonic"]
            if text.startswith("db ") or "far" in text.split() or text.split()[0] in UNSUPPORTED:
                continue
            result = client.tool("veh_assemble", {"code": text, "address": insn["address"]})
            checked += 1
            if "error" in result:
                failures.append((insn["address"], text, result["error"]))
            elif result["bytes"] != insn["bytes"].upper() and not _equivalent(text, result["listing"]):
                failures.append((insn["address"], text, insn["bytes"], result["bytes"]))
        assert checked > 1800 and not failures, failures[:10]

        # write=true patches the target; the arch follows the target automatically.
        cave = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        target = int(cave["address"], 16)
        written = client.tool("veh_assemble", {"code": "xor eax, eax; ret", "address": hex(target), "write": True})
        assert written.get("written") and written["arch"] == ("x86" if IS_X86 else "x64"), written
        memory = client.tool("veh_read_memory", {"address": hex(target), "size": 3})
        assert memory["hex"].replace(" ", "").upper() == written["bytes"].replace(" ", ""), memory
