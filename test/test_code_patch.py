"""Whole-instruction patching through the real DLL, batch and breakpoint actions."""
import json
from pathlib import Path
import tempfile

from build_paths import RELEASE, IS_X86
from owned_mcp_client import OwnedMcpClient

BIN = Path(RELEASE)
SEED = bytes.fromhex("30 C0 B8 01 00 00 00 C3 90 90 90 90 90 90 90 90")


def run(directory):
    log = directory / "patch.log"
    with OwnedMcpClient(args=["--log=" + str(log)]) as client:
        client.initialize()
        launched = client.tool("veh_launch", {"program": str(BIN / "test_target.exe"), "stopOnEntry": True})
        assert launched.get("success"), launched
        cave = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        address = int(cave["address"], 16)

        def seed(at=address, data=SEED):
            result = client.tool("veh_write_memory", {"address": hex(at), "data": data.hex()})
            assert result.get("success"), result

        def read(at=address, size=len(SEED)):
            result = client.tool("veh_read_memory", {"address": hex(at), "size": size})
            return bytes.fromhex(result["hex"])

        def patch(code="ret", **options):
            return client.tool("veh_assemble", {"code": code, "address": hex(address), "write": True, **options})

        seed()
        padded = patch()
        assert padded.get("written") and padded["patchSize"] == 2, padded
        assert padded["nopBytes"] == 1 and padded["overwrittenInstructions"] == 1, padded
        assert padded["originalBytes"] == "30 C0" and padded["patchedBytes"] == "C3 90", padded
        assert read() == b"\xc3\x90" + SEED[2:]

        seed()
        # Five-byte JMP automatically covers the two-byte XOR plus five-byte MOV.
        jump = "jmp " + hex(address + 0x1000)
        automatic = patch(jump)
        assert automatic.get("written") and automatic["patchSize"] == 7, automatic
        assert automatic["nopBytes"] == 2 and automatic["overwrittenInstructions"] == 2, automatic
        assert read()[7:] == SEED[7:]
        seed()
        refused = patch(jump, overwrite_size=2)
        assert "exceeds" in refused.get("error", "") and read() == SEED, refused
        explicit = patch(jump, overwrite_size=7)
        assert explicit == automatic, (explicit, automatic)
        seed()
        jump_batch = client.tool("veh_batch", {"steps": [{"tool": "veh_assemble", "args": {
            "code": jump, "address": hex(address), "write": True}}]})
        assert jump_batch["failed"] == 0 and jump_batch["results"][0]["result"] == automatic, jump_batch
        assert explicit.get("written") and explicit["patchSize"] == 7, explicit
        assert explicit["size"] == 5 and explicit["nopBytes"] == 2, explicit
        assert explicit["overwrittenInstructions"] == 2, explicit
        assert read()[:7] == bytes.fromhex(explicit["patchedBytes"]) and read()[7:] == SEED[7:]

        seed()
        for options in ({"overwrite_size": 5}, {"overwrite_size": 4097},
                        {"overwrite_size": 0}, {"overwrite_size": 1.5},
                        {"overwrite_size": True}, {"overwrite_size": -1},
                        {"nop_fill": "yes"}, {"raw_write": True, "overwrite_size": 2}):
            result = patch(**options)
            assert "error" in result, (options, result)
            assert read() == SEED, (options, "refused patch changed memory")
        preserved = patch(nop_fill=False)
        assert preserved.get("written") and preserved["nopBytes"] == 0 and preserved["preservedBytes"] == 1, preserved
        assert read() == b"\xc3" + SEED[1:]
        seed()
        unpadded_jump = patch(jump, nop_fill=False)
        assert unpadded_jump.get("written") and unpadded_jump["patchSize"] == 7, unpadded_jump
        assert unpadded_jump["preservedBytes"] == 2 and read()[5:] == SEED[5:]
        seed()
        exact = patch("xor al, al", nop_fill=False)
        assert exact.get("written") and exact["nopBytes"] == 0 and exact["preservedBytes"] == 0, exact

        seed()
        installed = client.tool("veh_set_breakpoint", {"address": hex(address)})
        assert installed.get("success"), installed
        blocked = patch()
        assert blocked.get("code") == "invalid_state" and "breakpoint" in blocked["error"], blocked
        assert client.tool("veh_remove_breakpoint", {"id": installed["id"]}).get("success")
        assert read() == SEED

        # An INT3 in look-ahead but outside the actual replacement does not forbid patching.
        installed = client.tool("veh_set_breakpoint", {"address": hex(address + 7)})
        assert installed.get("success"), installed
        assert patch().get("written")
        assert client.tool("veh_remove_breakpoint", {"id": installed["id"]}).get("success")
        assert read()[7:] == SEED[7:]

        # End-of-region decode/cross-region errors must leave original bytes alone.
        edge = address + 4095
        seed(edge, b"\x0f")
        invalid = client.tool("veh_assemble", {"code": "nop", "address": hex(edge), "write": True})
        assert "error" in invalid and read(edge, 1) == b"\x0f", invalid
        crossing = client.tool("veh_assemble", {"code": "nop", "address": hex(edge),
                                              "write": True, "overwrite_size": 2})
        assert "error" in crossing and read(edge, 1) == b"\x0f", crossing

        seed()
        wrong_arch = patch(arch="x64" if IS_X86 else "x86")
        assert "error" in wrong_arch and read() == SEED, wrong_arch

        # Reinitializing the same original bytes makes complete direct/batch results comparable.
        direct = patch()
        seed()
        report = client.tool("veh_batch", {"steps": [{"tool": "veh_assemble", "args": {
            "code": "ret", "address": hex(address), "write": True}}]})
        assert report["failed"] == 0 and report["results"][0]["result"] == direct, report

        seed()
        raw = patch(jump, raw_write=True)
        assert raw.get("written") and raw.get("rawWrite") and "nopBytes" not in raw, raw
        assert read()[:5] == bytes.fromhex(raw["bytes"]) and read()[5:] == SEED[5:]

        # A native breakpoint action patches a different region, then auto-continues
        # to an ordinary stop, exercising the same backend path from the action worker.
        seed()
        work = client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        assert work.get("success"), work
        assert client.tool("veh_remove_breakpoint", {"id": work["id"]}).get("success")
        outer = client.tool("veh_set_breakpoint", {"address": work["address"], "action": [{
            "tool": "veh_assemble", "args": {"code": jump, "address": hex(address), "write": True}}]})
        assert outer.get("success"), outer
        next_stop = client.tool("veh_set_function_breakpoint", {"name": "kernel32!SleepEx"})
        assert next_stop.get("success"), next_stop
        stop = client.tool("veh_continue", {"wait": True, "timeout": 5}, timeout=10)
        assert stop.get("breakpointId") == next_stop["id"], stop
        assert read() == bytes.fromhex(automatic["patchedBytes"]) + SEED[7:]
        assert client.tool("veh_terminate").get("success")

        # Guest metadata selects x86 assembly even though no host process handle exists.
        attached = client.tool("veh_attach", {"pid": 424242,
            "agent": str(BIN / "guest_backend_fixture.exe"), "target_scope": "guest",
            "agent_args": ["--metadata", "shellcode-action"]})
        assert attached.get("success"), attached
        assembled = client.tool("veh_assemble", {"code": "inc eax"})
        assert assembled["arch"] == "x86" and assembled["bytes"] == "40", assembled
        args = {"code": "nop", "address": "0x1000", "write": True}
        unsupported = client.tool("veh_assemble", args)
        assert unsupported.get("backendStatus") == 4 and "unsupported" in unsupported["error"], unsupported
        report = client.tool("veh_batch", {"steps": [{"tool": "veh_assemble", "args": args}]})
        assert report["failed"] == 1 and report["results"][0]["result"] == unsupported, report
        installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
            {"tool": "veh_assemble", "args": args}]})
        assert installed.get("success"), installed
        stop = client.tool("veh_continue", {"wait": True, "timeout": 4})
        assert stop.get("breakpointId") == 7, stop
        assert client.tool("veh_detach").get("success")
    marker = "Breakpoint action completed with an error: "
    reports = [json.loads(line.split(marker, 1)[1])
               for line in log.read_text(encoding="utf-8").splitlines() if marker in line]
    assert len(reports) == 1 and reports[0]["results"][0]["result"] == unsupported, reports
    print("PASS automatic whole-instruction spans, default/disabled NOP fill, explicit bounds, native/batch/action and guest parity")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="veh-code-patch-") as directory:
        run(Path(directory))
