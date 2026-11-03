"""Process steps finish on actual same-thread terminal stops and consume them."""
import time
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"


def run():
    cases = [("veh_step_in", "exception"), ("veh_step_over", "exception"), ("veh_step_out", "exception"),
             ("veh_step_in", "exception-before"), ("veh_step_in", "breakpoint"),
             ("veh_step_in", "thread-exit"), ("veh_step_in", "exit"),
             ("veh_step_in", "foreign"), ("veh_step_in", "exception-batch"),
             ("veh_step_over", "exception-batch"), ("veh_step_out", "exception-batch")]
    for tool, suffix in cases:
        batch = suffix.endswith("-batch")
        mode = "step-stop-" + suffix.removesuffix("-batch")
        with OwnedMcpClient() as client:
            client.initialize("step-interruptions")
            attached = client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                "agent": str(FIXTURE), "agent_args": ["--metadata", mode]})
            assert attached.get("success"), attached
            started = time.monotonic()
            args = {"threadId": 77, "timeout": 1}
            if batch:
                envelope = client.tool("veh_batch", {"steps": [{"tool": tool, "args": args}]}, timeout=7)
                result = envelope["results"][0]["result"]
            else:
                result = client.tool(tool, args, timeout=7)
            assert time.monotonic() - started < 2, (tool, mode, result)
            expected = "step" if suffix == "foreign" else "exception" if suffix.startswith("exception") else suffix
            assert result.get("reason") == expected, (tool, mode, result)
            assert result.get("stepCompleted") == (expected == "step"), result
            assert result.get("success") == (expected == "step"), result
            if expected == "exception":
                assert int(result["exception"]["exceptionCode"], 16) == 0xC000001D, result
                assert int(result["instructionPointer"], 16) == 0x2000, result
                assert int(client.tool("veh_exception_info")["address"], 16) == 0x2000
            if expected not in ("exit", "thread-exit"):
                continued = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 2}, timeout=5)
                expected_address = 0x4000 if suffix == "foreign" else 0x3000
                assert int(continued["address"], 16) == expected_address, (mode, continued)
                threads = client.tool("veh_threads")
                assert threads["threads"][0]["name"] == ("continues=0" if suffix == "foreign" else "continues=1"), threads
            assert client.tool("veh_detach").get("success")
    check_actions()
    print("PASS process step exception/BP/thread/process exit, receipt consumption, foreign-stop preservation and batch/action parity")


def check_actions():
    for tool in ("veh_step_in", "veh_step_out"):
        with OwnedMcpClient() as client:
            client.initialize("step-action-interruption")
            attached = client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                "agent": str(FIXTURE), "agent_args": ["--metadata", "step-stop-action"]})
            assert attached.get("success"), attached
            bp = client.tool("veh_set_breakpoint", {"address": "0x1000",
                "action": [{"tool": tool, "args": {"threadId": 77, "timeout": 1}}]})
            assert bp.get("success"), bp
            assert client.tool("veh_continue", {"wait": False}).get("success")
            client.wait_notification("notifications/logging",
                lambda p: "automatic continue was skipped" in p.get("data", ""), timeout=5)
            info = client.tool("veh_exception_info")
            assert int(info["exceptionCode"], 16) == 0xC000001D and int(info["address"], 16) == 0x2000, info
            threads = client.tool("veh_threads")
            assert threads["threads"][0]["name"] == "continues=1", threads
            continued = client.tool("veh_continue", {"wait": True, "timeout": 2}, timeout=5)
            assert int(continued["address"], 16) == 0x3000, continued
            assert client.tool("veh_detach").get("success")


if __name__ == "__main__":
    run()
