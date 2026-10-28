"""Status-only shellcode failures stay truthful across direct, batch and BP actions."""
import json
import tempfile
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"


def run(directory):
    log = directory / "mcp.log"
    client = OwnedMcpClient(args=["--log=" + str(log)])
    expected_state = None
    try:
        client.initialize()

        def attach(mode):
            result = client.tool("veh_attach", {"pid": 424242, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", mode]})
            assert result.get("success"), result

        def execute():
            return client.tool("veh_execute_shellcode", {"shellcode": "C3"})

        for mode, status in (("shellcode-state", 6), ("shellcode-state-full", 6),
                             ("shellcode-error", 1), ("shellcode-unknown", 99),
                             ("shellcode-short", 0), ("shellcode-ok", None)):
            attach(mode)
            result = execute()
            if status is None:
                assert result.get("success") and result.get("exitCode") == 7, result
            else:
                assert "error" in result and result.get("backendStatus") == status, result
                assert "alloc or thread creation" not in result["error"], result
                if status == 6:
                    assert result.get("code") == "invalid_state", result
                    assert "current target state" in result["error"], result
                    expected_state = result
                if mode == "shellcode-short":
                    assert "incomplete" in result["error"], result
            batch = client.tool("veh_batch", {"steps": [
                {"tool": "veh_execute_shellcode", "args": {"shellcode": "C3"}}]})
            assert batch["results"][0]["result"] == result, batch
            assert batch["failed"] == (0 if status is None else 1), batch
            assert client.tool("veh_detach").get("success")

        attach("shellcode-drop")
        result = execute()
        assert "error" in result and "backendStatus" not in result, result
        # A transport error is not a target-state refusal and must not block reconnect.
        attach("shellcode-action")
        installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
            {"tool": "veh_execute_shellcode", "args": {"shellcode": "C3"}}]})
        assert installed.get("success") and installed.get("hasAction"), installed
        stop = client.tool("veh_continue", {"wait": True, "timeout": 4})
        assert stop.get("breakpointId") == 7, stop
        threads = client.tool("veh_threads")
        assert threads["threads"][0]["name"] == "shellcode-calls:1", threads
        assert client.tool("veh_detach").get("success")
    finally:
        client.close(terminate_target=False)
    marker = "Breakpoint action completed with an error: "
    reports = [json.loads(line.split(marker, 1)[1])
               for line in log.read_text(encoding="utf-8").splitlines() if marker in line]
    assert len(reports) == 1, reports
    assert reports[0]["results"][0]["result"] == expected_state, reports
    print("PASS shellcode direct/batch/action state refusal, generic/unknown status, malformed success and disconnect")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="veh-shellcode-results-") as directory:
        run(Path(directory))
