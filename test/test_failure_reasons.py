"""Backend failure reasons (kCapFailureReasonV1) and unconfirmed Terminate keep the session."""
import tempfile
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"
REASON = "process stopped as a whole?"  # the fixture's 0x01 byte is shown as '?'


def run(directory):
    client = OwnedMcpClient(args=["--log=" + str(directory / "mcp.log")])
    try:
        client.initialize()

        def attach(mode):
            result = client.tool("veh_attach", {"pid": 424242, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", mode]})
            assert result.get("success"), result

        calls = (
            ("veh_write_memory", {"address": "0x2000", "data": "90"}),
            ("veh_write_memory", {"patches": [{"address": "0x2000", "data": "90"}]}),
            ("veh_allocate_memory", {"size": 4096, "protection": "rw"}),
            ("veh_protect_memory", {"address": "0x2000", "size": 4096, "protection": "rx", "method": "nt"}),
            ("veh_free_memory", {"address": "0x2000"}),
            ("veh_execute_shellcode", {"shellcode": "C3"}),
        )
        for mode in ("fail-reason", "fail-legacy", "fail-malformed"):
            attach(mode)
            for tool, args in calls:
                result = client.tool(tool, args)
                text = result["errors"][0]["error"] if "errors" in result else result.get("error", "")
                assert text, (mode, tool, result)
                assert (REASON in text) == (mode == "fail-reason"), (mode, tool, result)
            if mode == "fail-reason":
                assert "0xC0000022" in client.tool(*calls[3])["error"]

            # An Error reply to Terminate is not an exit: no success, no detach.
            result = client.tool("veh_terminate", {})
            assert "success" not in result and result.get("attached") is True, result
            assert "not confirmed" in result["error"], result
            assert client.tool("veh_threads").get("threads") is not None
            assert client.tool("veh_detach").get("success")
    finally:
        client.close(terminate_target=False)
    print("PASS failure reasons shown only when selected and well-formed; failed Terminate keeps the session")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="veh-failure-reasons-") as directory:
        run(Path(directory))
