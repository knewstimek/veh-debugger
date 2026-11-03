"""A same-TID newer stop must supersede a candidate probed during continue."""
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"


def run():
    for mode, expected_continues, batch in (("stop-race-cached", 0, False), ("stop-race-inflight", 1, False),
                                            ("stop-race-restop", 1, False), ("stop-race-inflight", 1, True)):
        with OwnedMcpClient() as client:
            client.initialize("continue-stop-identity")
            attached = client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                "agent": str(FIXTURE), "agent_args": ["--metadata", mode]})
            assert attached.get("success"), attached
            if mode == "stop-race-cached":
                assert client.tool("veh_threads").get("count") == 1
            arguments = {"threadId": 0, "wait": True, "timeout": 2}
            if batch:
                envelope = client.tool("veh_batch", {"steps": [{"tool": "veh_continue", "args": arguments}]}, timeout=5)
                assert envelope.get("failed") == 0, envelope
                result = envelope["results"][0]["result"]
            else:
                result = client.tool("veh_continue", arguments, timeout=5)
            info = client.tool("veh_exception_info")
            assert result.get("stopped") and result.get("reason") == "exception", result
            expected_address = 0x1000 if mode == "stop-race-restop" else 0x2000
            expected_code = 0xC0000005 if mode == "stop-race-restop" else 0xC0000094
            assert int(result["address"], 16) == expected_address, (mode, result, info)
            assert result["threadId"] == info["threadId"] == 77, (result, info)
            assert int(info["address"], 16) == expected_address and int(info["exceptionCode"], 16) == expected_code, info
            threads = client.tool("veh_threads")
            assert threads["threads"][0]["name"] == f"continues={expected_continues}", threads
            assert client.tool("veh_detach").get("success")
    print("PASS same-thread cached/in-flight stop identity, exception-info alignment and no duplicate continue")


if __name__ == "__main__":
    run()
