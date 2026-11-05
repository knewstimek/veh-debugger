"""Per-request decode modes through MCP and standard DAP guest requests."""
from pathlib import Path
from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient
from dap_test_client import DapClient

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def run():
    with OwnedMcpClient() as client:
        client.initialize()
        attached = client.tool("veh_attach", {"pid": 4242, "agent": AGENT,
            "target_scope": "guest", "agent_args": ["--metadata", "control-context"]})
        assert attached.get("success") and attached["addressBits"] == 32, attached
        for bits, address in ((64, "0x120000000"), (32, "0x1000"), (64, "0x120000000")):
            stopped = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 2})
            assert stopped.get("stopped"), stopped
            direct = client.tool("veh_disassemble", {"address": address, "count": 1, "include_annotations": False})
            assert direct.get("addressBits") == bits, direct
            assert direct["instructions"][0]["bytes"].replace(" ", "") == ("48890424" if bits == 64 else "48"), direct
            explicit = client.tool("veh_disassemble", {"address": address, "count": 1, "threadId": 77, "include_annotations": False})
            assert explicit == direct, explicit
        rejected = client.tool("veh_disassemble", {"address": "0x1000", "threadId": 88})
        assert "error" in rejected, rejected
        assert client.tool("veh_detach").get("success")
    client = DapClient(str(Path(RELEASE) / "veh-debug-adapter.exe"))
    try:
        client.initialize()
        attached = client.request("attach", {"processId": 4242, "targetScope": "guest",
            "agent": AGENT, "agentArgs": ["--metadata", "control-context"]})
        assert attached["success"], attached
        assert client.request("configurationDone")["success"]
        for bits, address in ((64, "0x120000000"), (32, "0x1000"), (64, "0x120000000")):
            assert client.request("continue", {"threadId": 77})["success"]
            client.wait_for(lambda m: m.get("event") == "stopped", timeout=3)
            decoded = client.request("disassemble", {"memoryReference": address, "instructionCount": 1})
            assert decoded["success"], decoded
            row = decoded["body"]["instructions"][0]
            assert row["instructionBytes"].replace(" ", "") == ("48890424" if bits == 64 else "48"), row
            memory = client.request("readMemory", {"memoryReference": address, "count": 4})
            assert memory["success"], memory
        assert client.request("disconnect", {"terminateDebuggee": False})["success"]
        assert client.proc.wait(timeout=3) == 0
    finally:
        client.close(terminate_debuggee=False)
    print("PASS MCP/DAP mixed decode modes, native high addresses and legacy metadata")


if __name__ == "__main__":
    run()
