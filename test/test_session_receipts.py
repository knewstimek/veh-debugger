"""Target-width and exact deletion-receipt checks through direct and batch MCP."""
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

FIXTURE = Path(RELEASE) / "guest_backend_fixture.exe"


def run():
    with OwnedMcpClient() as client:
        client.initialize("session-receipts")

        def attach(mode):
            result = client.tool("veh_attach", {"pid": 424242, "agent": str(FIXTURE),
                "target_scope": "guest", "agent_args": ["--metadata", mode]})
            assert result.get("success") and result.get("addressBits") == 32, result

        attach("receipt-ok")
        pointer_args = {"base": "0x1000", "offsets": [0]}
        pointer = client.tool("veh_read_pointer_chain", pointer_args)
        assert pointer.get("pointerSize") == 4, pointer
        # The synthetic memory begins 42 C3 90 90; the guest pointer consumes four bytes.
        assert int(pointer["resolved"], 16) == 0x9090C342, pointer
        batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_read_pointer_chain", "args": pointer_args}]})
        assert batch["failed"] == 0 and batch["results"][0]["result"] == pointer, batch

        operations = ("veh_remove_breakpoint", "veh_remove_data_breakpoint")
        expected_status = {"error": 1, "invalid": 99, "unsupported": 4, "not-found": 2}
        for mode in ("error", "short", "long", "invalid", "unsupported", "not-found", "ok"):
            attach("receipt-" + mode)
            direct = [client.tool(tool, {"id": 123}) for tool in operations]
            for tool, result in zip(operations, direct):
                if mode == "ok":
                    assert result.get("success") and result.get("id") == 123, (tool, result)
                else:
                    assert "error" in result and not result.get("success"), (mode, tool, result)
                    if mode in expected_status:
                        assert result.get("backendStatus") == expected_status[mode], (mode, tool, result)
                    else:
                        assert "backendStatus" not in result and "malformed" in result["error"], (mode, result)
                    if mode == "not-found":
                        assert "not found" in result["error"], result
            batch = client.tool("veh_batch", {"steps": [
                {"tool": tool, "args": {"id": 123}} for tool in operations]})
            assert batch["failed"] == (0 if mode == "ok" else 2), (mode, batch)
            assert [entry["result"] for entry in batch["results"]] == direct, (mode, batch)
            assert client.tool("veh_threads").get("count") == 1, (mode, "receipt error lost the session")

        assert client.tool("veh_detach").get("success")
        attached = client.tool("veh_attach", {"agent": str(FIXTURE), "target_scope": "vm",
            "agent_args": ["--metadata", "machine"]})
        assert attached.get("success"), attached
        no_width = client.tool("veh_read_pointer_chain", pointer_args)
        assert "error" in no_width and "address width" in no_width["error"], no_width
        assert "pointerSize" not in no_width, no_width
        assert client.tool("veh_detach").get("success")

    print("PASS guest pointer width and direct/batch deletion status, malformed receipt and NotFound semantics")


if __name__ == "__main__":
    run()
