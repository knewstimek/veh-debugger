"""The address-space response may arrive after the old 30-second frontend deadline."""
from pathlib import Path
import time

from build_paths import RELEASE
from mcp_test_client import McpClient


def run():
    with McpClient() as client:
        client.initialize()
        attached = client.tool("veh_attach", {
            "pid": 4242, "target_scope": "guest",
            "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
            "agent_args": ["--metadata", "address-delay"],
        })
        assert attached.get("success"), attached
        started = time.monotonic()
        result = client.tool("veh_address_space", {"method": "scan", "use": "chosen"}, timeout=45)
        assert time.monotonic() - started >= 30, result
        assert "error" not in result and result["in_use"] == "0x22000", result
        # The same connection must remain usable after the late root application.
        assert client.tool("veh_threads")["count"] == 1
        report = client.tool("veh_batch", {"steps": [
            {"tool": "veh_address_space", "args": {"method": "scan", "use": "chosen"}},
        ]})
        assert report["failed"] == 0 and report["results"][0]["result"] == result, report
        assert client.tool("veh_detach").get("success")
    print("PASS address-space result after 31s, root application and continued connection usability")


if __name__ == "__main__":
    run()
