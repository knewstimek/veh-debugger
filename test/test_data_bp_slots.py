"""Slot-exhaustion error parity across MCP exposure profiles and dispatch paths."""
import json
import os

from build_paths import RELEASE
from mcp_test_client import McpClient

MCP_EXE = os.path.join(RELEASE, "veh-mcp-server.exe")
TARGET = os.path.join(RELEASE, "test_target.exe")
PROFILES = ("lite", "interactive", "capture", "analysis", "vmguest", "full")


def check_profile(profile):
    c = McpClient(MCP_EXE, args=[f"--profile={profile}"])
    try:
        c.initialize()
        exposed = c.call("tools/list", {})["result"]["tools"]
        names = {tool["name"] for tool in exposed}
        assert "veh_toolbox" in names, names
        assert ("veh_set_data_breakpoint" in names) == (profile in ("interactive", "analysis", "vmguest", "full")), names
        if profile in ("lite", "interactive", "capture"):
            assert len(names) <= 10, (profile, len(names))
        catalog = c.tool("veh_toolbox", {"operation": "profiles"})
        counts = {entry["name"]: entry["eager_tools"] for entry in catalog["profiles"]}
        assert catalog["active"] == profile and counts[profile] == len(names), catalog

        launched = c.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}, 30)
        assert launched.get("success"), launched
        base = int(launched["mainModule"]["baseAddress"], 16) if "mainModule" in launched else int(
            next(m for m in c.tool("veh_modules")["modules"]
                 if m["name"].lower() == "test_target.exe")["baseAddress"], 16)
        for i in range(4):
            result = c.tool("veh_set_data_breakpoint", {
                "address": hex(base + 0x100 + i * 4), "size": 4, "type": "write",
            })
            assert result.get("success") and result.get("id"), result

        args = {"address": hex(base + 0x110), "size": 4, "type": "write"}
        errors = []
        for name, arguments in (
            ("veh_set_data_breakpoint", args),
            ("veh_toolbox", {"operation": "call", "tool": "veh_set_data_breakpoint", "arguments": args}),
        ):
            response = c.call("tools/call", {"name": name, "arguments": arguments})["result"]
            assert response.get("isError") is True, response
            result = json.loads(response["content"][0]["text"])
            errors.append(result["error"])
            if name == "veh_toolbox":
                assert result["result"]["error"] == result["error"], result

        batch = c.tool("veh_batch", {"steps": [{"tool": "veh_set_data_breakpoint", "args": args}]})
        assert batch["failed"] == 1 and batch["succeeded"] == 0, batch
        step = batch["results"][0]
        assert step["status"] == "failed", step
        errors.append(step["result"]["error"])
        assert len(set(errors)) == 1 and "no free slot" in errors[0], errors
        print(f"ok {profile}: direct/toolbox/batch capacity errors agree; eager={len(names)}")
    finally:
        c.close()
        assert c.proc.poll() is not None, "MCP server did not exit"


def main():
    for profile in PROFILES:
        check_profile(profile)
    print(f"Results: {len(PROFILES) * 3} profile/dispatch cases passed")


if __name__ == "__main__":
    main()
