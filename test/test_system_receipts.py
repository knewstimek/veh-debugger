"""System-event and hidden-hook receipts must not imply absent or installed state on failure."""
from pathlib import Path

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient


AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def run():
    with OwnedMcpClient() as client:
        client.initialize("system-receipts")
        for mode in ("error", "short", "long", "ok", "empty", "count"):
            attached = client.tool("veh_attach", {
                "pid": 424242, "target_scope": "guest", "agent": AGENT,
                "agent_args": ["--metadata", "system-receipts-" + mode],
            })
            assert attached.get("success"), attached

            cases = (
                ("veh_event", {"operation": "list"}),
                ("veh_hidden_hook", {"operation": "list"}),
                ("veh_event", {"operation": "remove", "id": 7}),
                ("veh_hidden_hook", {"operation": "remove", "id": 7}),
                ("veh_event", {"operation": "add", "type": "cpuid", "value": "0x1"}),
                ("veh_hidden_hook", {
                    "operation": "add", "pid": 424242, "address": "0x1000", "set": {"rax": "0x10"},
                }),
            )
            for tool, args in cases:
                result = client.tool(tool, args)
                listing = args["operation"] == "list"
                rejected = mode in ("error", "short", "long") or (listing and mode == "count")
                if rejected:
                    assert "error" in result, (mode, tool, args, result)
                    assert not any(key in result for key in ("events", "hooks", "removed", "id")), result
                elif listing:
                    key = "events" if tool == "veh_event" else "hooks"
                    expected = 0 if mode == "empty" else 1
                    assert len(result[key]) == expected and "error" not in result, (mode, tool, result)
                    if expected:
                        assert result[key][0]["id"] == 7, result
                elif args["operation"] == "remove":
                    assert result.get("removed") == 7 and "error" not in result, result
                else:
                    assert result.get("id") == 7 and "error" not in result, result
                    if tool == "veh_hidden_hook":
                        note = result.get("note", "")
                        assert "Registration confirmed" in note and "does not report" in note, result
                        assert "every hit" not in note, result

                batch = client.tool("veh_batch", {"steps": [{"tool": tool, "args": args}]})
                assert batch["results"][0]["result"] == result, (mode, tool, result, batch)
                assert batch["failed"] == (1 if rejected else 0), batch

            assert client.tool("veh_detach").get("success")
    print("PASS system event/hook exact receipts, valid empty lists, bounded counts and direct/batch parity")


if __name__ == "__main__":
    run()
