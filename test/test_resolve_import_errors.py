"""Import probe errors stay failures through direct, batch and actions."""
from pathlib import Path
import tempfile
from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def attach(client, mode):
    value = client.tool("veh_attach", {"pid": 424242, "agent": AGENT,
        "target_scope": "guest", "agent_args": ["--metadata", mode]})
    assert value.get("success"), value


def invoke(client, batch=False):
    arguments = {"threadId": 77, "addresses": ["0x1000", "0x2000"], "max_steps": 1}
    if batch:
        out = client.tool("veh_batch", {"steps": [{"tool": "veh_resolve_imports", "args": arguments}]})
        return out["results"][0]["result"]
    return client.tool("veh_resolve_imports", arguments)


def run():
    bad = ("resolve-error", "resolve-short", "resolve-status-only", "resolve-truncated",
           "resolve-count", "resolve-order", "resolve-name", "resolve-trace", "resolve-reserved", "resolve-bool")
    with OwnedMcpClient() as client:
        client.initialize()
        for mode in bad:
            attach(client, mode)
            for batch in (False, True):
                value = invoke(client, batch)
                assert "error" in value and value["error"], (mode, batch, value)
            assert client.tool("veh_threads")["count"] == 1
            assert client.tool("veh_detach").get("success")
        for mode in ("resolve-ok", "resolve-unresolved"):
            attach(client, mode)
            direct, batch = invoke(client), invoke(client, True)
            assert direct == batch and "error" not in direct and direct["total"] == 2, direct
            assert len(direct["imports"]) == 2 and direct["resolved"] == (2 if mode == "resolve-ok" else 0), direct
            assert [e["steps"] for e in direct["imports"]] == [1, 1], direct
            assert client.tool("veh_detach").get("success")
    with tempfile.TemporaryDirectory(prefix="resolve-action-") as directory:
        log = Path(directory) / "action.log"
        with OwnedMcpClient(args=["--log=" + str(log)]) as client:
            client.initialize()
            attach(client, "resolve-error")
            assert client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                {"tool": "veh_resolve_imports", "args": {"threadId": 77, "addresses": ["0x1000"], "max_steps": 1}}
            ]}).get("success")
            stopped = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
            assert stopped.get("breakpointId") == 7, stopped
            text = log.read_text(encoding="utf-8")
            assert "Breakpoint action completed with an error:" in text and "ResolveImport" in text, text[-1500:]
            assert client.tool("veh_detach").get("success")
    print("PASS import errors/malformed replies stay failures; successful unresolved probes and direct/batch/action parity")


if __name__ == "__main__":
    run()
