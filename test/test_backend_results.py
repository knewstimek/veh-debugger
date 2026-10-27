"""Backend refusal, malformed replies and true empty stacks through MCP and DAP."""
from contextlib import contextmanager
from pathlib import Path

from build_paths import RELEASE
from dap_test_client import DapClient
from mcp_test_client import McpClient


ADAPTER = str(Path(RELEASE) / "veh-debug-adapter.exe")
AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


@contextmanager
def dap_session(mode):
    client = DapClient(ADAPTER)
    try:
        caps = client.initialize()["body"]
        assert [f["filter"] for f in caps["exceptionBreakpointFilters"]] == ["all"], caps
        assert client.request("setExceptionBreakpoints", {"filters": ["all"], "filterOptions": []})["success"]
        for filters in ([], ["uncaught"], ["unknown"]):
            rejected = client.request("setExceptionBreakpoints", {"filters": filters})
            assert not rejected["success"] and "Only" in rejected["message"], rejected
        attached = client.request("attach", {
            "targetScope": "guest", "processId": 4242, "agent": AGENT,
            "agentArgs": ["--metadata", mode],
        })
        assert attached["success"], attached
        yield client
    finally:
        client.close(terminate_debuggee=False)


def no_stop(client):
    try:
        unexpected = client.event("stopped", timeout=0.15)
    except TimeoutError:
        return
    raise AssertionError(("Invented stopped event", unexpected))


def run():
    for mode in ("control-error", "control-short", "control-long"):
        with dap_session(mode) as client:
            for command in ("pause", "next", "stepIn", "stepOut", "continue"):
                response = client.request(command, {"threadId": 77, "granularity": "instruction"})
                assert not response["success"] and response["message"], (mode, command, response)
                no_stop(client)
            response = client.request("writeMemory", {"memoryReference": "0x1000", "data": "QUI="})
            assert not response["success"] and "bytesWritten" not in response.get("body", {}), response
            response = client.request("terminateThreads", {"threadIds": [77]})
            assert not response["success"] and response["message"], response

    with dap_session("control-exit") as client:
        failed = client.request("terminateThreads", {"threadIds": [77]})
        assert not failed["success"], failed

    with dap_session("control-ok") as client:
        assert client.request("pause", {"threadId": 0})["success"]
        pause = client.event("stopped")
        assert pause["body"]["threadId"] == 88 and not pause["body"]["allThreadsStopped"], pause
        no_stop(client)
        for command in ("next", "stepIn", "stepOut"):
            assert client.request(command, {"threadId": 77, "granularity": "instruction"})["success"]
            stopped = client.event("stopped")
            assert stopped["body"]["threadId"] == 77, stopped
        continued = client.request("continue", {"threadId": 77})
        assert continued["success"] and continued["body"]["allThreadsContinued"], continued
        write = client.request("writeMemory", {"memoryReference": "0x1000", "data": "QUI="})
        assert write["success"] and write["body"]["bytesWritten"] == 2, write
        assert client.request("terminateThreads", {"threadIds": [77]})["success"]

    with dap_session("control-partial") as client:
        partial = client.request("continue")
        assert partial["success"] and not partial["body"]["allThreadsContinued"], partial
        refused = client.request("continue", {"threadId": 88, "singleThread": True})
        assert not refused["success"] and "still stopped" in refused["message"], refused

    with dap_session("control-retained") as client:
        refused = client.request("continue")
        assert not refused["success"] and "No thread resumed" in refused["message"], refused

    for mode in ("stack-ok", "stack-empty", "stack-error", "stack-short", "stack-name", "stack-status-ok", "stack-exit"):
        with dap_session(mode) as client:
            stack = client.request("stackTrace", {"threadId": 77})
            if mode in ("stack-ok", "stack-empty"):
                expected = 1 if mode == "stack-ok" else 0
                assert stack["success"] and len(stack["body"]["stackFrames"]) == expected, (mode, stack)
                assert stack["body"]["totalFrames"] == expected, stack
            else:
                assert not stack["success"] and stack["message"], (mode, stack)
                assert not stack.get("body", {}).get("stackFrames"), stack
        with McpClient() as client:
            client.initialize()
            attached = client.tool("veh_attach", {
                "pid": 4242, "target_scope": "guest", "agent": AGENT,
                "agent_args": ["--metadata", mode],
            })
            assert attached.get("success"), attached
            stack = client.tool("veh_stack_trace", {"threadId": 77})
            if mode in ("stack-ok", "stack-empty"):
                assert stack["count"] == (1 if mode == "stack-ok" else 0), (mode, stack)
            else:
                assert "error" in stack and "frames" not in stack, (mode, stack)
            if mode != "stack-exit":
                batch = client.tool("veh_batch", {"steps": [
                    {"tool": "veh_stack_trace", "args": {"threadId": 77}},
                ]})
                result = batch["results"][0]["result"]
                assert result == stack, (mode, batch, stack)
                assert batch["failed"] == (0 if mode in ("stack-ok", "stack-empty") else 1), batch
                assert client.tool("veh_detach").get("success")
    print("PASS backend acknowledgements, pause identity, exception filters and MCP/DAP stack errors")


if __name__ == "__main__":
    run()
