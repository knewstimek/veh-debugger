"""Backend refusal, malformed replies and true empty stacks through MCP and DAP."""
from mcp_test_client import inline_trace_args
from contextlib import contextmanager
from pathlib import Path

from build_paths import RELEASE
from dap_test_client import DapClient
from mcp_test_client import McpClient
from owned_mcp_client import OwnedMcpClient


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


def check_trace_policy_results():
    client = OwnedMcpClient()
    try:
        client.initialize("trace-policy-receipts")
        for mode, expected in (
            ("path-ok", None),
            ("path-bad-repeat", "invalid_compressed_path"),
            ("path-bad-count", "compressed_path_count_mismatch"),
            ("path-bad-thread", "invalid_compressed_path"),
            ("path-bad-policy", "trace_collection_policy_not_acknowledged"),
            ("path-refused", "hardware_breakpoint_conflict"),
        ):
            attached = client.tool("veh_attach", {"pid": 4242, "target_scope": "guest",
                "agent": AGENT, "agent_args": ["--metadata", mode]})
            assert attached.get("success"), attached
            args = {"threadId": 77, "start": "0x1000", "end": "0x1100",
                    "collect_code": True, "collect_snapshots": False, "compress_paths": True}
            result = client.tool("veh_trace_basic_blocks", inline_trace_args(args))
            if expected is None:
                assert "error" not in result and result["ordering"]["expanded_events_captured"] == 3, result
            else:
                assert "error" in result and result["failure"]["reason"] == expected, (mode, result)
            batch = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_basic_blocks", "args": inline_trace_args(args)}]})
            assert batch["results"][0]["result"] == result, (mode, batch)
            assert batch["failed"] == (0 if expected is None else 1), batch
            assert client.tool("veh_detach").get("success")
    finally:
        client.close(terminate_target=False)


def check_locals_results():
    import json
    import tempfile
    with tempfile.TemporaryDirectory(prefix="veh-locals-results-") as directory:
        log = Path(directory) / "mcp.log"
        client = OwnedMcpClient(args=["--log=" + str(log)])
        expected_errors = []
        try:
            client.initialize("locals-receipts")
            for mode in ("locals-empty", "locals-ok", "locals-error", "locals-status-ok",
                         "locals-count-short", "locals-long", "locals-value-size", "locals-name"):
                attached = client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                    "agent": AGENT, "agent_args": ["--metadata", mode]})
                assert attached.get("success"), attached
                with dap_session(mode) as dap:
                    stack = dap.request("stackTrace", {"threadId": 77})
                    assert stack["success"] and stack["body"]["stackFrames"], stack
                    scopes = dap.request("scopes", {"frameId": stack["body"]["stackFrames"][0]["id"]})
                    assert scopes["success"] and "scopes" in scopes.get("body", {}), scopes
                    ref = next(s["variablesReference"] for s in scopes["body"]["scopes"] if s["name"] == "Locals")
                    variables = dap.request("variables", {"variablesReference": ref})
                    if mode in ("locals-empty", "locals-ok"):
                        assert variables["success"], variables
                        rows = variables["body"]["variables"]
                        assert len(rows) == (mode == "locals-ok"), variables
                        if rows: assert rows[0]["name"] == "[param] value", variables
                    else:
                        assert not variables["success"] and variables["message"], variables
                        assert not variables.get("body", {}).get("variables"), variables
                frame_args = {"threadId": 77, "maxFrames": 1, "include_annotations": False}
                wire_stack = client.tool("veh_stack_trace", frame_args)
                assert wire_stack["frames"][0]["returnAddress"] == "0x5678", wire_stack
                if mode == "locals-ok":
                    invalid_args = [{"threadId": 77, field: value}
                        for field in ("instructionAddress", "frameBase")
                        for value in ("bad-address", "0x1000junk", "-1",
                                      "18446744073709551616", 1.5, True, None)]
                    failures = [client.tool("veh_enum_locals", args) for args in invalid_args]
                    assert all("unsigned decimal or 0x" in item.get("error", "")
                               and "variables" not in item for item in failures), failures
                    refused = client.tool("veh_batch", {"steps": [
                        {"tool": "veh_enum_locals", "args": args} for args in invalid_args]})
                    assert refused["failed"] == len(invalid_args), refused
                    assert [item["result"] for item in refused["results"]] == failures, refused
                result = client.tool("veh_enum_locals", {"threadId": 77})
                valid = mode in ("locals-empty", "locals-ok")
                if valid:
                    assert "error" not in result and result["count"] == (mode == "locals-ok"), (mode, result)
                else:
                    assert "error" in result and "variables" not in result, (mode, result)
                batch = client.tool("veh_batch", {"steps": [
                    {"tool": "veh_enum_locals", "args": {"threadId": 77}},
                    {"tool": "veh_stack_trace", "args": frame_args}]})
                assert batch["results"][0]["result"] == result and batch["failed"] == (not valid), (mode, batch)
                assert batch["results"][1]["result"] == wire_stack, (mode, batch)
                installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                    {"tool": "veh_enum_locals", "args": {"threadId": 77}},
                    {"tool": "veh_stack_trace", "args": frame_args}]})
                assert installed.get("success") and installed.get("hasAction"), installed
                stop = client.tool("veh_continue", {"wait": True, "timeout": 4})
                assert stop.get("breakpointId") == 7, stop
                threads = client.tool("veh_threads")
                assert threads["threads"][0]["name"] == "locals-calls:3", (mode, threads)
                if not valid: expected_errors.append(result)
                if mode == "locals-ok":
                    # The fixture dispatches actions on its first continue only.
                    assert client.tool("veh_detach").get("success")
                    assert client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                        "agent": AGENT, "agent_args": ["--metadata", mode]}).get("success")
                    installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                        {"tool": "veh_enum_locals", "args": invalid_args[0]},
                        {"tool": "veh_stack_trace", "args": frame_args}]})
                    assert installed.get("success") and installed.get("hasAction"), installed
                    assert client.tool("veh_continue", {"wait": True, "timeout": 4}).get("breakpointId") == 7
                    assert client.tool("veh_threads")["threads"][0]["name"] == "locals-calls:0"
                    expected_errors.append(failures[0])
                assert client.tool("veh_detach").get("success")
        finally:
            client.close(terminate_target=False)
        marker = "Breakpoint action completed with an error: "
        reports = [json.loads(line.split(marker, 1)[1]) for line in log.read_text(encoding="utf-8").splitlines()
                   if marker in line]
        assert [row["results"][0]["result"] for row in reports] == expected_errors, reports
        assert all(row["results"][1]["result"] == wire_stack for row in reports), reports
    print("PASS locals empty/success/refusal/malformed MCP direct/batch/action and DAP variables parity")


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
    check_trace_policy_results()
    print("PASS backend acknowledgements, pause identity, exception filters, MCP/DAP stack errors and trace policy receipts")


if __name__ == "__main__":
    import sys
    if "--locals-only" in sys.argv:
        check_locals_results()
    else:
        run()
        check_locals_results()
