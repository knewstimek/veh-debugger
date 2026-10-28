"""Additive instrumentation wire contract through the real MCP transport; no VM required."""
from pathlib import Path
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def attach(client, mode):
    result = client.tool("veh_attach", {"pid": 424242, "agent": AGENT,
        "target_scope": "guest", "agent_args": ["--metadata", mode]})
    assert result.get("success"), result


def endpoint(kind):
    return ("veh_trace_callers", {"mode": "detour"}) if kind == "detour" else (
        "veh_branch_trace", {"kind": "ptwrite"})


def call(client, kind, operation="status", batch=False, **args):
    tool, options = endpoint(kind)
    options.update(operation=operation, **args)
    if not batch:
        return client.tool(tool, options)
    result = client.tool("veh_batch", {"steps": [{"tool": tool, "args": options}]})
    return result["results"][0]["result"]


def good(result):
    assert "error" not in result, result
    return result


def run(directory):
    with OwnedMcpClient() as client:
        client.initialize()
        for kind in ("detour", "ptwrite"):
            for batch in (False, True):
                attach(client, "inst-ok")
                status = good(call(client, kind, batch=batch))
                assert status["available"] and status["intelPtSupported"] and status["ptwriteSupported"], status
                args = {"address": "0x1000"} if kind == "detour" else {}
                start = good(call(client, kind, "start", batch=batch, **args))
                trace = start["trace_id"]
                assert isinstance(trace, str) and int(trace) > 2**53, start
                assert start["active"] and start["data_policy"] == "original" and start["transaction_policy"] == "omit", start
                assert "records" not in start
                assert "error" in call(client, kind, "start", **args)  # no implicit replacement
                summary = good(call(client, kind, "read", trace_id=trace, batch=batch))
                assert summary["active"] and "records" not in summary, summary
                assert "error" in call(client, kind, "read", trace_id=trace, max=1)  # no speculative/live pages
                stopped = good(call(client, kind, "stop", trace_id=trace, batch=batch))
                assert not stopped["active"] and stopped["totalRecords"] == "3", stopped
                assert good(call(client, kind, "stop", trace_id=trace)) == stopped  # idempotent
                first = good(call(client, kind, "read", trace_id=trace, max=2, batch=batch))
                assert len(first["records"]) == 2 and first["nextCursor"] == "2" and first["hasMore"], first
                last = good(call(client, kind, "read", trace_id=trace, cursor=first["nextCursor"], max=2, batch=batch))
                assert len(last["records"]) == 1 and not last["hasMore"], last
                record = first["records"][0]
                assert record["instructionAddress"] is not None
                assert int(record["value"], 16) == 0xFEDCBA9876543210 if kind == "ptwrite" else (
                    int(record["functionAddress"], 16) == 0x1000 and int(record["callerAddress"], 16) == 0x2000)
                for bad in ({"trace_id": int(trace)}, {"trace_id": "0" + trace},
                            {"trace_id": trace, "max": 257}, {"trace_id": trace, "cursor": 0},
                            {"trace_id": trace, "cursor": "-1"}, {"trace_id": trace, "max": -1}):
                    assert "error" in call(client, kind, "read", **bad), bad
                newer = good(call(client, kind, "start", data_policy="patched",
                    transaction_policy="rollback", **args))
                assert newer["trace_id"] != trace and "warning" in newer and "E9" in newer["warning"], newer
                assert newer["transaction_policy"] == "rollback"
                assert "error" in call(client, kind, "read", trace_id=trace)
                good(call(client, kind, "stop", trace_id=newer["trace_id"]))

        for mode in ("inst-no-caps", "inst-partial", "inst-cpu-off"):
            attach(client, mode)
            status = good(call(client, "ptwrite"))
            assert not status["available"], status
            if mode == "inst-no-caps":
                assert status["intelPtSupported"] is None and status["ptwriteSupported"] is None, status
            assert "error" in call(client, "ptwrite", "start")
        for mode in ("inst-no-original", "inst-no-rollback"):
            attach(client, mode)
            assert "error" in call(client, "ptwrite", "start", **(
                {"transaction_policy": "rollback"} if mode.endswith("rollback") else {}))

        for mode in ("inst-query-short", "inst-query-long", "inst-version", "inst-error"):
            attach(client, mode)
            assert "error" in call(client, "ptwrite"), mode
        for mode in ("inst-reply-short", "inst-reply-long", "inst-count", "inst-bad-cursor",
                     "inst-kind-mismatch", "inst-policy-mismatch"):
            attach(client, mode)
            assert "error" in call(client, "ptwrite", "start"), mode

        for mode in ("inst-loss", "inst-unknown-loss", "inst-ip-missing", "inst-record-flags", "inst-low-limit"):
            attach(client, mode)
            started = good(call(client, "ptwrite", "start"))
            trace = started["trace_id"]
            if mode == "inst-low-limit":
                assert started["bufferRecords"] == 16, started
            stopped = good(call(client, "ptwrite", "stop", trace_id=trace))
            records = call(client, "ptwrite", "read", trace_id=trace, max=3)
            if mode == "inst-record-flags":
                assert "error" in records, records
            else:
                good(records)
                if mode in ("inst-loss", "inst-unknown-loss"):
                    assert stopped["bufferOverflow"] and stopped["incomplete"], stopped
                    assert stopped["lostRecords"] == ("9" if mode == "inst-loss" else None), stopped
                if mode == "inst-ip-missing":
                    assert records["incomplete"] and records["records"][1]["instructionAddress"] is None, records

        attach(client, "inst-ok")
        assert good(client.tool("veh_branch_trace"))["full_path"]["available"]
        assert good(client.tool("veh_branch_trace", {"kind": "full", "operation": "start"}))["started"] == "full"
        branches = good(client.tool("veh_branch_trace", {"kind": "full", "operation": "read"}))
        assert branches["kind"] == "full" and branches["count"] == 1 and "branches" in branches, branches
        assert good(client.tool("veh_branch_trace", {"kind": "full", "operation": "stop"}))["stopped"] == "full"
        assert "error" in client.tool("veh_trace_callers", {"address": "0x1000", "mode": "typo"})
        assert "error" in client.tool("veh_trace_callers", {"address": "0x1000", "data_policy": "patched"})
        assert "error" in client.tool("veh_branch_trace", {"kind": "typo"})
        assert "error" in client.tool("veh_branch_trace", {"kind": "full", "data_policy": "patched"})
        assert "error" in call(client, "ptwrite", "start", address="0x1000")
        assert "error" in call(client, "detour", "start", address="0x100000000")

        # Legacy command and duration semantics remain available without new capabilities.
        attach(client, "trace")
        legacy = good(client.tool("veh_trace_callers", {"address": "0x1000", "duration_ms": 50}))
        assert legacy["totalHits"] == 0 and legacy["callers"] == [] and legacy["durationMs"] == 50, legacy
        assert not good(call(client, "ptwrite"))["available"]

    # The same dispatch path is used by breakpoint actions, including exact string references.
    logfile = directory / "action.log"
    with OwnedMcpClient(args=["--log=" + str(logfile)]) as client:
        client.initialize()
        for kind in ("detour", "ptwrite"):
            attach(client, "ops-action-inst")
            tool, selector = endpoint(kind)
            start_args = dict(selector, operation="start")
            if kind == "detour":
                start_args["address"] = "0x1000"
            steps = [
                {"tool": tool, "args": start_args, "as": "$capture"},
                {"tool": tool, "args": dict(selector, operation="stop", trace_id="$capture.trace_id")},
                {"tool": tool, "args": dict(selector, operation="read", trace_id="$capture.trace_id", max=2)},
            ]
            assert client.tool("veh_set_breakpoint", {"address": "0x1800", "action": steps}).get("success")
            stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
            assert stop.get("breakpointId") == 7, stop
            action_errors = [line for line in logfile.read_text(encoding="utf-8").splitlines()
                            if "Breakpoint action completed with an error:" in line]
            assert not action_errors, action_errors
            result = good(call(client, kind, "read", trace_id="9007199254740994", max=2))
            assert not result["active"] and len(result["records"]) == 2, result
            good(client.tool("veh_detach"))
    assert "Breakpoint action completed with an error:" not in logfile.read_text(encoding="utf-8")
    print("PASS explicit detour/PTWRITE contract, bounded pages, policy/capability rejection, exact values and direct/batch/action parity")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="veh-instrumentation-") as directory:
        run(Path(directory))
