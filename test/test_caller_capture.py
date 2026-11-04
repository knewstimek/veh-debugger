"""Detailed hit-time caller capture contract through real MCP, without a VM."""
import hashlib
import json
from pathlib import Path
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

AGENT = str(Path(RELEASE) / "guest_backend_fixture.exe")


def attach(client, mode="cc-ok"):
    result = client.tool("veh_attach", {"pid": 424242, "agent": AGENT,
        "target_scope": "guest", "agent_args": ["--metadata", mode]})
    assert result.get("success"), result


def call(client, operation="status", batch=False, **args):
    args = dict(mode="detailed", operation=operation, **args)
    if batch:
        value = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_callers", "args": args}]})
        return value["results"][0]["result"]
    return client.tool("veh_trace_callers", args)


def good(value):
    assert "error" not in value, value
    return value


def artifact(value, owned):
    receipt = value["output_file"]
    path = Path(receipt["path"])
    owned.append(path)
    data = path.read_bytes()
    assert str(len(data)) == receipt["size"]
    assert hashlib.sha256(data).hexdigest() == receipt["sha256"]
    assert value["storage_completed"] and "records" not in value
    return data


def run(directory, owned):
    with OwnedMcpClient() as client:
        client.initialize()
        for mode in ("cc-ok", "cc-x86"):
            for batch in (False, True):
                attach(client, mode)
                status = good(call(client, batch=batch))
                assert status["available"] and status["trace_id"] is None, status
                start = good(call(client, "start", batch=batch, address="0x1000",
                    filters=[{"register": "rcx", "mask": "0xffff", "equals": "0x1234"}]))
                trace = start["trace_id"]
                assert int(trace) > 2**53 and start["active"], start
                assert good(call(client))["trace_id"] == trace
                assert "error" in call(client, "start", address="0x1000")
                assert "error" in call(client, "read", trace_id=trace, max=1)
                summary = good(call(client, "read", trace_id=trace))
                assert summary["active"] and "records" not in summary
                stopped = good(call(client, "stop", batch=batch, trace_id=trace))
                assert not stopped["active"] and stopped["stop_reason"] == "user"
                assert good(call(client, "stop", trace_id=trace)) == stopped
                page = good(call(client, "read", batch=batch, trace_id=trace, max=2))
                assert page["nextCursor"] == "2" and page["hasMore"]
                record = page["records"][0]
                assert record["sequence"] == "1" and record["tid"] == 77
                assert record["addressBits"] == (32 if mode == "cc-x86" else 64)
                assert record["timestamp"] == "9007199254741001"
                assert record["registers"]["rcx"] == "0x1234"
                assert record["stack"]["hex"].startswith("0001020304050607")
                assert record["stack"]["status"] == "complete"
                assert page["filteredHits"] == "7"
                assert page["config"]["filters"][0]["equals"] == "0x1234"
                if mode == "cc-ok" and not batch:
                    output = good(call(client, "read", trace_id=trace, max=1,
                        output_file={"path": str(directory / "one-page.jsonl"), "format": "jsonl"}))
                    lines = [json.loads(line) for line in artifact(output, owned).splitlines()]
                    assert lines[0]["record"] == "manifest" and len(lines) == 2
                    assert lines[1]["section"] == "records" and lines[1]["value"]["sequence"] == "1"
                last = good(call(client, "read", trace_id=trace, cursor="2", max=2))
                assert last["records"][0]["sequence"] == "3" and not last["hasMore"]
                assert good(call(client, "read", trace_id=trace, cursor="3", max=2))["records"] == []
                out = directory / f"{mode}-{batch}.json"
                exported = good(call(client, "export", batch=batch, trace_id=trace,
                    output_file={"path": str(out), "format": "json"}))
                saved = json.loads(artifact(exported, owned))
                assert len(saved["records"]) == 3 and saved["cursor"] == "0"
                assert "error" in call(client, "export", trace_id=trace,
                    output_file={"path": str(out)})  # never overwrite
                newer = good(call(client, "start", address="0x1000", stack_bytes=0))
                assert newer["trace_id"] != trace
                assert "error" in call(client, "read", trace_id=trace)
                good(call(client, "stop", trace_id=newer["trace_id"]))
                empty_stack = good(call(client, "read", trace_id=newer["trace_id"], max=1))["records"][0]["stack"]
                assert empty_stack["status"] == "not_requested" and empty_stack["hex"] == ""

        for mode in ("cc-no-caps", "cc-partial-caps", "trace"):
            attach(client, mode)
            assert not good(call(client))["available"]
            assert "error" in call(client, "start", address="0x1000")
            if mode == "trace":
                assert good(client.tool("veh_trace_callers", {"address": "0x1000", "duration_ms": 50}))["totalHits"] == 0

        attach(client)
        for invalid in (
            {"max_hits": 10}, {"max_hits": "01"}, {"max_hits": "18446744073709551616"},
            {"max_hits": "0", "duration_ms": 0}, {"duration_ms": -1}, {"duration_ms": True},
            {"stack_bytes": 4097}, {"buffer_bytes": 215}, {"buffer_records": 0},
            {"filters": [{"register": "rcx", "mask": "0xf", "equals": "0x10"}]},
            {"filters": [{"register": "rcx", "mask": "0xff", "equals": "0x1", "extra": 1}]},
            {"filters": [{"register": "xmm0", "mask": "0xff", "equals": "0x1"}]},
            {"filters": [{"register": "rcx", "mask": "255", "equals": "0x1"}]},
            {"filters": [{}] * 9}, {"duration_sec": 1}, {"include_ip": False},
        ):
            assert "error" in call(client, "start", address="0x1000", **invalid), invalid
            assert good(call(client))["trace_id"] is None  # admission never submitted
        for invalid in ({"trace_id": 9007199254740994}, {"trace_id": "09007199254740994"},
                        {"trace_id": "1", "cursor": 0}, {"trace_id": "1", "max": 257},
                        {"trace_id": "1", "output_file": {"path": "bad\0path"}}):
            assert "error" in call(client, "read", **invalid), invalid
        for mode in ("cc-no-filters", "cc-no-x64"):
            attach(client, mode)
            assert "error" in call(client, "start", address="0x1000",
                filters=[{"register": "rcx", "mask": "0xff", "equals": "0x1"}])
        for mode in ("cc-query-short", "cc-query-version", "cc-query-limits", "cc-query-clock"):
            attach(client, mode)
            assert "error" in call(client), mode
        for mode in ("cc-reply-short", "cc-bad-config", "cc-bad-cursor", "cc-bad-count"):
            attach(client, mode)
            assert "error" in call(client, "start", address="0x1000"), mode

        for mode in ("cc-partial", "cc-unreadable", "cc-loss", "cc-unknown-loss", "cc-no-timestamp",
                     "cc-unknown-filtered", "cc-low-limit", "cc-large", "cc-auto-stop",
                     "cc-bad-sequence", "cc-bad-registers", "cc-bad-width", "cc-bad-stack", "cc-stack-wrap", "cc-change-export"):
            attach(client, mode)
            options = {"stack_bytes": 4096} if mode == "cc-large" else {"max_hits": "3"} if mode == "cc-auto-stop" else {}
            start = good(call(client, "start", address="0x1000", **options))
            trace = start["trace_id"]
            stopped = good(call(client, "stop", trace_id=trace))
            if mode == "cc-auto-stop":
                assert stopped["stop_reason"] == "max_hits" and stopped["matchedHits"] == "3"
            if mode == "cc-low-limit":
                assert start["stackBytes"] == 16 and start["bufferRecords"] == 2 and start["bufferBytes"] == 1024
            if mode == "cc-change-export":
                assert "error" in call(client, "export", trace_id=trace)
                continue
            page = call(client, "read", trace_id=trace, max=256)
            if mode.startswith("cc-bad-") or mode == "cc-stack-wrap":
                assert "error" in page, (mode, page)
                continue
            good(page)
            if mode == "cc-large":
                saved = json.loads(artifact(page, owned))
                assert len(saved["records"]) < 32 and page["hasMore"]
                exported = good(call(client, "export", trace_id=trace))
                whole = json.loads(artifact(exported, owned))
                assert len(whole["records"]) == 32 and whole["nextCursor"] == "32"
            elif mode in ("cc-partial", "cc-unreadable", "cc-loss", "cc-unknown-loss"):
                assert page["incomplete"], page
                if mode == "cc-unknown-loss":
                    assert page["lostRecords"] is None
                exported = good(call(client, "export", trace_id=trace))
                whole = json.loads(artifact(exported, owned))
                assert whole["incomplete"]
            elif mode == "cc-no-timestamp":
                assert page["records"][0]["timestamp"] is None
            elif mode == "cc-unknown-filtered":
                assert page["filteredHits"] is None

        attach(client, "cc-filter-mismatch")
        trace = good(call(client, "start", address="0x1000",
            filters=[{"register": "rcx", "mask": "0xffff", "equals": "0x1234"}]))["trace_id"]
        good(call(client, "stop", trace_id=trace))
        assert "error" in call(client, "read", trace_id=trace, max=1)

        attach(client, "cc-reused-id")
        trace = good(call(client, "start", address="0x1000"))["trace_id"]
        good(call(client, "stop", trace_id=trace))
        assert "error" in call(client, "start", address="0x1000")

        # Detail-only options must not silently disappear in older modes.
        assert "error" in client.tool("veh_trace_callers", {"address": "0x1000", "stack_bytes": 32})
        assert "error" in client.tool("veh_trace_callers", {"mode": "detour", "operation": "start",
            "address": "0x1000", "stack_bytes": 32})

    # Actions run the same dispatcher and string references as direct/batch.
    log = directory / "actions.log"
    with OwnedMcpClient(args=["--log=" + str(log)]) as client:
        client.initialize()
        attach(client, "ops-action-callers")
        steps = [
            {"tool": "veh_trace_callers", "args": {"mode": "detailed", "operation": "start", "address": "0x1000"}, "as": "$capture"},
            {"tool": "veh_trace_callers", "args": {"mode": "detailed", "operation": "stop", "trace_id": "$capture.trace_id"}},
            {"tool": "veh_trace_callers", "args": {"mode": "detailed", "operation": "read", "trace_id": "$capture.trace_id", "max": 2}},
        ]
        assert client.tool("veh_set_breakpoint", {"address": "0x1800", "action": steps}).get("success")
        stop = client.tool("veh_continue", {"threadId": 77, "wait": True, "timeout": 3}, timeout=5)
        assert stop.get("breakpointId") == 7, stop
        lines = log.read_text(encoding="utf-8")
        assert "Breakpoint action completed with an error:" not in lines, lines[-2000:]
        page = good(call(client, "read", trace_id="9007199254740994", max=2))
        assert len(page["records"]) == 2

    print("PASS detailed caller raw snapshots, exact IDs/clocks, bounds and malformed peers, immutable export, legacy compatibility and direct/batch/action parity")


if __name__ == "__main__":
    owned = []
    try:
        with tempfile.TemporaryDirectory(prefix="veh-callers-") as directory:
            run(Path(directory), owned)
    finally:
        for path in owned:
            path.unlink(missing_ok=True)
