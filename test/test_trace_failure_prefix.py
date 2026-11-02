"""Verified event prefixes and uncertain execution through the owned IPC fixture."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from read_trace_event_stream import convert


def main():
    with tempfile.TemporaryDirectory(prefix="veh-prefix-") as temporary:
        root = Path(temporary)
        env = dict(os.environ, TEMP=temporary, TMP=temporary)
        logfile = root / "trace-actions.log"
        with OwnedMcpClient(env=env, args=["--log=" + str(logfile)]) as client:
            client.initialize("trace-failure-prefix")
            def attach(mode):
                result = client.tool("veh_attach", {"pid": 424242, "target_scope": "guest",
                    "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"), "agent_args": ["--metadata", mode]})
                assert result.get("success"), result

            for mode in ("path-stream-prefix", "path-stream-bad-hash", "path-inline-error"):
                attach(mode)
                common = {"threadId": 77, "start": "0x1000", "end": "0x1100", "max_steps": 1000,
                    "collect_register_events": True, "collect_memory_events": True}
                if mode == "path-inline-error":
                    common.update(events_output="inline", output_mode="inline")
                for batch in (False, True):
                    args = dict(common)
                    if mode != "path-inline-error":
                        args["events_output_path"] = str(root / (mode + str(batch) + ".vte"))
                    result = client.tool("veh_batch", {"steps": [{"tool": "veh_trace_basic_blocks", "args": args}]}) if batch else client.tool("veh_trace_basic_blocks", args)
                    if batch:
                        assert result["failed"] == 1, result
                        result = result["results"][0]["result"]
                    assert "error" in result and result["capture_incomplete"], result
                    assert result["execution_count_incomplete"] and result["lost_records"] is None, result
                    assert result["final_address"] is None, result
                    if mode == "path-stream-prefix":
                        artifact = result["event_file"]
                        assert artifact["storage_complete"] and not artifact["complete"], artifact
                        path = Path(artifact["path"])
                        assert path.is_relative_to(root) and hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
                        try:
                            convert(path, io.StringIO())
                            raise AssertionError("Incomplete artifact accepted without explicit opt-in")
                        except ValueError as error:
                            assert "not complete" in str(error), error
                        output = io.StringIO()
                        convert(path, output, allow_incomplete=True)
                        rows = [json.loads(line) for line in output.getvalue().splitlines()]
                        assert rows[0]["capture_incomplete"] and rows[0]["final_address"] is None
                        assert rows[0]["counts"] == {"events": 0, "register_events": 300, "memory_events": 300}
                        assert len(rows) == 601 and sum(artifact["counts"].values()) == 600
                    else:
                        assert "event_file" not in result, result
                    if mode == "path-inline-error":
                        assert result["failure"]["steps_executed"] is None, result
                        assert result["failure"]["backend_reported"]["steps_executed"] == 0, result
                    assert len(json.dumps(result).encode()) < 8192
                if mode == "path-inline-error":
                    expected = result
                    installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                        {"tool": "veh_trace_basic_blocks", "args": common}]})
                    assert installed.get("id"), installed
                    stop = client.tool("veh_continue", {"wait": True, "timeout": 2}, timeout=5)
                    assert stop.get("breakpointId") == 7, stop
                assert client.tool("veh_detach").get("success")
        marker = "Breakpoint action completed with an error: "
        reports = [json.loads(line.split(marker, 1)[1]) for line in logfile.read_text(encoding="utf-8").splitlines() if marker in line]
        assert len(reports) == 1 and reports[0]["results"][0]["result"] == expected, reports
    print("PASS verified prefix salvage, partial-tail truncation, reader opt-in, checksum rejection and direct/batch/action execution uncertainty")


if __name__ == "__main__":
    main()
