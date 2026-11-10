"""Memory capture failures are errors across inline/artifacts, batch and actions."""
import json
import os
from pathlib import Path
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient


def main():
    with tempfile.TemporaryDirectory(prefix="veh-memory-gap-") as temporary:
        root = Path(temporary)
        log = root / "actions.log"
        with OwnedMcpClient(args=["--log=" + str(log)]) as client:
            client.initialize("memory-gap-errors")
            def attach():
                attached = client.tool("veh_attach", {
                    "pid": 4242, "target_scope": "guest",
                    "agent": os.path.join(RELEASE, "guest_backend_fixture.exe"),
                    "agent_args": ["--metadata", "path-wide-limits"],
                })
                assert attached.get("success"), attached
            def verify(result, mode):
                assert "error" in result and result["code"] == "memory_capture_incomplete" and result["fatal"], result
                assert result["unsupported_memory_reads"] == 4294967299, result
                assert result["unsupported_memory_writes"] == 4294967298, result
                assert result["capture_complete"] is False, result
                if "memory_ordering" in result:
                    assert result["memory_ordering"]["complete"] is False, result["memory_ordering"]
                if mode == "file":
                    artifact = result["output_file"]
                    assert artifact["storage_complete"] and not artifact["capture_complete"]
                    saved = json.loads(Path(artifact["path"]).read_text(encoding="utf-8"))
                    assert saved["code"] == result["code"] and "error" in saved
                return result
            for mode in ("inline", "file"):
                attach()
                common = {
                    "threadId": 77, "start": "0x1000", "end": "0x1100",
                    "max_steps": "10000000000", "max_decoded_instructions": 64,
                    "events_output": "inline", "output_mode": mode, "collect_memory_events": True,
                }
                direct = dict(common)
                if mode == "file":
                    direct["output_file"] = str(root / "direct.json")
                verify(client.tool("veh_trace_basic_blocks", direct), mode)
                batch = dict(common)
                if mode == "file":
                    batch["output_file"] = str(root / "batch.json")
                result = client.tool("veh_batch", {"stop_on_error": False, "steps": [
                    {"tool": "veh_trace_basic_blocks", "args": batch},
                    {"tool": "veh_trace_basic_blocks", "args": batch},
                ]})
                assert result["failed"] == 1 and result["totalSteps"] == 1, (result["failed"], result["totalSteps"])
                assert result["results"][-1].get("aborted"), result["results"][-1]
                verify(result["results"][0]["result"], mode)
                trace_step = {"tool": "veh_trace_basic_blocks", "args": dict(common, output_mode="inline")}
                for nested in (
                    {"if": "1 == 1", "then": [trace_step, trace_step]},
                    {"loop": [trace_step, trace_step], "max": 3},
                    {"for_each": [1, 2, 3], "do": [trace_step, trace_step]},
                ):
                    before = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
                    nested_result = client.tool("veh_batch", {"stop_on_error": False,
                        "steps": [dict(nested, result_fields=["type", "result", "results"]), trace_step]})
                    assert nested_result.get("fatal") and nested_result.get("code") == "memory_capture_incomplete", {
                        "fatal": nested_result.get("fatal"), "failed": nested_result.get("failed")}
                    after = int(client.tool("veh_threads")["threads"][0]["name"].split(":")[1])
                    assert after == before + 1, (before, after)
                    assert len(nested_result["trace_summary"]) == 1, nested_result["trace_summary"]
                if mode == "inline":
                    targeted = client.tool("veh_targeted_capture", {
                        "inputs": [1, 2], "steps": [], "trace": dict(common, output_mode="file",
                            collect_code=False, collect_register_events=False),
                        "trigger": {"address": "0x1000"},
                        "window": {"before_steps": 0, "after_steps": 1},
                        "output_directory": str(root / "targeted"), "stop_on_error": False,
                    })
                    assert targeted.get("fatal") and targeted.get("code") == "memory_capture_incomplete", {
                        "fatal": targeted.get("fatal"), "error": targeted.get("error")}
                    assert len(targeted["inputs"]) == 1, targeted
                    setup_failure = client.tool("veh_targeted_capture", {
                        "inputs": [1, 2], "steps": [trace_step],
                        "trace": dict(common, output_mode="file", collect_code=False),
                        "trigger": {"address": "0x1000"},
                        "window": {"before_steps": 0, "after_steps": 1},
                        "output_directory": str(root / "targeted-setup"), "stop_on_error": False,
                    })
                    assert setup_failure.get("fatal") and len(setup_failure["inputs"]) == 1, setup_failure
                action = dict(common)
                if mode == "file":
                    action["output_file"] = str(root / "action.json")
                bp = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                    {"tool": "veh_trace_basic_blocks", "args": action},
                    {"tool": "veh_trace_basic_blocks", "args": action},
                ]})
                assert bp.get("id"), bp
                client.tool("veh_continue", {"wait": True, "timeout": 2}, timeout=5)
                client.wait_notification("notifications/logging",
                    lambda p: "automatic continue was skipped" in p.get("data", ""), timeout=5)
                client.tool("veh_remove_breakpoint", {"id": bp["id"]})
                assert client.tool("veh_detach").get("success")
        marker = "Breakpoint action completed with an error: "
        reports = [json.loads(line.split(marker, 1)[1])
                   for line in log.read_text(encoding="utf-8").splitlines() if marker in line]
        assert len(reports) == 2, reports
        for report, mode in zip(reports, ("inline", "file")):
            assert report["totalSteps"] == 1 and report["results"][-1].get("aborted"), report
            verify(report["results"][0]["result"], mode)
    print("PASS memory-gap errors, exact counters, artifact retention and direct/batch/action refusal")


if __name__ == "__main__":
    main()
