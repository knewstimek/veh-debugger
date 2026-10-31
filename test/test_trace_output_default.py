"""Default file receipts and explicit inline parity, without a VM or real target."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

from build_paths import RELEASE
from owned_mcp_client import OwnedMcpClient


def main():
    with tempfile.TemporaryDirectory(prefix="veh-trace-output-") as temporary:
        root = Path(temporary)
        environment = dict(os.environ, TEMP=temporary, TMP=temporary)
        with OwnedMcpClient(env=environment) as client:
            client.initialize("trace-output-default")
            schema = client.tool("veh_toolbox", {"operation": "describe", "tool": "veh_trace_basic_blocks"})
            assert '"output_mode"' in json.dumps(schema) and '"file"' in json.dumps(schema), schema
            assert '"run_peer_cpus"' in json.dumps(schema), schema
            attached = client.tool("veh_attach", {
                "pid": 4242, "target_scope": "guest",
                "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
                "agent_args": ["--metadata", "path-file-output"],
            })
            assert attached.get("success"), attached
            args = {"threadId": 77, "start": "0x1000", "end": "0x1100",
                    "collect_code": True, "collect_snapshots": False, "compress_paths": True}
            inline = client.tool("veh_trace_basic_blocks", dict(args, output_mode="inline"))
            assert "error" not in inline and inline["events"], inline

            def verify(receipt, expected_format="json"):
                assert receipt.get("mode") == "file" and "error" not in receipt, receipt
                assert "events" not in receipt and "blocks" not in receipt, receipt
                assert len(json.dumps(receipt).encode()) < 8192
                output = receipt["output_file"]
                path = Path(output["path"])
                assert path.is_relative_to(root) and path.suffix == "." + expected_format, output
                raw = path.read_bytes()
                assert len(raw) == output["size"], output
                assert hashlib.sha256(raw).hexdigest() == output["sha256"], output
                assert receipt["counts"]["events"] == len(inline["events"]), receipt
                if expected_format == "json":
                    assert json.loads(raw) == inline, receipt
                else:
                    rows = [json.loads(line) for line in raw.splitlines()]
                    assert rows[0]["record"] == "manifest" and len(rows) > 1, rows[0]
                return path

            direct = client.tool("veh_trace_basic_blocks", args)
            first = verify(direct)
            second = verify(client.tool("veh_trace_basic_blocks", args))
            assert second != first, "Generated artifacts must never overwrite"
            verify(client.tool("veh_trace_basic_blocks", dict(args, output_format="jsonl")), "jsonl")
            batch = client.tool("veh_batch", {
                "steps": [{"tool": "veh_trace_basic_blocks", "args": args}]})
            assert batch["failed"] == 0, batch
            verify(batch["results"][0]["result"])
            assert any(a.get("path") == batch["results"][0]["result"]["output_file"]["path"]
                       for a in batch["artifacts"]), batch

            # Explicit paths and inline retain their established contracts.
            explicit = root / "explicit.json"
            verify(client.tool("veh_trace_basic_blocks", dict(args, output_file=str(explicit))))
            before = client.tool("veh_threads")["threads"][0]["name"]
            for invalid, fragment in (
                ({"run_peer_cpus": True}, "supported only for KD"),
                ({"run_peer_cpus": False}, "supported only for KD"),
                ({"output_mode": 7}, "output_mode must be a string"),
                ({"output_mode": "unknown"}, "output_mode must be file or inline"),
                ({"output_mode": "inline", "output_file": str(root / "bad.json")}, "output_file requires"),
                ({"output_mode": "inline", "output_format": "json"}, "output_format requires"),
                ({"output_format": "unknown"}, "output_format must be"),
                ({"output_file": str(explicit)}, "already exists"),
            ):
                refused = client.tool("veh_trace_basic_blocks", dict(args, **invalid))
                assert fragment in refused.get("error", ""), refused
            assert client.tool("veh_threads")["threads"][0]["name"] == before
            assert json.loads(explicit.read_bytes()) == inline

            # An action uses the same default without a supplied output path.
            artifacts = root / "veh-mcp-artifacts"
            existing = set(artifacts.glob("*.json"))
            installed = client.tool("veh_set_breakpoint", {
                "address": "0x1000",
                "action": [{"tool": "veh_trace_basic_blocks", "args": args}],
            })
            assert installed.get("id"), installed
            assert client.tool("veh_continue").get("success")
            client.wait_notification("notifications/logging",
                lambda p: "Breakpoint #7 hit" in p.get("data", ""), timeout=15)
            created = set(artifacts.glob("*.json")) - existing
            assert len(created) == 1, created
            assert json.loads(created.pop().read_bytes()) == inline
            assert client.tool("veh_detach").get("success")
    print("PASS: default JSON/JSONL, direct/batch/action parity, inline, no-overwrite, validation before IPC")


if __name__ == "__main__":
    main()
