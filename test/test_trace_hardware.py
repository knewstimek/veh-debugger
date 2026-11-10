"""Hardware trace frontend wire/file boundaries using the owned synthetic guest peer."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile

from build_paths import RELEASE, ROOT
from owned_mcp_client import OwnedMcpClient

spec = importlib.util.spec_from_file_location("hardware_event_reader", Path(ROOT) / "tools/read_trace_event_stream.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def main():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="veh-hardware-") as temporary:
        root = Path(temporary)
        with OwnedMcpClient(env=dict(os.environ, TEMP=temporary, TMP=temporary)) as client:
            client.initialize("hardware-trace-frontend")
            args = {"threadId": 77, "start": "0x1000", "end": "0x1100",
                    "collect_hardware_events": True}
            def attach(mode):
                client.tool("veh_detach")
                result = client.tool("veh_attach", {
                    "pid": 4242, "target_scope": "guest",
                    "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
                    "agent_args": ["--metadata", mode]})
                assert result.get("success"), result

            def trace(extra=None):
                return client.tool("veh_trace_basic_blocks", dict(args, **(extra or {})))

            def counters():
                return client.tool("veh_threads")["threads"][0]["name"]

            def verify(receipt, complete=True):
                assert "error" not in receipt, receipt
                assert len(json.dumps(receipt).encode()) <= 8192, receipt
                assert receipt["storage_complete"] is True, receipt
                assert receipt["capture_complete"] is complete and receipt["complete"] is complete, receipt
                collection = receipt["hardware_collection"]
                assert collection["protocol_version"] == 1 and collection["requested"] is True, receipt
                assert collection["requested_kinds"] == collection["applied_kinds"], receipt
                assert collection["complete"] is complete and collection["events"] == receipt["hardware"]["retained_records"], receipt
                event_file = receipt["event_file"]
                raw = Path(event_file["path"]).read_bytes()
                assert hashlib.sha256(raw).hexdigest() == event_file["sha256"], receipt
                assert len(raw) == event_file["size"], receipt
                exported = Path(receipt["output_file"]["path"]).read_bytes()
                assert hashlib.sha256(exported).hexdigest() == receipt["output_file"]["sha256"]
                with io.BytesIO(raw) as stream:
                    header = reader.read_header(stream)
                    rows = list(reader.iter_records(stream, header))
                assert header["schema_version"] == 3 and header["flags"] & 4
                assert str(len(rows)) == receipt["hardware"]["retained_records"]
                return raw, rows

            attach("hardware-ok")
            for extra in ({"collect_hardware_events": "true"}, {"hardware_kinds": []},
                          {"hardware_kinds": ["msr", "msr"]}, {"hardware_kinds": ["unknown"]},
                          {"hardware_kinds": [1]}, {"hardware_kinds": ["msr"], "collect_hardware_events": False},
                          {"events_output": "inline"}, {"output_mode": "inline"},
                          {"collect_snapshots": False}, {"compress_paths": True},
                          {"target_window": {"address": "0x1000", "occurrence": 1, "before_steps": 0, "after_steps": 1}}):
                assert "error" in trace(extra), extra
                checks += 1
            assert counters() == "hardware:0:0", counters()
            # No new negotiation or execution command when explicitly disabled.
            assert "error" in trace({"collect_hardware_events": False})
            assert counters() == "hardware:0:0", counters()
            checks += 1
            attach("hardware-memory-gap")
            incomplete = trace()
            assert incomplete.get("fatal") and incomplete.get("code") == "memory_capture_incomplete", incomplete
            assert not incomplete["capture_complete"] and not incomplete["complete"], incomplete
            assert not incomplete["event_file"]["complete"], incomplete
            assert not incomplete["hardware_collection"]["complete"], incomplete
            assert not incomplete["output_file"]["capture_complete"], incomplete
            checks += 1
            attach("hardware-ok")
            direct = trace({"timeout_ms": 120000})
            raw, rows = verify(direct)
            assert rows[0]["subject"] == "0x3" and rows[0]["value"] != rows[0]["after"], rows
            assert rows[0]["attempt"] == "9007199254740993", rows
            assert rows[1]["value"] == "0xFFFF800000002000" and rows[1]["before"] is None, rows
            assert rows[2]["value"] == "0x0" and rows[2]["after"] is None, rows
            checks += 1
            query = {"operation": "read_events", "event_file": direct["event_file"]["path"],
                     "sha256": direct["event_file"]["sha256"], "limit": 1}
            page = client.tool("veh_trace_basic_blocks", query)
            assert page["events"] == rows[:1] and page["next_offset"] == "1", page
            second = client.tool("veh_trace_basic_blocks", dict(query, offset=page["next_offset"]))
            assert second["events"] == rows[1:2], second
            filtered = client.tool("veh_trace_basic_blocks", dict(query, hardware_kind="io_port"))
            assert filtered["events"] == rows[2:], filtered
            analysis = client.tool("veh_trace_basic_blocks", dict(query, operation="analyze_events"))
            assert analysis["hardware"]["counts"] == direct["hardware"]["counts"], analysis
            assert analysis["hardware"]["operations"]["io_port"] == {"read": "1", "write": "0"}, analysis
            assert "error" in client.tool("veh_trace_basic_blocks", dict(query, sha256="0" * 64))
            assert "error" in client.tool("veh_trace_basic_blocks", dict(query, offset=9007199254740993))
            checks += 1
            batch = client.tool("veh_batch", {"steps": [
                {"tool": "veh_trace_basic_blocks", "args": args},
                {"tool": "veh_trace_basic_blocks", "args": query},
                {"tool": "veh_trace_basic_blocks", "args": dict(query, operation="analyze_events")}]})
            assert batch["failed"] == 0, batch
            _, batch_rows = verify(batch["results"][0]["result"])
            assert batch_rows == rows and batch["results"][1]["result"] == page, batch
            checks += 1
            # All three supported operations also execute through breakpoint actions.
            outputs = root / "veh-mcp-artifacts"
            existing = set(outputs.glob("*.json"))
            installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                {"tool": "veh_trace_basic_blocks", "args": args},
                {"tool": "veh_trace_basic_blocks", "args": query},
                {"tool": "veh_trace_basic_blocks", "args": dict(query, operation="analyze_events")}]})
            assert installed.get("id"), installed
            assert client.tool("veh_continue").get("success")
            client.wait_notification("notifications/logging",
                lambda p: "Breakpoint #7 hit" in p.get("data", ""), timeout=15)
            created = set(outputs.glob("*.json")) - existing
            assert len(created) == 1, created
            saved = json.loads(created.pop().read_bytes())
            assert saved["hardware"] == direct["hardware"], saved
            checks += 1
            for mode in ("hardware-legacy", "hardware-zero", "hardware-partial-kinds", "hardware-version",
                         "hardware-size", "hardware-reserved", "hardware-cap-short", "hardware-budget"):
                attach(mode)
                refused = trace()
                assert "error" in refused and counters() == "hardware:1:0", (mode, refused, counters())
                checks += 1
            attach("hardware-user-only")
            assert "error" in trace({"start": "0xFFFF800000001000", "end": "0xFFFF800000001100"})
            assert counters() == "hardware:1:0"
            checks += 1
            attach("hardware-ok")
            verify(trace({"start": "0xFFFF800000001000", "end": "0xFFFF800000001100"}))
            checks += 1
            attach("hardware-partial-kinds")
            _, selected = verify(trace({"hardware_kinds": ["control_register"]}))
            assert len(selected) == 1 and selected[0]["kind"] == "control_register"
            checks += 1
            for mode in ("hardware-bad-known", "hardware-bad-index", "hardware-bad-count",
                         "hardware-bad-applied", "hardware-no-pc", "hardware-envelope-reserved",
                         "hardware-bad-hash", "hardware-bad-token", "hardware-bad-offset", "hardware-trailing",
                         "hardware-bad-scope-zero", "hardware-bad-scope-unflagged", "hardware-bad-scope-value",
                         "hardware-unknown-flags"):
                attach(mode)
                refused = trace()
                assert "error" in refused and refused["final_address"] is None, (mode, refused)
                checks += 1
            for mode in ("hardware-maxsteps", "hardware-uncertain", "hardware-code",
                         "hardware-unsupported", "hardware-unknown-loss"):
                attach(mode)
                partial = trace()
                _, partial_rows = verify(partial, False)
                if mode == "hardware-uncertain":
                    assert partial["steps_executed"] is None and partial["steps_executed_lower_bound"] == "2", partial
                    assert partial["hardware"]["lost_records"] is None, partial
                    assert partial_rows[-1]["sequence"] is None and partial_rows[-1]["completion"] == "uncertain"
                if mode == "hardware-code":
                    assert partial["decode_incomplete"] and partial["capture_incomplete"], partial
                if mode == "hardware-unsupported":
                    assert partial["stop_reason"] == "unsupported_hardware", partial
                if mode == "hardware-unknown-loss":
                    assert partial["hardware"]["lost_records"] is None, partial
                checks += 1
            for code, reason in enumerate(("address_space", "cpl", "thread", "rip_range", "identity_unavailable"), 1):
                attach(f"hardware-scope-{code}")
                scoped = trace()
                _, scope_rows = verify(scoped)
                assert scoped["stop_reason"] == "left_scope" and scoped["scope_exit"] == reason, scoped
                assert scoped["hardware_collection"]["scope_exit"] == reason and scoped["steps_executed"] == "3", scoped
                assert scope_rows[0]["before"] != scope_rows[0]["after"], scope_rows
                checks += 1
            attach("hardware-scope-priority")
            priority = trace()
            verify(priority, False)
            assert priority["stop_reason"] == "completion_uncertain" and priority["scope_exit"] == "address_space", priority
            checks += 1
            attach("hardware-export-fail")
            failed_export = trace({"output_file": str(root / "export-collision.json")})
            assert "error" in failed_export and failed_export["event_file"]["storage_complete"], failed_export
            assert Path(failed_export["event_file"]["path"]).exists(), failed_export
            assert failed_export["storage_complete"] is False, failed_export
            checks += 1
            attach("hardware-raw-error")
            refused = trace()
            assert "error" in refused and refused["event_file"]["raw_prefix"], refused
            prefix_raw = Path(refused["event_file"]["path"]).read_bytes()
            assert hashlib.sha256(prefix_raw).hexdigest() == refused["event_file"]["sha256"], refused
            checks += 1
            attach("hardware-many")
            many = trace()
            _, many_rows = verify(many)
            query_many = dict(query, event_file=many["event_file"]["path"], sha256=many["event_file"]["sha256"], limit=100)
            offset, observed = "0", []
            for _ in range(20):
                page_many = client.tool("veh_trace_basic_blocks", dict(query_many, offset=offset))
                assert "error" not in page_many and len(json.dumps(page_many).encode()) <= 8192, page_many
                observed.extend(page_many["events"])
                offset = page_many["next_offset"]
                if offset is None:
                    break
            assert observed == many_rows, (len(observed), len(many_rows))
            checks += 1
            # Review regressions are collected together so every defect is visible.
            review_failures = []
            client.tool("veh_detach")
            host_attached = client.tool("veh_attach", {
                "pid": client.proc.pid, "target_scope": "host",
                "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
                "agent_args": ["--metadata", "hardware-host"]})
            assert host_attached.get("success"), host_attached
            host_capture = trace()
            if "error" in host_capture:
                review_failures.append("host-scope hypervisor process refused: " + json.dumps(host_capture, separators=(",", ":")))
            else:
                verify(host_capture)
                assert counters() == "hardware:1:1", counters()
            checks += 1
            attach("hardware-no-eof")
            missing_eof = trace()
            if "error" not in missing_eof or missing_eof.get("complete") is not False:
                review_failures.append("EOF drain cancellation accepted as a complete capture")
            else:
                prefix = missing_eof["event_file"]
                prefix_bytes = Path(prefix["path"]).read_bytes()
                assert prefix["raw_prefix"] and hashlib.sha256(prefix_bytes).hexdigest() == prefix["sha256"], missing_eof
                assert "error" in client.tool("veh_trace_basic_blocks", {
                    "operation": "read_events", "event_file": prefix["path"]}), missing_eof
            checks += 1
            attach("hardware-limit-ok")
            verify(trace())
            attach("hardware-limit-exceeded")
            exceeded = trace()
            if "error" not in exceeded:
                review_failures.append("negotiated max_per_instruction=1 accepted two records")
            checks += 1
            attach("hardware-legacy-file")
            legacy_long = trace({"collect_hardware_events": False, "events_output": "file",
                                 "collect_events": True, "timeout_ms": 120000})
            if "error" in legacy_long or "hardware_collection" in legacy_long or counters() != "hardware:0:1":
                review_failures.append("ordinary guest file capture rejected its 120000ms budget")
            checks += 1
            # Offline reads do not require an attached guest.
            client.tool("veh_detach")
            offline = client.tool("veh_trace_basic_blocks", query)
            assert offline == client.tool("veh_trace_basic_blocks", query)
            assert offline["events"] == rows[:1], offline
            offline_batch = client.tool("veh_batch", {"steps": [
                {"tool": "veh_trace_basic_blocks", "args": query},
                {"tool": "veh_trace_basic_blocks", "args": dict(query, operation="analyze_events")}]})
            assert offline_batch["failed"] == 0 and offline_batch["results"][0]["result"] == offline, offline_batch
            checks += 1
            # Legacy artifact schemas remain readable and reject new hardware records.
            for version in (1, 2):
                legacy = reader.HEADER.pack(reader.MAGIC, version, 88, 1, 8, 48, 84, 320, 0, 0, 0, 0, 0, 0, 0, 0)
                stream = io.BytesIO(legacy)
                legacy_header = reader.read_header(stream)
                assert list(reader.iter_records(stream, legacy_header)) == []
                legacy_path = root / f"legacy-{version}.vte"
                legacy_path.write_bytes(legacy)
                legacy_page = client.tool("veh_trace_basic_blocks", {
                    "operation": "read_events", "event_file": str(legacy_path)})
                assert legacy_page["events"] == [] and legacy_page["schema_version"] == version, legacy_page
                checks += 1
            # The native reader must reject the same malformed basic payload as Python.
            malformed_basic = reader.BASIC_BLOCK.pack(0, 0, 0, 0, 77, 0, 0xFFFFFFFF, 255, 0, 0, 0)
            bad_header = list(reader.HEADER.unpack(raw[:88]))
            bad_header[8] += reader.RECORD_HEADER.size + len(malformed_basic)
            bad_header[9] += 1
            invalid_basic = reader.HEADER.pack(*bad_header) + reader.RECORD_HEADER.pack(1, 0, len(malformed_basic)) + malformed_basic + raw[88:]
            invalid_path = root / "invalid-basic.vte"
            invalid_path.write_bytes(invalid_basic)
            native_invalid = client.tool("veh_trace_basic_blocks", {
                "operation": "read_events", "event_file": str(invalid_path)})
            if "error" not in native_invalid:
                review_failures.append("native artifact reader accepted unknown basic-event type")
            checks += 1
            # Reader rejects count, reserved, size, unknown record, truncation, and EOF corruption.
            for corrupted in (raw + b"x", raw[:-1],
                              raw[:84] + struct.pack("<I", 9) + raw[88:],
                              raw[:88] + struct.pack("<HHI", 5, 0, 80) + raw[96:],
                              raw[:12] + struct.pack("<I", 7) + raw[16:]):
                try:
                    stream = io.BytesIO(corrupted)
                    header = reader.read_header(stream)
                    list(reader.iter_records(stream, header))
                except (ValueError, struct.error):
                    checks += 1
                else:
                    raise AssertionError("reader accepted corrupted schema3 artifact")
            assert not review_failures, review_failures
    print(f"PASS: hardware trace frontend {checks} boundaries; direct/batch/action, exact values, schema3, partial files and offline pages")


if __name__ == "__main__":
    main()
