"""Integration smoke test for veh_trace_basic_blocks."""
import json
import hashlib
import ctypes
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter

from mcp_test_client import McpClient as Client


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
MCP_EXE = os.path.join(BUILD_DIR, "bin", "Release", "veh-mcp-server.exe")
TARGET = os.environ.get("VEH_TEST_TARGET",
                        os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe"))


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("PartitionId", ctypes.c_ushort),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


def committed_region(pid, address):
    process = ctypes.windll.kernel32.OpenProcess(0x0400, False, pid)
    assert process, ctypes.get_last_error()
    try:
        mbi = MemoryBasicInformation()
        size = ctypes.windll.kernel32.VirtualQueryEx(
            process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        assert size == ctypes.sizeof(mbi) and mbi.State == 0x1000, (size, mbi.State)
        return mbi.BaseAddress, mbi.RegionSize
    finally:
        ctypes.windll.kernel32.CloseHandle(process)


def read_code_artifact(path):
    data = open(path, "rb").read()
    header_format = "<QIIIIQQQQII"
    record_format = "<QQQQQII"
    header_size = struct.calcsize(header_format)
    fields = struct.unpack_from(header_format, data)
    artifact = {
        "magic": fields[0], "schema": fields[1], "header_size": fields[2],
        "flags": fields[3], "chunk_bytes": fields[4], "range_start": fields[5],
        "range_end": fields[6], "code_bytes": fields[7], "record_bytes": fields[8],
        "versions": fields[9], "chunks": fields[10], "records": [],
        "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
    }
    assert artifact["magic"] == 0x0045444F43484556, artifact
    assert artifact["schema"] == 1 and artifact["header_size"] == header_size, artifact
    assert len(data) == header_size + artifact["record_bytes"], artifact
    cursor = header_size
    expected_data_offset = 0
    for _ in range(artifact["versions"]):
        record = struct.unpack_from(record_format, data, cursor)
        cursor += struct.calcsize(record_format)
        size = record[6]
        code = data[cursor:cursor + size]
        assert len(code) == size and record[4] == expected_data_offset, artifact
        cursor += size
        expected_data_offset += size
        artifact["records"].append({"block": record[0], "end": record[1],
                                    "hash": record[2], "first_sequence": record[3],
                                    "data_offset": record[4], "id": record[5],
                                    "size": size, "bytes": code})
    assert cursor == len(data) and expected_data_offset == artifact["code_bytes"], artifact
    return artifact


def main():
    client = Client()
    artifact_paths = []
    artifact_dirs = []
    def artifact_path(label):
        path = os.path.join(tempfile.gettempdir(),
                            f"veh-trace-{os.getpid()}-{time.time_ns()}-{label}.vtc")
        artifact_paths.append(path)
        return path
    def output_path(label, extension="json"):
        path = os.path.join(tempfile.gettempdir(),
                            f"veh-trace-{os.getpid()}-{time.time_ns()}-{label}.{extension}")
        artifact_paths.append(path)
        return path
    def validate_output(path, expected_sha256):
        completed = subprocess.run([
            sys.executable, os.path.join(ROOT, "tools", "validate_trace_output.py"),
            path, "--sha256", expected_sha256,
        ], cwd=ROOT, capture_output=True, text=True, timeout=15)
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)
    try:
        client.call("initialize", {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "trace-basic-blocks-test", "version": "1"},
            "capabilities": {},
        })
        listed = client.call("tools/list")["result"]["tools"]
        trace_tool = next((tool for tool in listed
                           if tool.get("name") == "veh_trace_basic_blocks"), None)
        assert trace_tool, listed
        assert any(tool.get("name") == "veh_targeted_capture" for tool in listed), listed
        trace_properties = trace_tool["inputSchema"]["properties"]
        assert all(name in trace_properties for name in (
            "collect_events", "max_events", "collect_code", "max_code_bytes", "max_code_versions",
            "code_output", "code_output_path", "code_chunk_bytes",
            "collect_memory_events", "max_memory_events",
            "collect_register_events", "max_register_events", "stop_on_return", "target_window",
        )), trace_tool
        launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
        assert launch.get("success"), launch

        bp = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
        assert bp.get("success") and bp.get("address"), bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        thread_id = stop["threadId"]
        start = int(bp["address"], 0)
        regs = client.tool("veh_registers", {"threadId": thread_id})["registers"]

        # Start rejection must expose the exact stopped/IP/range/decode decision.
        # Starting one byte after the current EIP/RIP keeps the range readable
        # while deliberately excluding the stopped instruction pointer.
        rejected = client.tool("veh_trace_basic_blocks", {
            "threadId": thread_id, "start": hex(start + 1), "end": hex(start + 0x100),
            "max_steps": 8, "timeout_ms": 1000,
        })
        failure = rejected.get("failure", {})
        assert failure.get("reason") == "instruction_pointer_outside_range", rejected
        assert failure.get("status") == "not_found" and failure.get("status_code") == 2, rejected
        assert failure.get("control_response_received") is True, rejected
        assert failure.get("control_response_bytes", 0) > 0, rejected
        assert failure.get("advertised_payload_bytes") == failure["control_response_bytes"], rejected
        assert failure.get("response_header_bytes") == failure.get("expected_response_bytes"), rejected
        assert failure.get("stopped") is True and failure.get("ip_in_range") is False, rejected
        assert failure.get("decode_succeeded") is True, rejected
        assert failure.get("decoded_instruction_count", 0) > 0, rejected
        assert int(failure["normalized_ip"], 0) == start, rejected
        assert int(failure["normalized_start"], 0) == start + 1, rejected
        assert int(failure["normalized_end"], 0) == start + 0x100, rejected

        rejected_batch = client.tool("veh_batch", {"steps": [{
            "tool": "veh_trace_basic_blocks", "args": {
                "threadId": thread_id, "start": hex(start + 1), "end": hex(start + 0x100),
                "max_steps": 8, "timeout_ms": 1000,
            },
        }]})
        batch_failure = rejected_batch["results"][0]["result"]["failure"]
        assert batch_failure == failure, rejected_batch

        if "rsp" in regs:
            dependency_sources = ["rcx"]
        else:
            dependency_sources = [{"address": hex(int(regs["esp"], 0) + 4),
                                   "size": 4, "label": "input"}]

        trace = client.tool("veh_trace_basic_blocks", {
            "threadId": thread_id,
            "start": hex(start),
            "end": hex(start + 0x100),
            "max_steps": 1000,
            "timeout_ms": 5000,
            "stack_bytes": 32,
            "collect_memory_writes": True,
            "max_memory_writes": 64,
            "collect_memory_reads": True,
            "max_memory_reads": 64,
            "collect_memory_events": True,
            "max_memory_events": 256,
            "collect_register_events": True,
            "max_register_events": 256,
            "collect_events": True,
            "max_events": 256,
            "collect_code": True,
            "max_code_bytes": 4096,
            "max_code_versions": 256,
            "dependency_sources": dependency_sources,
        }, timeout=15)
        assert "error" not in trace, trace
        assert len(trace["blocks"]) >= 2, trace
        assert len(trace["edges"]) >= 1, trace
        assert trace["schema_version"] == 4 and trace["mode"] == "aggregated", trace
        assert trace["thread_id"] == thread_id, trace
        assert trace["ordering"] == {
            "available": True, "granularity": "basic_block_transitions",
            "event_schema_version": 2, "complete": True,
            "events_captured": len(trace["events"]), "events_dropped": 0,
        }, trace
        assert trace["events"] and trace["events"][0]["type"] == "block_entry", trace
        assert all(event["thread_id"] == thread_id for event in trace["events"]), trace
        assert [event["sequence"] for event in trace["events"]] == sorted(
            event["sequence"] for event in trace["events"]), trace
        assert any(event["type"] == "edge" for event in trace["events"]), trace
        assert trace["events_truncated"] is False, trace
        assert trace["memory_ordering"] == {
            "available": True, "granularity": "instruction_memory_accesses",
            "event_schema_version": 1, "complete": True,
            "events_captured": len(trace["memory_events"]), "events_dropped": 0,
        }, trace
        assert trace["memory_events"] and trace["memory_events_truncated"] is False, trace
        assert trace["memory_events_dropped"] == 0, trace
        assert all(event["thread_id"] == thread_id for event in trace["memory_events"]), trace
        assert [event["sequence"] for event in trace["memory_events"]] == sorted(
            event["sequence"] for event in trace["memory_events"]), trace
        assert len({(event["sequence"], event["kind"], event["access_index"])
                    for event in trace["memory_events"]}) == len(trace["memory_events"]), trace
        assert all((event["kind"] == "read" and "value" in event) or
                   (event["kind"] == "write" and "before" in event and "after" in event)
                   for event in trace["memory_events"]), trace
        assert any(event.get("dependencies") for event in trace["memory_events"]), trace
        assert trace["register_ordering"] == {
            "available": True, "granularity": "instruction_register_deltas",
            "event_schema_version": 1,
            "scope": "completed_instruction_occurrences_in_collection_window",
            "complete": True, "events_captured": len(trace["register_events"]),
            "events_dropped": 0,
        }, trace
        assert trace["register_events"] and trace["register_events_truncated"] is False, trace
        assert trace["register_events_dropped"] == 0, trace
        assert all(event["thread_id"] == thread_id for event in trace["register_events"]), trace
        assert [event["sequence"] for event in trace["register_events"]] == \
            list(range(1, trace["steps_executed"] + 1)), trace
        assert all("instruction" in event and "changes" in event
                   for event in trace["register_events"]), trace

        write_occurrences = Counter(
            (event["instruction"], event["address"], event["size"],
             event["before"], event["after"])
            for event in trace["memory_events"] if event["kind"] == "write")
        read_occurrences = Counter(
            (event["instruction"], event["address"], event["size"], event["value"])
            for event in trace["memory_events"] if event["kind"] == "read")
        assert all(write_occurrences[(item["instruction"], item["address"], item["size"],
                                      item["before"], item["after"])] == item["hits"]
                   for item in trace["memory_writes"]), trace
        assert all(read_occurrences[(item["instruction"], item["address"], item["size"],
                                     item["value"])] == item["hits"]
                   for item in trace["memory_reads"]), trace
        assert trace["code_capture"]["available"] is True, trace
        assert trace["code_capture"]["complete"] is True, trace
        assert trace["code_versions"] and trace["code_truncated"] is False, trace
        assert all(version["bytes"] and version["size"] > 0 for version in trace["code_versions"]), trace
        assert all("code_version" in event for event in trace["events"]
                   if event["type"] == "block_entry" or event.get("kind") != "range_exit"), trace
        assert trace["snapshots"], trace
        assert sum(block["hits"] for block in trace["blocks"]) > 0, trace
        assert trace["hot_blocks"] and trace["hot_edges"], trace
        assert trace["loop_folds"], trace
        assert trace["hot_blocks"][0]["hits"] >= trace["hot_blocks"][-1]["hits"], trace
        assert any(edge.get("register_delta") for edge in trace["edges"]), trace
        assert all("source_instruction" in edge for edge in trace["edges"]), trace
        assert trace["memory_writes"], trace
        assert trace["memory_reads"], trace
        assert trace["memory_reads_truncated"] is False, trace
        assert all(read["size"] > 0 and read["hits"] > 0 and read["value"]
                   for read in trace["memory_reads"]), trace
        assert any(item.get("dependencies") for item in trace["edges"] + trace["memory_writes"]), trace
        assert trace["dependency_incomplete"] is False, trace
        assert trace["memory_writes_truncated"] is False, trace
        assert any(write["before"] != write["after"] for write in trace["memory_writes"]), trace
        assert all(write["size"] > 0 and write["hits"] > 0 for write in trace["memory_writes"]), trace
        assert all(write.get("region", {}).get("type") in {"image", "mapped", "private", "stack"}
                   for write in trace["memory_writes"]), trace
        classified_deltas = [change for edge in trace["edges"]
                             for change in edge.get("register_delta", {}).values()
                             if "after_region" in change]
        assert classified_deltas, trace

        trigger_block = max((block for block in trace["blocks"] if block["hits"] >= 3),
                            key=lambda block: block["hits"])
        trigger_address = int(trigger_block["start"], 0)
        targeted_stop = client.tool("veh_continue", {
            "wait": True, "timeout": 10,
        }, timeout=15)
        assert targeted_stop.get("reason") == "breakpoint", targeted_stop
        targeted_path = output_path("target-window", "json")
        targeted = client.tool("veh_trace_basic_blocks", {
            "threadId": targeted_stop["threadId"], "start": hex(start),
            "end": hex(start + 0x100), "max_steps": 1000, "timeout_ms": 5000,
            "target_window": {"address": hex(trigger_address), "occurrence": 3,
                              "before_steps": 3, "after_steps": 4},
            "collect_events": True, "max_events": 32,
            "collect_memory_events": True, "max_memory_events": 64,
            "collect_register_events": True, "max_register_events": 32,
            "collect_code": True, "max_code_bytes": 4096, "max_code_versions": 64,
            "output_file": targeted_path,
        }, timeout=15)
        assert targeted.get("stop_reason") == "target_window", targeted
        target_meta = targeted["target_window"]
        assert target_meta["matched"] is True, targeted
        assert target_meta["matched_occurrence_count"] == 3, targeted
        assert target_meta["capture_start_sequence"] == target_meta["trigger_sequence"] - 3, targeted
        assert target_meta["capture_end_sequence"] == target_meta["trigger_sequence"] + 4, targeted
        with open(targeted_path, encoding="utf-8") as targeted_file:
            targeted_full = json.load(targeted_file)
        assert targeted_full["target_window"] == target_meta, targeted_full
        register_sequences = [event["sequence"] for event in targeted_full["register_events"]]
        assert register_sequences == list(range(target_meta["capture_start_sequence"],
                                                target_meta["capture_end_sequence"] + 1)), targeted_full
        assert all(target_meta["capture_start_sequence"] <= event["sequence"] <=
                   target_meta["capture_end_sequence"]
                   for event in targeted_full["events"] + targeted_full["memory_events"]), targeted_full
        assert all(event.get("code_version", 0) < len(targeted_full["code_versions"])
                   for event in targeted_full["events"] if "code_version" in event), targeted_full

        function_bp = client.tool("veh_set_function_breakpoint", {
            "name": "TraceFunctionScopeTarget",
        })
        assert function_bp.get("success") and function_bp.get("address"), function_bp
        function_start = int(function_bp["address"], 0)
        function_stop = client.tool("veh_continue", {
            "wait": True, "timeout": 10,
        }, timeout=15)
        assert function_stop.get("reason") == "breakpoint", function_stop
        function_regs = client.tool("veh_registers", {
            "threadId": function_stop["threadId"],
        })["registers"]
        function_sp_name = "esp" if "esp" in function_regs else "rsp"
        function_pointer_size = 4 if function_sp_name == "esp" else 8
        expected_entry_sp = int(function_regs[function_sp_name], 0)
        entry_return_bytes = client.tool("veh_read_memory", {
            "address": hex(expected_entry_sp), "size": function_pointer_size,
        })["hex"]
        expected_return_address = int.from_bytes(bytes.fromhex(entry_return_bytes), "little")
        function_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": function_stop["threadId"],
            "start": hex(function_start), "end": hex(function_start + 0x100),
            "stop_on_return": True, "max_steps": 20000, "timeout_ms": 10000,
            "stack_bytes": 32, "collect_events": True, "max_events": 256,
            "collect_memory_events": True, "max_memory_events": 256,
            "collect_register_events": True, "max_register_events": 256,
            "collect_code": True, "max_code_bytes": 4096, "max_code_versions": 256,
        }, timeout=20)
        assert function_trace.get("stop_reason") == "function_return", function_trace
        scope = function_trace["function_scope"]
        assert scope["supported"] is True and scope["stop_on_return"] is True, function_trace
        assert scope["returned"] is True and scope["external_steps"] > 0, function_trace
        assert int(scope["entry_stack_pointer"], 0) == expected_entry_sp, function_trace
        assert int(scope["return_address"], 0) == expected_return_address, function_trace
        assert int(scope["return_address"], 0) == int(function_trace["final_address"], 0), function_trace
        assert scope["return_snapshot"]["id"] == scope["return_snapshot_id"], function_trace
        assert scope["return_snapshot"]["instruction_pointer"] == scope["return_address"], function_trace
        assert any(edge["kind"] == "call" for edge in function_trace["edges"]), function_trace
        return_edges = [edge for edge in function_trace["edges"] if edge["kind"] == "return"]
        assert return_edges and return_edges[-1]["target"] == scope["return_address"], function_trace
        assert all(function_start <= int(event["instruction"], 0) < function_start + 0x100
                   for event in function_trace["memory_events"]), function_trace
        assert all(function_start <= int(event["instruction"], 0) < function_start + 0x100
                   for event in function_trace["register_events"]), function_trace
        assert client.tool("veh_remove_breakpoint", {
            "id": function_bp["id"],
        }).get("success"), function_bp
        assert client.tool("veh_remove_breakpoint", {"id": bp["id"]}).get("success"), bp

        batch_function_bp = client.tool("veh_set_function_breakpoint", {
            "name": "TraceFunctionScopeTarget",
        })
        assert batch_function_bp.get("success"), batch_function_bp
        function_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(function_start),
                "end": hex(function_start + 0x100), "stop_on_return": True,
                "max_steps": 20000, "timeout_ms": 10000,
            }},
        ]}, timeout=25)
        batch_function_trace = function_batch["results"][1]["result"]
        assert batch_function_trace.get("stop_reason") == "function_return", function_batch
        assert batch_function_trace["function_scope"]["returned"] is True, function_batch
        assert client.tool("veh_remove_breakpoint", {
            "id": batch_function_bp["id"],
        }).get("success"), batch_function_bp

        function_action_output = output_path("function-scope-action", "json")
        function_action_bp = client.tool("veh_set_breakpoint", {
            "address": hex(function_start), "action": [
                {"tool": "veh_trace_basic_blocks", "args": {
                    "threadId": thread_id, "start": hex(function_start),
                    "end": hex(function_start + 0x100), "stop_on_return": True,
                    "max_steps": 20000, "timeout_ms": 10000,
                    "output_file": function_action_output,
                }},
                {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
            ],
        })
        assert function_action_bp.get("success") and function_action_bp.get("hasAction"), function_action_bp
        function_action_stop = client.tool("veh_continue", {
            "wait": True, "timeout": 15,
        }, timeout=20)
        assert function_action_stop.get("reason") == "breakpoint", function_action_stop
        assert function_action_stop.get("breakpointId") != function_action_bp["id"], function_action_stop
        with open(function_action_output, encoding="utf-8") as action_file:
            function_action_trace = json.load(action_file)
        assert function_action_trace.get("stop_reason") == "function_return", function_action_trace
        assert function_action_trace["function_scope"]["returned"] is True, function_action_trace
        assert client.tool("veh_remove_breakpoint", {
            "id": function_action_stop["breakpointId"],
        }).get("success"), function_action_stop
        assert client.tool("veh_remove_breakpoint", {
            "id": function_action_bp["id"],
        }).get("success"), function_action_bp
        bp = client.tool("veh_set_breakpoint", {"address": hex(start)})
        assert bp.get("success"), bp

        # Batch dispatch must use the same implementation and result shape as a
        # direct call. The continue result also verifies $N.threadId expansion.
        batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_blocks": 4096, "max_edges": 8192, "max_steps": 1000,
                "timeout_ms": 5000, "stack_bytes": 32,
                "collect_memory_writes": True, "max_memory_writes": 64,
                "collect_memory_events": True, "max_memory_events": 256,
                "collect_register_events": True, "max_register_events": 256,
                "collect_events": True, "max_events": 256,
                "collect_code": True, "max_code_bytes": 400 * 1024 * 1024,
                "max_code_versions": 256,
                "code_output": "file",
                "code_chunk_bytes": 256 * 1024,
            }},
        ]}, timeout=20)
        assert batch.get("totalSteps") == 2, batch
        batch_stop = batch["results"][0]["result"]
        assert batch_stop.get("reason") == "breakpoint", batch_stop
        batch_trace = batch["results"][1]["result"]
        assert "error" not in batch_trace, batch_trace
        assert set(batch_trace) == set(trace), (batch_trace, trace)
        assert batch_trace["register_order"] == trace["register_order"], batch_trace
        assert len(batch_trace["blocks"]) >= 2, batch_trace
        assert len(batch_trace["edges"]) >= 1, batch_trace
        assert batch_trace["ordering"]["available"] is True, batch_trace
        assert batch_trace["code_capture"]["available"] is True, batch_trace
        assert batch_trace["code_capture"]["storage"] == "file" and not batch_trace["code_versions"], batch_trace
        batch_artifact_path = batch_trace["code_capture"]["path"]
        artifact_paths.append(batch_artifact_path)
        batch_artifact = read_code_artifact(batch_artifact_path)
        assert batch_artifact["versions"] == batch_trace["code_capture"]["versions_captured"], batch_trace
        assert batch_artifact["sha256"] == batch_trace["code_capture"]["sha256"], batch_trace
        assert all(event["thread_id"] == batch_stop["threadId"]
                   for event in batch_trace["events"]), batch_trace
        assert all(event["thread_id"] == batch_stop["threadId"]
                   for event in batch_trace["memory_events"]), batch_trace
        assert all(event["thread_id"] == batch_stop["threadId"]
                   for event in batch_trace["register_events"]), batch_trace

        truncated_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                "collect_memory_writes": True, "max_memory_writes": 1,
                "collect_memory_reads": True, "max_memory_reads": 1,
                "collect_memory_events": True, "max_memory_events": 1,
                "collect_register_events": True, "max_register_events": 1,
                "max_events": 1,
            }},
        ]}, timeout=20)
        truncated_writes = truncated_batch["results"][1]["result"]
        assert len(truncated_writes["memory_writes"]) == 1, truncated_writes
        assert truncated_writes["memory_writes_truncated"] is True, truncated_writes
        assert len(truncated_writes["memory_reads"]) == 1, truncated_writes
        assert truncated_writes["memory_reads_truncated"] is True, truncated_writes
        assert len(truncated_writes["events"]) == 1, truncated_writes
        assert truncated_writes["events_truncated"] is True, truncated_writes
        assert truncated_writes["events_dropped"] > 0, truncated_writes
        assert truncated_writes["ordering"]["complete"] is False, truncated_writes
        assert truncated_writes["ordering"]["events_dropped"] == \
            truncated_writes["events_dropped"], truncated_writes
        assert len(truncated_writes["memory_events"]) == 1, truncated_writes
        assert truncated_writes["memory_events_truncated"] is True, truncated_writes
        assert truncated_writes["memory_events_dropped"] > 0, truncated_writes
        assert truncated_writes["memory_ordering"]["complete"] is False, truncated_writes
        assert truncated_writes["memory_ordering"]["events_dropped"] == \
            truncated_writes["memory_events_dropped"], truncated_writes
        assert len(truncated_writes["register_events"]) == 1, truncated_writes
        assert truncated_writes["register_events_truncated"] is True, truncated_writes
        assert truncated_writes["register_events_dropped"] > 0, truncated_writes
        assert truncated_writes["register_ordering"]["complete"] is False, truncated_writes
        assert truncated_writes["register_ordering"]["events_dropped"] == \
            truncated_writes["register_events_dropped"], truncated_writes

        conditional_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                "start_condition": f"rip != {hex(start)}",
                "stop_condition": "[rsp] != 0",
            }},
        ]}, timeout=20)
        conditional = conditional_batch["results"][1]["result"]
        assert conditional["stop_reason"] == "condition", conditional
        assert conditional["start_condition_met"] is True and conditional["filtered_steps"] >= 1, conditional

        filtered_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                "collect_condition": f"rip == {hex(start)}",
            }},
        ]}, timeout=20)
        filtered = filtered_batch["results"][1]["result"]
        assert filtered["filtered_steps"] > 0 and filtered["blocks"], filtered

        invalid_condition = client.tool("veh_trace_basic_blocks", {
            "threadId": filtered_batch["results"][0]["result"]["threadId"],
            "start": hex(start), "end": hex(start + 0x100),
            "stop_condition": "rax == 1 || rbx == 2 && rcx == 3",
        })
        assert "cannot mix" in invalid_condition.get("error", ""), invalid_condition

        # The independent instruction limit must stop and park the thread without
        # waiting for range exit.
        limited_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 3, "timeout_ms": 5000, "stack_bytes": 0,
            }},
        ]}, timeout=20)
        assert limited_batch.get("totalSteps") == 2, limited_batch
        limited = limited_batch["results"][1]["result"]
        assert limited.get("stop_reason") == "max_steps", limited
        assert limited.get("truncated") is True, limited

        # Breakpoint actions use BatchExecutor too. The trace action installs a
        # sentinel breakpoint at its returned final_address; hitting that new
        # breakpoint proves the trace completed and its result was referenceable.
        action_artifact_path = artifact_path("action")
        action_output_path = output_path("action", "jsonl")
        action_bp = client.tool("veh_set_breakpoint", {
            "address": hex(start),
            "action": [
                {"tool": "veh_trace_basic_blocks", "args": {
                    "threadId": thread_id, "start": hex(start), "end": hex(start + 0x100),
                    "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                    "collect_memory_events": True, "max_memory_events": 256,
                    "collect_register_events": True, "max_register_events": 256,
                    "collect_events": True, "max_events": 256,
                    "collect_code": True, "max_code_bytes": 400 * 1024 * 1024,
                    "max_code_versions": 256,
                    "code_output": "file", "code_output_path": action_artifact_path,
                    "code_chunk_bytes": 256 * 1024,
                    "output_file": action_output_path, "output_format": "jsonl",
                }},
                {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
            ],
        })
        assert action_bp.get("success") and action_bp.get("hasAction"), action_bp
        action_stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert action_stop.get("reason") == "breakpoint", action_stop
        assert action_stop.get("breakpointId") != action_bp["id"], action_stop
        action_artifact = read_code_artifact(action_artifact_path)
        assert action_artifact["versions"] > 0 and action_artifact["flags"] & 1, action_artifact
        action_lines = [json.loads(line) for line in open(action_output_path, encoding="utf-8")]
        assert action_lines[0]["record"] == "manifest", action_lines[0]
        action_hash = hashlib.sha256(open(action_output_path, "rb").read()).hexdigest()
        validated_action = validate_output(action_output_path, action_hash)
        assert validated_action["counts"]["code_versions"] == 0, validated_action
        assert client.tool("veh_remove_breakpoint", {
            "id": action_stop["breakpointId"],
        }).get("success"), action_stop
        restored_bp = client.tool("veh_set_breakpoint", {"address": hex(start), "action": []})
        assert restored_bp.get("success"), restored_bp

        # An indirect call site must be identified from its decoded operand and
        # grouped by the destinations actually observed at runtime.
        indirect_bp = client.tool("veh_set_function_breakpoint", {"name": "TraceIndirectCoverageTarget"})
        assert indirect_bp.get("success") and indirect_bp.get("address"), indirect_bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        indirect_start = int(indirect_bp["address"], 0)
        indirect_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": stop["threadId"], "start": hex(indirect_start),
            "end": hex(indirect_start + 0x200), "max_steps": 1000,
            "timeout_ms": 5000, "stack_bytes": 0,
        }, timeout=15)
        assert indirect_trace.get("indirect_branches"), indirect_trace
        profile = indirect_trace["indirect_branches"][0]
        assert profile["total_hits"] >= 1 and profile["unique_targets"] >= 1, profile
        assert all(target["hits"] >= 1 for target in profile["targets"]), profile

        executable_bp = client.tool("veh_set_function_breakpoint", {"name": "TraceExecutableWriteTarget"})
        assert executable_bp.get("success") and executable_bp.get("address"), executable_bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        executable_start = int(executable_bp["address"], 0)
        executable_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": stop["threadId"], "start": hex(executable_start),
            "end": hex(executable_start + 0x100), "max_steps": 100,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_memory_writes": True, "max_memory_writes": 16,
        }, timeout=15)
        assert executable_trace["executable_writes"], executable_trace
        assert any(write.get("executed_after_write") for write in executable_trace["executable_writes"]), executable_trace
        assert all(write["region"]["protection"].startswith("rwx")
                   for write in executable_trace["executable_writes"]), executable_trace

        checkpoint_thread = stop["threadId"]
        scratch = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rw"})
        assert scratch.get("success"), scratch
        scratch_address = scratch["address"]
        assert client.tool("veh_write_memory", {"address": scratch_address, "data": "AA " * 16}).get("success")
        reg_name = "eax" if "esp" in regs else "rax"
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": reg_name, "value": "0x1111",
        }).get("success")
        checkpoint_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_checkpoint_create", "args": {
                "threadId": checkpoint_thread,
                "regions": [{"address": scratch_address, "size": 16}],
                "capture_teb": True, "teb_size": 256,
            }},
            {"tool": "veh_set_register", "args": {
                "threadId": checkpoint_thread, "name": reg_name, "value": "0x2222",
            }},
            {"tool": "veh_write_memory", "args": {"address": scratch_address, "data": "BB " * 16}},
            {"tool": "veh_checkpoint_diff", "args": {"id": "$0.id"}},
            {"tool": "veh_checkpoint_restore", "args": {"id": "$0.id"}},
            {"tool": "veh_checkpoint_delete", "args": {"id": "$0.id"}},
        ]}, timeout=20)
        assert checkpoint_batch.get("totalSteps") == 6, checkpoint_batch
        checkpoint_created = checkpoint_batch["results"][0]["result"]
        assert checkpoint_created["teb_captured"] is True, checkpoint_created
        assert int(checkpoint_created["thread_environment"]["teb"], 0) != 0, checkpoint_created
        segment_name = "fs" if "esp" in regs else "gs"
        assert int(checkpoint_created["thread_environment"][segment_name]["base"], 0) != 0, checkpoint_created
        assert checkpoint_created["memory_bytes"] == 272, checkpoint_created
        checkpoint_diff = checkpoint_batch["results"][3]["result"]
        assert reg_name in checkpoint_diff["register_delta"], checkpoint_diff
        assert checkpoint_diff["memory_changes"], checkpoint_diff
        assert checkpoint_batch["results"][4]["result"].get("restored") is True, checkpoint_batch
        assert checkpoint_batch["results"][5]["result"].get("deleted") is True, checkpoint_batch
        restored_memory = client.tool("veh_read_memory", {"address": scratch_address, "size": 16})
        assert restored_memory["hex"].replace(" ", "").lower() == "aa" * 16, restored_memory
        restored_regs = client.tool("veh_registers", {"threadId": checkpoint_thread})["registers"]
        assert int(restored_regs[reg_name], 0) == 0x1111, restored_regs

        input_batch = client.tool("veh_batch", {
            "stop_on_error": True,
            "inputs": [
                {"name": "valid", "register": reg_name, "value": "0x3333"},
                {"name": "invalid", "register": "not_a_register", "value": "0x4444"},
                {"name": "not_run", "register": reg_name, "value": "0x5555"},
            ],
            "steps": [{"tool": "veh_set_register", "args": {
                "threadId": checkpoint_thread, "name": "$input.register", "value": "$input.value",
            }}],
        })
        assert input_batch["succeeded"] == 1 and input_batch["failed"] == 1, input_batch
        assert input_batch["first_failed_input"] == 1 and len(input_batch["inputs"]) == 2, input_batch
        assert input_batch["inputs"][1]["first_failed_step"] == 0, input_batch
        bad_input_variable = client.tool("veh_batch", {
            "steps": [{"tool": "veh_registers", "args": {"threadId": checkpoint_thread}}],
            "inputs": [1], "input_variable": 7,
        })
        assert bad_input_variable == {"error": "input_variable must be a string"}, bad_input_variable
        nested_stop = client.tool("veh_batch", {
            "stop_on_error": True,
            "steps": [{"for_each": [
                {"register": reg_name, "value": "0x3333"},
                {"register": "not_a_register", "value": "0x4444"},
                {"register": reg_name, "value": "0x5555"},
            ], "as": "$case", "do": [{"tool": "veh_set_register", "args": {
                "threadId": checkpoint_thread, "name": "$case.register", "value": "$case.value",
            }}]}],
        })
        nested_result = nested_stop["results"][0]["result"]
        assert nested_stop["failed"] == 1 and nested_result["count"] == 2, nested_stop
        assert len(nested_result["results"]) == 2, nested_stop
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": reg_name, "value": "0x1111",
        }).get("success")

        stale_mapping = client.tool("veh_checkpoint_create", {
            "threadId": checkpoint_thread,
            "regions": [{"address": scratch_address, "size": 16}],
        })
        assert stale_mapping.get("id"), stale_mapping
        assert client.tool("veh_free_memory", {"address": scratch_address}).get("success")
        refused = client.tool("veh_checkpoint_restore", {"id": stale_mapping["id"]})
        assert "mapping changed" in refused.get("error", ""), refused
        assert client.tool("veh_checkpoint_delete", {"id": stale_mapping["id"]}).get("deleted") is True
        orphaned_checkpoint = client.tool("veh_checkpoint_create", {"threadId": checkpoint_thread})
        assert orphaned_checkpoint.get("id"), orphaned_checkpoint

        # PUSH writes at post-decrement SP, while POP reads from the current SP.
        # Verify both architectures report the same concrete slot and value.
        saved = client.tool("veh_registers", {"threadId": checkpoint_thread})["registers"]
        is_32bit = "eip" in saved
        ip_name = "eip" if is_32bit else "rip"
        sp_name = "esp" if is_32bit else "rsp"
        accumulator_name = "eax" if is_32bit else "rax"
        pointer_size = 4 if is_32bit else 8
        pushed_value = 0x11223344 if is_32bit else 0x1122334455667788
        expected_stack_address = int(saved[sp_name], 0) - pointer_size
        original_stack_slot = client.tool("veh_read_memory", {
            "address": hex(expected_stack_address), "size": pointer_size,
        })["hex"]
        sentinel_before = bytes([0xA5] * pointer_size).hex(" ")
        assert client.tool("veh_write_memory", {
            "address": hex(expected_stack_address), "data": sentinel_before,
        }).get("success")
        stack_code = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert stack_code.get("success"), stack_code
        stack_start = int(stack_code["address"], 0)
        resume_address = int(saved[ip_name], 0)
        if is_32bit:
            code = (bytes.fromhex("50 58 FF 25") + (stack_start + 8).to_bytes(4, "little") +
                    resume_address.to_bytes(4, "little"))
        else:
            code = bytes.fromhex("50 58 FF 25 00 00 00 00") + resume_address.to_bytes(8, "little")
        assert client.tool("veh_write_memory", {
            "address": hex(stack_start), "data": code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": accumulator_name, "value": hex(pushed_value),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(stack_start),
        }).get("success")
        stack_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(stack_start),
            "end": hex(stack_start + len(code)), "max_steps": 8,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_memory_writes": True, "max_memory_writes": 8,
            "collect_memory_reads": True, "max_memory_reads": 8,
            "collect_memory_events": True, "max_memory_events": 8,
            "collect_register_events": True, "max_register_events": 8,
            "dependency_sources": [accumulator_name],
        }, timeout=15)
        assert stack_trace.get("stop_reason") == "left_range", stack_trace
        push_event = next(event for event in stack_trace["memory_events"]
                          if event["kind"] == "write" and
                          int(event["instruction"], 0) == stack_start)
        pop_event = next(event for event in stack_trace["memory_events"]
                         if event["kind"] == "read" and
                         int(event["instruction"], 0) == stack_start + 1)
        expected_value = pushed_value.to_bytes(pointer_size, "little").hex(" ")
        assert push_event["sequence"] == 1 and pop_event["sequence"] == 2, stack_trace
        assert int(push_event["address"], 0) == expected_stack_address, stack_trace
        assert push_event["before"] == sentinel_before, stack_trace
        assert push_event["after"] == expected_value, stack_trace
        assert int(pop_event["address"], 0) == expected_stack_address, stack_trace
        assert pop_event["value"] == expected_value, stack_trace
        assert push_event.get("dependencies") == [accumulator_name], stack_trace
        assert pop_event.get("dependencies") == [accumulator_name], stack_trace
        push_register = next(event for event in stack_trace["register_events"]
                             if event["sequence"] == 1)
        pop_register = next(event for event in stack_trace["register_events"]
                            if event["sequence"] == 2)
        assert int(push_register["changes"][sp_name]["before"], 0) == int(saved[sp_name], 0), stack_trace
        assert int(push_register["changes"][sp_name]["after"], 0) == expected_stack_address, stack_trace
        assert int(pop_register["changes"][sp_name]["before"], 0) == expected_stack_address, stack_trace
        assert int(pop_register["changes"][sp_name]["after"], 0) == int(saved[sp_name], 0), stack_trace
        aggregate_push = next(item for item in stack_trace["memory_writes"]
                              if int(item["instruction"], 0) == stack_start)
        assert aggregate_push["address"] == push_event["address"], stack_trace
        assert aggregate_push["before"] == push_event["before"], stack_trace
        assert aggregate_push["after"] == push_event["after"], stack_trace
        assert client.tool("veh_write_memory", {
            "address": hex(expected_stack_address), "data": original_stack_slot,
        }).get("success")
        assert client.tool("veh_free_memory", {"address": hex(stack_start)}).get("success")

        # LEA's source is a Zydis memory-form operand even though the
        # instruction reads no memory. Its base/index origins must reach the
        # largest enclosing destination register; writing EAX defines RAX via
        # architectural zero-extension. Run this immediately before terminating
        # the target so the synthetic register state cannot affect other cases.
        lea_code = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert lea_code.get("success"), lea_code
        lea_start = int(lea_code["address"], 0)
        resume_address = int(saved[ip_name], 0)
        if is_32bit:
            code = (bytes.fromhex("81 F1 78 56 34 12 8D 04 0A BB") +
                    resume_address.to_bytes(4, "little") + bytes.fromhex("FF E3"))
        else:
            code = (bytes.fromhex("81 F1 78 56 34 12 8D 04 0A 49 BB") +
                    resume_address.to_bytes(8, "little") + bytes.fromhex("41 FF E3"))
        assert client.tool("veh_write_memory", {
            "address": hex(lea_start), "data": code.hex(" "),
        }).get("success")
        rcx_name, rdx_name = (("ecx", "edx") if is_32bit else ("rcx", "rdx"))
        for name, value in ((rcx_name, "0x11111111"), (rdx_name, "0x22222222"),
                            (ip_name, hex(lea_start))):
            assert client.tool("veh_set_register", {
                "threadId": checkpoint_thread, "name": name, "value": value,
            }).get("success")
        lea_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(lea_start),
            "end": hex(lea_start + len(code)), "max_steps": 16,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_memory_reads": True, "max_memory_reads": 16,
            "collect_register_events": True, "max_register_events": 16,
            "dependency_sources": [rcx_name, rdx_name],
        }, timeout=15)
        assert lea_trace.get("stop_reason") == "left_range", lea_trace
        destination_name = "eax" if is_32bit else "rax"
        assert set(lea_trace["final_dependencies"].get(destination_name, [])) == \
            {rcx_name, rdx_name}, lea_trace
        assert lea_trace["memory_reads"] == [], lea_trace
        xor_event = next(event for event in lea_trace["register_events"]
                         if int(event["instruction"], 0) == lea_start)
        lea_event = next(event for event in lea_trace["register_events"]
                         if int(event["instruction"], 0) == lea_start + 6)
        xor_after = 0x11111111 ^ 0x12345678
        assert xor_event["sequence"] == 1, lea_trace
        assert int(xor_event["changes"][rcx_name]["before"], 0) == 0x11111111, lea_trace
        assert int(xor_event["changes"][rcx_name]["after"], 0) == xor_after, lea_trace
        assert lea_event["sequence"] == 2, lea_trace
        assert int(lea_event["changes"][destination_name]["after"], 0) == \
            ((xor_after + 0x22222222) & 0xFFFFFFFF), lea_trace
        assert client.tool("veh_free_memory", {"address": hex(lea_start)}).get("success")

        # Multi-byte NOP has a decorative memory-form operand but performs no
        # address calculation or memory read, even when the named register is
        # null. It must not inflate unsupported-memory diagnostics.
        nop_code = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert nop_code.get("success"), nop_code
        nop_start = int(nop_code["address"], 0)
        if is_32bit:
            code = (bytes.fromhex("31 C0 0F 1F 00 BB") +
                    resume_address.to_bytes(4, "little") + bytes.fromhex("FF E3"))
        else:
            code = (bytes.fromhex("31 C0 0F 1F 00 49 BB") +
                    resume_address.to_bytes(8, "little") + bytes.fromhex("41 FF E3"))
        assert client.tool("veh_write_memory", {
            "address": hex(nop_start), "data": code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(nop_start),
        }).get("success")
        nop_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(nop_start),
            "end": hex(nop_start + len(code)), "max_steps": 8,
            "timeout_ms": 5000, "collect_memory_reads": True,
            "max_memory_reads": 8, "collect_memory_events": True,
            "max_memory_events": 8,
        }, timeout=15)
        assert nop_trace.get("unsupported_memory_reads") == 0, nop_trace
        assert nop_trace["memory_reads"] == [] and nop_trace["memory_events"] == [], nop_trace
        assert client.tool("veh_free_memory", {"address": hex(nop_start)}).get("success")

        # A loop that rewrites its own XOR immediate produces two runtime byte
        # versions of the same block. Ordered edge occurrences must identify
        # which retained version was entered at each trace sequence.
        smc = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert smc.get("success"), smc
        smc_start = int(smc["address"], 0)
        smc_code = (bytes.fromhex("80 35") +
                    ((smc_start + 6).to_bytes(4, "little") if is_32bit else bytes.fromhex("FF FF FF FF")) +
                    bytes.fromhex("01 EB F7"))
        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        oversized_code = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "max_code_bytes": 16 * 1024 * 1024 + 1,
        })
        assert oversized_code == {
            "error": "max_code_bytes must be 1-16777216 for code_output=inline",
        }, oversized_code
        smc_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 4,
            "timeout_ms": 5000, "stack_bytes": 0,
            # Exercise the enlarged opt-in budget without producing a large
            # response; only actually captured bytes are returned over IPC.
            "collect_code": True, "max_code_bytes": 16 * 1024 * 1024,
            "max_code_versions": 8, "max_events": 16,
        }, timeout=15)
        assert smc_trace.get("stop_reason") == "max_steps", smc_trace
        assert smc_trace["ordering"]["event_schema_version"] == 2, smc_trace
        assert smc_trace["code_capture"] == {
            "available": True, "schema_version": 1, "complete": True,
            "bytes_captured": 18, "versions_captured": 2,
        }, smc_trace
        versions = smc_trace["code_versions"]
        assert len(versions) == 2 and versions[0]["block"] == versions[1]["block"], smc_trace
        assert versions[0]["hash"] != versions[1]["hash"], smc_trace
        occurrences = [(event["sequence"], event.get("code_version"))
                       for event in smc_trace["events"]]
        assert occurrences == [(0, 0), (2, 1), (4, 1)], smc_trace

        # A self-modified direct branch can enter the middle of a statically
        # decoded block. The aggregate CFG retains that synthetic block start,
        # but code completeness must cover the concrete executed destination
        # rather than spending its budget on the unexecuted prefix.
        mid_entry = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert mid_entry.get("success"), mid_entry
        mid_start = int(mid_entry["address"], 0)
        mid_target_offset = 270
        static_target_offset = 280
        new_relative = mid_target_offset - 15
        old_relative = static_target_offset - 15
        if is_32bit:
            patch_branch = (bytes.fromhex("c7 05") +
                            (mid_start + 11).to_bytes(4, "little") +
                            new_relative.to_bytes(4, "little"))
        else:
            patch_branch = (bytes.fromhex("c7 05 01 00 00 00") +
                            new_relative.to_bytes(4, "little"))
        mid_code = (patch_branch + bytes.fromhex("e9") +
                    old_relative.to_bytes(4, "little") +
                    b"\x90" * (static_target_offset - 15) + bytes.fromhex("eb fe"))
        assert len(mid_code) == static_target_offset + 2, len(mid_code)

        def run_mid_entry_trace(**extra):
            assert client.tool("veh_write_memory", {
                "address": hex(mid_start), "data": mid_code.hex(" "),
            }).get("success")
            assert client.tool("veh_set_register", {
                "threadId": checkpoint_thread, "name": ip_name, "value": hex(mid_start),
            }).get("success")
            args = {
                "threadId": checkpoint_thread, "start": hex(mid_start),
                "end": hex(mid_start + len(mid_code)), "max_steps": 14,
                "timeout_ms": 5000, "stack_bytes": 0, "collect_code": True,
                "max_code_bytes": 32, "max_code_versions": 8, "max_events": 32,
            }
            args.update(extra)
            return client.tool("veh_trace_basic_blocks", args, timeout=15)

        mid_trace = run_mid_entry_trace()
        assert mid_trace["code_truncated"] is False, mid_trace
        assert mid_trace["code_capture"]["complete"] is True, mid_trace
        assert any(block["hits"] == 0 for block in mid_trace["blocks"]), mid_trace
        mid_edge = next(event for event in mid_trace["events"]
                        if int(event.get("source_instruction", "0"), 0) == mid_start + 10)
        mid_version = next(version for version in mid_trace["code_versions"]
                           if version["id"] == mid_edge["code_version"])
        assert int(mid_edge["target"], 0) == mid_start + 15, mid_trace
        assert int(mid_version["block"], 0) == mid_start + mid_target_offset, mid_trace

        mid_artifact_path = artifact_path("mid-entry")
        mid_file_trace = run_mid_entry_trace(
            code_output="file", code_output_path=mid_artifact_path,
            code_chunk_bytes=256 * 1024)
        assert mid_file_trace["code_truncated"] is False, mid_file_trace
        assert mid_file_trace["code_capture"]["complete"] is True, mid_file_trace
        mid_artifact = read_code_artifact(mid_artifact_path)
        assert any(record["block"] == mid_start + mid_target_offset
                   for record in mid_artifact["records"]), mid_artifact

        # Exercise a multi-megabyte control response like generated opcode VMs:
        # 20k ordered register records, 20k read/write memory records, 10k edge
        # events, and code versions must survive the control-pipe transfer.
        stress = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert stress.get("success"), stress
        stress_start = int(stress["address"], 0)
        counter_address = stress_start + 16
        if is_32bit:
            stress_instruction = bytes.fromhex("ff 05") + counter_address.to_bytes(4, "little")
        else:
            stress_instruction = bytes.fromhex("ff 05 0a 00 00 00")
        stress_code = stress_instruction + bytes.fromhex("eb f8") + b"\x90" * 8 + b"\0" * 4
        assert client.tool("veh_write_memory", {
            "address": hex(stress_start), "data": stress_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(stress_start),
        }).get("success")
        stress_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(stress_start),
            "end": hex(stress_start + 8), "max_steps": 20000,
            "timeout_ms": 60000, "stack_bytes": 0,
            "collect_events": True, "max_events": 20000,
            "collect_memory_events": True, "max_memory_events": 20000,
            "collect_register_events": True, "max_register_events": 20000,
            "collect_code": True, "max_code_bytes": 1024, "max_code_versions": 8,
        }, timeout=80)
        assert stress_trace.get("steps_executed") == 20000, stress_trace
        assert len(stress_trace["register_events"]) == 20000, stress_trace
        assert stress_trace["register_events_dropped"] == 0, stress_trace
        assert len(stress_trace["memory_events"]) == 20000, stress_trace
        assert stress_trace["memory_events_dropped"] == 0, stress_trace
        assert stress_trace["code_capture"]["complete"] is True, stress_trace

        # Dispatcher occurrence windows are entry-to-entry and AND-compose with
        # the existing start/collect conditions. The fourth visit closes [2,3]
        # before its instruction executes, so only two loop cycles are exported.
        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        occurrence_output_path = output_path("occurrence", "json")
        occurrence_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 20,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_events": True, "max_events": 32,
            "collect_memory_events": True, "max_memory_events": 32,
            "collect_register_events": True, "max_register_events": 32,
            "collect_code": True, "max_code_bytes": 1024, "max_code_versions": 8,
            "occurrence_window": {"address": hex(smc_start), "from": 2, "to": 3},
            "output_file": occurrence_output_path, "output_format": "json",
        }, timeout=15)
        assert occurrence_trace["mode"] == "file", occurrence_trace
        assert occurrence_trace["stop_reason"] == "occurrence_window", occurrence_trace
        assert occurrence_trace["occurrence_window"]["hits"] == 4, occurrence_trace
        assert occurrence_trace["occurrence_window"]["started"] is True, occurrence_trace
        assert occurrence_trace["occurrence_window"]["completed"] is True, occurrence_trace
        occurrence_document = json.load(open(occurrence_output_path, encoding="utf-8"))
        assert occurrence_document["stop_reason"] == "occurrence_window", occurrence_document
        assert occurrence_trace["counts"]["register_events"] == len(occurrence_document["register_events"]), occurrence_trace
        assert occurrence_trace["output_file"]["sha256"] == hashlib.sha256(
            open(occurrence_output_path, "rb").read()).hexdigest(), occurrence_trace
        validated_occurrence = validate_output(
            occurrence_output_path, occurrence_trace["output_file"]["sha256"])
        assert validated_occurrence["counts"]["register_events"] == \
            occurrence_trace["counts"]["register_events"], validated_occurrence

        bad_occurrence = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)),
            "occurrence_window": {"address": hex(smc_start), "from": 3, "to": 2},
        })
        assert "from >= 1" in bad_occurrence.get("error", ""), bad_occurrence
        negative_occurrence = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)),
            "occurrence_window": {"address": hex(smc_start), "from": -1},
        })
        assert "unsigned 32-bit" in negative_occurrence.get("error", ""), negative_occurrence
        bad_output_type = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "output_file": 7,
        })
        assert bad_output_type == {"error": "output_file must be a string"}, bad_output_type

        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        batch_output_path = output_path("batch", "json")
        exported_batch = client.tool("veh_batch", {"stop_on_error": True, "steps": [
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": checkpoint_thread, "start": hex(smc_start),
                "end": hex(smc_start + len(smc_code)), "max_steps": 2,
                "timeout_ms": 5000, "output_file": batch_output_path,
            }},
        ]}, timeout=15)
        assert exported_batch["succeeded"] == 1 and exported_batch["failed"] == 0, exported_batch
        assert exported_batch["results"][0]["status"] == "ok", exported_batch
        assert exported_batch["artifacts"][0]["path"] == os.path.abspath(batch_output_path), exported_batch

        # File mode streams portable version records over a private data pipe;
        # the control response retains event/version IDs but no inline byte blob.
        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        direct_artifact_path = artifact_path("direct-smc")
        file_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 4,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_code": True, "max_code_bytes": 400 * 1024 * 1024,
            "max_code_versions": 8, "max_events": 16,
            "code_output": "file", "code_output_path": direct_artifact_path,
            "code_chunk_bytes": 8 * 1024 * 1024,
        }, timeout=15)
        assert file_trace.get("stop_reason") == "max_steps", file_trace
        assert file_trace["code_versions"] == [] and file_trace["code_truncated"] is False, file_trace
        direct_capture = file_trace["code_capture"]
        assert direct_capture["storage"] == "file" and direct_capture["complete"] is True, file_trace
        assert direct_capture["chunk_bytes"] == 8 * 1024 * 1024, file_trace
        direct_artifact = read_code_artifact(direct_artifact_path)
        assert direct_artifact["versions"] == 2 and direct_artifact["code_bytes"] == 18, direct_artifact
        assert [record["bytes"] for record in direct_artifact["records"]] == [
            bytes.fromhex(version["bytes"]) for version in versions
        ], direct_artifact
        assert direct_capture["sha256"] == direct_artifact["sha256"], file_trace
        assert [(event["sequence"], event.get("code_version"))
                for event in file_trace["events"]] == occurrences, file_trace

        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        limited_code = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 1,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_code": True, "max_code_bytes": 1,
            "max_code_versions": 1, "max_events": 4,
        }, timeout=15)
        assert limited_code["code_truncated"] is True, limited_code
        assert limited_code["code_capture"]["complete"] is False, limited_code

        assert client.tool("veh_write_memory", {
            "address": hex(smc_start), "data": smc_code.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(smc_start),
        }).get("success")
        limited_artifact_path = artifact_path("limited")
        limited_file = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 1,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_code": True, "max_code_bytes": 1,
            "max_code_versions": 1, "max_events": 4,
            "code_output": "file", "code_output_path": limited_artifact_path,
            "code_chunk_bytes": 256 * 1024,
        }, timeout=15)
        assert limited_file["code_truncated"] is True, limited_file
        assert limited_file["code_capture"]["complete"] is False, limited_file
        limited_artifact = read_code_artifact(limited_artifact_path)
        assert limited_artifact["flags"] == 3 and limited_artifact["versions"] == 0, limited_artifact
        assert limited_artifact["code_bytes"] == 0 and limited_artifact["chunks"] == 0, limited_artifact

        bad_file_limit = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "code_output": "file", "max_code_bytes": 400 * 1024 * 1024 + 1,
        })
        assert bad_file_limit == {
            "error": "max_code_bytes must be 1-419430400 for code_output=file",
        }, bad_file_limit
        bad_chunk = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "code_output": "file", "code_chunk_bytes": 256 * 1024 - 64 * 1024,
        })
        assert bad_chunk == {
            "error": "code_chunk_bytes must be 262144-8388608 and a multiple of 65536",
        }, bad_chunk
        bad_large_chunk = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "code_output": "file", "code_chunk_bytes": 8 * 1024 * 1024 + 64 * 1024,
        })
        assert bad_large_chunk == bad_chunk, bad_large_chunk
        bad_unaligned_chunk = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "code_output": "file", "code_chunk_bytes": 256 * 1024 + 1,
        })
        assert bad_unaligned_chunk == bad_chunk, bad_unaligned_chunk
        existing_artifact_path = artifact_path("existing")
        with open(existing_artifact_path, "wb") as existing_artifact:
            existing_artifact.write(b"do-not-overwrite")
        existing_output = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "collect_code": True,
            "code_output": "file", "code_output_path": existing_artifact_path,
        })
        assert existing_output == {"error": "code output file already exists"}, existing_output
        assert open(existing_artifact_path, "rb").read() == b"do-not-overwrite"
        existing_trace_path = output_path("existing-trace", "json")
        with open(existing_trace_path, "wb") as existing_trace:
            existing_trace.write(b"do-not-overwrite")
        existing_trace_output = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "output_file": existing_trace_path,
        })
        assert existing_trace_output == {"error": "output_file already exists"}, existing_trace_output
        assert open(existing_trace_path, "rb").read() == b"do-not-overwrite"

        # One large static block crosses a 256 KiB transport boundary even
        # though only its first instruction executes. This exercises framing,
        # offsets, the final short chunk, and artifact reconstruction cheaply.
        large_size = 1024 * 1024
        large = client.tool("veh_allocate_memory", {"size": large_size, "protection": "rwx"})
        assert large.get("success"), large
        large_start = int(large["address"], 0)
        long_nop = bytes.fromhex("66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00")
        large_body = (long_nop * ((large_size - 1) // len(long_nop)) +
                      b"\x90" * ((large_size - 1) % len(long_nop)))
        large_code = large_body + b"\xc3"
        assert client.tool("veh_write_memory", {
            "address": hex(large_start), "data": large_code.hex(" "),
        }, timeout=20).get("success")
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": hex(large_start),
        }).get("success")
        multi_artifact_path = artifact_path("multi-chunk")
        multi_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(large_start),
            "end": hex(large_start + large_size), "max_steps": 1,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_code": True, "max_code_bytes": 400 * 1024 * 1024,
            "max_code_versions": 4, "max_events": 4,
            "code_output": "file", "code_output_path": multi_artifact_path,
            "code_chunk_bytes": 256 * 1024,
        }, timeout=30)
        assert multi_trace.get("stop_reason") == "max_steps", multi_trace
        multi_artifact = read_code_artifact(multi_artifact_path)
        assert multi_artifact["versions"] == 1 and multi_artifact["chunks"] == 5, multi_artifact
        assert multi_artifact["code_bytes"] == large_size, multi_artifact
        assert multi_artifact["records"][0]["bytes"] == large_code, multi_artifact
        assert multi_trace["code_capture"]["chunk_count"] == 5, multi_trace
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": saved[ip_name],
        }).get("success")
        assert client.tool("veh_free_memory", {"address": hex(smc_start)}).get("success")
        assert client.tool("veh_free_memory", {"address": hex(mid_start)}).get("success")
        assert client.tool("veh_free_memory", {"address": hex(stress_start)}).get("success")
        assert client.tool("veh_free_memory", {"address": hex(large_start)}).get("success")

        terminated = client.tool("veh_terminate")
        assert terminated.get("success"), terminated
        launch = client.tool("veh_launch", {
            "program": TARGET, "args": ["--trace-exception"], "stopOnEntry": True,
        })
        assert launch.get("success"), launch
        assert client.tool("veh_checkpoint_delete", {"id": orphaned_checkpoint["id"]}).get("deleted") is False
        exception_bp = client.tool("veh_set_function_breakpoint", {"name": "TraceExceptionCoverageTarget"})
        assert exception_bp.get("success") and exception_bp.get("address"), exception_bp
        stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert stop.get("reason") == "breakpoint", stop
        exception_start = int(exception_bp["address"], 0)
        exception_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": stop["threadId"], "start": hex(exception_start),
            "end": hex(exception_start + 0x100), "max_steps": 1000,
            "timeout_ms": 5000, "stack_bytes": 16, "follow_exceptions": True,
        }, timeout=15)
        assert exception_trace.get("exceptions_followed", 0) >= 1, exception_trace
        assert any(edge.get("kind") == "exception" for edge in exception_trace["edges"]), exception_trace
        assert exception_trace["exceptions"], exception_trace
        exception_event = exception_trace["exceptions"][0]
        assert exception_event["type"] == "illegal_instruction", exception_event
        assert "fault_snapshot" in exception_event and "continuation_snapshot" in exception_event, exception_event
        assert int(exception_event["continuation"], 0) > int(exception_event["fault_rip"], 0), exception_event

        # Run the high-level matrix last so repeated synthetic inputs cannot
        # perturb the state expected by the other integration cases.
        matrix_thread = stop["threadId"]
        matrix_regs = client.tool("veh_registers", {"threadId": matrix_thread})["registers"]
        matrix_ip = "eip" if "eip" in matrix_regs else "rip"
        matrix_accumulator = "eax" if matrix_ip == "eip" else "rax"
        matrix_code = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
        assert matrix_code.get("success"), matrix_code
        matrix_start = int(matrix_code["address"], 0)
        matrix_bytes = bytes.fromhex("31 C0 83 C0 01 83 F8 05 75 F8 EB FE")
        assert client.tool("veh_write_memory", {
            "address": hex(matrix_start), "data": matrix_bytes.hex(" "),
        }).get("success")
        assert client.tool("veh_set_register", {
            "threadId": matrix_thread, "name": matrix_ip, "value": hex(matrix_start),
        }).get("success")
        matrix_sp = int(matrix_regs["esp" if matrix_ip == "eip" else "rsp"], 0)
        stack_base, stack_size = committed_region(launch["pid"], matrix_sp)
        matrix_checkpoint = client.tool("veh_checkpoint_create", {
            "threadId": matrix_thread,
            "regions": [{"address": hex(stack_base), "size": stack_size}],
        })
        assert matrix_checkpoint.get("id"), matrix_checkpoint
        stack_region = matrix_checkpoint["regions"][0]
        assert stack_region["kind"] == "stack", matrix_checkpoint
        assert int(stack_region["restore_start"], 0) == matrix_sp, matrix_checkpoint
        assert stack_region["live_prefix_skipped"] == matrix_sp - stack_base, matrix_checkpoint
        matrix_dir = tempfile.mkdtemp(prefix=f"veh-targeted-{os.getpid()}-")
        artifact_dirs.append(matrix_dir)
        matrix = client.tool("veh_targeted_capture", {
            "inputs": [{"name": "first"}, {"name": "second"}],
            "steps": [
                {"tool": "veh_checkpoint_restore", "args": {
                    "id": matrix_checkpoint["id"],
                }},
                {"tool": "veh_set_register", "args": {
                    "threadId": matrix_thread, "name": matrix_accumulator, "value": "0",
                }},
            ],
            "trace": {
                "threadId": matrix_thread, "start": hex(matrix_start),
                "end": hex(matrix_start + len(matrix_bytes)), "max_steps": 1000,
                "timeout_ms": 5000, "max_code_bytes": 4096, "max_code_versions": 64,
            },
            "trigger": {"address": hex(matrix_start + 2), "occurrence": 3},
            "window": {"before_steps": 3, "after_steps": 4},
            "environment": {"capture_teb": True, "teb_size": 256},
            "output_directory": matrix_dir,
        }, timeout=30)
        assert matrix.get("succeeded") == 2 and matrix.get("failed") == 0, matrix
        matrix_paths = []
        for item in matrix["inputs"]:
            assert item["status"] == "ok" and item["stop_reason"] == "target_window", item
            assert item["target_window"]["matched"] is True, item
            assert item["drop_counts"] == {
                "events": 0, "memory_events": 0, "register_events": 0,
            }, item
            artifact = item["artifact"]
            matrix_paths.append(artifact["path"])
            data = open(artifact["path"], "rb").read()
            assert hashlib.sha256(data).hexdigest() == artifact["sha256"], item
            matrix_full = json.loads(data)
            assert matrix_full["mode"] == "targeted", matrix_full
            assert matrix_full["aggregate_scope"] == "trigger_and_post_trigger", matrix_full
            captured_environment = matrix_full["capture_environment"]
            teb_region = next(region for region in captured_environment["regions"]
                              if region["kind"] == "teb")
            assert teb_region["encoding"] == "hex" and len(teb_region["data"]) == 512, teb_region
        assert len(set(matrix_paths)) == 2, matrix_paths
        for path in matrix_paths:
            os.remove(path)
        os.rmdir(matrix_dir)
        artifact_dirs.remove(matrix_dir)
        assert client.tool("veh_checkpoint_delete", {
            "id": matrix_checkpoint["id"],
        }).get("deleted") is True

        targeted_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_set_register", "args": {
                "threadId": matrix_thread, "name": matrix_accumulator, "value": "0",
            }},
            {"tool": "veh_set_register", "args": {
                "threadId": matrix_thread, "name": matrix_ip, "value": hex(matrix_start),
            }},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": matrix_thread, "start": hex(matrix_start),
                "end": hex(matrix_start + len(matrix_bytes)), "max_steps": 1000,
                "timeout_ms": 5000,
                "target_window": {"address": hex(matrix_start + 2), "occurrence": 3,
                                  "before_steps": 2, "after_steps": 2},
                "collect_events": True, "max_events": 16,
                "collect_register_events": True, "max_register_events": 16,
            }},
        ]}, timeout=20)
        targeted_batch_trace = targeted_batch["results"][2]["result"]
        assert targeted_batch_trace["stop_reason"] == "target_window", targeted_batch
        assert targeted_batch_trace["target_window"]["matched"] is True, targeted_batch

        targeted_action_output = output_path("target-window-action", "json")
        targeted_action_bp = client.tool("veh_set_breakpoint", {
            "address": hex(matrix_start),
            "action": [
                {"tool": "veh_trace_basic_blocks", "args": {
                    "threadId": matrix_thread, "start": hex(matrix_start),
                    "end": hex(matrix_start + len(matrix_bytes)), "max_steps": 1000,
                    "timeout_ms": 5000,
                    "target_window": {"address": hex(matrix_start + 2), "occurrence": 3,
                                      "before_steps": 2, "after_steps": 2},
                    "collect_events": True, "max_events": 16,
                    "output_file": targeted_action_output,
                }},
                {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
            ],
        })
        assert targeted_action_bp.get("success") and targeted_action_bp.get("hasAction"), targeted_action_bp
        for name, value in ((matrix_accumulator, "0"), (matrix_ip, hex(matrix_start))):
            assert client.tool("veh_set_register", {
                "threadId": matrix_thread, "name": name, "value": value,
            }).get("success")
        targeted_action_stop = client.tool("veh_continue", {
            "wait": True, "timeout": 10,
        }, timeout=15)
        assert targeted_action_stop.get("reason") == "breakpoint", targeted_action_stop
        with open(targeted_action_output, encoding="utf-8") as action_file:
            targeted_action_trace = json.load(action_file)
        assert targeted_action_trace["stop_reason"] == "target_window", targeted_action_trace
        assert targeted_action_trace["target_window"]["matched"] is True, targeted_action_trace
        if targeted_action_stop.get("breakpointId") != targeted_action_bp["id"]:
            assert client.tool("veh_remove_breakpoint", {
                "id": targeted_action_stop["breakpointId"],
            }).get("success")
        assert client.tool("veh_remove_breakpoint", {
            "id": targeted_action_bp["id"],
        }).get("success")
        print(json.dumps({
            "stop_reason": trace["stop_reason"],
            "blocks": len(trace["blocks"]),
            "edges": len(trace["edges"]),
            "steps": trace["steps_executed"],
            "batch_blocks": len(batch_trace["blocks"]),
            "batch_edges": len(batch_trace["edges"]),
            "exception_edges": sum(edge.get("kind") == "exception" for edge in exception_trace["edges"]),
            "indirect_sites": len(indirect_trace["indirect_branches"]),
            "memory_writes": len(trace["memory_writes"]),
            "memory_events": len(trace["memory_events"]),
            "register_events": len(trace["register_events"]),
            "executed_writes": sum(bool(w.get("executed_after_write")) for w in executable_trace["executable_writes"]),
            "lea_dependencies": lea_trace["final_dependencies"][destination_name],
            "code_versions": len(smc_trace["code_versions"]),
            "stress_register_events": len(stress_trace["register_events"]),
            "stress_memory_events": len(stress_trace["memory_events"]),
            "checkpoint_restored": True,
            "targeted_inputs": matrix["succeeded"],
            "targeted_parity": True,
        }))
    finally:
        client.close()
        for path in artifact_paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        for directory in artifact_dirs:
            try:
                for name in os.listdir(directory):
                    os.remove(os.path.join(directory, name))
                os.rmdir(directory)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
