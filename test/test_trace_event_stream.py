"""Integration coverage for file-backed ordered trace events."""
import collections
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

from mcp_test_client import McpClient, ROOT


BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
TARGET = os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe")
READER = os.path.join(ROOT, "tools", "read_trace_event_stream.py")


def temporary_path(paths, label, extension):
	path = os.path.join(
		tempfile.gettempdir(),
		f"veh-event-stream-{os.getpid()}-{time.time_ns()}-{label}.{extension}")
	paths.append(path)
	return path


def parse_jsonl(artifact_path, paths, label):
	jsonl_path = temporary_path(paths, label, "jsonl")
	completed = subprocess.run(
		[sys.executable, READER, artifact_path, "--output", jsonl_path],
		cwd=ROOT, capture_output=True, text=True, timeout=120)
	assert completed.returncode == 0, completed.stderr
	counts = collections.Counter()
	manifest = None
	last_sequence = 0
	with open(jsonl_path, encoding="utf-8") as stream:
		for line_number, line in enumerate(stream):
			value = json.loads(line)
			if line_number == 0:
				assert value["record"] == "manifest", value
				manifest = value
				continue
			counts[value["record"]] += 1
			assert value["sequence"] >= last_sequence, (last_sequence, value)
			last_sequence = value["sequence"]
	assert manifest is not None
	return manifest, {
		"events": counts["event"],
		"memory_events": counts["memory_event"],
		"register_events": counts["register_event"],
	}


def set_ip(client, thread_id, ip_name, value):
	result = client.tool("veh_set_register", {
		"threadId": thread_id, "name": ip_name, "value": hex(value),
	})
	assert result.get("success"), result


def main():
	client = McpClient(args=["--profile=full"])
	paths = []
	try:
		client.initialize("trace-event-stream-test")
		listed = client.call("tools/list")["result"]["tools"]
		trace_tool = next(tool for tool in listed if tool["name"] == "veh_trace_basic_blocks")
		properties = trace_tool["inputSchema"]["properties"]
		assert all(name in properties for name in (
			"events_output", "events_output_path", "max_event_file_bytes")), trace_tool

		launch = client.tool("veh_launch", {"program": TARGET, "stopOnEntry": True})
		assert launch.get("success"), launch
		breakpoint = client.tool("veh_set_function_breakpoint", {"name": "TraceCoverageTarget"})
		assert breakpoint.get("success"), breakpoint
		stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
		assert stop.get("reason") == "breakpoint", stop
		thread_id = stop["threadId"]
		registers = client.tool("veh_registers", {"threadId": thread_id})["registers"]
		ip_name = "eip" if "eip" in registers else "rip"
		is_32bit = ip_name == "eip"

		allocation = client.tool("veh_allocate_memory", {"size": 4096, "protection": "rwx"})
		assert allocation.get("success"), allocation
		loop = int(allocation["address"], 0)
		counter = loop + 16
		if is_32bit:
			code = b"\xff\x05" + struct.pack("<I", counter) + b"\xeb\xf8"
		else:
			code = b"\xff\x05\x0a\x00\x00\x00\xeb\xf8"
		code += b"\x90" * (16 - len(code)) + b"\x00\x00\x00\x00"
		written = client.tool("veh_write_memory", {
			"address": hex(loop), "data": code.hex(" "),
		})
		assert written.get("success"), written

		# A single artifact exceeds both the old basic-event and register-event caps.
		set_ip(client, thread_id, ip_name, loop)
		artifact_path = temporary_path(paths, "long", "vte")
		output_path = temporary_path(paths, "long-result", "json")
		long_trace = client.tool("veh_trace_basic_blocks", {
			"threadId": thread_id, "start": hex(loop), "end": hex(loop + 8),
			"max_steps": 68000, "timeout_ms": 60000, "stack_bytes": 0,
			"collect_events": True,
			"collect_memory_events": True,
			"collect_register_events": True,
			"events_output": "file", "events_output_path": artifact_path,
			"output_file": output_path,
		}, timeout=120)
		assert long_trace.get("mode") == "file", long_trace
		metadata = long_trace["event_file"]
		assert metadata["path"] == artifact_path and metadata["size"] > 0, metadata
		assert metadata["counts"]["events"] > 32768, metadata
		assert metadata["counts"]["register_events"] > 65536, metadata
		assert metadata["counts"]["memory_events"] > 0, metadata
		assert metadata["truncated"] is False and metadata["limit_reason"] == "none", metadata
		assert metadata["wait_time_ns"] >= 0 and metadata["wait_time_ms"] >= 0, metadata
		assert long_trace["drop_counts"] == {
			"events": 0, "memory_events": 0, "register_events": 0,
		}, long_trace
		with open(output_path, encoding="utf-8") as stream:
			full_result = json.load(stream)
		assert all(name not in full_result for name in (
			"events", "memory_events", "register_events")), full_result.keys()
		assert full_result["event_file"] == metadata, full_result["event_file"]
		manifest, parsed_counts = parse_jsonl(artifact_path, paths, "long")
		assert parsed_counts == metadata["counts"], (parsed_counts, metadata)
		assert manifest["counts"] == metadata["counts"], manifest
		assert manifest["record_bytes"] == metadata["record_bytes"], manifest
		assert manifest["truncated"] is False, manifest
		duplicate = client.tool("veh_trace_basic_blocks", {
			"threadId": thread_id, "start": hex(loop), "end": hex(loop + 8),
			"max_steps": 1, "timeout_ms": 1000, "stack_bytes": 0,
			"collect_events": True,
			"events_output": "file", "events_output_path": artifact_path,
		})
		assert "already exists" in duplicate.get("error", ""), duplicate

		# A low byte limit stops at a complete record and preserves a parseable file.
		set_ip(client, thread_id, ip_name, loop)
		limited_path = temporary_path(paths, "limited", "vte")
		limited = client.tool("veh_batch", {"steps": [{
			"tool": "veh_trace_basic_blocks",
			"args": {
				"threadId": thread_id, "start": hex(loop), "end": hex(loop + 8),
				"max_steps": 1000, "timeout_ms": 15000, "stack_bytes": 0,
				"collect_events": True,
				"collect_memory_events": True,
				"collect_register_events": True,
				"events_output": "file", "events_output_path": limited_path,
				"max_event_file_bytes": 4096,
			},
		}]}, timeout=30)
		limited_result = limited["results"][0]["result"]
		limited_metadata = limited_result["event_file"]
		assert any(item.get("path") == limited_path for item in limited["artifacts"]), limited
		assert limited_metadata["truncated"] is True, limited_metadata
		assert limited_metadata["limit_reason"] == "size_limit", limited_metadata
		assert 88 <= limited_metadata["size"] <= 4096, limited_metadata
		assert limited_result["events_dropped"] == 0, limited_result
		assert limited_result["memory_events_dropped"] == 0, limited_result
		assert limited_result["register_events_dropped"] == 0, limited_result
		limited_manifest, limited_counts = parse_jsonl(limited_path, paths, "limited")
		assert limited_counts == limited_metadata["counts"], limited_metadata
		assert limited_manifest["truncated"] is True, limited_manifest
		assert limited_manifest["truncation_reason"] == "size_limit", limited_manifest

		# Omitting events_output retains the legacy inline result and cap semantics.
		set_ip(client, thread_id, ip_name, loop)
		inline = client.tool("veh_trace_basic_blocks", {
			"threadId": thread_id, "start": hex(loop), "end": hex(loop + 8),
			"max_steps": 64, "timeout_ms": 5000, "stack_bytes": 0,
			"collect_events": True, "max_events": 64,
			"collect_memory_events": True, "max_memory_events": 64,
			"collect_register_events": True, "max_register_events": 64,
		})
		assert "event_file" not in inline, inline
		assert all(name in inline for name in (
			"events", "memory_events", "register_events")), inline
		assert inline["ordering"]["events_captured"] == len(inline["events"]), inline
		assert inline["memory_ordering"]["events_captured"] == len(inline["memory_events"]), inline
		assert inline["register_ordering"]["events_captured"] == len(inline["register_events"]), inline
		assert inline["events_dropped"] == 0, inline
		assert inline["memory_events_dropped"] == 0, inline
		assert inline["register_events_dropped"] == 0, inline

		print({
			"long_counts": metadata["counts"],
			"long_bytes": metadata["size"],
			"wait_time_ms": metadata["wait_time_ms"],
			"limited_counts": limited_metadata["counts"],
			"limited_bytes": limited_metadata["size"],
		})
	finally:
		client.close()
		for path in paths:
			try:
				os.remove(path)
			except OSError:
				pass


if __name__ == "__main__":
	main()
