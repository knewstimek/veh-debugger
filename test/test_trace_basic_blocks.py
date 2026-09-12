"""Integration smoke test for veh_trace_basic_blocks."""
import json
import os
import queue
import subprocess
import threading
import time
from collections import Counter


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUILD_DIR = os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))
MCP_EXE = os.path.join(BUILD_DIR, "bin", "Release", "veh-mcp-server.exe")
TARGET = os.path.join(BUILD_DIR, "bin", "Release", "test_target.exe")


class Client:
    def __init__(self):
        self.proc = subprocess.Popen(
            [MCP_EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.seq = 0
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self._read_responses, daemon=True)
        self.reader.start()

    def _read_responses(self):
        try:
            for line in self.proc.stdout:
                self.responses.put(json.loads(line))
        finally:
            self.responses.put(None)

    def call(self, method, params=None, timeout=20):
        self.seq += 1
        request = {"jsonrpc": "2.0", "id": self.seq, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write((json.dumps(request) + "\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(method)
            try:
                message = self.responses.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError(method) from error
            if message is None:
                raise RuntimeError(f"MCP server exited while waiting for {method}")
            if message.get("id") == self.seq:
                return message

    def tool(self, name, arguments=None, timeout=20):
        response = self.call("tools/call", {"name": name, "arguments": arguments or {}}, timeout)
        content = response["result"]["content"][0]["text"]
        return json.loads(content)

    def close(self):
        try:
            self.tool("veh_terminate", timeout=5)
        except Exception:
            pass
        finally:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)


def main():
    client = Client()
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
        trace_properties = trace_tool["inputSchema"]["properties"]
        assert all(name in trace_properties for name in (
            "collect_events", "max_events", "collect_code", "max_code_bytes", "max_code_versions",
            "collect_memory_events", "max_memory_events",
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
        assert trace["schema_version"] == 3 and trace["mode"] == "aggregated", trace
        assert trace["thread_id"] == thread_id, trace
        assert trace["ordering"] == {
            "available": True, "granularity": "basic_block_transitions",
            "event_schema_version": 2, "complete": True,
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
                "collect_events": True, "max_events": 256,
                "collect_code": True, "max_code_bytes": 4096, "max_code_versions": 256,
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
        assert batch_trace["code_capture"]["available"] is True and batch_trace["code_versions"], batch_trace
        assert all(event["thread_id"] == batch_stop["threadId"]
                   for event in batch_trace["events"]), batch_trace
        assert all(event["thread_id"] == batch_stop["threadId"]
                   for event in batch_trace["memory_events"]), batch_trace

        truncated_batch = client.tool("veh_batch", {"steps": [
            {"tool": "veh_continue", "args": {"wait": True, "timeout": 10}},
            {"tool": "veh_trace_basic_blocks", "args": {
                "threadId": "$0.threadId", "start": hex(start), "end": hex(start + 0x100),
                "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                "collect_memory_writes": True, "max_memory_writes": 1,
                "collect_memory_reads": True, "max_memory_reads": 1,
                "collect_memory_events": True, "max_memory_events": 1,
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
        assert truncated_writes["ordering"]["complete"] is False, truncated_writes
        assert len(truncated_writes["memory_events"]) == 1, truncated_writes
        assert truncated_writes["memory_events_truncated"] is True, truncated_writes
        assert truncated_writes["memory_events_dropped"] > 0, truncated_writes
        assert truncated_writes["memory_ordering"]["complete"] is False, truncated_writes
        assert truncated_writes["memory_ordering"]["events_dropped"] == \
            truncated_writes["memory_events_dropped"], truncated_writes

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
        action_bp = client.tool("veh_set_breakpoint", {
            "address": hex(start),
            "action": [
                {"tool": "veh_trace_basic_blocks", "args": {
                    "threadId": thread_id, "start": hex(start), "end": hex(start + 0x100),
                    "max_steps": 1000, "timeout_ms": 5000, "stack_bytes": 0,
                    "collect_memory_events": True, "max_memory_events": 256,
                    "collect_events": True, "max_events": 256,
                    "collect_code": True, "max_code_bytes": 4096, "max_code_versions": 256,
                }},
                {"tool": "veh_set_breakpoint", "args": {"address": "$0.final_address"}},
            ],
        })
        assert action_bp.get("success") and action_bp.get("hasAction"), action_bp
        action_stop = client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15)
        assert action_stop.get("reason") == "breakpoint", action_stop
        assert action_stop.get("breakpointId") != action_bp["id"], action_stop
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
        checkpoint_diff = checkpoint_batch["results"][3]["result"]
        assert reg_name in checkpoint_diff["register_delta"], checkpoint_diff
        assert checkpoint_diff["memory_changes"], checkpoint_diff
        assert checkpoint_batch["results"][4]["result"].get("restored") is True, checkpoint_batch
        assert checkpoint_batch["results"][5]["result"].get("deleted") is True, checkpoint_batch
        restored_memory = client.tool("veh_read_memory", {"address": scratch_address, "size": 16})
        assert restored_memory["hex"].replace(" ", "").lower() == "aa" * 16, restored_memory
        restored_regs = client.tool("veh_registers", {"threadId": checkpoint_thread})["registers"]
        assert int(restored_regs[reg_name], 0) == 0x1111, restored_regs

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

        # LEA's source is a Zydis memory-form operand even though the
        # instruction reads no memory. Its base/index origins must reach the
        # largest enclosing destination register; writing EAX defines RAX via
        # architectural zero-extension. Run this immediately before terminating
        # the target so the synthetic register state cannot affect other cases.
        saved = client.tool("veh_registers", {"threadId": checkpoint_thread})["registers"]
        is_32bit = "eip" in saved
        ip_name = "eip" if is_32bit else "rip"
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
            "dependency_sources": [rcx_name, rdx_name],
        }, timeout=15)
        assert lea_trace.get("stop_reason") == "left_range", lea_trace
        destination_name = "eax" if is_32bit else "rax"
        assert set(lea_trace["final_dependencies"].get(destination_name, [])) == \
            {rcx_name, rdx_name}, lea_trace
        assert lea_trace["memory_reads"] == [], lea_trace
        assert client.tool("veh_free_memory", {"address": hex(lea_start)}).get("success")

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
        smc_trace = client.tool("veh_trace_basic_blocks", {
            "threadId": checkpoint_thread, "start": hex(smc_start),
            "end": hex(smc_start + len(smc_code)), "max_steps": 4,
            "timeout_ms": 5000, "stack_bytes": 0,
            "collect_code": True, "max_code_bytes": 64,
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
        assert client.tool("veh_set_register", {
            "threadId": checkpoint_thread, "name": ip_name, "value": saved[ip_name],
        }).get("success")
        assert client.tool("veh_free_memory", {"address": hex(smc_start)}).get("success")

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
            "executed_writes": sum(bool(w.get("executed_after_write")) for w in executable_trace["executable_writes"]),
            "lea_dependencies": lea_trace["final_dependencies"][destination_name],
            "code_versions": len(smc_trace["code_versions"]),
            "checkpoint_restored": True,
        }))
    finally:
        client.close()


if __name__ == "__main__":
    main()
