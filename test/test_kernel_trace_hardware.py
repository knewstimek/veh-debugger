"""Owned synthetic RSP tests for KD hardware runtime and immutable artifact routes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import time

from build_paths import RELEASE, ROOT
from owned_mcp_client import OwnedMcpClient
from test_kernel_debug_protocol import Stub

CAP = struct.Struct("<10IQIIQ")
STATUS = struct.Struct("<4I2Q4I13Q4I3Q")
PAGE = struct.Struct("<HHI4QIIQQ")
COMPACT = struct.Struct("<3Q3I4B16s")
EVENT = struct.Struct("<7QIBBHIHBBBBHI")
GEN = 9007199254740993
spec = importlib.util.spec_from_file_location("kd_hw_events", Path(ROOT) / "tools/read_trace_event_stream.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def payload_hash(data):
    value = 1469598103934665603
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


class HardwareStub(Stub):
    def __init__(self, mode="ok"):
        self.mode = mode
        self.generation = GEN - 1
        self.request_id = self.high_id = 0
        self.chunk = self.offset = self.count = self.hardware_offset = 0
        self.limit = self.kinds = self.flags = self.resumes = 0
        self.released = True
        self.cancelled = False
        self.delivered = {1: set(), 2: set()}
        self.raw_events = []
        self.paths = None
        self.status_delay = False
        super().__init__()

    def pc(self, index):
        return self.start + 7 * (index // 3) + (0, 3, 5)[index % 3]

    def total(self):
        return self.limit - 1 if self.mode == "uncertain" else self.limit

    def terminal(self):
        if self.mode in ("file-budget", "no-attempt"):
            return 12 if self.mode == "file-budget" else 7
        if self.offset + self.count < self.total():
            return 8
        return {"uncertain": 10, "code": 9, "scope": 11, "budget": 1}.get(self.mode, 2)

    def next_chunk(self):
        self.count = 0 if self.mode == "no-attempt" else min(3, self.total() - self.offset)
        self.raw_events = self.make_events()
        self.delivered = {1: set(), 2: set()}

    def make_events(self):
        rows = []
        for i in range(self.offset, self.offset + self.count):
            kind = i % 3 + 1
            if self.mode != "event-kind" and not self.kinds & (1 << (kind - 1)):
                continue
            if i + 1 == self.limit and self.mode not in ("code", "scope", "budget", "file-budget"):
                continue  # final normal range-exit instruction is RET
            known = 1 | 8 | 16 | 32 | 64 | 128
            before = after = 0
            if kind == 1:
                subject, value = 3, 0x12345005
                before, after = 0x11111001, 0x22222002
                known |= 6
            elif kind == 2:
                subject, value = 0xC0000082, 0xFFFF800000002000
            else:
                subject, value = 0x80, 0
            sequence = i + 1
            pc = self.pc(i)
            cpu = 1 if self.mode == "event-cpu" and self.chunk else 0
            index = 16 if self.mode == "event-index" and self.chunk else 0
            if self.mode == "event-sequence" and self.chunk:
                sequence = self.limit + 1
            if self.mode == "event-pc" and self.chunk:
                pc += 1
            rows.append(EVENT.pack(sequence, i + 1, pc, subject, value, before, after,
                                   index, 0, 0, 0, 77, cpu, kind, 1 if kind == 3 else 2, 1 if kind == 3 else 8,
                                   1, known, int(self.mode == "code" and i + 1 == self.limit)))
        if self.mode == "uncertain" and self.offset + self.count == self.total():
            rows.append(EVENT.pack(0, self.limit, self.pc(self.total()), 3, 5, 0, 0,
                                   0, 0, 255, 0, 77, 0, 1, 2, 8, 2, 1 | 8 | 16 | 64, 0))
        return rows

    def all_counters(self):
        # Small fixture; recompute prefix counts independently of page receipt code.
        saved_offset, saved_count, saved_chunk = self.offset, self.count, self.chunk
        self.offset, self.count = 0, saved_offset + saved_count
        all_rows = self.make_events()
        self.offset, self.count, self.chunk = saved_offset, saved_count, saved_chunk
        unknown = 0
        for raw in all_rows:
            known = EVENT.unpack(raw)[17]
            unknown += sum(not known & bit for bit in (1, 2, 4))
        return len(all_rows), unknown, int(self.mode == "uncertain" and self.offset + self.count == self.total())

    def header(self):
        end = 3 if self.cancelled else self.terminal()
        steps = self.offset + self.count
        final = self.pc(steps)
        if end in (2, 9):
            final = self.end
        if end == 10:
            final = 0x1800
        flags = 1 | (2 if end == 10 else 0) | (16 if end == 9 else 0) | (32 if end == 11 else 0)
        if self.mode == "no-attempt":
            flags |= 4 | 8
        retained, unknown, uncertain = self.all_counters()
        values = [1, 0, 192, 200 if self.flags & 1 else 56, self.generation, self.request_id,
                  0, self.flags, self.kinds, end, self.chunk, self.offset, self.count, self.hardware_offset,
                  len(self.raw_events), steps, steps + int(end == 10), self.limit, final, retained,
                  0, unknown, uncertain, flags, 1 if end == 11 else 0, int(end == 8), 1, 0, 0, 0]
        if self.mode == "bad-offset" and self.chunk:
            values[11] -= 1
        if self.mode == "bad-kinds" and self.chunk:
            values[8] ^= 1
        if self.mode == "bad-request" and self.chunk:
            values[5] += 1
        if self.mode == "bad-halt" and self.chunk:
            values[26] = 0
        if self.mode == "bad-count" and self.chunk:
            values[21] += 1
        if self.mode == "bad-final" and self.chunk:
            values[18] += 1
        return STATUS.pack(*values)

    def instruction(self, index):
        final = index + 1 == self.total() and self.terminal() != 8
        next_pc = self.pc(index + 1)
        code = (b"\x0f\x22\xd8", b"\x0f\x30", b"\xe4\x80")[index % 3]
        reserved = 0
        if final and self.mode in ("ok", "release-fail", "export-fail"):
            code, next_pc = b"\xc3", self.end
        elif final and self.mode == "code":
            code, reserved, next_pc = b"", 1, self.end
        raw = COMPACT.pack(self.pc(index), next_pc, 0x12345005,
                           1 if self.mode == "instruction-cpu" and self.chunk else 0, 4242, 77,
                           64, 0, len(code), reserved, code.ljust(16, b"\0"))
        return raw + (struct.pack("<18Q", *([0] * 16 + [self.pc(index), 2])) if self.flags & 1 else b"")

    def packet(self, text):
        if not text.startswith(("qTraceHW:", "vTraceHW:")):
            if text == "qC":
                self.commands.append(text)
                self.send("QC1")
            else:
                super().packet(text)
            return
        self.commands.append(text)
        if text == "qTraceHW:cap1":
            if self.mode == "no-caps":
                self.send("")
                return
            caps = [1, 64, 1 if self.mode == "partial-kinds" else 7,
                    0 if self.mode == "no-flags" else 3, 3, 16, 16, 5000000, 600000, 80,
                    4294967296, 529, 3, 0]
            if self.mode == "cap-version":
                caps[0] = 2
            if self.mode == "cap-reserved":
                caps[-1] = 1
            raw = CAP.pack(*caps)
            self.send((raw[:-1] if self.mode == "cap-short" else raw).hex())
        elif text.startswith("vTraceHW:1,"):
            _, cpu, limit, start, end, flags, kinds, timeout, budget, request = text.split(",")
            assert self.released and int(request, 16) > self.high_id, text
            assert int(cpu, 16) == 0 and int(budget, 16) >= 1912, text
            self.request_id = self.high_id = int(request, 16)
            self.limit, self.start, self.end, self.flags, self.kinds = map(
                lambda s: int(s, 16), (limit, start, end, flags, kinds))
            self.generation += 1
            self.chunk = self.offset = self.hardware_offset = self.resumes = 0
            self.released = self.cancelled = False
            self.next_chunk()
            self.send("T05thread:02;" if self.mode == "peer-stop" else "T05thread:01;")
        elif text.startswith("qTraceHW:status1,"):
            assert int(text.split(",")[1], 16) == self.request_id
            if self.mode == "export-fail" and self.terminal() != 8 and self.paths:
                Path(self.paths[0]).write_text("collision", encoding="utf-8")
            self.send("E23" if self.mode == "E23" and self.chunk else self.header().hex())
        elif text.startswith("qTraceHW:read1,"):
            _, gen, request, chunk, stream, offset, count = text.split(",")
            gen, request, chunk, stream, offset, count = map(lambda s: int(s, 16), (gen, request, chunk, stream, offset, count))
            assert (gen, request, chunk) == (self.generation, self.request_id, self.chunk)
            if self.mode == "read-E23" and self.chunk and stream == 2:
                self.send("E23")
                return
            first = self.offset if stream == 1 else self.hardware_offset
            size = 200 if self.flags & 1 else 56
            records = ([self.instruction(i) for i in range(offset, offset + count)] if stream == 1 else
                       self.raw_events[offset - first:offset - first + count])
            size = size if stream == 1 else 80
            assert len(records) == count and first <= offset and offset + count <= first + (self.count if stream == 1 else len(self.raw_events))
            self.delivered[stream].update(range(offset, offset + count))
            raw = b"".join(records)
            digest = payload_hash(raw) + int(self.mode == "bad-hash" and self.chunk and stream == 2)
            if self.mode == "slow-read" and stream == 2:
                time.sleep(0.1)
            page = PAGE.pack(1, 64, size, gen, request, chunk, offset, count, stream, digest & 0xFFFFFFFFFFFFFFFF, 0)
            self.send((page + raw).hex())
        elif text.startswith("vTraceHW:resume1,"):
            _, gen, request, chunk, instructions, events = text.split(",")
            expected = (self.generation, self.request_id, self.chunk, self.offset + self.count,
                        self.hardware_offset + len(self.raw_events))
            assert tuple(int(s, 16) for s in (gen, request, chunk, instructions, events)) == expected
            assert self.delivered[1] == set(range(self.offset, self.offset + self.count))
            assert self.delivered[2] == set(range(self.hardware_offset, self.hardware_offset + len(self.raw_events)))
            if self.paths:
                code_path, event_path = self.paths[0] + ".records", self.paths[1]
                assert Path(code_path).stat().st_size == 216 + (self.offset + self.count) * 200
                assert Path(event_path).stat().st_size == 88 + (self.hardware_offset + len(self.raw_events)) * 88
            self.offset += self.count
            self.hardware_offset += len(self.raw_events)
            self.chunk += 1
            self.resumes += 1
            self.next_chunk()
            self.send("T05thread:01;")
        elif text.startswith("qTraceHW:cancel1,"):
            self.cancelled = True
            self.send("OK")
        elif text.startswith("qTraceHW:release1,"):
            _, gen, request, chunk, instructions, events = text.split(",")
            assert tuple(int(s, 16) for s in (gen, request, chunk, instructions, events)) == (
                self.generation, self.request_id, self.chunk, self.offset + self.count,
                self.hardware_offset + len(self.raw_events))
            if self.mode == "release-fail":
                self.send("E21")
            else:
                self.released = True
                self.send("OK")
        else:
            raise AssertionError(text)


def main():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="veh-kd-hw-") as temporary:
        root = Path(temporary)
        def run(mode="ok", extra=None, expect_error=False):
            nonlocal checks
            stub = HardwareStub(mode)
            try:
                with OwnedMcpClient(env=dict(os.environ, TEMP=temporary, TMP=temporary)) as client:
                    client.initialize("kd-hardware-runtime")
                    assert client.tool("veh_kd_connect", {"transport": "tcp", "address": f"127.0.0.1:{stub.port}"}).get("halted")
                    args = {"execution_context": "kd", "start": "0x1000", "end": "0x2000",
                            "max_steps": 7, "timeout_ms": 10000, "collect_hardware_events": True,
                            "collect_code": True, "collect_events": True,
                            "output_file": str(root / f"{mode}-{checks}.json"),
                            "events_output_path": str(root / f"{mode}-{checks}.vte")}
                    args.update(extra or {})
                    stub.paths = (args["output_file"], args["events_output_path"])
                    result = client.tool("veh_trace_basic_blocks", args, timeout=25)
                    if expect_error:
                        assert "error" in result, (mode, result)
                    else:
                        assert "error" not in result and len(json.dumps(result).encode()) <= 8192, (mode, result)
                        assert result["hardware_collection"]["transport"] == "kd-rsp-hardware-v1", result
                        assert result["generation"] == str(GEN), result
                        for key in ("capture_file", "event_file", "output_file"):
                            artifact = result[key]
                            assert artifact["storage_complete"], (mode, artifact)
                            raw = Path(artifact["path"]).read_bytes()
                            assert len(raw) == artifact["size"] and hashlib.sha256(raw).hexdigest() == artifact["sha256"], artifact
                        with open(result["event_file"]["path"], "rb") as source:
                            header = reader.read_header(source)
                            events = list(reader.iter_records(source, header))
                        assert str(len(events)) == result["hardware_collection"]["events"], result
                        page_args = {"execution_context": "kd", "operation": "read_events",
                                     "event_file": result["event_file"]["path"], "limit": 1}
                        page = client.tool("veh_trace_basic_blocks", page_args)
                        assert "error" not in page and len(page["events"]) <= 1, page
                        decoded = client.tool("veh_trace_basic_blocks", {
                            "execution_context": "kd", "operation": "read_capture",
                            "capture_file": result["capture_file"]["path"], "include_registers": True})
                        assert "error" not in decoded and bool(decoded["records"]) == (result["steps_executed"] != "0"), decoded
                        assert client.tool("veh_kd_disconnect").get("detached")
                        batch = client.tool("veh_batch", {"steps": [
                            {"tool": "veh_trace_basic_blocks", "args": page_args},
                            {"tool": "veh_trace_basic_blocks", "args": dict(page_args, operation="analyze_events")},
                            {"tool": "veh_trace_basic_blocks", "args": {"execution_context": "kd", "operation": "read_capture",
                                "capture_file": result["capture_file"]["path"]}}]})
                        assert batch["failed"] == 0, batch
                        if mode == "ok" and checks == 0:
                            attached = client.tool("veh_attach", {"pid": 4242, "target_scope": "guest",
                                "agent": str(Path(RELEASE) / "guest_backend_fixture.exe"),
                                "agent_args": ["--metadata", "path-file-output"]})
                            assert attached.get("success"), attached
                            installed = client.tool("veh_set_breakpoint", {"address": "0x1000", "action": [
                                {"tool": "veh_trace_basic_blocks", "args": {
                                    "execution_context": "kd", "operation": "read_capture",
                                    "capture_file": result["capture_file"]["path"]}},
                                {"tool": "veh_trace_basic_blocks", "args": page_args},
                                {"tool": "veh_trace_basic_blocks", "args": dict(page_args, operation="analyze_events")},
                                {"tool": "veh_set_breakpoint", "args": {"address": "$0.records.0.cr3"}}]})
                            assert installed.get("id"), installed
                            assert client.tool("veh_continue").get("success")
                            client.wait_notification("notifications/logging",
                                lambda p: "Breakpoint #7 hit" in p.get("data", ""), timeout=15)
                            listed = client.tool("veh_list_breakpoints")
                            assert any(int(row["address"], 0) == 0x12345005 for row in listed["software"]), listed
                            assert client.tool("veh_detach").get("success")
                    if expect_error:
                        assert client.tool("veh_kd_disconnect").get("detached")
                    assert not any("qTraceBB:" in command or command.startswith("vTraceBB:") for command in stub.commands), stub.commands
                    checks += 1
                    return result, list(stub.commands), stub.resumes
            finally:
                stub.close()
        good, commands, resumes = run()
        assert good["complete"] and good["hardware_collection"]["events"] == "6" and resumes == 2, good
        assert good["hardware_counts"] == {"control_register": "2", "msr": "2", "io_port": "2"}
        assert not good["backend_buffer_retained"]
        run("ok", {"collect_snapshots": False, "output_file": str(root / "compact.json")})
        run("ok", {"run_peer_cpus": True, "output_file": str(root / "peers.json")})
        selected, _, _ = run("ok", {"hardware_kinds": ["msr"], "output_file": str(root / "selected.json")})
        assert selected["hardware_collection"]["applied_kinds"] == ["msr"]
        for mode in ("no-caps", "partial-kinds", "no-flags", "cap-version", "cap-reserved", "cap-short"):
            failure, log, _ = run(mode, expect_error=True)
            assert not any(c.startswith("vTraceHW:1,") for c in log), (mode, log)
        for extra in ({"collect_hardware_events": "true"}, {"hardware_kinds": []}, {"hardware_kinds": ["msr", "msr"]},
                      {"events_output": "inline"}, {"output_mode": "inline"}, {"run_peer_cpus": 1},
                      {"compress_paths": True}, {"threadId": 77}, {"max_event_file_bytes": 1911}, {"operation": "unknown"}):
            _, log, _ = run("invalid", extra, True)
            assert not any(c.startswith("vTraceHW:1,") for c in log)
        for mode in ("bad-offset", "bad-kinds", "bad-request", "bad-halt", "bad-count", "bad-final",
                     "bad-hash", "instruction-cpu", "event-cpu", "event-index", "event-sequence", "event-pc", "E23", "read-E23"):
            failure, log, resumes = run(mode, expect_error=True)
            assert resumes == 1 and failure["capture_file"]["records"] == "3", (mode, failure, log)
            assert not any(c.startswith("qTraceHW:release1,") for c in log)
            if mode in ("E23", "read-E23", "bad-halt"):
                assert failure["final_address"] is None and not failure["halted"], failure
        _, kind_log, _ = run("event-kind", {"hardware_kinds": ["msr"]}, expect_error=True)
        assert not any(c.startswith("vTraceHW:resume1,") for c in kind_log)
        peer, _, resumes = run("peer-stop", expect_error=True)
        assert resumes == 0 and peer["capture_file"]["records"] == "3", peer
        unattempted, _, _ = run("no-attempt")
        assert not unattempted["complete"] and unattempted["steps_executed"] == "0"
        uncertain, _, _ = run("uncertain")
        assert not uncertain["complete"] and uncertain["steps_executed"] is None
        assert uncertain["steps_executed_lower_bound"] == "6" and uncertain["hardware_collection"]["uncertain_records"] == "1"
        code, _, _ = run("code")
        assert not code["complete"] and code["decode_incomplete"] and code["stop_reason"] == "code_uncertain"
        scope, _, _ = run("scope")
        assert not scope["complete"] and scope["scope_exit"] == "address_space"
        file_limit, _, resumes = run("file-budget", {"max_event_file_bytes": 1912})
        assert not file_limit["complete"] and file_limit["stop_reason"] == "size_limit" and resumes == 0
        budget, _, _ = run("budget")
        assert not budget["complete"] and budget["stop_reason"] == "max_steps"
        retained, log, _ = run("release-fail")
        assert retained["backend_buffer_retained"] and sum(c.startswith("qTraceHW:release1,") for c in log) == 2
        cancelled, log, resumes = run("slow-read", {"timeout_ms": 100})
        assert not cancelled["complete"] and resumes == 0 and any(c.startswith("qTraceHW:cancel1,") for c in log)
        exported, log, _ = run("export-fail", expect_error=True)
        assert exported["event_file"]["storage_complete"] and exported["capture_complete"] and not exported["storage_complete"]
    print(f"PASS KD hardware runtime {checks} scenarios: independent negotiation, paired durable ACKs, exact files/pages, partial results and old-path exclusion")


if __name__ == "__main__":
    main()
