"""Convert a VEH ordered-event artifact (.vte) to JSON lines."""
import argparse
import json
import os
import struct
import sys


MAGIC = 0x00544E5645484556
SCHEMA_VERSION = 1
HEADER = struct.Struct("<Q7I5Q3I")
RECORD_HEADER = struct.Struct("<HHI")
BASIC_BLOCK = struct.Struct("<QQQQIIIBBBB")
MEMORY = struct.Struct("<QQQIIBBBB16s16s16s")
REGISTER = struct.Struct("<QQII18Q18QB7s")
HARDWARE = struct.Struct("<7QIBBHIHBBBBHI")

RECORD_BASIC_BLOCK = 1
RECORD_MEMORY = 2
RECORD_REGISTER = 3
RECORD_HARDWARE = 4

EDGE_KINDS = {
    0: "fallthrough",
    1: "branch",
    2: "call",
    3: "return",
    4: "exception",
    5: "range_exit",
}
TRUNCATION_REASONS = {0: "none", 1: "size_limit", 2: "transfer_failure"}
REGISTERS_64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
REGISTERS_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]


def _hex(value):
    return f"0x{value:X}"


def _bytes(value, size):
    return value[:size].hex(" ")


def read_header(stream):
    raw = stream.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise ValueError("file is too small for an event artifact header")
    values = HEADER.unpack(raw)
    header = {
        "magic": values[0],
        "schema_version": values[1],
        "header_size": values[2],
        "flags": values[3],
        "record_header_size": values[4],
        "entry_sizes": {
            "event": values[5],
            "memory_event": values[6],
            "register_event": values[7],
        },
        "record_bytes": values[8],
        "counts": {
            "events": values[9],
            "memory_events": values[10],
            "register_events": values[11],
        },
        "wait_time_ns": values[12],
        "truncation_reason_code": values[13],
        "chunk_count": values[14],
    }
    if header["magic"] != MAGIC:
        raise ValueError("invalid event artifact magic")
    if header["schema_version"] not in (SCHEMA_VERSION, 2, 3):
        raise ValueError(f"unsupported event artifact schema {header['schema_version']}")
    if header["header_size"] != HEADER.size or header["record_header_size"] != RECORD_HEADER.size:
        raise ValueError("unsupported event artifact structure sizes")
    expected_sizes = (BASIC_BLOCK.size, MEMORY.size, REGISTER.size)
    if tuple(header["entry_sizes"].values()) != expected_sizes:
        raise ValueError("event artifact entry sizes do not match schema 1")
    if not header["flags"] & 1:
        raise ValueError("event artifact is not complete")
    if header["flags"] & ~(7 if header["schema_version"] == 3 else 3):
        raise ValueError("unknown artifact flags")
    if header["schema_version"] == 3:
        if not header["flags"] & 4:
            raise ValueError("schema3 requires HAS_HARDWARE")
        header["counts"]["hardware_events"] = values[15]
    elif values[15]:
        raise ValueError("reserved header field must be zero")
    header["truncated"] = bool(header["flags"] & 2)
    if header["truncation_reason_code"] not in TRUNCATION_REASONS or (not header["truncated"] and header["truncation_reason_code"]):
        raise ValueError("invalid truncation reason")
    header["truncation_reason"] = TRUNCATION_REASONS.get(
        header["truncation_reason_code"], "unknown")
    header["wait_time_ms"] = header["wait_time_ns"] / 1_000_000
    return header


def _decode_basic(payload):
    values = BASIC_BLOCK.unpack(payload)
    if values[8] not in EDGE_KINDS or values[9] > 1:
        raise ValueError("invalid edge kind or indirect flag")
    if values[7] == 2 and (values[5] or values[6] != 0xFFFFFFFF or values[8] or values[9]):
        raise ValueError("invalid repeat semantic fields")
    result = {
        "record": "event",
        "sequence": values[0],
        "thread_id": values[4],
    }
    if values[6] != 0xFFFFFFFF:
        result["code_version"] = values[6]
    if values[7] == 0:
        result["type"] = "block_entry"
        result["block"] = _hex(values[3])
    elif values[7] == 2:
        result.update({"type": "repeat", "pattern_events": values[1],
                       "additional_repetitions": values[2], "sequence_stride": values[3]})
    elif values[7] == 1:
        result.update({
            "type": "edge",
            "source": _hex(values[1]),
            "source_instruction": _hex(values[2]),
            "target": _hex(values[3]),
            "kind": EDGE_KINDS.get(values[8], "unknown"),
        })
        if values[9]:
            result["indirect"] = True
        if values[5]:
            result["exception_code"] = _hex(values[5])
    else:
        raise ValueError("invalid basic event type")
    if values[10]:
        raise ValueError("nonzero basic event reserved byte")
    return result


def _decode_memory(payload):
    values = MEMORY.unpack(payload)
    size = values[5]
    if not 0 < size <= 16:
        raise ValueError(f"invalid memory event size {size}")
    result = {
        "record": "memory_event",
        "sequence": values[0],
        "instruction": _hex(values[1]),
        "address": _hex(values[2]),
        "thread_id": values[3],
        "dependency_mask": values[4],
        "size": size,
        "access_index": values[7],
        "flags": values[8],
    }
    if values[6] == 0:
        result["kind"] = "read"
        result["value"] = _bytes(values[9], size)
    elif values[6] == 1:
        result["kind"] = "write"
        result["before"] = _bytes(values[10], size)
        result["after"] = _bytes(values[11], size)
    else:
        raise ValueError(f"invalid memory event kind {values[6]}")
    return result


def _decode_register(payload):
    values = REGISTER.unpack(payload)
    before = values[4:22]
    after = values[22:40]
    is_32bit = values[40] != 0
    names = REGISTERS_32 if is_32bit else REGISTERS_64
    changes = {}
    for index, name in enumerate(names):
        if values[3] & (1 << index):
            changes[name] = {"before": _hex(before[index]), "after": _hex(after[index])}
    if values[3] & (1 << 17):
        changes["eflags"] = {"before": _hex(before[17]), "after": _hex(after[17])}
    return {
        "record": "register_event",
        "sequence": values[0],
        "instruction": _hex(values[1]),
        "thread_id": values[2],
        "is_32bit": is_32bit,
        "changes": changes,
    }


class HardwareDecoder:
    """Preserve exact integers and validate confirmed versus uncertain attempts."""
    def __init__(self):
        self.last = None
        self.last_sequence = 0

    def decode(self, payload):
        (sequence, attempt, pc, subject, value, before, after, index, cpl_before,
         cpl_after, reserved, thread, cpu, kind, operation, width, completion,
         known, flags) = HARDWARE.unpack(payload)
        if (not attempt or index >= 16 or reserved or known & ~255 or flags & ~1 or
                cpl_before > 3 or known & 80 != 80 or
                (cpl_after > 3 if known & 128 else cpl_after != 255) or
                (not thread if known & 8 else thread != 0) or
                any(n and not known & bit for n, bit in ((value, 1), (before, 2), (after, 4))) or
                operation not in (1, 2) or completion not in (1, 2)):
            raise ValueError("invalid hardware event fields")
        if completion == 1:
            if not sequence or not known & 32 or not known & 1:
                raise ValueError("confirmed hardware event lacks step/value")
        elif sequence or known & 32:
            raise ValueError("uncertain hardware event claims a completed step")
        if kind == 1:
            valid = width in (4, 8) and subject in (0, 2, 3, 4, 8)
        elif kind == 2:
            valid = width == 8 and subject <= 0xFFFFFFFF
        elif kind == 3:
            valid = (width in (1, 2, 4) and subject <= 0xFFFF and
                     not known & 6 and value < (1 << (width * 8)))
        else:
            valid = False
        if not valid:
            raise ValueError("invalid hardware kind/subject/width")
        current = (attempt, sequence, index, completion, pc, thread, cpu, cpl_before)
        if self.last is not None:
            old = self.last
            if attempt < old[0] or (old[3] == 2 and attempt != old[0]):
                raise ValueError("hardware attempts are unordered or follow an uncertain tail")
            if attempt == old[0]:
                if index != old[2] + 1 or current[1:2] != old[1:2] or current[3:] != old[3:]:
                    raise ValueError("inconsistent hardware attempt")
            elif index or (sequence and sequence <= self.last_sequence):
                raise ValueError("invalid hardware event index/sequence")
        elif index:
            raise ValueError("hardware event index must start at zero")
        self.last = current
        if sequence:
            self.last_sequence = sequence
        return {
            "record": "hardware_event",
            "sequence": str(sequence) if known & 32 else None,
            "attempt": str(attempt), "instruction": _hex(pc), "subject": _hex(subject),
            "value": _hex(value) if known & 1 else None,
            "before": _hex(before) if known & 2 else None,
            "after": _hex(after) if known & 4 else None,
            "event_index": index, "cpu": cpu,
            "thread_id": str(thread) if known & 8 else None,
            "kind": {1: "control_register", 2: "msr", 3: "io_port"}[kind],
            "operation": "read" if operation == 1 else "write",
            "width": width, "completion": "confirmed" if completion == 1 else "uncertain",
            "code_verified": not bool(flags & 1), "cpl_before": cpl_before,
            "cpl_after": cpl_after if known & 128 else None,
        }


class PathDecoder:
    """Validate bounded non-nested raw-suffix references without expanding runs."""
    def __init__(self):
        self.history = []
        self.last_sequence = 0
        self.thread_id = None
        self.expanded_count = 0

    def accept(self, event):
        sequence = event["sequence"]
        if not isinstance(sequence, int) or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("invalid event sequence")
        if sequence < self.last_sequence:
            raise ValueError("path sequences are not ordered")
        if self.thread_id is not None and event["thread_id"] != self.thread_id:
            raise ValueError("path contains another thread")
        self.thread_id = event["thread_id"]
        if event.get("type") != "repeat":
            if event.get("type") not in ("edge", "block_entry"):
                raise ValueError("invalid path event type")
            self.last_sequence = sequence
            self.history = (self.history + [event])[-32:]
            self.expanded_count += 1
            return None
        n = event.get("pattern_events")
        repeats = event.get("additional_repetitions")
        stride = event.get("sequence_stride")
        if (any(type(x) is not int for x in (n, repeats, stride)) or
                not 1 <= n <= min(32, len(self.history)) or repeats < 1 or stride < 1):
            raise ValueError("invalid repeat bounds")
        pattern = self.history[-n:]
        if any(e.get("type") != "edge" or "code_version" not in e or
               e.get("exception_code") or e.get("kind") == "exception" for e in pattern):
            raise ValueError("repeat references an unknown/exception/non-edge template")
        if ("code_version" in event or event.get("exception_code") or event.get("indirect") or
                stride <= pattern[-1]["sequence"] - pattern[0]["sequence"] or
                sequence != pattern[0]["sequence"] + stride):
            raise ValueError("invalid repeat template or sequence stride")
        last = pattern[-1]["sequence"] + repeats * stride
        if last > 0xFFFFFFFFFFFFFFFF or self.expanded_count + n * repeats > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("repeat arithmetic overflow")
        self.last_sequence = last
        self.expanded_count += n * repeats
        self.history = []
        return pattern, repeats, stride


def expand_path_events(events, max_events=5_000_001):
    """Bounded streaming expansion shared by artifact consumers and regressions."""
    decoder = PathDecoder()
    for event in events:
        repeat = decoder.accept(event)
        if decoder.expanded_count > max_events:
            raise ValueError("expanded path exceeds event budget")
        if repeat is None:
            yield event
        else:
            pattern, repetitions, stride = repeat
            for cycle in range(1, repetitions + 1):
                for template in pattern:
                    yield dict(template, sequence=template["sequence"] + cycle * stride)


def iter_records(stream, header):
    remaining = header["record_bytes"]
    paths = PathDecoder()
    hardware = HardwareDecoder()
    counts = {"events": 0, "memory_events": 0, "register_events": 0}
    if header["schema_version"] == 3:
        counts["hardware_events"] = 0
    while remaining:
        raw = stream.read(RECORD_HEADER.size)
        if len(raw) != RECORD_HEADER.size or remaining < RECORD_HEADER.size:
            raise ValueError("incomplete event record header")
        record_type, reserved, payload_size = RECORD_HEADER.unpack(raw)
        if hardware.last is not None and hardware.last[3] == 2 and record_type != RECORD_HARDWARE:
            raise ValueError("record follows an uncertain hardware tail")
        if header["schema_version"] == 2 and record_type != RECORD_BASIC_BLOCK:
            raise ValueError("compressed artifact requires basic path records only")
        remaining -= RECORD_HEADER.size
        expected = {
            RECORD_BASIC_BLOCK: BASIC_BLOCK.size,
            RECORD_MEMORY: MEMORY.size,
            RECORD_REGISTER: REGISTER.size,
            RECORD_HARDWARE: HARDWARE.size if header["schema_version"] == 3 else None,
        }.get(record_type)
        if reserved or expected is None or payload_size != expected or payload_size > remaining:
            raise ValueError("invalid event record header")
        payload = stream.read(payload_size)
        if len(payload) != payload_size:
            raise ValueError("incomplete event record payload")
        remaining -= payload_size
        if record_type == RECORD_BASIC_BLOCK:
            counts["events"] += 1
            event = _decode_basic(payload)
            if event["type"] == "repeat" and header["schema_version"] != 2:
                raise ValueError("repeat record requires artifact schema 2")
            paths.accept(event)
            yield event
        elif record_type == RECORD_MEMORY:
            counts["memory_events"] += 1
            yield _decode_memory(payload)
        elif record_type == RECORD_HARDWARE:
            counts["hardware_events"] += 1
            yield hardware.decode(payload)
        else:
            counts["register_events"] += 1
            yield _decode_register(payload)
    if counts != header["counts"]:
        raise ValueError(f"record counts do not match header: {counts} != {header['counts']}")
    if stream.read(1):
        raise ValueError("event artifact has bytes beyond the declared record stream")


def convert(input_path, output, expand_paths=False):
    with open(input_path, "rb") as stream:
        header = read_header(stream)
        manifest = dict(header)
        manifest["record"] = "manifest"
        manifest.pop("magic")
        output.write(json.dumps(manifest, separators=(",", ":")) + "\n")
        records = iter_records(stream, header)
        if expand_paths and header["schema_version"] == 2:
            records = expand_path_events(records)
        for record in records:
            output.write(json.dumps(record, separators=(",", ":")) + "\n")
    return header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact")
    parser.add_argument("--expand-paths", action="store_true", help="Expand schema 2 repeats (at most 5,000,001 events)")
    parser.add_argument("--output", help="New JSONL file (default: stdout)")
    args = parser.parse_args()
    if args.output and os.path.exists(args.output):
        parser.error("output file already exists")
    try:
        if args.output:
            with open(args.output, "x", encoding="utf-8", newline="\n") as output:
                convert(args.artifact, output, args.expand_paths)
        else:
            convert(args.artifact, sys.stdout, args.expand_paths)
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
