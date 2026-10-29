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

RECORD_BASIC_BLOCK = 1
RECORD_MEMORY = 2
RECORD_REGISTER = 3

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
    if header["schema_version"] not in (SCHEMA_VERSION, 2):
        raise ValueError(f"unsupported event artifact schema {header['schema_version']}")
    if header["header_size"] != HEADER.size or header["record_header_size"] != RECORD_HEADER.size:
        raise ValueError("unsupported event artifact structure sizes")
    expected_sizes = (BASIC_BLOCK.size, MEMORY.size, REGISTER.size)
    if tuple(header["entry_sizes"].values()) != expected_sizes:
        raise ValueError("event artifact entry sizes do not match schema 1")
    if not header["flags"] & 1:
        raise ValueError("event artifact is not complete")
    header["truncated"] = bool(header["flags"] & 2)
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
    counts = {"events": 0, "memory_events": 0, "register_events": 0}
    while remaining:
        raw = stream.read(RECORD_HEADER.size)
        if len(raw) != RECORD_HEADER.size or remaining < RECORD_HEADER.size:
            raise ValueError("incomplete event record header")
        record_type, reserved, payload_size = RECORD_HEADER.unpack(raw)
        if header["schema_version"] == 2 and record_type != RECORD_BASIC_BLOCK:
            raise ValueError("compressed artifact requires basic path records only")
        remaining -= RECORD_HEADER.size
        expected = {
            RECORD_BASIC_BLOCK: BASIC_BLOCK.size,
            RECORD_MEMORY: MEMORY.size,
            RECORD_REGISTER: REGISTER.size,
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
